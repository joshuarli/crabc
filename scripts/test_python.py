#!/usr/bin/env python3
"""Run selected unittest modules in isolated, bounded worker processes.

The runner deliberately has a small surface: select either a directory of
``test_*.py`` files or one or more files, then each ordinary file gets one
Python process. The audited parity-ledger module is bounded into selected-case
workers by default. This keeps module globals, patches, and ``tempfile`` state
from leaking between tests without making the suite depend on a test framework.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final


REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
WORK_ROOT_NAME: Final = ".work"
RUN_ROOT_NAME: Final = "python-test-runs"
DEFAULT_JOBS_CAP: Final = 4
MAX_JOBS: Final = 8
DEFAULT_TIMEOUT_SECONDS: Final = 300.0
DEFAULT_CASE_SHARD_SIZE: Final = 40
TERMINATION_GRACE_SECONDS: Final = 2.0
LOG_TAIL_BYTES: Final = 64 * 1024
RESULT_PREFIX: Final = "CRABC_PYTHON_TEST_RESULT "
PROGRESS_PREFIX: Final = "CRABC_PYTHON_TEST_PROGRESS "
PARITY_LEDGER_TEST_MODULE: Final = "compat/x86_64/tests/test_parity_ledger.py"


class TestPythonError(RuntimeError):
    """A selection, workspace, or worker-protocol contract violation."""


@dataclass(frozen=True)
class WorkerPaths:
    """The private writable directories provided to one test module."""

    root: Path
    temporary: Path
    scratch: Path
    reports: Path
    stdout: Path
    stderr: Path


@dataclass(frozen=True)
class TestJob:
    """One module or an isolated, selected-case subset of one module."""

    module: Path
    case_ids: tuple[str, ...] = ()


@dataclass
class ActiveWorker:
    """A started module process and its immutable accounting information."""

    index: int
    module: Path
    process: subprocess.Popen[bytes]
    started_at: float
    paths: WorkerPaths
    case_ids: tuple[str, ...]


@dataclass(frozen=True)
class WorkerProgress:
    """Last flushed case boundary, usable when a worker has no final record."""

    tests_started: int
    tests_completed: int
    current_test_id: str | None
    current_started_at: float | None
    last_test_id: str | None
    last_elapsed_seconds: float | None


@dataclass(frozen=True)
class WorkerPayload:
    """The typed final worker record, including selected-case completion proof."""

    tests_run: int
    failures: int
    errors: int
    discovery_errors: int
    completed_case_ids: tuple[str, ...]


@dataclass(frozen=True)
class ModuleResult:
    """One module's final outcome, retained in discovery order."""

    index: int
    module: Path
    status: str
    elapsed_seconds: float
    tests_run: int
    tests_completed: int
    exit_code: int | None
    paths: WorkerPaths
    case_ids: tuple[str, ...]
    current_test_id: str | None
    current_test_elapsed_seconds: float | None


def relative_to_repository(path: Path) -> str:
    """Render a checked repository descendant without exposing host paths."""

    return path.relative_to(REPOSITORY_ROOT).as_posix()


def require_directory_without_symlink(path: Path, description: str, *, create: bool) -> Path:
    """Return a physical directory while refusing a symlink at this boundary."""

    if create:
        path.mkdir(parents=True, exist_ok=True)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise TestPythonError(f"{description} does not exist: {path}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise TestPythonError(f"{description} must not be a symlink: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise TestPythonError(f"{description} must be a directory: {path}")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise TestPythonError(f"{description} must be a physical checkout path: {path}")
    return resolved


def resolve_selected_path(raw: str, description: str) -> Path:
    """Resolve one existing repository-relative path without crossing symlinks."""

    requested = Path(raw)
    if requested.is_absolute() or not requested.parts:
        raise TestPythonError(f"{description} must be a non-empty repository-relative path: {raw}")

    candidate = REPOSITORY_ROOT
    for component in requested.parts:
        if component in ("", ".", ".."):
            raise TestPythonError(f"{description} must not contain traversal: {raw}")
        candidate /= component
        if os.path.lexists(candidate) and candidate.is_symlink():
            raise TestPythonError(f"{description} must not cross a symlink: {raw}")

    if not candidate.exists():
        raise TestPythonError(f"discovery error: {description} does not exist: {raw}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(REPOSITORY_ROOT):
        raise TestPythonError(f"{description} escapes the checkout: {raw}")
    if resolved != candidate:
        raise TestPythonError(f"{description} must be a physical checkout path: {raw}")
    return resolved


def module_paths_in_directory(directory: Path, pattern: str) -> list[Path]:
    """Find regular matching modules and reject symlinked discovery inputs."""

    if Path(pattern).name != pattern:
        raise TestPythonError(f"test pattern must match filenames only: {pattern}")

    def on_walk_error(error: OSError) -> None:
        reason = error.strerror or str(error)
        raise TestPythonError(f"discovery error: unable to read selected directory: {reason}")

    modules: list[Path] = []
    try:
        walked = os.walk(directory, followlinks=False, onerror=on_walk_error)
        for current, directories, filenames in walked:
            current_path = Path(current)
            for name in directories:
                if (current_path / name).is_symlink():
                    raise TestPythonError(
                        f"discovery error: selected directory contains a symlink: "
                        f"{relative_to_repository(current_path / name)}"
                    )
            for name in filenames:
                path = current_path / name
                if not fnmatch.fnmatch(name, pattern):
                    continue
                if path.is_symlink():
                    raise TestPythonError(
                        f"discovery error: selected test module is a symlink: "
                        f"{relative_to_repository(path)}"
                    )
                if not path.is_file():
                    raise TestPythonError(
                        f"discovery error: selected test module is not a regular file: "
                        f"{relative_to_repository(path)}"
                    )
                modules.append(path.resolve(strict=True))
    except OSError as error:
        on_walk_error(error)
    return sorted(modules, key=relative_to_repository)


def select_modules(args: argparse.Namespace) -> list[Path]:
    """Turn the focused command-line selection into a stable module list."""

    if args.directory is not None:
        directory = resolve_selected_path(args.directory, "test directory")
        if not directory.is_dir():
            raise TestPythonError(f"test directory must be a directory: {args.directory}")
        modules = module_paths_in_directory(directory, args.pattern)
    else:
        modules = []
        seen: set[Path] = set()
        for raw in args.modules:
            module = resolve_selected_path(raw, "test module")
            if module.suffix != ".py" or not module.is_file():
                raise TestPythonError(f"test module must be a regular Python file: {raw}")
            if module not in seen:
                modules.append(module)
                seen.add(module)

    if not modules:
        raise TestPythonError("discovery error: selection matched zero test modules")
    return modules


def test_cases_in_suite(suite: unittest.TestSuite | unittest.TestCase) -> list[unittest.TestCase]:
    """Flatten discovery without running test setup or test bodies."""

    if isinstance(suite, unittest.TestSuite):
        cases: list[unittest.TestCase] = []
        for child in suite:
            cases.extend(test_cases_in_suite(child))
        return cases
    if not isinstance(suite, unittest.TestCase):
        raise TestPythonError("discovery error: suite contains a non-test case")
    return [suite]


def parity_ledger_case_ids(module: Path) -> tuple[str, ...]:
    """Discover the audited parity tests once, solely to form safe case shards."""

    if relative_to_repository(module) != PARITY_LEDGER_TEST_MODULE:
        raise TestPythonError(
            "case sharding is currently limited to " + PARITY_LEDGER_TEST_MODULE
        )
    original_dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        suite = unittest.defaultTestLoader.discover(str(module.parent), pattern=module.name)
    finally:
        sys.dont_write_bytecode = original_dont_write_bytecode
    case_ids = tuple(case.id() for case in test_cases_in_suite(suite))
    if len(set(case_ids)) != len(case_ids):
        raise TestPythonError("case-shard discovery produced duplicate test IDs")
    return case_ids


def sharded_parity_jobs(module: Path, shard_size: int) -> list[TestJob]:
    """Form bounded jobs from the one audited module that is process-safe to shard."""

    case_ids = parity_ledger_case_ids(module)
    if not case_ids:
        # Preserve the ordinary zero-test outcome instead of silently passing
        # an empty selected-case shard.
        return [TestJob(module)]
    return [
        TestJob(module, case_ids[index : index + shard_size])
        for index in range(0, len(case_ids), shard_size)
    ]


def select_jobs(args: argparse.Namespace) -> list[TestJob]:
    """Shard only audited parity cases; leave every other selected module whole."""

    modules = select_modules(args)
    if args.case_ids:
        if args.directory is not None or len(modules) != 1:
            raise TestPythonError("selected cases require exactly one --module selection")
        if len(set(args.case_ids)) != len(args.case_ids):
            raise TestPythonError("selected cases must not contain duplicate test IDs")
        case_ids = tuple(args.case_ids)
        if args.case_shard_size is None:
            return [TestJob(modules[0], case_ids)]
        return [
            TestJob(modules[0], case_ids[index : index + args.case_shard_size])
            for index in range(0, len(case_ids), args.case_shard_size)
        ]

    if args.no_case_sharding:
        return [TestJob(module) for module in modules]

    parity_modules = [
        module
        for module in modules
        if relative_to_repository(module) == PARITY_LEDGER_TEST_MODULE
    ]
    if args.case_shard_size is not None and not parity_modules:
        raise TestPythonError(
            "case sharding without --case is currently limited to "
            + PARITY_LEDGER_TEST_MODULE
        )
    shard_size = args.case_shard_size or DEFAULT_CASE_SHARD_SIZE
    jobs: list[TestJob] = []
    for module in modules:
        if module in parity_modules:
            jobs.extend(sharded_parity_jobs(module, shard_size))
        else:
            jobs.append(TestJob(module))
    return jobs


def worker_paths(run_root: Path, index: int, module: Path) -> WorkerPaths:
    """Create a unique, stable-named private directory for one module."""

    stem = "".join(character if character.isalnum() else "-" for character in module.stem)
    root = run_root / "modules" / f"{index:03d}-{stem}"
    temporary = root / "tmp"
    scratch = root / "scratch"
    reports = root / "reports"
    for directory in (temporary, scratch, reports):
        directory.mkdir(parents=True, exist_ok=False)
    return WorkerPaths(
        root=root,
        temporary=temporary,
        scratch=scratch,
        reports=reports,
        stdout=root / "stdout.log",
        stderr=root / "stderr.log",
    )


def worker_environment(paths: WorkerPaths, run_root: Path) -> dict[str, str]:
    """Give a module only checkout-contained defaults for its mutable state."""

    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "TMPDIR": str(paths.temporary),
            "TEMP": str(paths.temporary),
            "TMP": str(paths.temporary),
            "CRABC_PYTHON_TEST_RUN_ROOT": str(run_root),
            "CRABC_PYTHON_TEST_WORK_ROOT": str(paths.root),
            "CRABC_PYTHON_TEST_SCRATCH": str(paths.scratch),
            "CRABC_PYTHON_TEST_REPORTS": str(paths.reports),
            # The allocator unit modules import `compat/allocator/run.py`,
            # whose own temporary/report roots are selected at import time.
            "CRABC_WORK_DIR": str(paths.root),
        }
    )
    return environment


def start_worker(index: int, job: TestJob, paths: WorkerPaths, run_root: Path) -> ActiveWorker:
    """Start one isolated worker with captured logs and a new process group."""

    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        relative_to_repository(job.module),
    ]
    for case_id in job.case_ids:
        command.extend(("--worker-case", case_id))
    with paths.stdout.open("wb") as stdout, paths.stderr.open("wb") as stderr:
        process = subprocess.Popen(
            command,
            cwd=REPOSITORY_ROOT,
            env=worker_environment(paths, run_root),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
    return ActiveWorker(index, job.module, process, time.monotonic(), paths, job.case_ids)


def read_log_tail(path: Path) -> str:
    """Read enough of a log to find the trailing worker protocol record."""

    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - LOG_TAIL_BYTES))
        return stream.read().decode("utf-8", errors="replace")


def worker_payload(path: Path) -> WorkerPayload | None:
    """Return the final typed worker record, never arbitrary test output."""

    for line in reversed(read_log_tail(path).splitlines()):
        if not line.startswith(RESULT_PREFIX):
            continue
        try:
            decoded = json.loads(line.removeprefix(RESULT_PREFIX))
        except json.JSONDecodeError:
            return None
        if not isinstance(decoded, dict):
            return None
        expected = {
            "tests_run",
            "failures",
            "errors",
            "discovery_errors",
            "completed_case_ids",
        }
        if set(decoded) != expected:
            return None
        counts = (decoded["tests_run"], decoded["failures"], decoded["errors"], decoded["discovery_errors"])
        completed_case_ids = decoded["completed_case_ids"]
        if (
            any(type(value) is not int or value < 0 for value in counts)
            or not isinstance(completed_case_ids, list)
            or any(not isinstance(case_id, str) for case_id in completed_case_ids)
        ):
            return None
        return WorkerPayload(*counts, tuple(completed_case_ids))
    return None


def worker_progress(path: Path) -> WorkerProgress | None:
    """Read the last complete per-case checkpoint from one private worker log."""

    for line in reversed(read_log_tail(path).splitlines()):
        if not line.startswith(PROGRESS_PREFIX):
            continue
        try:
            decoded = json.loads(line.removeprefix(PROGRESS_PREFIX))
        except json.JSONDecodeError:
            continue
        if not isinstance(decoded, dict) or set(decoded) != {
            "tests_started",
            "tests_completed",
            "current_test_id",
            "current_started_at",
            "last_test_id",
            "last_elapsed_seconds",
        }:
            continue
        started = decoded["tests_started"]
        completed = decoded["tests_completed"]
        if (
            type(started) is not int
            or type(completed) is not int
            or started < completed
            or completed < 0
        ):
            continue
        current = decoded["current_test_id"]
        current_started_at = decoded["current_started_at"]
        last = decoded["last_test_id"]
        last_elapsed = decoded["last_elapsed_seconds"]
        if current is not None and not isinstance(current, str):
            continue
        if last is not None and not isinstance(last, str):
            continue
        if current_started_at is not None and (
            type(current_started_at) not in (int, float)
            or not math.isfinite(current_started_at)
        ):
            continue
        if last_elapsed is not None and (
            type(last_elapsed) not in (int, float)
            or not math.isfinite(last_elapsed)
            or last_elapsed < 0
        ):
            continue
        return WorkerProgress(
            started,
            completed,
            current,
            current_started_at,
            last,
            last_elapsed,
        )
    return None


def group_is_alive(process_group: int) -> bool:
    """Ask the kernel whether a worker's original process group remains."""

    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def process_group_has_live_members(process_group: int) -> bool:
    """Detect non-zombie descendants left in a finished worker's group."""

    if not group_is_alive(process_group):
        return False
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                fields = (entry / "stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
                state, group = fields[0], int(fields[2])
            except (IndexError, OSError, ValueError):
                continue
            if group == process_group and state not in ("X", "Z"):
                return True
    except OSError:
        # The worker group still exists but `/proc` could not establish that
        # it is zombie-only. Treat it as live rather than silently passing.
        return True
    return False


def terminate_worker_group(worker: ActiveWorker) -> None:
    """Terminate one timed-out/interrupted worker group, then reap its leader."""

    process = worker.process
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass

    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    while group_is_alive(process_group) and time.monotonic() < deadline:
        time.sleep(0.05)
    if group_is_alive(process_group):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        # A direct child that ignored both group signals is still reaped before
        # returning; its process group was already sent SIGKILL above.
        process.kill()
        process.wait()


def completed_result(worker: ActiveWorker, status: str | None = None) -> ModuleResult:
    """Classify a reaped worker without printing its captured output."""

    elapsed = time.monotonic() - worker.started_at
    exit_code = worker.process.returncode
    payload = worker_payload(worker.paths.stdout)
    progress = worker_progress(worker.paths.stdout)
    tests_run = 0 if payload is None else payload.tests_run
    tests_completed = tests_run
    current_test_id = None
    current_test_elapsed_seconds = None
    if progress is not None:
        if payload is None:
            tests_run = progress.tests_started
        tests_completed = progress.tests_completed
        current_test_id = progress.current_test_id
        if progress.current_started_at is not None:
            current_test_elapsed_seconds = max(
                0.0, time.monotonic() - progress.current_started_at
            )
    if status is not None:
        return ModuleResult(
            worker.index,
            worker.module,
            status,
            elapsed,
            tests_run,
            tests_completed,
            exit_code,
            worker.paths,
            worker.case_ids,
            current_test_id,
            current_test_elapsed_seconds,
        )
    if payload is None:
        return ModuleResult(
            worker.index,
            worker.module,
            "worker-protocol-error",
            elapsed,
            tests_run,
            tests_completed,
            exit_code,
            worker.paths,
            worker.case_ids,
            current_test_id,
            current_test_elapsed_seconds,
        )
    selected_cases_complete = (
        not worker.case_ids
        or (
            payload.tests_run == len(worker.case_ids)
            and payload.completed_case_ids == worker.case_ids
        )
    )
    if payload.discovery_errors:
        state = "discovery-error"
    elif not selected_cases_complete:
        state = "incomplete-selection"
    elif exit_code != 0 or payload.failures or payload.errors:
        state = "failed"
    elif payload.tests_run == 0:
        state = "zero-tests"
    else:
        state = "passed"
    return ModuleResult(
        worker.index,
        worker.module,
        state,
        elapsed,
        tests_run,
        tests_completed,
        exit_code,
        worker.paths,
        worker.case_ids,
        current_test_id,
        current_test_elapsed_seconds,
    )


def terminate_active_workers(active: Iterable[ActiveWorker]) -> None:
    """Use the bounded group cleanup path for every currently active worker."""

    for worker in active:
        terminate_worker_group(worker)


def run_modules(jobs_to_run: Sequence[TestJob], jobs: int, timeout_seconds: float, run_root: Path) -> tuple[list[ModuleResult], int | None]:
    """Schedule isolated module or selected-case jobs in stable discovery order."""

    pending = iter(enumerate(jobs_to_run, start=1))
    active: dict[int, ActiveWorker] = {}
    results: list[ModuleResult] = []
    interrupted_by: int | None = None

    def note_interruption(signum: int, _frame: object) -> None:
        nonlocal interrupted_by
        interrupted_by = signum

    previous_handlers = {
        signum: signal.signal(signum, note_interruption) for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        exhausted = False
        while active or not exhausted:
            if interrupted_by is not None:
                terminate_active_workers(active.values())
                return results, interrupted_by

            while len(active) < jobs and not exhausted:
                try:
                    index, job = next(pending)
                except StopIteration:
                    exhausted = True
                    break
                paths = worker_paths(run_root, index, job.module)
                active[index] = start_worker(index, job, paths, run_root)

            made_progress = False
            now = time.monotonic()
            for index in sorted(tuple(active)):
                worker = active[index]
                if worker.process.poll() is not None:
                    worker.process.wait()
                    if process_group_has_live_members(worker.process.pid):
                        terminate_worker_group(worker)
                        results.append(completed_result(worker, "process-group-leak"))
                    else:
                        results.append(completed_result(worker))
                    del active[index]
                    made_progress = True
                elif now - worker.started_at >= timeout_seconds:
                    terminate_worker_group(worker)
                    results.append(completed_result(worker, "timeout"))
                    del active[index]
                    made_progress = True

            if not made_progress and active:
                time.sleep(0.05)
    except BaseException:
        terminate_active_workers(active.values())
        raise
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
    return results, None


def describe_result(result: ModuleResult) -> str:
    """Make one concise, ordered failure line without copying child output."""

    logs = f"{relative_to_repository(result.paths.stdout)}, {relative_to_repository(result.paths.stderr)}"
    exit_detail = "" if result.exit_code is None else f", exit={result.exit_code}"
    progress_detail = f", completed={result.tests_completed}"
    if result.current_test_id is not None:
        current_elapsed = ""
        if result.current_test_elapsed_seconds is not None:
            current_elapsed = f" {result.current_test_elapsed_seconds:.1f}s"
        progress_detail += f", current={result.current_test_id}{current_elapsed}"
    return (
        f"  {result.status.upper()} {relative_to_repository(result.module)} "
        f"({result.elapsed_seconds:.1f}s, tests={result.tests_run}{progress_detail}"
        f"{exit_detail}; logs: {logs})"
    )


def print_summary(results: Sequence[ModuleResult], jobs: int, run_root: Path, started_at: float) -> int:
    """Print a compact outcome and return the suite exit status."""

    ordered = sorted(results, key=lambda result: result.index)
    failures = [result for result in ordered if result.status != "passed"]
    tests_run = sum(result.tests_run for result in ordered)
    tests_completed = sum(result.tests_completed for result in ordered)
    elapsed = time.monotonic() - started_at
    artifact_root = relative_to_repository(run_root)
    sharded = any(result.case_ids for result in ordered)
    unit = "jobs" if sharded else "modules"
    # Retain successful-module timings too: throughput decisions need the
    # whole workload, not only the slow modules that happened to fail. This
    # private run owns the sidecar; no shared timing cache or scheduler state.
    summary = {
        "schema": 1,
        "jobs": jobs,
        "tests_run": tests_run,
        "tests_completed": tests_completed,
        "elapsed_seconds": elapsed,
        "modules": [
            {
                "module": relative_to_repository(result.module),
                "status": result.status,
                "tests_run": result.tests_run,
                "tests_completed": result.tests_completed,
                "exit_code": result.exit_code,
                "elapsed_seconds": result.elapsed_seconds,
                "selected_case_ids": list(result.case_ids),
                "current_test_id": result.current_test_id,
                "current_test_elapsed_seconds": result.current_test_elapsed_seconds,
            }
            for result in ordered
        ],
    }
    with (run_root / "summary.json").open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    if not failures:
        print(
            f"test-python: passed {len(ordered)} {unit} / {tests_run} tests "
            f"in {elapsed:.1f}s (jobs={jobs}); logs: {artifact_root}"
        )
        return 0

    print(
        f"test-python: {len(failures)} of {len(ordered)} {unit} failed "
        f"after {elapsed:.1f}s (tests={tests_run}, completed={tests_completed}, jobs={jobs}); "
        f"logs: {artifact_root}"
    )
    print("test-python: ordered failures:")
    for result in failures:
        print(describe_result(result))
    return 1


def failed_test_count(suite: unittest.TestSuite | unittest.TestCase) -> int:
    """Count loader-created failed tests before running consumes their suites."""

    failed_type = unittest.loader._FailedTest
    if isinstance(suite, failed_type):
        return 1
    if isinstance(suite, unittest.TestSuite):
        return sum(failed_test_count(test) for test in suite)
    return 0


def selected_case_suite(
    suite: unittest.TestSuite | unittest.TestCase, case_ids: Sequence[str]
) -> unittest.TestSuite | unittest.TestCase:
    """Select exact discovered IDs without importing a second copy of a module."""

    if not case_ids:
        return suite
    if len(set(case_ids)) != len(case_ids):
        raise TestPythonError("worker selected duplicate test case IDs")
    by_id = {case.id(): case for case in test_cases_in_suite(suite)}
    missing = [case_id for case_id in case_ids if case_id not in by_id]
    if missing:
        raise TestPythonError("worker selected test case was not discovered: " + missing[0])
    return unittest.TestSuite(by_id[case_id] for case_id in case_ids)


class ImmediateDiagnosticResult(unittest.TextTestResult):
    """Retain normal unittest accounting but flush each failure immediately.

    Long modules must not hide the first actionable traceback until their
    last test finishes. Logs remain worker-private; only diagnostic timing
    changes, not test selection, assertions, or the parent's result protocol.
    """

    def __init__(self, *arguments, **keywords) -> None:
        super().__init__(*arguments, **keywords)
        self._tests_completed = 0
        self._current_test_id: str | None = None
        self._current_started_at: float | None = None
        self._last_test_id: str | None = None
        self._last_elapsed_seconds: float | None = None
        self._completed_case_ids: list[str] = []
        self.emit_progress()

    @property
    def completed_case_ids(self) -> tuple[str, ...]:
        """Return the exact cases whose ``stopTest`` boundary was reached."""

        return tuple(self._completed_case_ids)

    def emit_progress(self) -> None:
        """Flush a compact checkpoint so a killed worker retains its position."""

        print(
            PROGRESS_PREFIX
            + json.dumps(
                {
                    "tests_started": self.testsRun,
                    "tests_completed": self._tests_completed,
                    "current_test_id": self._current_test_id,
                    "current_started_at": self._current_started_at,
                    "last_test_id": self._last_test_id,
                    "last_elapsed_seconds": self._last_elapsed_seconds,
                },
                sort_keys=True,
            ),
            flush=True,
        )

    def startTest(self, test) -> None:
        super().startTest(test)
        self._current_test_id = test.id()
        self._current_started_at = time.monotonic()
        self.emit_progress()

    def stopTest(self, test) -> None:
        started_at = self._current_started_at
        super().stopTest(test)
        self._tests_completed += 1
        self._completed_case_ids.append(test.id())
        self._last_test_id = test.id()
        self._last_elapsed_seconds = 0.0 if started_at is None else max(
            0.0, time.monotonic() - started_at
        )
        self._current_test_id = None
        self._current_started_at = None
        self.emit_progress()

    def emit_latest(self, label: str, records: list) -> None:
        self.stream.writeln()
        self.printErrorList(label, records[-1:])
        self.stream.flush()

    def addFailure(self, test, err) -> None:
        super().addFailure(test, err)
        self.emit_latest("FAIL", self.failures)

    def addError(self, test, err) -> None:
        super().addError(test, err)
        self.emit_latest("ERROR", self.errors)

    def addSubTest(self, test, subtest, err) -> None:
        failures, errors = len(self.failures), len(self.errors)
        super().addSubTest(test, subtest, err)
        if len(self.failures) != failures:
            self.emit_latest("FAIL", self.failures)
        if len(self.errors) != errors:
            self.emit_latest("ERROR", self.errors)

    def addUnexpectedSuccess(self, test) -> None:
        super().addUnexpectedSuccess(test)
        self.stream.writeln(f"\nUNEXPECTED SUCCESS: {self.getDescription(test)}")
        self.stream.flush()

    def printErrors(self) -> None:
        # Details were already flushed. TextTestRunner still prints its
        # ordinary final counts using the untouched result lists.
        if self.dots or self.showAll:
            self.stream.writeln()


def worker_main(raw_module: str, case_ids: Sequence[str]) -> int:
    """Private child entry point; its JSON line is the parent protocol."""

    try:
        # Fixtures can deliberately abort native children. Apply the policy
        # before discovery/import, and lower the hard limit so ordinary child
        # processes cannot re-enable shared-CWD core dumps. The launcher and
        # its caller retain their own limits.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        module = resolve_selected_path(raw_module, "worker test module")
        if module.suffix != ".py" or not module.is_file():
            raise TestPythonError(f"worker test module must be a regular Python file: {raw_module}")
        suite = unittest.defaultTestLoader.discover(str(module.parent), pattern=module.name)
        discovery_errors = failed_test_count(suite)
        suite = selected_case_suite(suite, case_ids)
        result = unittest.TextTestRunner(
            verbosity=1, stream=sys.stderr, resultclass=ImmediateDiagnosticResult
        ).run(suite)
        payload = {
            "tests_run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "discovery_errors": discovery_errors,
            "completed_case_ids": list(result.completed_case_ids) if case_ids else [],
        }
        print(RESULT_PREFIX + json.dumps(payload, sort_keys=True), flush=True)
        selection_complete = not case_ids or (
            result.testsRun == len(case_ids)
            and result.completed_case_ids == tuple(case_ids)
        )
        if not selection_complete:
            print(
                "test-python worker: selected cases stopped before completion "
                f"({len(result.completed_case_ids)}/{len(case_ids)})",
                file=sys.stderr,
            )
        return 0 if result.wasSuccessful() and selection_complete else 1
    except TestPythonError as error:
        print(f"test-python worker: {error}", file=sys.stderr)
        print(
            RESULT_PREFIX
            + json.dumps(
                {
                    "tests_run": 0,
                    "failures": 0,
                    "errors": 1,
                    "discovery_errors": 1,
                    "completed_case_ids": [],
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 2


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the intentionally narrow public selection and scheduling surface."""

    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--directory", help="repository-relative directory of test files")
    selection.add_argument(
        "--module",
        dest="modules",
        action="append",
        default=[],
        help="repository-relative test file; may be repeated",
    )
    parser.add_argument(
        "--case",
        dest="case_ids",
        action="append",
        default=[],
        help="exact unittest ID; requires one --module and may be repeated",
    )
    parser.add_argument("--pattern", default="test_*.py", help="filename pattern for --directory (default: %(default)s)")
    parser.add_argument("--jobs", type=int, help=f"workers, from 1 to {MAX_JOBS} (default: conservative CPU bound)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"per-worker seconds before group termination (default: {DEFAULT_TIMEOUT_SECONDS:g})",
    )
    sharding = parser.add_mutually_exclusive_group()
    sharding.add_argument(
        "--case-shard-size",
        type=int,
        help=(
            "split the audited parity-ledger module into selected-case workers "
            f"of this size (use {DEFAULT_CASE_SHARD_SIZE} for the normal bounded shard)"
        ),
    )
    sharding.add_argument(
        "--no-case-sharding",
        action="store_true",
        help="keep the audited parity-ledger module as one monolithic worker",
    )
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    parser.add_argument("--worker-case", action="append", default=[], help=argparse.SUPPRESS)
    args = parser.parse_args(arguments)
    if args.worker is not None:
        if (
            args.directory is not None
            or args.modules
            or args.case_ids
            or args.case_shard_size is not None
        ):
            parser.error("--worker cannot be combined with test selection")
        return args
    if args.worker_case:
        parser.error("--worker-case is only valid with --worker")
    if args.directory is None and not args.modules:
        parser.error("one of --directory or --module is required")
    if args.case_ids and args.directory is not None:
        parser.error("--case requires exactly one --module selection")
    if args.jobs is None:
        args.jobs = min(max(1, os.cpu_count() or 1), DEFAULT_JOBS_CAP)
    if not 1 <= args.jobs <= MAX_JOBS:
        parser.error(f"--jobs must be between 1 and {MAX_JOBS}")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and greater than zero")
    if args.case_shard_size is not None and args.case_shard_size <= 0:
        parser.error("--case-shard-size must be greater than zero")
    return args


def new_run_root() -> Path:
    """Allocate a retained unique run directory below physical checkout ``.work``."""

    work_root = require_directory_without_symlink(
        REPOSITORY_ROOT / WORK_ROOT_NAME,
        "checkout .work directory",
        create=True,
    )
    runs_root = require_directory_without_symlink(
        work_root / RUN_ROOT_NAME,
        "Python test run directory",
        create=True,
    )
    return Path(tempfile.mkdtemp(prefix="run-", dir=runs_root)).resolve(strict=True)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the requested selected suite, preserving failed-run artifacts."""

    args = parse_args(arguments)
    if args.worker is not None:
        return worker_main(args.worker, args.worker_case)
    try:
        jobs_to_run = select_jobs(args)
        run_root = new_run_root()
        started_at = time.monotonic()
        results, interrupted_by = run_modules(jobs_to_run, args.jobs, args.timeout, run_root)
        if interrupted_by is not None:
            print(
                f"test-python: interrupted by signal {interrupted_by}; "
                f"retained logs: {relative_to_repository(run_root)}",
                file=sys.stderr,
            )
            return 128 + interrupted_by
        return print_summary(results, args.jobs, run_root, started_at)
    except TestPythonError as error:
        print(f"test-python: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
