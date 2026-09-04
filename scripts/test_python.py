#!/usr/bin/env python3
"""Run selected unittest modules in isolated, bounded worker processes.

The runner deliberately has a small surface: select either a directory of
``test_*.py`` files or one or more files, then each file gets one Python
process.  This keeps module globals, patches, and ``tempfile`` state from
leaking between tests without making the suite depend on a test framework.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
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
TERMINATION_GRACE_SECONDS: Final = 2.0
LOG_TAIL_BYTES: Final = 64 * 1024
RESULT_PREFIX: Final = "CRABC_PYTHON_TEST_RESULT "


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


@dataclass
class ActiveWorker:
    """A started module process and its immutable accounting information."""

    index: int
    module: Path
    process: subprocess.Popen[bytes]
    started_at: float
    paths: WorkerPaths


@dataclass(frozen=True)
class ModuleResult:
    """One module's final outcome, retained in discovery order."""

    index: int
    module: Path
    status: str
    elapsed_seconds: float
    tests_run: int
    exit_code: int | None
    paths: WorkerPaths


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


def start_worker(index: int, module: Path, paths: WorkerPaths, run_root: Path) -> ActiveWorker:
    """Start one isolated worker with captured logs and a new process group."""

    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        relative_to_repository(module),
    ]
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
    return ActiveWorker(index, module, process, time.monotonic(), paths)


def read_log_tail(path: Path) -> str:
    """Read enough of a log to find the trailing worker protocol record."""

    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - LOG_TAIL_BYTES))
        return stream.read().decode("utf-8", errors="replace")


def worker_payload(path: Path) -> dict[str, int] | None:
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
        expected = {"tests_run", "failures", "errors", "discovery_errors"}
        if set(decoded) != expected or any(
            type(value) is not int or value < 0 for value in decoded.values()
        ):
            return None
        return decoded
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
    if status is not None:
        tests_run = 0 if payload is None else payload["tests_run"]
        return ModuleResult(worker.index, worker.module, status, elapsed, tests_run, exit_code, worker.paths)
    if payload is None:
        return ModuleResult(
            worker.index,
            worker.module,
            "worker-protocol-error",
            elapsed,
            0,
            exit_code,
            worker.paths,
        )
    if payload["discovery_errors"]:
        state = "discovery-error"
    elif exit_code != 0 or payload["failures"] or payload["errors"]:
        state = "failed"
    elif payload["tests_run"] == 0:
        state = "zero-tests"
    else:
        state = "passed"
    return ModuleResult(
        worker.index,
        worker.module,
        state,
        elapsed,
        payload["tests_run"],
        exit_code,
        worker.paths,
    )


def terminate_active_workers(active: Iterable[ActiveWorker]) -> None:
    """Use the bounded group cleanup path for every currently active worker."""

    for worker in active:
        terminate_worker_group(worker)


def run_modules(modules: Sequence[Path], jobs: int, timeout_seconds: float, run_root: Path) -> tuple[list[ModuleResult], int | None]:
    """Schedule modules up to ``jobs`` at once and preserve discovery ordering."""

    pending = iter(enumerate(modules, start=1))
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
                    index, module = next(pending)
                except StopIteration:
                    exhausted = True
                    break
                paths = worker_paths(run_root, index, module)
                active[index] = start_worker(index, module, paths, run_root)

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
    return (
        f"  {result.status.upper()} {relative_to_repository(result.module)} "
        f"({result.elapsed_seconds:.1f}s, tests={result.tests_run}{exit_detail}; logs: {logs})"
    )


def print_summary(results: Sequence[ModuleResult], jobs: int, run_root: Path, started_at: float) -> int:
    """Print a compact outcome and return the suite exit status."""

    ordered = sorted(results, key=lambda result: result.index)
    failures = [result for result in ordered if result.status != "passed"]
    tests_run = sum(result.tests_run for result in ordered)
    elapsed = time.monotonic() - started_at
    artifact_root = relative_to_repository(run_root)
    # Retain successful-module timings too: throughput decisions need the
    # whole workload, not only the slow modules that happened to fail. This
    # private run owns the sidecar; no shared timing cache or scheduler state.
    summary = {
        "schema": 1,
        "jobs": jobs,
        "tests_run": tests_run,
        "elapsed_seconds": elapsed,
        "modules": [
            {
                "module": relative_to_repository(result.module),
                "status": result.status,
                "tests_run": result.tests_run,
                "exit_code": result.exit_code,
                "elapsed_seconds": result.elapsed_seconds,
            }
            for result in ordered
        ],
    }
    with (run_root / "summary.json").open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    if not failures:
        print(
            f"test-python: passed {len(ordered)} modules / {tests_run} tests "
            f"in {elapsed:.1f}s (jobs={jobs}); logs: {artifact_root}"
        )
        return 0

    print(
        f"test-python: {len(failures)} of {len(ordered)} modules failed "
        f"after {elapsed:.1f}s (tests={tests_run}, jobs={jobs}); logs: {artifact_root}"
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


def worker_main(raw_module: str) -> int:
    """Private child entry point; its JSON line is the parent protocol."""

    try:
        module = resolve_selected_path(raw_module, "worker test module")
        if module.suffix != ".py" or not module.is_file():
            raise TestPythonError(f"worker test module must be a regular Python file: {raw_module}")
        suite = unittest.defaultTestLoader.discover(str(module.parent), pattern=module.name)
        discovery_errors = failed_test_count(suite)
        result = unittest.TextTestRunner(verbosity=1, stream=sys.stderr).run(suite)
        payload = {
            "tests_run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "discovery_errors": discovery_errors,
        }
        print(RESULT_PREFIX + json.dumps(payload, sort_keys=True), flush=True)
        return 0 if result.wasSuccessful() else 1
    except TestPythonError as error:
        print(f"test-python worker: {error}", file=sys.stderr)
        print(
            RESULT_PREFIX
            + json.dumps(
                {"tests_run": 0, "failures": 0, "errors": 1, "discovery_errors": 1},
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
    parser.add_argument("--pattern", default="test_*.py", help="filename pattern for --directory (default: %(default)s)")
    parser.add_argument("--jobs", type=int, help=f"workers, from 1 to {MAX_JOBS} (default: conservative CPU bound)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"per-module seconds before group termination (default: {DEFAULT_TIMEOUT_SECONDS:g})",
    )
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    args = parser.parse_args(arguments)
    if args.worker is not None:
        if args.directory is not None or args.modules:
            parser.error("--worker cannot be combined with test selection")
        return args
    if args.directory is None and not args.modules:
        parser.error("one of --directory or --module is required")
    if args.jobs is None:
        args.jobs = min(max(1, os.cpu_count() or 1), DEFAULT_JOBS_CAP)
    if not 1 <= args.jobs <= MAX_JOBS:
        parser.error(f"--jobs must be between 1 and {MAX_JOBS}")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and greater than zero")
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
        return worker_main(args.worker)
    try:
        modules = select_modules(args)
        run_root = new_run_root()
        started_at = time.monotonic()
        results, interrupted_by = run_modules(modules, args.jobs, args.timeout, run_root)
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
