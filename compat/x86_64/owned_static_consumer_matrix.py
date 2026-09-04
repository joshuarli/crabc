#!/usr/bin/env python3
"""Run the independent owned-static consumers with bounded process ownership.

The installed-sysroot producer remains deliberately sequential.  This helper
only schedules already independent consumer jobs, each in a fresh process
group with a private captured log.  It is local to that product runner rather
than a general test framework.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Sequence


DEFAULT_WORKERS: Final = 4
MAX_WORKERS: Final = 8
DEFAULT_TIMEOUT_SECONDS: Final = 300.0
MAX_TIMEOUT_SECONDS: Final = 900.0
TERMINATION_GRACE_SECONDS: Final = 2.0
POLL_SECONDS: Final = 0.05
JOB_NAME: Final = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
CHECKOUT_ROOT: Final = Path(__file__).resolve().parents[2]
CHECKOUT_WORK_ROOT: Final = CHECKOUT_ROOT / ".work"


class MatrixError(RuntimeError):
    """A matrix input or checkout-state boundary is invalid."""


@dataclass(frozen=True)
class ConsumerJob:
    """One independently runnable installed consumer command."""

    index: int
    name: str
    argv: tuple[str, ...]


@dataclass
class ActiveJob:
    """A running child and the process group it exclusively owns."""

    job: ConsumerJob
    process: subprocess.Popen[bytes]
    started_at: float
    log_path: Path


@dataclass(frozen=True)
class JobResult:
    """The retained terminal result for one started matrix job."""

    job: ConsumerJob
    status: str
    exit_code: int | None
    elapsed_seconds: float
    log_path: Path
    detail: str | None = None


def reject_symlinked_components(path: Path, description: str) -> None:
    """Reject an absolute lexical path that crosses a present symlink."""

    if not path.is_absolute() or any(part in ("", ".", "..") for part in path.parts[1:]):
        raise MatrixError(f"{description} must be an absolute path without traversal: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if os.path.lexists(current) and current.is_symlink():
            raise MatrixError(f"{description} crosses a symlink: {path}")


def require_physical_directory(path: Path, description: str) -> Path:
    """Resolve one existing directory only after rejecting symlink aliases."""

    reject_symlinked_components(path, description)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise MatrixError(f"{description} does not exist: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise MatrixError(f"{description} is not a physical directory: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise MatrixError(f"{description} is unreadable: {path}") from error
    if resolved != path:
        raise MatrixError(f"{description} is not a physical directory: {path}")
    return resolved


def require_checkout_state_root(path: Path) -> Path:
    """Accept only a dedicated physical state directory below this checkout."""

    checkout_work_root = require_physical_directory(
        CHECKOUT_WORK_ROOT, "checkout .work root"
    )
    state_root = require_physical_directory(path, "state root")
    try:
        relative = state_root.relative_to(checkout_work_root)
    except ValueError as error:
        raise MatrixError(
            f"state root must stay below checkout .work: {state_root}"
        ) from error
    if not relative.parts:
        raise MatrixError("state root must name a dedicated directory below checkout .work")
    return state_root


def require_child_path(root: Path, path: Path, description: str) -> Path:
    """Require a physical existing path below the caller-owned state root."""

    reject_symlinked_components(path, description)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise MatrixError(f"{description} escapes the state root: {path}") from error
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise MatrixError(f"{description} does not exist: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise MatrixError(f"{description} is not a regular file: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise MatrixError(f"{description} is unreadable: {path}") from error
    if resolved != path or not resolved.is_relative_to(root):
        raise MatrixError(f"{description} escapes the state root: {path}")
    return resolved


def create_log_directory(root: Path, path: Path) -> Path:
    """Create one fresh physical directory below the owned state root."""

    reject_symlinked_components(path, "log directory")
    try:
        path.relative_to(root)
    except ValueError as error:
        raise MatrixError(f"log directory escapes the state root: {path}") from error
    if path.exists() or path.is_symlink():
        raise MatrixError(f"log directory already exists or is unsafe: {path}")
    parent = path.parent
    require_physical_directory(parent, "log directory parent")
    try:
        path.mkdir(mode=0o750)
    except OSError as error:
        raise MatrixError(f"cannot create log directory: {path}") from error
    return require_physical_directory(path, "log directory")


def parse_manifest(path: Path) -> tuple[ConsumerJob, ...]:
    """Decode the small fixed-schema argv manifest without shell evaluation."""

    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MatrixError(f"consumer manifest is unreadable: {path}") from error
    if not isinstance(decoded, dict) or set(decoded) != {"schema", "jobs"}:
        raise MatrixError("consumer manifest has an invalid schema")
    if (
        type(decoded["schema"]) is not int
        or decoded["schema"] != 1
        or not isinstance(decoded["jobs"], list)
        or not decoded["jobs"]
    ):
        raise MatrixError("consumer manifest has no jobs")

    jobs: list[ConsumerJob] = []
    names: set[str] = set()
    for index, record in enumerate(decoded["jobs"], start=1):
        if not isinstance(record, dict) or set(record) != {"name", "argv"}:
            raise MatrixError("consumer manifest job has an invalid schema")
        name = record["name"]
        argv = record["argv"]
        if not isinstance(name, str) or JOB_NAME.fullmatch(name) is None or name in names:
            raise MatrixError(f"consumer manifest job name is invalid: {name!r}")
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(argument, str) or not argument or "\0" in argument for argument in argv)
        ):
            raise MatrixError(f"consumer manifest command is invalid: {name}")
        names.add(name)
        jobs.append(ConsumerJob(index, name, tuple(argv)))
    return tuple(jobs)


def open_private_log(log_directory: Path, job: ConsumerJob) -> tuple[Path, object]:
    """Create one non-following, non-overwriting log for a matrix job."""

    path = log_directory / f"{job.name}.log"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o640)
    except OSError as error:
        raise MatrixError(f"cannot create private log for {job.name}: {error}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise MatrixError(f"private log is not regular: {job.name}")
        return path, os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise


def start_job(job: ConsumerJob, log_directory: Path) -> ActiveJob:
    """Start one command in a new session so its descendants stay owned."""

    log_path, stream = open_private_log(log_directory, job)
    try:
        # Keep the product runner's inherited checkout CWD. Existing installed
        # probes deliberately create their disposable fixtures below that
        # repository-local `.work` boundary; mode roots and logs already give
        # concurrent jobs their distinct output paths.
        process = subprocess.Popen(
            job.argv,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as error:
        stream.write(f"matrix could not start {job.name}: {error}\n".encode("utf-8"))
        stream.close()
        raise MatrixError(f"cannot start consumer {job.name}: {error}") from error
    stream.close()
    return ActiveJob(job, process, time.monotonic(), log_path)


def group_is_alive(process_group: int) -> bool:
    """Ask the kernel whether the original owned process group remains."""

    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def group_has_live_members(process_group: int) -> bool:
    """Distinguish live descendants from a transient zombie-only group."""

    if not group_is_alive(process_group):
        return False
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                fields = (entry / "stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
                state = fields[0]
                group = int(fields[2])
            except (IndexError, OSError, ValueError):
                continue
            if group == process_group and state not in {"X", "Z"}:
                return True
    except OSError:
        # Failing open would make a successful leader exit able to leak a
        # child into later consumer checks. Treat an unreadable /proc as live.
        return True
    return False


def terminate_group(active: ActiveJob) -> None:
    """Stop an owned job group and reap its direct child before returning."""

    process_group = active.process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass

    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    while group_has_live_members(process_group) and time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
    if group_has_live_members(process_group):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
        while group_has_live_members(process_group) and time.monotonic() < deadline:
            time.sleep(POLL_SECONDS)

    try:
        active.process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        active.process.kill()
        active.process.wait()


def result_for(active: ActiveJob, status: str, detail: str | None = None) -> JobResult:
    """Snapshot a result only after the direct child has been reaped."""

    return JobResult(
        active.job,
        status,
        active.process.returncode,
        time.monotonic() - active.started_at,
        active.log_path,
        detail,
    )


def run_jobs(
    jobs: Sequence[ConsumerJob], workers: int, timeout_seconds: float, log_directory: Path
) -> tuple[list[JobResult], int | None]:
    """Schedule all independent jobs, retaining every failure in manifest order."""

    pending = iter(jobs)
    active: dict[int, ActiveJob] = {}
    results: list[JobResult] = []
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
                for index in sorted(active):
                    job = active[index]
                    terminate_group(job)
                    results.append(result_for(job, "cancelled"))
                active.clear()
                return results, interrupted_by

            while len(active) < workers and not exhausted:
                try:
                    job = next(pending)
                except StopIteration:
                    exhausted = True
                    break
                active[job.index] = start_job(job, log_directory)

            made_progress = False
            now = time.monotonic()
            for index in sorted(tuple(active)):
                job = active[index]
                if job.process.poll() is not None:
                    job.process.wait()
                    del active[index]
                    if group_has_live_members(job.process.pid):
                        terminate_group(job)
                        results.append(result_for(job, "process-group-leak"))
                    elif job.process.returncode == 0:
                        results.append(result_for(job, "passed"))
                    else:
                        results.append(result_for(job, "failed"))
                    made_progress = True
                elif now - job.started_at >= timeout_seconds:
                    terminate_group(job)
                    del active[index]
                    results.append(result_for(job, "timeout"))
                    made_progress = True
            if not made_progress and active:
                time.sleep(POLL_SECONDS)
    except BaseException:
        for job in active.values():
            terminate_group(job)
        raise
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
    return results, None


def write_summary(
    log_directory: Path,
    results: Sequence[JobResult],
    workers: int,
    timeout_seconds: float,
    elapsed_seconds: float,
    interrupted_by: int | None,
) -> None:
    """Persist compact timing and outcome evidence next to the private logs."""

    payload = {
        "schema": 1,
        "workers": workers,
        "timeout_seconds": timeout_seconds,
        "elapsed_seconds": elapsed_seconds,
        "interrupted_by": interrupted_by,
        "jobs": [
            {
                "name": result.job.name,
                "status": result.status,
                "exit_code": result.exit_code,
                "elapsed_seconds": result.elapsed_seconds,
                "log": result.log_path.name,
                **({"detail": result.detail} if result.detail is not None else {}),
            }
            for result in sorted(results, key=lambda result: result.job.index)
        ],
    }
    with (log_directory / "summary.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")


def parse_workers(value: str) -> int:
    """Accept the intentionally small 1..8 consumer concurrency range."""

    if not value.isdecimal() or not (1 <= int(value) <= MAX_WORKERS):
        raise MatrixError(f"workers must be an integer from 1 through {MAX_WORKERS}")
    return int(value)


def parse_timeout(value: str) -> float:
    """Require a finite bounded per-job deadline rather than an implicit hang."""

    try:
        timeout = float(value)
    except ValueError as error:
        raise MatrixError("timeout must be a finite number of seconds") from error
    if not math.isfinite(timeout) or not 0.0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise MatrixError(f"timeout must be finite, positive, and at most {MAX_TIMEOUT_SECONDS:g} seconds")
    return timeout


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    """Parse the deliberately narrow matrix invocation contract."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--log-directory", required=True)
    parser.add_argument("--workers", default=str(DEFAULT_WORKERS))
    parser.add_argument("--timeout", default=str(DEFAULT_TIMEOUT_SECONDS))
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the matrix and report only aggregate outcomes, never child output."""

    try:
        args = parse_arguments(sys.argv[1:] if arguments is None else arguments)
        state_root = require_checkout_state_root(Path(args.state_root))
        manifest = require_child_path(state_root, Path(args.manifest), "consumer manifest")
        workers = parse_workers(args.workers)
        timeout_seconds = parse_timeout(args.timeout)
        jobs = parse_manifest(manifest)
        log_directory = create_log_directory(state_root, Path(args.log_directory))
    except (MatrixError, OSError) as error:
        print(f"owned-static consumer matrix: ERROR: {error}", file=sys.stderr)
        return 2

    started_at = time.monotonic()
    try:
        results, interrupted_by = run_jobs(jobs, workers, timeout_seconds, log_directory)
    except MatrixError as error:
        print(f"owned-static consumer matrix: ERROR: {error}", file=sys.stderr)
        return 2
    elapsed_seconds = time.monotonic() - started_at
    write_summary(log_directory, results, workers, timeout_seconds, elapsed_seconds, interrupted_by)

    if interrupted_by is not None:
        print(
            f"owned-static consumer matrix: interrupted by signal {interrupted_by}; "
            f"retained logs: {log_directory}"
        )
        return 128 + interrupted_by

    failures = [result for result in results if result.status != "passed"]
    if failures:
        print(
            f"owned-static consumer matrix: {len(failures)} of {len(results)} jobs failed "
            f"after {elapsed_seconds:.1f}s (workers={workers}); retained logs: {log_directory}"
        )
        for result in sorted(failures, key=lambda result: result.job.index):
            print(
                f"  {result.status.upper()} {result.job.name} "
                f"({result.elapsed_seconds:.1f}s, exit={result.exit_code}; log: {result.log_path.name})"
            )
        return 1

    print(
        f"owned-static consumer matrix: passed {len(results)} jobs in {elapsed_seconds:.1f}s "
        f"(workers={workers}); logs: {log_directory}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
