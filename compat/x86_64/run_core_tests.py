#!/usr/bin/env python3
"""Run cached development-only native ``crabc-core`` library tests safely.

The normal ``core`` command deliberately keeps its cold disposable target and
remains the qualification boundary.  This helper is opt-in developer feedback:
it reuses only a checkout-local Cargo target, asks Cargo for the current lib
test executable on every invocation, and copies that exact artifact into a
private run directory before executing it.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterator, Mapping, Sequence


ROOT: Final = Path(__file__).resolve().parents[2]
CHECKOUT_WORK_ROOT: Final = ROOT / ".work"
CHECKOUT_X86_WORK_ROOT: Final = CHECKOUT_WORK_ROOT / "x86_64"
DEFAULT_STATE_ROOT: Final = CHECKOUT_X86_WORK_ROOT / "core-tests"
CORE_LIB_SOURCE: Final = ROOT / "crabc-core" / "src" / "lib.rs"
TARGET: Final = "x86_64-unknown-linux-musl"
DEFAULT_TIMEOUT_SECONDS: Final = 300.0
MAX_TIMEOUT_SECONDS: Final = 900.0
FXRSTOR: Final = re.compile(rb"\bfxrstor(?:64)?\b", re.IGNORECASE)
TERMINATION_GRACE_SECONDS: Final = 2.0


class CoreTestError(RuntimeError):
    """The development-only helper could not preserve its execution boundary."""

    def __init__(self, message: str, run_directory: Path | None = None) -> None:
        super().__init__(message)
        self.run_directory = run_directory


class CoreTestInterrupted(KeyboardInterrupt):
    """A terminal signal whose owned child session has to be reaped first."""

    def __init__(self, signal_number: int) -> None:
        super().__init__()
        self.signal_number = signal_number
        self.run_directory: Path | None = None


@dataclass(frozen=True)
class ChildResult:
    """Captured result of one child whose session is owned by this helper."""

    command: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool


@dataclass(frozen=True)
class CoreTestRun:
    """The private execution copy and the reusable development target it used."""

    run_directory: Path
    cache_target_directory: Path
    test_executable: Path


def reject_symlinked_components(path: Path, description: str) -> None:
    """Reject an absolute lexical path that crosses a present symlink."""

    if not path.is_absolute() or any(part in ("", ".", "..") for part in path.parts[1:]):
        raise CoreTestError(f"{description} must be an absolute path without traversal: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if os.path.lexists(current) and current.is_symlink():
            raise CoreTestError(f"{description} crosses a symlink: {path}")


def require_physical_directory(path: Path, description: str) -> Path:
    """Return one existing physical directory after refusing aliases."""

    reject_symlinked_components(path, description)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise CoreTestError(f"{description} does not exist: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CoreTestError(f"{description} is not a physical directory: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CoreTestError(f"{description} is unreadable: {path}") from error
    if resolved != path:
        raise CoreTestError(f"{description} is not a physical directory: {path}")
    return resolved


def create_physical_child(parent: Path, name: str, description: str) -> Path:
    """Create or re-open one direct physical child of an owned directory."""

    if not name or "/" in name or name in {".", ".."}:
        raise CoreTestError(f"{description} has an invalid child name: {name!r}")
    parent = require_physical_directory(parent, f"{description} parent")
    child = parent / name
    reject_symlinked_components(child, description)
    if os.path.lexists(child):
        return require_physical_directory(child, description)
    try:
        child.mkdir(mode=0o750)
    except FileExistsError:
        pass
    except OSError as error:
        raise CoreTestError(f"cannot create {description}: {child}") from error
    return require_physical_directory(child, description)


def prepare_state_root(state_root: Path = DEFAULT_STATE_ROOT) -> Path:
    """Accept only a dedicated physical helper state root below this checkout."""

    checkout_x86 = require_physical_directory(
        CHECKOUT_X86_WORK_ROOT, "checkout .work/x86_64 root"
    )
    reject_symlinked_components(state_root, "state root")
    try:
        relative = state_root.relative_to(checkout_x86)
    except ValueError as error:
        raise CoreTestError(
            f"state root must stay below checkout .work/x86_64: {state_root}"
        ) from error
    if not relative.parts:
        raise CoreTestError("state root must name a dedicated directory below checkout .work/x86_64")
    if os.path.lexists(state_root):
        return require_physical_directory(state_root, "state root")
    return create_physical_child(state_root.parent, state_root.name, "state root")


def create_private_run_directory(runs_root: Path) -> Path:
    """Allocate an unshared run directory below the checked checkout state."""

    runs_root = require_physical_directory(runs_root, "private run root")
    try:
        directory = Path(tempfile.mkdtemp(prefix="run-", dir=runs_root))
    except OSError as error:
        raise CoreTestError(f"cannot create private run directory below {runs_root}") from error
    return require_physical_directory(directory, "private run directory")


def require_regular_file_below(path: Path, root: Path, description: str) -> Path:
    """Require an executable physical regular file beneath the given root."""

    root = require_physical_directory(root, f"{description} root")
    reject_symlinked_components(path, description)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise CoreTestError(f"{description} escapes cached target: {path}") from error
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise CoreTestError(f"{description} does not exist: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CoreTestError(f"{description} is not a regular file: {path}")
    if not metadata.st_mode & stat.S_IXUSR:
        raise CoreTestError(f"{description} is not executable: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CoreTestError(f"{description} is unreadable: {path}") from error
    if resolved != path or not resolved.is_relative_to(root):
        raise CoreTestError(f"{description} escapes cached target: {path}")
    return resolved


def write_private_bytes(directory: Path, name: str, content: bytes, mode: int = 0o600) -> Path:
    """Write one non-overwriting private regular file in a fresh run directory."""

    if not name or "/" in name or name in {".", ".."}:
        raise CoreTestError(f"private output has an invalid name: {name!r}", directory)
    directory = require_physical_directory(directory, "private run directory")
    path = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise CoreTestError(f"cannot create private output {path.name}: {error}", directory) from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise CoreTestError(f"private output is not regular: {path.name}", directory)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
    finally:
        if descriptor != -1:
            os.close(descriptor)
    return path


def copy_private_executable(source: Path, target_root: Path, run_directory: Path) -> Path:
    """Copy Cargo's selected current executable before releasing the build lock."""

    source = require_regular_file_below(source, target_root, "Cargo test executable")
    destination = write_private_bytes(run_directory, "crabc-core-tests", b"", mode=0o700)
    try:
        with source.open("rb") as input_stream, destination.open("wb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
        destination.chmod(0o700)
    except OSError as error:
        raise CoreTestError(f"cannot copy Cargo test executable: {error}", run_directory) from error
    return require_regular_file_below(destination, run_directory, "private test executable")


def suppress_core_dumps() -> None:
    """Keep an aborting compiler or test from writing a shared-CWD core file."""

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def terminate_owned_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the child session and every descendant it owns."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def reap_interrupted_child(process: subprocess.Popen[bytes], command: Sequence[str]) -> ChildResult:
    """Kill and reap an owned session before a cancellation can escape."""

    terminate_owned_group(process)
    try:
        stdout, stderr = process.communicate(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        terminate_owned_group(process)
        stdout, stderr = process.communicate()
    return ChildResult(tuple(command), process.returncode, stdout, stderr, False)


def interrupted_child_result(error: BaseException) -> ChildResult | None:
    """Recover the retained output that was attached during exceptional cleanup."""

    result = getattr(error, "core_test_child_result", None)
    return result if isinstance(result, ChildResult) else None


def run_owned_child(
    command: Sequence[str], environment: Mapping[str, str], timeout_seconds: float
) -> ChildResult:
    """Run one bounded child in its own session with core dumps suppressed."""

    if not command or any(not isinstance(argument, str) or not argument for argument in command):
        raise CoreTestError("child command is invalid")
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=suppress_core_dumps,
        )
    except OSError as error:
        raise CoreTestError(f"cannot start child {command[0]}: {error}") from error
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return ChildResult(tuple(command), process.returncode, stdout, stderr, False)
    except subprocess.TimeoutExpired:
        terminate_owned_group(process)
        stdout, stderr = process.communicate()
        return ChildResult(tuple(command), process.returncode, stdout, stderr, True)
    except BaseException as error:
        result = reap_interrupted_child(process, command)
        try:
            error.core_test_child_result = result
        except AttributeError:
            pass
        raise


def render_child_log(label: str, result: ChildResult) -> bytes:
    """Retain command output before reporting a child failure to the caller."""

    command = " ".join(result.command)
    header = (
        f"{label} command: {command}\n"
        f"exit code: {result.returncode}\n"
        f"timed out: {str(result.timed_out).lower()}\n\n"
    ).encode("utf-8")
    return header + b"stdout:\n" + result.stdout + b"\n\nstderr:\n" + result.stderr


def require_child_success(label: str, result: ChildResult, run_directory: Path) -> None:
    """Turn retained child status into one concise helper failure."""

    if result.timed_out:
        raise CoreTestError(f"{label} timed out", run_directory)
    if result.returncode != 0:
        raise CoreTestError(f"{label} exited {result.returncode}", run_directory)


def selected_current_test_executable(output: bytes, target_root: Path) -> Path:
    """Select exactly Cargo's current ``crabc_core`` lib-test artifact message."""

    candidates: list[Path] = []
    expected_source = CORE_LIB_SOURCE.resolve(strict=True)
    for raw_line in output.splitlines():
        if not raw_line:
            continue
        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError as error:
            raise CoreTestError("Cargo --message-format=json emitted non-JSON output") from error
        if not isinstance(message, dict) or message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        profile = message.get("profile")
        executable = message.get("executable")
        if not isinstance(target, dict) or not isinstance(profile, dict):
            continue
        if (
            target.get("name") != "crabc_core"
            or target.get("kind") != ["lib"]
            or profile.get("test") is not True
            or not isinstance(executable, str)
        ):
            continue
        source = target.get("src_path")
        if not isinstance(source, str):
            continue
        try:
            observed_source = Path(source).resolve(strict=True)
        except OSError:
            continue
        if observed_source != expected_source:
            continue
        candidates.append(Path(executable))
    if len(candidates) != 1:
        raise CoreTestError(
            f"Cargo must report exactly one current crabc-core lib test executable, found {len(candidates)}"
        )
    return require_regular_file_below(candidates[0], target_root, "Cargo test executable")


@contextmanager
def build_lock(cache_root: Path) -> Iterator[None]:
    """Serialize shared-target mutation and the exact executable copy."""

    cache_root = require_physical_directory(cache_root, "development cache root")
    path = cache_root / "build.lock"
    flags = os.O_WRONLY | os.O_CREAT
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise CoreTestError(f"cannot open development cache lock: {error}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise CoreTestError("development cache lock is not regular")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def child_environment(
    target_root: Path, run_directory: Path, environment: Mapping[str, str] | None
) -> dict[str, str]:
    """Set per-run temporary state while leaving normal pinned tool variables intact."""

    temporary = create_physical_child(run_directory, "tmp", "private TMPDIR")
    values = dict(os.environ)
    if environment is not None:
        values.update(environment)
    values["CARGO_TARGET_DIR"] = str(target_root)
    values["TMPDIR"] = str(temporary)
    values["PYTHONDONTWRITEBYTECODE"] = "1"
    return values


def parse_timeout(value: str) -> float:
    """Require one finite bounded child deadline."""

    try:
        timeout = float(value)
    except ValueError as error:
        raise CoreTestError("timeout must be a finite number of seconds") from error
    if not math.isfinite(timeout) or not 0.0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise CoreTestError(
            f"timeout must be finite, positive, and at most {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    return timeout


def remove_successful_run(run_directory: Path, runs_root: Path) -> None:
    """Remove only a completed helper-owned physical run directory."""

    runs_root = require_physical_directory(runs_root, "private run root")
    run_directory = require_physical_directory(run_directory, "private run directory")
    if run_directory.parent != runs_root:
        raise CoreTestError(f"private run directory escapes its root: {run_directory}")
    shutil.rmtree(run_directory)


@contextmanager
def cancellation_handlers() -> Iterator[None]:
    """Translate terminal signals into catchable cleanup before reporting them."""

    def interrupted(signal_number: int, _frame: object) -> None:
        raise CoreTestInterrupted(signal_number)

    signals = (signal.SIGINT, signal.SIGTERM)
    previous = {signal_number: signal.getsignal(signal_number) for signal_number in signals}
    try:
        for signal_number in signals:
            signal.signal(signal_number, interrupted)
        yield
    finally:
        for signal_number in signals:
            signal.signal(signal_number, previous[signal_number])


def run_core_tests(
    *,
    state_root: Path = DEFAULT_STATE_ROOT,
    cargo: Sequence[str] = ("cargo",),
    objdump: Sequence[str] = ("objdump",),
    environment: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    retain_success: bool = False,
) -> CoreTestRun:
    """Build, copy, inspect, and serially run current core tests from one cache."""

    if not math.isfinite(timeout_seconds) or not 0.0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise CoreTestError(
            f"timeout must be finite, positive, and at most {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    state_root = prepare_state_root(state_root)
    cache_root = create_physical_child(state_root, "cache", "development cache root")
    target_root = create_physical_child(cache_root, "target", "development cache target")
    runs_root = create_physical_child(state_root, "runs", "private run root")
    run_directory = create_private_run_directory(runs_root)
    succeeded = False
    try:
        values = child_environment(target_root, run_directory, environment)
        with build_lock(cache_root):
            cargo_command = [
                *cargo,
                "test",
                "--locked",
                "--target",
                TARGET,
                "-p",
                "crabc-core",
                "--lib",
                "--no-default-features",
                "--no-run",
                "--message-format=json",
            ]
            try:
                cargo_result = run_owned_child(cargo_command, values, timeout_seconds)
            except BaseException as error:
                result = interrupted_child_result(error)
                if result is not None:
                    write_private_bytes(run_directory, "cargo.log", render_child_log("cargo", result))
                raise
            write_private_bytes(run_directory, "cargo.log", render_child_log("cargo", cargo_result))
            require_child_success("Cargo test build", cargo_result, run_directory)
            cargo_executable = selected_current_test_executable(cargo_result.stdout, target_root)
            test_executable = copy_private_executable(cargo_executable, target_root, run_directory)

        objdump_command = [*objdump, "-d", "--", str(test_executable)]
        try:
            objdump_result = run_owned_child(objdump_command, values, timeout_seconds)
        except BaseException as error:
            result = interrupted_child_result(error)
            if result is not None:
                write_private_bytes(run_directory, "fenv-disassembly", result.stdout)
                write_private_bytes(run_directory, "objdump.log", render_child_log("objdump", result))
            raise
        write_private_bytes(run_directory, "fenv-disassembly", objdump_result.stdout)
        write_private_bytes(run_directory, "objdump.log", render_child_log("objdump", objdump_result))
        require_child_success("objdump fenv proof", objdump_result, run_directory)
        if FXRSTOR.search(objdump_result.stdout) is not None:
            raise CoreTestError(
                "x86 fenv codegen must not reload XMM state with fxrstor", run_directory
            )

        test_command = [str(test_executable), "--test-threads=1"]
        try:
            test_result = run_owned_child(test_command, values, timeout_seconds)
        except BaseException as error:
            result = interrupted_child_result(error)
            if result is not None:
                write_private_bytes(run_directory, "test.log", render_child_log("core tests", result))
            raise
        write_private_bytes(run_directory, "test.log", render_child_log("core tests", test_result))
        require_child_success("core test executable", test_result, run_directory)
        succeeded = True
        return CoreTestRun(run_directory, target_root, test_executable)
    except CoreTestError as error:
        if error.run_directory is None:
            raise CoreTestError(str(error), run_directory) from error
        raise
    except BaseException as error:
        if getattr(error, "run_directory", None) is None:
            try:
                error.run_directory = run_directory
            except AttributeError:
                pass
        raise
    finally:
        if succeeded and not retain_success:
            remove_successful_run(run_directory, runs_root)


def main(arguments: Sequence[str] | None = None) -> int:
    """Expose the opt-in development helper without changing the cold core gate."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", default=str(DEFAULT_TIMEOUT_SECONDS))
    parsed = parser.parse_args(arguments)
    try:
        with cancellation_handlers():
            run_core_tests(timeout_seconds=parse_timeout(parsed.timeout))
    except CoreTestInterrupted as error:
        retained = f"; retained failure: {error.run_directory}" if error.run_directory else ""
        print(
            f"x86 cached core tests: interrupted by signal {error.signal_number}{retained}",
            file=sys.stderr,
        )
        return 128 + error.signal_number
    except CoreTestError as error:
        retained = f"; retained failure: {error.run_directory}" if error.run_directory else ""
        print(f"x86 cached core tests: ERROR: {error}{retained}", file=sys.stderr)
        return 1
    print(
        "x86 cached core tests: PASS (development cache only; cold core qualification remains separate)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
