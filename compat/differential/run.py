#!/usr/bin/env python3
"""Run an equivalent workload against pinned musl and crabc.

The runner intentionally has no fetch/install step.  The native AArch64
development image supplies musl 1.2.6 at /opt/musl-1.2.6, and the caller
supplies already-built crabc artifacts in target/debug.  Keeping those inputs
explicit makes a run safe to repeat offline and makes a missing oracle an
actionable error.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


MUSL_VERSION = "1.2.6"
DEFAULT_MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
DEFAULT_CASE = "foundational"
CASES = (DEFAULT_CASE,)
ERRNO_PATTERN = re.compile(rb"^foundational: errno=([0-9]+) .*$")


class RunnerError(Exception):
    """A configuration or setup error, distinct from a differential failure."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compile and run one workload against pinned musl 1.2.6 and crabc, "
            "then compare exit status, stdout, stderr, and errno."
        )
    )
    parser.add_argument(
        "case",
        nargs="?",
        choices=CASES,
        default=DEFAULT_CASE,
        help="workload to execute (default: %(default)s)",
    )
    parser.add_argument(
        "--musl-root",
        type=Path,
        default=Path(os.environ.get("MUSL_ROOT", DEFAULT_MUSL_ROOT)),
        help="pinned musl installation (default: MUSL_ROOT or /opt/musl-1.2.6)",
    )
    parser.add_argument(
        "--musl-cc",
        default=os.environ.get("MUSL_CC", "musl-gcc"),
        help="musl compiler command (default: MUSL_CC or musl-gcc)",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_TARGET_DIR", repository_root() / "target/debug")),
        help="directory containing crabc artifacts (default: CRABC_TARGET_DIR or target/debug)",
    )
    parser.add_argument(
        "--ldso",
        type=Path,
        default=None,
        help="crabc loader (default: CRABC_LDSO or <target-dir>/libldso.so)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("CRABC_DIFFERENTIAL_TIMEOUT", "10")),
        help="per-workload timeout in seconds (default: CRABC_DIFFERENTIAL_TIMEOUT or 10)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help=(
            "JSON result path (default: CRABC_DIFFERENTIAL_REPORT or "
            "compat/reports/differential/<case>.json)"
        ),
    )
    return parser.parse_args()


def fail(message: str) -> RunnerError:
    return RunnerError(message)


def resolve_path(path: Path) -> Path:
    return path.expanduser().resolve()


def check_inputs(args: argparse.Namespace, root: Path, ldso: Path) -> tuple[list[str], Path]:
    if platform.machine() != "aarch64":
        raise fail(f"requires native AArch64 (platform.machine() was {platform.machine()})")

    musl_root = resolve_path(args.musl_root)
    if musl_root.name != f"musl-{MUSL_VERSION}":
        raise fail(
            f"--musl-root must name the pinned musl-{MUSL_VERSION} tree: {musl_root}"
        )
    if not (musl_root / "include").is_dir():
        raise fail(f"pinned musl headers not found: {musl_root / 'include'}")
    if not (musl_root / "lib/ld-musl-aarch64.so.1").is_file():
        raise fail(f"pinned AArch64 musl loader not found: {musl_root / 'lib/ld-musl-aarch64.so.1'}")
    if not (musl_root / "lib/libc.so").is_file():
        raise fail(f"pinned musl libc not found: {musl_root / 'lib/libc.so'}")

    compiler = shlex.split(args.musl_cc)
    if not compiler:
        raise fail("--musl-cc/MUSL_CC is empty")
    if shutil.which(compiler[0]) is None:
        raise fail(f"compiler not found: {compiler[0]}")

    target_dir = resolve_path(args.target_dir)
    if not (target_dir / "libc.so").is_file():
        raise fail(f"crabc libc not found: {target_dir / 'libc.so'}")
    if not ldso.is_file() or not os.access(ldso, os.X_OK):
        raise fail(f"crabc dynamic linker not found or not executable: {ldso}")

    source = root / "compat/differential/tests" / f"{args.case}.c"
    if not source.is_file():
        raise fail(f"workload source not found: {source}")
    if args.timeout <= 0:
        raise fail(f"--timeout must be positive: {args.timeout}")

    return compiler, source


def command_text(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def compile_checked(command: list[str], root: Path) -> None:
    try:
        subprocess.run(command, cwd=root, check=True)
    except FileNotFoundError as error:
        raise fail(f"unable to execute compiler {command[0]}: {error}") from error
    except subprocess.CalledProcessError as error:
        raise fail(f"command failed ({error.returncode}): {command_text(command)}") from error


def run_binary(
    binary: Path,
    stdout_path: Path,
    stderr_path: Path,
    environment: dict[str, str],
    root: Path,
    timeout: float,
) -> int | str:
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            result = subprocess.run(
                [str(binary)],
                cwd=root,
                env=environment,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=timeout,
            )
        # Python preserves signal termination as a negative return code (for
        # example -11 for SIGSEGV), so a signal cannot compare equal to a
        # normal exit merely because both shells report a numeric status.
        return result.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except OSError as error:
        return f"EXEC_ERROR:{error.errno or 'unknown'}"


def stream_diff(name: str, reference: bytes, candidate: bytes) -> None:
    print(f"differential: FAIL: {name} differs", file=sys.stderr)
    reference_text = reference.decode("utf-8", errors="replace").splitlines(keepends=True)
    candidate_text = candidate.decode("utf-8", errors="replace").splitlines(keepends=True)
    diff = difflib.unified_diff(
        reference_text,
        candidate_text,
        fromfile=f"musl/{name}",
        tofile=f"crabc/{name}",
    )
    rendered = "".join(diff)
    if rendered:
        print(rendered, end="", file=sys.stderr)
    else:
        print(
            f"  musl bytes={reference.hex()}\n  crabc bytes={candidate.hex()}",
            file=sys.stderr,
        )


def errno_marker(stream: bytes) -> list[int]:
    return [int(match.group(1)) for line in stream.splitlines() if (match := ERRNO_PATTERN.match(line))]


def stream_snapshot(stream: bytes) -> dict[str, object]:
    """Return bounded, exact-enough metadata for a stream in the JSON report."""
    snapshot: dict[str, object] = {
        "byte_length": len(stream),
        "sha256": hashlib.sha256(stream).hexdigest(),
    }
    try:
        snapshot["text"] = stream.decode("utf-8")
        snapshot["encoding"] = "utf-8"
    except UnicodeDecodeError:
        snapshot["text"] = stream.decode("utf-8", errors="replace")
        snapshot["encoding"] = "utf-8-replaced"
    return snapshot


def atomic_write_json(path: Path, report: dict[str, object]) -> None:
    """Write a complete JSON report and publish it with an atomic replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    except OSError as error:
        raise fail(f"could not atomically write report {path}: {error}") from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def compare_outputs(
    case: str,
    reference_status: int | str,
    candidate_status: int | str,
    reference_stdout: bytes,
    candidate_stdout: bytes,
    reference_stderr: bytes,
    candidate_stderr: bytes,
) -> tuple[bool, dict[str, object]]:
    passed = True
    # Successful startup must be silent on stderr. Keep these report fields as
    # an explicit invariant so adding normalization later cannot be accidental.
    normalized_lines: list[str] = []
    if reference_status != candidate_status:
        print(
            f"differential: FAIL: exit status musl={reference_status} "
            f"crabc={candidate_status}",
            file=sys.stderr,
        )
        passed = False

    stdout_match = reference_stdout == candidate_stdout
    stderr_match = reference_stderr == candidate_stderr
    if not stdout_match:
        stream_diff("stdout", reference_stdout, candidate_stdout)
        passed = False
    if not stderr_match:
        stream_diff("stderr", reference_stderr, candidate_stderr)
        passed = False

    reference_errno = errno_marker(reference_stdout)
    candidate_errno = errno_marker(candidate_stdout)
    errno_match = len(reference_errno) == 1 and len(candidate_errno) == 1
    if not errno_match:
        print(
            "differential: FAIL: errno marker count "
            f"musl={reference_errno or 'missing'} crabc={candidate_errno or 'missing'}",
            file=sys.stderr,
        )
        passed = False
    elif reference_errno[0] != candidate_errno[0]:
        errno_match = False
        print(
            f"differential: FAIL: errno musl={reference_errno[0]} "
            f"crabc={candidate_errno[0]}",
            file=sys.stderr,
        )
        passed = False
    else:
        print(f"differential: errno={reference_errno[0]}")

    if passed:
        print(f"differential: PASS: {case} (musl {MUSL_VERSION} vs crabc)")
    else:
        print(f"differential: FAIL: {case}", file=sys.stderr)
    report: dict[str, object] = {
        "schema_version": 1,
        "case": case,
        "musl_version": MUSL_VERSION,
        "platform": platform.machine(),
        "passed": passed,
        "result": "pass" if passed else "fail",
        "reference": {
            "exit_status": reference_status,
            "stdout": stream_snapshot(reference_stdout),
            "stderr": stream_snapshot(reference_stderr),
        },
        "candidate": {
            "exit_status": candidate_status,
            "stdout": stream_snapshot(candidate_stdout),
            "stderr": stream_snapshot(candidate_stderr),
            "stderr_normalized": stream_snapshot(candidate_stderr),
        },
        "comparisons": {
            "exit_status_match": reference_status == candidate_status,
            "stdout_match": stdout_match,
            "stderr_match": stderr_match,
            "errno_match": errno_match,
        },
        "normalized_lines": normalized_lines,
        "normalized_line_count": len(normalized_lines),
        "errno": {
            "reference": reference_errno[0] if len(reference_errno) == 1 else None,
            "candidate": candidate_errno[0] if len(candidate_errno) == 1 else None,
            "match": errno_match,
        },
    }
    return passed, report


def run(args: argparse.Namespace) -> bool:
    root = repository_root()
    target_dir = resolve_path(args.target_dir)
    ldso = resolve_path(args.ldso) if args.ldso else resolve_path(
        Path(os.environ.get("CRABC_LDSO", target_dir / "libldso.so"))
    )
    compiler, source = check_inputs(args, root, ldso)
    musl_root = resolve_path(args.musl_root)
    report_path = resolve_path(args.report) if args.report else resolve_path(
        Path(
            os.environ.get(
                "CRABC_DIFFERENTIAL_REPORT",
                root / "compat/reports/differential" / f"{args.case}.json",
            )
        )
    )

    with tempfile.TemporaryDirectory(prefix="crabc-differential-") as work_dir_name:
        work_dir = Path(work_dir_name)
        object_file = work_dir / f"{args.case}.o"
        reference_binary = work_dir / f"{args.case}.musl"
        candidate_binary = work_dir / f"{args.case}.crabc"
        reference_stdout_path = work_dir / "reference.stdout"
        candidate_stdout_path = work_dir / "candidate.stdout"
        reference_stderr_path = work_dir / "reference.stderr"
        candidate_stderr_path = work_dir / "candidate.stderr"

        print(f"differential: compiling {args.case} once with musl {MUSL_VERSION} headers")
        compile_checked(
            compiler
            + [
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-fPIE",
                "-I",
                str(musl_root / "include"),
                "-c",
                str(source),
                "-o",
                str(object_file),
            ],
            root,
        )

        print("differential: linking reference and candidate executables")
        compile_checked(compiler + ["-fPIE", "-pie", str(object_file), "-o", str(reference_binary)], root)
        compile_checked(
            compiler
            + [
                "-fPIE",
                "-pie",
                str(object_file),
                f"-Wl,--dynamic-linker={ldso}",
                f"-L{target_dir}",
                "-Wl,--allow-shlib-undefined",
                "-lc",
                "-o",
                str(candidate_binary),
            ],
            root,
        )

        reference_environment = os.environ.copy()
        reference_environment.pop("LD_LIBRARY_PATH", None)
        candidate_environment = os.environ.copy()
        candidate_environment["LD_LIBRARY_PATH"] = str(target_dir)

        print(f"differential: running musl {MUSL_VERSION}")
        reference_status = run_binary(
            reference_binary,
            reference_stdout_path,
            reference_stderr_path,
            reference_environment,
            root,
            args.timeout,
        )
        print("differential: running crabc")
        candidate_status = run_binary(
            candidate_binary,
            candidate_stdout_path,
            candidate_stderr_path,
            candidate_environment,
            root,
            args.timeout,
        )

        passed, report = compare_outputs(
            args.case,
            reference_status,
            candidate_status,
            reference_stdout_path.read_bytes(),
            candidate_stdout_path.read_bytes(),
            reference_stderr_path.read_bytes(),
            candidate_stderr_path.read_bytes(),
        )
        atomic_write_json(report_path, report)
        print(f"differential: report: {report_path}")
        return passed


def main() -> int:
    args = parse_args()
    try:
        return 0 if run(args) else 1
    except RunnerError as error:
        print(f"differential: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
