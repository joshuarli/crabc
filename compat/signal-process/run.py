#!/usr/bin/env python3
"""Run bounded signal/process workloads against musl and crabc.

The C workload is compiled once, using the headers from the pinned musl tree,
and the resulting object is linked once for each libc.  Every subcase is then
run in a fresh process group.  The runner deliberately compares the raw
return code and raw stdout/stderr bytes; it does not strip PIDs, signal names,
loader diagnostics, or any other process output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


MUSL_VERSION = "1.2.6"
DEFAULT_MUSL_ROOT = Path(
    os.environ.get("MUSL_ROOT", f"/opt/musl-{MUSL_VERSION}")
)
DEFAULT_MUSL_CC = os.environ.get("MUSL_CC", "musl-gcc")
DEFAULT_TIMEOUT = float(os.environ.get("CRABC_SIGNAL_PROCESS_TIMEOUT", "10"))
WORKLOAD_NAME = "signal_process"
SUBCASES = (
    "siginfo",
    "nodefer",
    "mask-pending",
    "sa-restart",
    "altstack",
    "thread-mask",
    "sigwait",
    "timer",
    "wait-signal",
    "wait-nohang",
    "atfork",
    "fork-worker-exec",
)
MAX_TIMEOUT = 300.0


class RunnerError(Exception):
    """A setup or configuration error, distinct from a libc mismatch."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def source_path() -> Path:
    return Path(__file__).resolve().parent / "tests" / "signal_process.c"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run bounded signal/process subcases against pinned musl "
            "and crabc, preserving raw status/stdout/stderr."
        )
    )
    parser.add_argument(
        "subcase",
        nargs="?",
        choices=("all",) + SUBCASES,
        default="all",
        help="subcase to run, or all subcases (default: %(default)s)",
    )
    parser.add_argument(
        "--musl-root",
        type=Path,
        default=DEFAULT_MUSL_ROOT,
        help=(
            "pinned musl installation (default: MUSL_ROOT or "
            f"/opt/musl-{MUSL_VERSION})"
        ),
    )
    parser.add_argument(
        "--musl-cc",
        default=DEFAULT_MUSL_CC,
        help="musl compiler command (default: MUSL_CC or musl-gcc)",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(
            os.environ.get("CRABC_TARGET_DIR", repository_root() / "target/debug")
        ),
        help="directory containing crabc libc.so and libldso.so",
    )
    parser.add_argument(
        "--ldso",
        type=Path,
        default=None,
        help="crabc dynamic linker (default: CRABC_LDSO or <target-dir>/libldso.so)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="per-subcase timeout in seconds (default: CRABC_SIGNAL_PROCESS_TIMEOUT or 10)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help=(
            "JSON report path (default: CRABC_SIGNAL_PROCESS_REPORT or "
            "compat/reports/signal-process.json)"
        ),
    )
    return parser.parse_args()


def resolve_path(path: Path) -> Path:
    return path.expanduser().resolve()


def fail(message: str) -> RunnerError:
    return RunnerError(message)


def command_text(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compiler_version(compiler: list[str]) -> str:
    """Return compiler identity for the report without making it a test input."""
    try:
        result = subprocess.run(
            compiler + ["--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=5,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"unavailable:{error}"
    return result.stdout.strip()


def check_inputs(
    args: argparse.Namespace, root: Path, ldso: Path
) -> tuple[list[str], Path, Path]:
    machine = platform.machine()
    if machine != "aarch64":
        raise fail(f"requires native AArch64 Linux (platform.machine() was {machine})")
    if platform.system() != "Linux":
        raise fail(f"requires Linux process semantics (platform.system() was {platform.system()})")

    musl_root = resolve_path(args.musl_root)
    if musl_root.name != f"musl-{MUSL_VERSION}":
        raise fail(
            f"--musl-root must name the pinned musl-{MUSL_VERSION} tree: {musl_root}"
        )
    headers = musl_root / "include"
    if not headers.is_dir():
        raise fail(f"pinned musl headers not found: {headers}")
    if not (musl_root / "lib/ld-musl-aarch64.so.1").is_file():
        raise fail(
            "pinned AArch64 musl loader not found: "
            f"{musl_root / 'lib/ld-musl-aarch64.so.1'}"
        )
    if not (musl_root / "lib/libc.so").is_file():
        raise fail(f"pinned musl libc not found: {musl_root / 'lib/libc.so'}")

    compiler = shlex.split(args.musl_cc)
    if not compiler:
        raise fail("--musl-cc/MUSL_CC is empty")
    if shutil.which(compiler[0]) is None:
        raise fail(f"compiler not found: {compiler[0]}")

    target_dir = resolve_path(args.target_dir)
    libc = target_dir / "libc.so"
    if not libc.is_file():
        raise fail(f"crabc libc not found: {libc}")
    if not ldso.is_file() or not os.access(ldso, os.X_OK):
        raise fail(f"crabc dynamic linker not found or not executable: {ldso}")

    source = source_path()
    if not source.is_file():
        raise fail(f"workload source not found: {source}")
    if args.timeout <= 0 or args.timeout > MAX_TIMEOUT:
        raise fail(f"--timeout must be greater than 0 and at most {MAX_TIMEOUT}: {args.timeout}")
    if not root.is_dir():
        raise fail(f"repository root not found: {root}")
    return compiler, source, headers


def compile_checked(command: list[str], cwd: Path) -> None:
    try:
        result = subprocess.run(command, cwd=cwd, check=False)
    except FileNotFoundError as error:
        raise fail(f"unable to execute compiler {command[0]}: {error}") from error
    except OSError as error:
        raise fail(f"unable to execute {command[0]}: {error}") from error
    if result.returncode != 0:
        raise fail(f"command failed ({result.returncode}): {command_text(command)}")


def run_binary(
    binary: Path,
    subcase: str,
    environment: dict[str, str],
    cwd: Path,
    timeout: float,
) -> tuple[int | str, bytes, bytes]:
    """Run one subcase in an isolated process group and retain raw streams."""
    try:
        process = subprocess.Popen(
            [str(binary), subcase],
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        return f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode()

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # The workload can own children and threads.  Kill the whole process
        # group so a timed-out subcase cannot affect the next isolated one.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        return "TIMEOUT", stdout, stderr
    return process.returncode, stdout, stderr


def stream_snapshot(stream: bytes) -> dict[str, Any]:
    """Record exact bytes plus bounded display metadata for the JSON report."""
    snapshot: dict[str, Any] = {
        "byte_length": len(stream),
        "sha256": hashlib.sha256(stream).hexdigest(),
        "hex": stream.hex(),
    }
    try:
        snapshot["text"] = stream.decode("utf-8")
        snapshot["encoding"] = "utf-8"
    except UnicodeDecodeError:
        snapshot["text"] = stream.decode("utf-8", errors="replace")
        snapshot["encoding"] = "utf-8-replaced"
    return snapshot


def compare_subcase(
    subcase: str,
    reference: tuple[int | str, bytes, bytes],
    candidate: tuple[int | str, bytes, bytes],
) -> tuple[bool, dict[str, Any]]:
    reference_status, reference_stdout, reference_stderr = reference
    candidate_status, candidate_stdout, candidate_stderr = candidate
    status_match = reference_status == candidate_status
    stdout_match = reference_stdout == candidate_stdout
    stderr_match = reference_stderr == candidate_stderr
    passed = status_match and stdout_match and stderr_match

    if not status_match:
        print(
            f"signal-process: FAIL: {subcase} exit status "
            f"musl={reference_status} crabc={candidate_status}",
            file=sys.stderr,
        )
    if not stdout_match:
        print(
            f"signal-process: FAIL: {subcase} stdout differs "
            f"musl={reference_stdout.hex()} crabc={candidate_stdout.hex()}",
            file=sys.stderr,
        )
    if not stderr_match:
        print(
            f"signal-process: FAIL: {subcase} stderr differs "
            f"musl={reference_stderr.hex()} crabc={candidate_stderr.hex()}",
            file=sys.stderr,
        )

    report: dict[str, Any] = {
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
        },
        "comparisons": {
            "exit_status_match": status_match,
            "stdout_match": stdout_match,
            "stderr_match": stderr_match,
            "normalization": "none",
        },
    }
    if passed:
        print(f"signal-process: PASS: {subcase}")
    return passed, report


def atomic_write_json(path: Path, report: dict[str, Any]) -> None:
    """Publish a complete report with an atomic replacement."""
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


def environment_report(
    args: argparse.Namespace,
    root: Path,
    musl_root: Path,
    target_dir: Path,
    ldso: Path,
    compiler: list[str],
    source: Path,
    headers: Path,
) -> dict[str, Any]:
    # Record inputs that can change execution without dumping arbitrary parent
    # environment values (which may contain credentials).
    inherited = {
        name: os.environ[name]
        for name in ("LANG", "LC_ALL", "LC_CTYPE", "TZ")
        if name in os.environ
    }
    return {
        "machine": platform.machine(),
        "system": platform.system(),
        "release": platform.release(),
        "python_version": platform.python_version(),
        "cwd": str(root),
        "inherited_locale_timezone": inherited,
        "musl": {
            "version": MUSL_VERSION,
            "root": str(musl_root),
            "headers": str(headers),
            "loader": str(musl_root / "lib/ld-musl-aarch64.so.1"),
            "libc": str(musl_root / "lib/libc.so"),
            "compiler": compiler,
            "compiler_version": compiler_version(compiler),
        },
        "crabc": {
            "target_dir": str(target_dir),
            "libc": str(target_dir / "libc.so"),
            "libc_sha256": sha256_file(target_dir / "libc.so"),
            "ldso": str(ldso),
            "ldso_sha256": sha256_file(ldso),
        },
        "runner": {
            "workload": WORKLOAD_NAME,
            "source": str(source),
            "source_sha256": sha256_file(source),
            "timeout_seconds": args.timeout,
            "process_group_isolation": True,
            "normalization": "none",
        },
    }


def run(args: argparse.Namespace) -> bool:
    root = repository_root()
    target_dir = resolve_path(args.target_dir)
    ldso = resolve_path(
        args.ldso
        if args.ldso is not None
        else Path(os.environ.get("CRABC_LDSO", target_dir / "libldso.so"))
    )
    compiler, source, headers = check_inputs(args, root, ldso)
    musl_root = resolve_path(args.musl_root)
    report_path = resolve_path(args.report) if args.report else resolve_path(
        Path(
            os.environ.get(
                "CRABC_SIGNAL_PROCESS_REPORT",
                root / "compat/reports/signal-process.json",
            )
        )
    )
    selected = SUBCASES if args.subcase == "all" else (args.subcase,)

    with tempfile.TemporaryDirectory(prefix="crabc-signal-process-") as work_name:
        work_dir = Path(work_name)
        object_file = work_dir / f"{WORKLOAD_NAME}.o"
        reference_binary = work_dir / f"{WORKLOAD_NAME}.musl"
        candidate_binary = work_dir / f"{WORKLOAD_NAME}.crabc"

        print(
            f"signal-process: compiling {WORKLOAD_NAME} once with musl "
            f"{MUSL_VERSION} headers"
        )
        compile_checked(
            compiler
            + [
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-fno-builtin",
                "-fPIE",
                "-I",
                str(headers),
                "-c",
                str(source),
                "-o",
                str(object_file),
            ],
            root,
        )

        print("signal-process: linking musl reference and crabc candidate")
        compile_checked(
            compiler + ["-fPIE", "-pie", str(object_file), "-o", str(reference_binary)],
            root,
        )
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

        subcase_reports: dict[str, Any] = {}
        overall_passed = True
        for subcase in selected:
            print(f"signal-process: running musl {MUSL_VERSION}: {subcase}")
            reference = run_binary(
                reference_binary,
                subcase,
                reference_environment,
                root,
                args.timeout,
            )
            print(f"signal-process: running crabc: {subcase}")
            candidate = run_binary(
                candidate_binary,
                subcase,
                candidate_environment,
                root,
                args.timeout,
            )
            passed, subcase_report = compare_subcase(subcase, reference, candidate)
            subcase_reports[subcase] = subcase_report
            overall_passed = overall_passed and passed

    report: dict[str, Any] = {
        "schema_version": 1,
        "runner": "crabc-signal-process",
        "workload": WORKLOAD_NAME,
        "subcases": list(selected),
        "musl_version": MUSL_VERSION,
        "passed": overall_passed,
        "result": "pass" if overall_passed else "fail",
        "inputs": environment_report(
            args,
            root,
            musl_root,
            target_dir,
            ldso,
            compiler,
            source,
            headers,
        ),
        "cases": subcase_reports,
        "comparisons": {
            "all_exit_status_match": all(
                case["comparisons"]["exit_status_match"] for case in subcase_reports.values()
            ),
            "all_stdout_match": all(
                case["comparisons"]["stdout_match"] for case in subcase_reports.values()
            ),
            "all_stderr_match": all(
                case["comparisons"]["stderr_match"] for case in subcase_reports.values()
            ),
            "normalization": "none",
        },
    }
    atomic_write_json(report_path, report)
    print(f"signal-process: report: {report_path}")
    if not overall_passed:
        print("signal-process: FAIL: one or more subcases differ", file=sys.stderr)
    return overall_passed


def main() -> int:
    args = parse_args()
    try:
        return 0 if run(args) else 1
    except RunnerError as error:
        print(f"signal-process: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
