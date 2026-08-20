#!/usr/bin/env python3
"""Run the bounded pthread/TLS stress workload against musl and crabc.

The workload is compiled exactly once, from the pinned musl headers, and the
resulting object is linked into a pinned-musl reference and a crabc candidate.
Each iteration starts both binaries in a fresh process group.  The report
keeps the raw status and stream bytes for every run; no output normalization is
allowed in this differential.

This runner is intended to be called by the native AArch64 Docker development
image.  It refuses to run on another host so a host libc cannot accidentally
become part of the oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


MUSL_VERSION = "1.2.6"
WORKLOAD_NAME = "pthread_stress"
DEFAULT_ITERATIONS = 10
MAX_ITERATIONS = 100
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 300.0


class RunnerError(Exception):
    """A setup or configuration error, distinct from a workload mismatch."""


@dataclass(frozen=True)
class ProcessResult:
    """Raw result of one isolated workload process."""

    status: int | str
    stdout: bytes
    stderr: bytes


SOURCE_SUCCESS_STATUS = 0
SOURCE_SUCCESS_STDOUT = b"pthread stress ok\n"
SOURCE_SUCCESS_STDERR = b""

# Pinned musl 1.2.6 leaves both stdio cancellation probes in this workload
# failing. The source checks `fgetc` cancellation/cleanup directly; crabc
# completes it. Keep this exact reference observation as a named improvement,
# rather than hiding a broad reference/candidate difference.
MUSL_STDIO_CANCELLATION_FAILURE = ProcessResult(
    1,
    b"pthread stress FAIL 4\n",
    b"FAIL: deferred stdio cancellation probe\n"
    b"FAIL: deferred stdio cancellation probe\n"
    b"FAIL: asynchronous stdio cancellation probe\n"
    b"FAIL: asynchronous stdio cancellation probe\n",
)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_source(root: Path | None = None) -> Path:
    """Use the existing stress fixture so the Rust and Python checks share it."""

    return (root or repository_root()) / "tests/fixtures/pthread_stress_test.c"


def parse_args() -> argparse.Namespace:
    root = repository_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--iterations",
        type=int,
        default=os.environ.get("CRABC_PTHREAD_STRESS_ITERATIONS", str(DEFAULT_ITERATIONS)),
        help=(
            "number of reference/candidate runs (1..%d; default: "
            "CRABC_PTHREAD_STRESS_ITERATIONS or %d)" % (MAX_ITERATIONS, DEFAULT_ITERATIONS)
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=os.environ.get("CRABC_PTHREAD_STRESS_TIMEOUT", str(DEFAULT_TIMEOUT)),
        help=(
            "timeout in seconds for each process run (0 < value <= %g; default: "
            "CRABC_PTHREAD_STRESS_TIMEOUT or %g)" % (MAX_TIMEOUT, DEFAULT_TIMEOUT)
        ),
    )
    parser.add_argument(
        "--musl-root",
        type=Path,
        default=Path(os.environ.get("MUSL_ROOT", f"/opt/musl-{MUSL_VERSION}")),
        help=f"pinned musl installation (default: MUSL_ROOT or /opt/musl-{MUSL_VERSION})",
    )
    parser.add_argument(
        "--musl-cc",
        default=os.environ.get("MUSL_CC", "musl-gcc"),
        help="pinned musl compiler command (default: MUSL_CC or musl-gcc)",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_TARGET_DIR", root / "target/debug")),
        help="directory containing crabc libc.so and libldso.so",
    )
    parser.add_argument(
        "--ldso",
        type=Path,
        default=None,
        help="crabc dynamic linker (default: CRABC_LDSO or <target-dir>/libldso.so)",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(os.environ.get("CRABC_PTHREAD_STRESS_SOURCE", default_source(root))),
        help="C workload source (default: tests/fixtures/pthread_stress_test.c)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help=(
            "JSON report path (default: CRABC_PTHREAD_STRESS_REPORT or "
            "compat/reports/pthread-stress/latest.json)"
        ),
    )
    return parser.parse_args()


def resolve_path(path: Path) -> Path:
    return path.expanduser().resolve()


def validate_limits(iterations: int, timeout: float) -> None:
    """Reject unbounded requests before any compiler or process is started."""

    if iterations < 1 or iterations > MAX_ITERATIONS:
        raise RunnerError(
            f"--iterations must be between 1 and {MAX_ITERATIONS}: {iterations}"
        )
    if not math.isfinite(timeout) or timeout <= 0 or timeout > MAX_TIMEOUT:
        raise RunnerError(
            f"--timeout must be greater than 0 and at most {MAX_TIMEOUT}: {timeout}"
        )


def command_text(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def check_inputs(
    args: argparse.Namespace, root: Path, ldso: Path
) -> tuple[list[str], Path, Path]:
    """Validate the native oracle, candidate artifacts, and one source file."""

    machine = platform.machine()
    if machine != "aarch64":
        raise RunnerError(f"requires native AArch64 (platform.machine() was {machine})")
    system = platform.system()
    if system != "Linux":
        raise RunnerError(f"requires Linux process semantics (platform.system() was {system})")
    validate_limits(args.iterations, args.timeout)
    if not root.is_dir():
        raise RunnerError(f"repository root not found: {root}")

    musl_root = resolve_path(args.musl_root)
    if musl_root.name != f"musl-{MUSL_VERSION}":
        raise RunnerError(
            f"--musl-root must name the pinned musl-{MUSL_VERSION} tree: {musl_root}"
        )
    headers = musl_root / "include"
    if not headers.is_dir():
        raise RunnerError(f"pinned musl headers not found: {headers}")
    loader = musl_root / "lib/ld-musl-aarch64.so.1"
    if not loader.is_file():
        raise RunnerError(f"pinned AArch64 musl loader not found: {loader}")
    if not (musl_root / "lib/libc.so").is_file():
        raise RunnerError(f"pinned musl libc not found: {musl_root / 'lib/libc.so'}")

    compiler = shlex.split(args.musl_cc)
    if not compiler:
        raise RunnerError("--musl-cc/MUSL_CC is empty")
    if shutil.which(compiler[0]) is None:
        raise RunnerError(f"compiler not found: {compiler[0]}")

    target_dir = resolve_path(args.target_dir)
    if not (target_dir / "libc.so").is_file():
        raise RunnerError(f"crabc libc not found: {target_dir / 'libc.so'}")
    if not ldso.is_file() or not os.access(ldso, os.X_OK):
        raise RunnerError(f"crabc dynamic linker not found or not executable: {ldso}")

    source = resolve_path(args.source)
    if not source.is_file():
        raise RunnerError(f"workload source not found: {source}")
    return compiler, source, headers


def compile_command(
    compiler: list[str], source: Path, headers: Path, object_file: Path
) -> list[str]:
    """Build the sole source compilation command.

    ``-isystem`` names the pinned tree explicitly.  The source is never passed
    to either link command, making one-and-only-one compilation auditable.
    """

    return compiler + [
        "-std=c11",
        "-O2",
        # The shared workload uses clock_gettime, fdopen, nanosleep, and
        # kill. Declare its POSIX.1-2008 contract explicitly instead of
        # accidentally inheriting the compiler's GNU default namespace.
        "-D_POSIX_C_SOURCE=200809L",
        "-fno-builtin",
        "-fPIE",
        "-isystem",
        str(headers),
        "-c",
        str(source),
        "-o",
        str(object_file),
    ]


def link_commands(
    compiler: list[str],
    object_file: Path,
    reference_binary: Path,
    candidate_binary: Path,
    target_dir: Path,
    ldso: Path,
) -> tuple[list[str], list[str]]:
    """Return the musl reference and crabc candidate link commands."""

    reference = compiler + [
        "-fPIE",
        "-pie",
        str(object_file),
        "-o",
        str(reference_binary),
    ]
    candidate = compiler + [
        "-fPIE",
        "-pie",
        str(object_file),
        f"-Wl,--dynamic-linker={ldso}",
        f"-L{target_dir}",
        "-Wl,--allow-shlib-undefined",
        "-lc",
        "-o",
        str(candidate_binary),
    ]
    return reference, candidate


def compile_checked(command: list[str], cwd: Path) -> None:
    try:
        result = subprocess.run(command, cwd=cwd, check=False)
    except FileNotFoundError as error:
        raise RunnerError(f"unable to execute compiler {command[0]}: {error}") from error
    except OSError as error:
        raise RunnerError(f"unable to execute {command[0]}: {error}") from error
    if result.returncode != 0:
        raise RunnerError(f"command failed ({result.returncode}): {command_text(command)}")


def run_binary(
    binary: Path,
    environment: Mapping[str, str],
    cwd: Path,
    timeout: float,
) -> ProcessResult:
    """Run one binary and kill its complete process group on timeout."""

    try:
        process = subprocess.Popen(
            [str(binary)],
            cwd=cwd,
            env=dict(environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        message = str(error).encode("utf-8", errors="replace")
        return ProcessResult(f"EXEC_ERROR:{error.errno or 'unknown'}", b"", message)

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        return ProcessResult("TIMEOUT", stdout, stderr)
    return ProcessResult(process.returncode, stdout, stderr)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compiler_version(compiler: list[str]) -> str:
    """Record compiler identity without making a second compilation."""

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


def stream_snapshot(stream: bytes) -> dict[str, Any]:
    """Represent exact output bytes with a bounded human-readable view."""

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


def result_snapshot(result: ProcessResult) -> dict[str, Any]:
    return {
        "exit_status": result.status,
        "stdout": stream_snapshot(result.stdout),
        "stderr": stream_snapshot(result.stderr),
    }


def compare_results(
    reference: ProcessResult, candidate: ProcessResult
) -> tuple[bool, dict[str, Any]]:
    """Compare one pair with no normalization or expected-output filtering."""

    status_match = reference.status == candidate.status
    stdout_match = reference.stdout == candidate.stdout
    stderr_match = reference.stderr == candidate.stderr
    # A timeout or execution error is never a successful stress iteration,
    # even if both runtimes happened to fail in precisely the same way.
    completed = isinstance(reference.status, int) and isinstance(candidate.status, int)
    passed = status_match and stdout_match and stderr_match and completed
    report: dict[str, Any] = {
        "passed": passed,
        "result": "pass" if passed else "fail",
        "reference": result_snapshot(reference),
        "candidate": result_snapshot(candidate),
        "comparisons": {
            "exit_status_match": status_match,
            "stdout_match": stdout_match,
            "stderr_match": stderr_match,
            "completed": completed,
            "normalization": "none",
        },
    }
    return passed, report


def source_contract_passed(result: ProcessResult) -> bool:
    """Return whether one runtime completed the workload's source contract."""

    return (
        result.status == SOURCE_SUCCESS_STATUS
        and result.stdout == SOURCE_SUCCESS_STDOUT
        and result.stderr == SOURCE_SUCCESS_STDERR
    )


def is_pinned_musl_stdio_cancellation_failure(result: ProcessResult) -> bool:
    """Match only the measured pinned-musl stdio-cancellation result."""

    return result == MUSL_STDIO_CANCELLATION_FAILURE


def classify_source_improvement(
    reference: ProcessResult, candidate: ProcessResult
) -> dict[str, Any] | None:
    """Recognize a clean candidate over the one exact pinned-musl failure.

    This rule is deliberately narrower than a generic candidate-success
    exemption: it requires complete reference status/stdout/stderr equality
    with the measured musl 1.2.6 outcome and complete candidate equality with
    the workload's declared success output.
    """

    if not (
        is_pinned_musl_stdio_cancellation_failure(reference)
        and source_contract_passed(candidate)
    ):
        return None
    return {
        "id": "pthread-stress.stdio-cancellation.musl-1.2.6",
        "reason": (
            "Pinned musl 1.2.6 fails the workload's deferred/asynchronous "
            "stdio cancellation probes; crabc meets the exact source success "
            "contract."
        ),
        "source": {
            "test": "tests/fixtures/pthread_stress_test.c:deferred_stdio_probe,asynchronous_stdio_probe",
            "expectation": "exit 0; stdout pthread stress ok\\n; empty stderr",
            "musl_version": MUSL_VERSION,
        },
        "reference": result_snapshot(reference),
        "candidate": result_snapshot(candidate),
    }


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
        raise RunnerError(f"could not atomically write report {path}: {error}") from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def provenance(
    args: argparse.Namespace,
    root: Path,
    musl_root: Path,
    target_dir: Path,
    ldso: Path,
    compiler: list[str],
    source: Path,
    headers: Path,
    compile_cmd: list[str],
    reference_link: list[str],
    candidate_link: list[str],
) -> dict[str, Any]:
    """Record inputs that affect the differential without leaking the env."""

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
        "workload": {
            "name": WORKLOAD_NAME,
            "source": str(source),
            "source_sha256": sha256_file(source),
        },
        "build": {
            "compile_command": compile_cmd,
            "reference_link_command": reference_link,
            "candidate_link_command": candidate_link,
            "source_compilation_count": 1,
        },
        "runtime": {
            "reference_ld_library_path": None,
            "candidate_ld_library_path": str(target_dir),
            "normalization": "none",
        },
        "limits": {
            "iterations": args.iterations,
            "timeout_seconds": args.timeout,
            "max_iterations": MAX_ITERATIONS,
            "max_timeout_seconds": MAX_TIMEOUT,
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
                "CRABC_PTHREAD_STRESS_REPORT",
                root / "compat/reports/pthread-stress/latest.json",
            )
        )
    )

    reference_environment = os.environ.copy()
    reference_environment.pop("LD_LIBRARY_PATH", None)
    reference_environment.pop("LD_PRELOAD", None)
    candidate_environment = os.environ.copy()
    candidate_environment.pop("LD_PRELOAD", None)
    candidate_environment["LD_LIBRARY_PATH"] = str(target_dir)

    raw_results: list[dict[str, Any]] = []
    source_improvements: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="crabc-pthread-stress-") as work_name:
        work_dir = Path(work_name)
        object_file = work_dir / f"{WORKLOAD_NAME}.o"
        reference_binary = work_dir / f"{WORKLOAD_NAME}.musl"
        candidate_binary = work_dir / f"{WORKLOAD_NAME}.crabc"
        source_compile = compile_command(compiler, source, headers, object_file)
        reference_link, candidate_link = link_commands(
            compiler,
            object_file,
            reference_binary,
            candidate_binary,
            target_dir,
            ldso,
        )

        print(f"pthread-stress: compiling {WORKLOAD_NAME} once with musl {MUSL_VERSION} headers")
        compile_checked(source_compile, root)
        print("pthread-stress: linking musl reference and crabc candidate")
        compile_checked(reference_link, root)
        compile_checked(candidate_link, root)

        for iteration in range(1, args.iterations + 1):
            print(f"pthread-stress: iteration {iteration}/{args.iterations}: musl")
            reference = run_binary(
                reference_binary, reference_environment, root, args.timeout
            )
            print(f"pthread-stress: iteration {iteration}/{args.iterations}: crabc")
            candidate = run_binary(
                candidate_binary, candidate_environment, root, args.timeout
            )
            passed, result = compare_results(reference, candidate)
            source_improvement = classify_source_improvement(reference, candidate)
            if source_improvement is not None:
                passed = True
                result["passed"] = True
                result["result"] = "pass-with-musl-source-failure"
                result["source_improvement"] = source_improvement
                source_improvement["iteration"] = iteration
                source_improvements.append(source_improvement)
            result["iteration"] = iteration
            raw_results.append(result)
            if passed:
                print(f"pthread-stress: PASS: iteration {iteration}")
            else:
                print(f"pthread-stress: FAIL: iteration {iteration}", file=sys.stderr)

    overall_passed = bool(raw_results) and all(item["passed"] for item in raw_results)
    report: dict[str, Any] = {
        "schema_version": 1,
        "runner": "crabc-pthread-stress",
        "workload": WORKLOAD_NAME,
        "musl_version": MUSL_VERSION,
        "passed": overall_passed,
        "result": "pass" if overall_passed else "fail",
        "iterations": args.iterations,
        "iteration_count": args.iterations,
        "completed_iterations": len(raw_results),
        "timeout_seconds": args.timeout,
        "provenance": provenance(
            args,
            root,
            musl_root,
            target_dir,
            ldso,
            compiler,
            source,
            headers,
            source_compile,
            reference_link,
            candidate_link,
        ),
        "raw_results": raw_results,
        "source_improvement_count": len(source_improvements),
        "source_improvements": source_improvements,
        "comparisons": {
            "all_exit_status_match": all(
                item["comparisons"]["exit_status_match"] for item in raw_results
            ),
            "all_stdout_match": all(
                item["comparisons"]["stdout_match"] for item in raw_results
            ),
            "all_stderr_match": all(
                item["comparisons"]["stderr_match"] for item in raw_results
            ),
            "all_completed": all(
                item["comparisons"]["completed"] for item in raw_results
            ),
            "normalization": "none",
        },
    }
    atomic_write_json(report_path, report)
    print(f"pthread-stress: report: {report_path}")
    if not overall_passed:
        print("pthread-stress: FAIL: one or more iterations differ", file=sys.stderr)
    return overall_passed


def main() -> int:
    args = parse_args()
    try:
        return 0 if run(args) else 1
    except RunnerError as error:
        print(f"pthread-stress: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
