#!/usr/bin/env python3
"""Measure equivalent dynamic-libc workloads under pinned musl and crabc.

The runner intentionally separates timed/resource samples from syscall and
resident-memory diagnostics.  A timed sample has no tracing or profiler in
its process.  Both runtime lanes use one musl-compiled AArch64 application;
only its PT_INTERP value and dynamic-library bytes differ.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import select
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = 1
MUSL_VERSION = "1.2.6"
DEFAULT_MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
EXPECTED_STDOUT = b"ok\n"


@dataclass(frozen=True)
class Workload:
    """One process-isolated operation and its intentionally fixed input."""

    name: str
    iterations: int
    extra_arguments: tuple[str, ...] = ()


WORKLOADS = (
    Workload("startup", 1),
    Workload("clock_gettime", 200_000),
    Workload("getpid", 200_000),
    Workload("open_close", 25_000),
    Workload("memcpy_16k", 25_000),
    Workload("memset_16k", 25_000),
    Workload("strlen_16k", 25_000),
    Workload("memchr_16k", 25_000),
    Workload("strstr_4k", 10_000),
    Workload("memmem_4k", 10_000),
    Workload("allocator_64", 100_000),
    Workload("allocator_4k", 50_000),
    Workload("dlsym_128", 5_000),
)


class RunnerError(Exception):
    """A setup or contract error, distinct from a measured runtime failure."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a controlled musl-vs-crabc AArch64 performance matrix. "
            "It writes evidence even when one lane is unsupported or fails."
        )
    )
    parser.add_argument(
        "--musl-root",
        type=Path,
        default=Path(os.environ.get("MUSL_ROOT", DEFAULT_MUSL_ROOT)),
        help="pinned musl installation (default: MUSL_ROOT or %(default)s)",
    )
    parser.add_argument(
        "--musl-cc",
        default=os.environ.get("MUSL_CC", "musl-gcc"),
        help="musl C compiler (default: MUSL_CC or %(default)s)",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_TARGET_DIR", repository_root() / "target/release")),
        help="directory containing release libc.so/libldso.so (default: %(default)s)",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=15,
        help="timed samples per lane/workload after warm-up (default: %(default)s)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        help="untimed warm-up processes per lane/workload (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="per-process timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--label",
        default="baseline",
        help="report label and default output filename (default: %(default)s)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="JSON report path (default: compat/reports/perf/<label>.json)",
    )
    parser.add_argument(
        "--skip-syscalls",
        action="store_true",
        help="do not collect the separate strace diagnostic lane",
    )
    return parser.parse_args()


def fail(message: str) -> RunnerError:
    return RunnerError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def command_output(command: list[str], cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as error:
        return f"unavailable: {error}"
    return result.stdout


def profile_release(root: Path) -> dict[str, str]:
    """Record the source configuration being measured without interpreting it."""

    cargo = root / "Cargo.toml"
    in_release = False
    entries: dict[str, str] = {}
    for raw_line in cargo.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("["):
            in_release = line == "[profile.release]"
            continue
        if in_release and "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            entries[key.strip()] = value.strip()
    return entries


def patched_interpreter_bytes(binary: bytes, interpreter: str) -> bytes:
    """Patch only PT_INTERP in an ELF64 little-endian AArch64 executable."""

    if len(binary) < 64 or binary[:4] != b"\x7fELF" or binary[4] != 2 or binary[5] != 1:
        raise fail("workload is not an ELF64 little-endian executable")
    if int.from_bytes(binary[18:20], "little") != 183:
        raise fail("workload is not an AArch64 executable")
    program_headers = int.from_bytes(binary[32:40], "little")
    entry_size = int.from_bytes(binary[54:56], "little")
    entries = int.from_bytes(binary[56:58], "little")
    patched = bytearray(binary)
    encoded = interpreter.encode("ascii") + b"\0"
    for index in range(entries):
        offset = program_headers + index * entry_size
        if offset + 56 > len(patched):
            raise fail("workload ELF program headers exceed the file")
        if int.from_bytes(patched[offset : offset + 4], "little") != 3:  # PT_INTERP
            continue
        file_offset = int.from_bytes(patched[offset + 8 : offset + 16], "little")
        file_size = int.from_bytes(patched[offset + 32 : offset + 40], "little")
        if len(encoded) > file_size or file_offset + file_size > len(patched):
            raise fail("replacement interpreter does not fit the workload PT_INTERP segment")
        patched[file_offset : file_offset + file_size] = encoded + b"\0" * (file_size - len(encoded))
        return bytes(patched)
    raise fail("workload is missing PT_INTERP")


def patch_interpreter(source: Path, destination: Path, interpreter: Path) -> None:
    destination.write_bytes(patched_interpreter_bytes(source.read_bytes(), str(interpreter)))
    destination.chmod(source.stat().st_mode | 0o100)


def compile_checked(command: list[str], cwd: Path) -> None:
    try:
        result = subprocess.run(command, cwd=cwd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as error:
        raise fail(f"could not execute {command[0]}: {error}") from error
    if result.returncode != 0:
        output = result.stdout.decode("utf-8", errors="replace")
        raise fail(f"compile command failed ({result.returncode}): {' '.join(command)}\n{output}")


def clean_environment(library_dir: Path) -> dict[str, str]:
    """Avoid host loader variables while retaining an executable search PATH."""

    path = os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    return {
        "PATH": path,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "LD_LIBRARY_PATH": str(library_dir),
    }


def rusage_record(value: resource.struct_rusage) -> dict[str, int]:
    # Linux documents ru_maxrss in KiB.  Keep the unit in the key so a report
    # cannot accidentally compare it with the byte-valued BSD/macOS field.
    return {
        "user_cpu_ns": round(value.ru_utime * 1_000_000_000),
        "system_cpu_ns": round(value.ru_stime * 1_000_000_000),
        "max_rss_kib": value.ru_maxrss,
        "minor_faults": value.ru_minflt,
        "major_faults": value.ru_majflt,
        "voluntary_context_switches": value.ru_nvcsw,
        "involuntary_context_switches": value.ru_nivcsw,
    }


def wait_with_rusage(pid: int, timeout: float) -> tuple[int, resource.struct_rusage, bool]:
    deadline = time.monotonic() + timeout
    while True:
        completed_pid, status, usage = os.wait4(pid, os.WNOHANG)
        if completed_pid == pid:
            return status, usage, False
        if time.monotonic() >= deadline:
            os.kill(pid, signal.SIGKILL)
            _, status, usage = os.wait4(pid, 0)
            return status, usage, True
        time.sleep(0.001)


def status_record(status: int, timed_out: bool) -> dict[str, Any]:
    if timed_out:
        return {"kind": "timeout"}
    if os.WIFEXITED(status):
        return {"kind": "exit", "code": os.WEXITSTATUS(status)}
    if os.WIFSIGNALED(status):
        return {"kind": "signal", "signal": os.WTERMSIG(status)}
    return {"kind": "unknown", "wait_status": status}


def run_measured(
    binary: Path,
    arguments: list[str],
    environment: dict[str, str],
    cwd: Path,
    output_root: Path,
    timeout: float,
) -> dict[str, Any]:
    """Run one child with isolated wait4 resource accounting and no tracing."""

    output_root.mkdir(parents=True, exist_ok=True)
    stdout_path = output_root / "stdout"
    stderr_path = output_root / "stderr"
    started = time.monotonic_ns()
    pid = os.fork()
    if pid == 0:
        try:
            stdout = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            stderr = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(stdout, 1)
            os.dup2(stderr, 2)
            os.close(stdout)
            os.close(stderr)
            os.chdir(cwd)
            os.execve(str(binary), [str(binary), *arguments], environment)
        except BaseException as error:
            os.write(2, f"exec failure: {error}\n".encode("utf-8", errors="replace"))
            os._exit(127)
    status, usage, timed_out = wait_with_rusage(pid, timeout)
    result = {
        "elapsed_wall_ns": time.monotonic_ns() - started,
        "status": status_record(status, timed_out),
        "resources": rusage_record(usage),
        "stdout_sha256": sha256_file(stdout_path) if stdout_path.exists() else None,
        "stderr_sha256": sha256_file(stderr_path) if stderr_path.exists() else None,
    }
    stdout = stdout_path.read_bytes() if stdout_path.exists() else b""
    stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
    result["stdout_matches"] = stdout == EXPECTED_STDOUT
    result["stderr_bytes"] = len(stderr)
    if not result["stdout_matches"] or stderr:
        result["stdout_preview"] = stdout[:512].decode("utf-8", errors="replace")
        result["stderr_preview"] = stderr[:512].decode("utf-8", errors="replace")
    return result


def valid_sample(sample: dict[str, Any]) -> bool:
    status = sample["status"]
    return status == {"kind": "exit", "code": 0} and sample["stdout_matches"] and sample["stderr_bytes"] == 0


def percentile(values: list[int], fraction: float) -> int:
    """Nearest-rank percentile; stable and dependency-free for report readers."""

    if not values:
        raise ValueError("cannot summarize no values")
    index = max(0, min(len(values) - 1, int((len(values) - 1) * fraction + 0.5)))
    return sorted(values)[index]


def summarize_samples(samples: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Return transparent quantiles for every directly measured numeric field."""

    fields: dict[str, list[int]] = {"elapsed_wall_ns": []}
    for key in (
        "user_cpu_ns",
        "system_cpu_ns",
        "max_rss_kib",
        "minor_faults",
        "major_faults",
        "voluntary_context_switches",
        "involuntary_context_switches",
    ):
        fields[f"resources.{key}"] = []
    for sample in samples:
        fields["elapsed_wall_ns"].append(sample["elapsed_wall_ns"])
        for key, value in sample["resources"].items():
            fields[f"resources.{key}"].append(value)
    return {
        key: {
            "min": min(values),
            "median": round(statistics.median(values)),
            "p95": percentile(values, 0.95),
            "max": max(values),
        }
        for key, values in fields.items()
    }


def syscall_summary(trace: str) -> dict[str, Any]:
    """Parse raw strace output without treating it as a timing measurement."""

    calls: dict[str, dict[str, int]] = {}
    pattern = re.compile(r"^(?:\[pid\s+\d+\]\s+)?(?:\d+\s+)?([A-Za-z_][A-Za-z0-9_]*)\(")
    for raw in trace.splitlines():
        match = pattern.match(raw)
        if match is None:
            continue
        name = match.group(1)
        current = calls.setdefault(name, {"calls": 0, "errors": 0})
        current["calls"] += 1
        if " = -1 " in raw:
            current["errors"] += 1
    ordered = {name: calls[name] for name in sorted(calls)}
    return {
        "calls": ordered,
        "total_calls": sum(entry["calls"] for entry in ordered.values()),
        "total_errors": sum(entry["errors"] for entry in ordered.values()),
    }


def syscall_diagnostic(
    binary: Path,
    arguments: list[str],
    environment: dict[str, str],
    cwd: Path,
    trace_path: Path,
    timeout: float,
) -> dict[str, Any]:
    if shutil.which("strace") is None:
        return {"status": "unsupported", "reason": "strace is unavailable", "diagnostic": True, "timing": False}
    command = ["strace", "-f", "-qq", "-o", str(trace_path), str(binary), *arguments]
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "diagnostic": True, "timing": False}
    trace = trace_path.read_text(encoding="utf-8", errors="replace") if trace_path.exists() else ""
    return {
        "status": "ok" if result.returncode == 0 and result.stdout == EXPECTED_STDOUT and not result.stderr else "failed",
        "diagnostic": True,
        "timing": False,
        "command": command,
        "exit_code": result.returncode,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_preview": result.stderr[:512].decode("utf-8", errors="replace"),
        "trace_sha256": hashlib.sha256(trace.encode("utf-8")).hexdigest(),
        **syscall_summary(trace),
    }


def proc_memory_snapshot(pid: int) -> dict[str, int]:
    """Capture the Linux resident/PSS view while live allocations are retained."""

    result: dict[str, int] = {}
    status = Path(f"/proc/{pid}/status")
    if status.is_file():
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"^(VmRSS|VmHWM|VmSize):\s+(\d+)\s+kB$", line)
            if match is not None:
                result[match.group(1).lower() + "_kib"] = int(match.group(2))
    rollup = Path(f"/proc/{pid}/smaps_rollup")
    if rollup.is_file():
        for line in rollup.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"^(Rss|Pss|Private_Clean|Private_Dirty):\s+(\d+)\s+kB$", line)
            if match is not None:
                result[match.group(1).lower() + "_kib"] = int(match.group(2))
    return result


def live_memory_diagnostic(
    binary: Path,
    environment: dict[str, str],
    cwd: Path,
    output_root: Path,
    timeout: float,
) -> dict[str, Any]:
    """Measure RSS/PSS after 32 MiB of allocator-owned memory becomes live."""

    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    stdout_path = output_root / "live.stdout"
    stderr_path = output_root / "live.stderr"
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_read)
            os.close(continue_write)
            stdout = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            stderr = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(stdout, 1)
            os.dup2(stderr, 2)
            os.dup2(ready_write, 97)
            os.dup2(continue_read, 98)
            for descriptor in (stdout, stderr, ready_write, continue_read):
                if descriptor not in (1, 2, 97, 98):
                    os.close(descriptor)
            os.chdir(cwd)
            os.execve(
                str(binary),
                [str(binary), "allocator_live", "128", "262144", "97", "98"],
                environment,
            )
        except BaseException as error:
            os.write(2, f"live probe exec failure: {error}\n".encode("utf-8", errors="replace"))
            os._exit(127)
    os.close(ready_write)
    os.close(continue_read)
    try:
        ready, _, _ = select.select([ready_read], [], [], timeout)
        if not ready or os.read(ready_read, 1) != b"R":
            os.kill(pid, signal.SIGKILL)
            _, status, usage = os.wait4(pid, 0)
            return {
                "status": "failed-before-ready",
                "child": status_record(status, False),
                "resources": rusage_record(usage),
            }
        memory = proc_memory_snapshot(pid)
        os.write(continue_write, b"C")
        status, usage, timed_out = wait_with_rusage(pid, timeout)
    finally:
        os.close(ready_read)
        os.close(continue_write)
    stdout = stdout_path.read_bytes() if stdout_path.exists() else b""
    stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
    return {
        "status": "ok" if not timed_out and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and stdout == EXPECTED_STDOUT and not stderr else "failed",
        "live_allocation_bytes": 128 * 262144,
        "memory": memory,
        "child": status_record(status, timed_out),
        "resources": rusage_record(usage),
        "stderr_preview": stderr[:512].decode("utf-8", errors="replace"),
    }


def workload_arguments(workload: Workload, dso: Path) -> list[str]:
    arguments = [workload.name, str(workload.iterations), *workload.extra_arguments]
    if workload.name == "dlsym_128":
        arguments.append(str(dso))
    return arguments


def measure_workload(
    lane: dict[str, Any],
    workload: Workload,
    samples: int,
    warmup: int,
    timeout: float,
    output_root: Path,
    collect_syscalls: bool,
) -> dict[str, Any]:
    arguments = workload_arguments(workload, lane["dso"])
    for index in range(warmup):
        warmup_result = run_measured(
            lane["binary"], arguments, lane["environment"], lane["runtime"],
            output_root / f"warmup-{lane['name']}-{workload.name}-{index}", timeout,
        )
        if not valid_sample(warmup_result):
            return {"status": "warmup-failed", "warmup": warmup_result}
    observed: list[dict[str, Any]] = []
    for index in range(samples):
        sample = run_measured(
            lane["binary"], arguments, lane["environment"], lane["runtime"],
            output_root / f"sample-{lane['name']}-{workload.name}-{index}", timeout,
        )
        if not valid_sample(sample):
            return {"status": "sample-failed", "samples": observed, "failure": sample}
        observed.append(sample)
    result: dict[str, Any] = {
        "status": "ok",
        "iterations_per_process": workload.iterations,
        "warmup_processes": warmup,
        "sample_count": samples,
        "samples": observed,
        "summary": summarize_samples(observed),
    }
    if collect_syscalls:
        result["syscalls"] = syscall_diagnostic(
            lane["binary"], arguments, lane["environment"], lane["runtime"],
            output_root / f"{lane['name']}-{workload.name}.strace", timeout,
        )
    return result


def stage_lanes(
    root: Path,
    compiler: str,
    musl_root: Path,
    target_dir: Path,
    temporary: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    """Compile once, then stage two runtime byte sets under short PT_INTERP paths."""

    source = root / "compat/perf/fixtures/workload.c"
    symbols = root / "compat/perf/fixtures/symbols.c"
    original = temporary / "workload"
    dso = temporary / "libsymbols.so"
    compile_checked([compiler, "-O3", "-fPIE", "-pie", "-fno-builtin", str(source), "-o", str(original)], root)
    compile_checked([compiler, "-O3", "-fPIC", "-shared", "-fno-builtin", str(symbols), "-o", str(dso)], root)
    runtime = Path(tempfile.mkdtemp(prefix="p-", dir="/tmp"))
    reference_library = runtime / "musl-lib"
    candidate_library = runtime / "crabc-lib"
    reference_library.mkdir()
    candidate_library.mkdir()
    reference_loader = runtime / "r"
    candidate_loader = runtime / "c"
    shutil.copy2(musl_root / "lib/ld-musl-aarch64.so.1", reference_loader)
    shutil.copy2(target_dir / "libldso.so", candidate_loader)
    candidate_loader.chmod(candidate_loader.stat().st_mode | 0o100)
    reference_binary = runtime / "reference"
    candidate_binary = runtime / "candidate"
    patch_interpreter(original, reference_binary, reference_loader)
    patch_interpreter(original, candidate_binary, candidate_loader)
    reference_dso = reference_library / "libsymbols.so"
    candidate_dso = candidate_library / "libsymbols.so"
    shutil.copy2(dso, reference_dso)
    shutil.copy2(dso, candidate_dso)
    shutil.copy2(musl_root / "lib/libc.so", reference_library / "libc.musl-aarch64.so.1")
    shutil.copy2(musl_root / "lib/libc.so", reference_library / "libc.so")
    reference = {
        "name": "musl",
        "binary": reference_binary,
        "runtime": runtime,
        "environment": clean_environment(reference_library),
        "dso": reference_dso,
        "loader_sha256": sha256_file(reference_loader),
        "libc_sha256": sha256_file(reference_library / "libc.so"),
    }
    candidate_library_sha = sha256_file(target_dir / "libc.so")
    shutil.copy2(target_dir / "libc.so", candidate_library / "libc.musl-aarch64.so.1")
    shutil.copy2(target_dir / "libc.so", candidate_library / "libc.so")
    candidate = {
        "name": "crabc",
        "binary": candidate_binary,
        "runtime": runtime,
        "environment": clean_environment(candidate_library),
        "dso": candidate_dso,
        "loader_sha256": sha256_file(candidate_loader),
        "libc_sha256": candidate_library_sha,
    }
    provenance = {
        "application_sha256": sha256_file(original),
        "application_path": str(original),
        "symbols_dso_sha256": sha256_file(dso),
        "symbols_dso_export_count": 128,
        "reference_binary_sha256": sha256_file(reference_binary),
        "candidate_binary_sha256": sha256_file(candidate_binary),
    }
    return reference, candidate, provenance


def validate_inputs(args: argparse.Namespace, root: Path) -> tuple[Path, Path, str]:
    if platform.machine() != "aarch64":
        raise fail(f"requires native Linux/AArch64; platform.machine() was {platform.machine()}")
    if sys.platform != "linux":
        raise fail(f"requires Linux; sys.platform was {sys.platform}")
    if args.samples <= 0 or args.warmup < 0 or args.timeout <= 0:
        raise fail("--samples must be positive; --warmup must be non-negative; --timeout must be positive")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.label):
        raise fail("--label may contain only letters, digits, dot, underscore, and dash")
    musl_root = args.musl_root.expanduser().resolve()
    if musl_root.name != f"musl-{MUSL_VERSION}" or not (musl_root / "include").is_dir():
        raise fail(f"--musl-root must be the pinned musl-{MUSL_VERSION} tree: {musl_root}")
    if not (musl_root / "lib/ld-musl-aarch64.so.1").is_file() or not (musl_root / "lib/libc.so").is_file():
        raise fail("pinned musl loader/libc artifacts are missing")
    target_dir = args.target_dir.expanduser().resolve()
    for name in ("libc.so", "libldso.so"):
        if not (target_dir / name).is_file():
            raise fail(f"crabc release artifact is missing: {target_dir / name}")
    compiler = shutil.which(args.musl_cc)
    if compiler is None:
        raise fail(f"musl compiler is unavailable: {args.musl_cc}")
    if not (root / "compat/perf/fixtures/workload.c").is_file():
        raise fail("workload source is unavailable")
    return musl_root, target_dir, compiler


def unsupported_report(root: Path, args: argparse.Namespace, reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "kind": "crabc-musl-performance",
        "status": "unsupported",
        "reason": reason,
        "host": {"system": platform.system(), "machine": platform.machine(), "release": platform.release()},
        "profile_release": profile_release(root),
        "label": args.label,
    }


def main() -> int:
    args = parse_args()
    root = repository_root()
    report_path = args.report or root / "compat/reports/perf" / f"{args.label}.json"
    try:
        musl_root, target_dir, compiler = validate_inputs(args, root)
    except RunnerError as error:
        report = unsupported_report(root, args, str(error))
        atomic_write_json(report_path, report)
        print(f"performance: unsupported: {error}", file=sys.stderr)
        print(report_path)
        return 0

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "kind": "crabc-musl-performance",
        "status": "ok",
        "label": args.label,
        "measurement_contract": {
            "timing": "parent monotonic clock around one child; no strace/profiler in timed samples",
            "cpu_and_process_resources": "isolated Linux wait4(2) rusage for each child",
            "resident_memory": "Linux /proc/<pid>/status and smaps_rollup while 32 MiB is live",
            "syscalls": "separate strace diagnostic; never a timing sample",
            "comparison": "same musl-compiled application bytes and inputs; PT_INTERP and runtime library bytes vary",
        },
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
            "cpuinfo_sha256": sha256_file(Path("/proc/cpuinfo")) if Path("/proc/cpuinfo").is_file() else None,
        },
        "inputs": {
            "musl_version": MUSL_VERSION,
            "musl_root": str(musl_root),
            "musl_compiler": compiler,
            "musl_compiler_version": command_output([compiler, "--version"]).splitlines()[:1],
            "target_dir": str(target_dir),
            "profile_release": profile_release(root),
            "samples": args.samples,
            "warmup": args.warmup,
            "timeout_seconds": args.timeout,
        },
        "workloads": [
            {"name": workload.name, "iterations_per_process": workload.iterations}
            for workload in WORKLOADS
        ],
        "lanes": {},
    }
    temporary = Path(tempfile.mkdtemp(prefix="crabc-perf-", dir="/tmp"))
    runtime: Path | None = None
    try:
        reference, candidate, provenance = stage_lanes(root, compiler, musl_root, target_dir, temporary)
        runtime = reference["runtime"]
        report["provenance"] = provenance
        report["lanes"] = {
            "musl": {
                "loader_sha256": reference["loader_sha256"],
                "libc_sha256": reference["libc_sha256"],
                "workloads": {},
            },
            "crabc": {
                "loader_sha256": candidate["loader_sha256"],
                "libc_sha256": candidate["libc_sha256"],
                "workloads": {},
            },
        }
        output_root = temporary / "output"
        output_root.mkdir()
        for lane_name, lane in (("musl", reference), ("crabc", candidate)):
            lane_report = report["lanes"][lane_name]
            lane_report["live_allocator_memory"] = live_memory_diagnostic(
                lane["binary"], lane["environment"], lane["runtime"], output_root, args.timeout,
            )
            for workload in WORKLOADS:
                lane_report["workloads"][workload.name] = measure_workload(
                    lane, workload, args.samples, args.warmup,
                    args.timeout, output_root, not args.skip_syscalls,
                )
                if lane_report["workloads"][workload.name]["status"] != "ok":
                    report["status"] = "partial"
            if lane_report["live_allocator_memory"]["status"] != "ok":
                report["status"] = "partial"
    except RunnerError as error:
        report["status"] = "setup-failed"
        report["error"] = str(error)
    finally:
        atomic_write_json(report_path, report)
        shutil.rmtree(temporary, ignore_errors=True)
        if runtime is not None:
            shutil.rmtree(runtime, ignore_errors=True)
    print(report_path)
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
