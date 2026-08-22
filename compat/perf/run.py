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
import random
import re
import resource
import secrets
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


SCHEMA = 5
MUSL_VERSION = "1.2.6"
DEFAULT_MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
EXPECTED_STDOUT = b"ok\n"
SCALAR_MATRIX_SIZES = (64, 16 * 1024, 256 * 1024)
CACHE_SPAN_BYTES = 128 * 1024 * 1024
CACHE_SPAN_NEEDLE = b"needle"
CACHE_SPAN_PADDING_BYTES = 16
CACHE_SPAN_WRITE_CHUNK_BYTES = 1024 * 1024
DIAGNOSTIC_MARKER_ENV = "CRABC_PERF_MARKER_FD"
DIAGNOSTIC_MARKER_BEGIN = "CRABC_PERF_BEGIN"
DIAGNOSTIC_MARKER_END = "CRABC_PERF_END"


@dataclass(frozen=True)
class Workload:
    """One process-isolated operation and its intentionally fixed input."""

    name: str
    iterations: int
    extra_arguments: tuple[str, ...] = ()
    fixture_mode: str | None = None
    binary: str = "workload"


WORKLOADS = (
    Workload("startup", 1),
    Workload("startup_constructor_destructor", 1, binary="constructor"),
    Workload("startup_dependency_graph", 1, binary="graph"),
    Workload("clock_gettime", 200_000),
    Workload("gettimeofday", 200_000),
    Workload("getpid", 200_000),
    Workload("open_close", 25_000),
    Workload("fd_file_4k", 5_000),
    Workload("stdio_file_4k", 100),
    Workload("stdio_format_parse", 1_000),
    Workload("pthread_create_join_tls", 1_000),
    Workload("pthread_mutex_uncontended", 2_000_000),
    Workload("pthread_mutex_cond_ping_pong", 10_000),
    Workload("loader_dynamic_tls_growth", 8),
    Workload("memcpy_16k", 25_000),
    Workload("memset_16k", 25_000),
    Workload("strlen_16k", 25_000),
    Workload("memchr_16k", 25_000),
    Workload("strstr_4k", 10_000),
    Workload("memmem_4k", 10_000),
    # Each scalar-matrix row moves or examines about 128 MiB for copy/fill and
    # about 32 MiB for search.  The fixed row name records the size and input
    # alignment; generic fixture modes keep that input contract explicit.
    Workload("memcpy_64_aligned", 2_000_000, ("64", "0", "0"), "memcpy_matrix"),
    Workload("memcpy_64_unaligned", 2_000_000, ("64", "1", "3"), "memcpy_matrix"),
    Workload("memcpy_16k_aligned", 8_000, ("16384", "0", "0"), "memcpy_matrix"),
    Workload("memcpy_16k_unaligned", 8_000, ("16384", "1", "3"), "memcpy_matrix"),
    Workload("memcpy_256k_aligned", 500, ("262144", "0", "0"), "memcpy_matrix"),
    Workload("memcpy_256k_unaligned", 500, ("262144", "1", "3"), "memcpy_matrix"),
    Workload("memset_64_aligned", 2_000_000, ("64", "0"), "memset_matrix"),
    Workload("memset_64_unaligned", 2_000_000, ("64", "3"), "memset_matrix"),
    Workload("memset_16k_aligned", 8_000, ("16384", "0"), "memset_matrix"),
    Workload("memset_16k_unaligned", 8_000, ("16384", "3"), "memset_matrix"),
    Workload("memset_256k_aligned", 500, ("262144", "0"), "memset_matrix"),
    Workload("memset_256k_unaligned", 500, ("262144", "3"), "memset_matrix"),
    Workload("strlen_64_aligned", 500_000, ("64", "0"), "strlen_matrix"),
    Workload("strlen_64_unaligned", 500_000, ("64", "3"), "strlen_matrix"),
    Workload("strlen_16k_aligned", 2_000, ("16384", "0"), "strlen_matrix"),
    Workload("strlen_16k_unaligned", 2_000, ("16384", "3"), "strlen_matrix"),
    Workload("strlen_256k_aligned", 125, ("262144", "0"), "strlen_matrix"),
    Workload("strlen_256k_unaligned", 125, ("262144", "3"), "strlen_matrix"),
    Workload("memchr_64_aligned", 500_000, ("64", "0"), "memchr_matrix"),
    Workload("memchr_64_unaligned", 500_000, ("64", "3"), "memchr_matrix"),
    Workload("memchr_16k_aligned", 2_000, ("16384", "0"), "memchr_matrix"),
    Workload("memchr_16k_unaligned", 2_000, ("16384", "3"), "memchr_matrix"),
    Workload("memchr_256k_aligned", 125, ("262144", "0"), "memchr_matrix"),
    Workload("memchr_256k_unaligned", 125, ("262144", "3"), "memchr_matrix"),
    Workload("strstr_64_aligned", 500_000, ("64", "0"), "strstr_matrix"),
    Workload("strstr_64_unaligned", 500_000, ("64", "3"), "strstr_matrix"),
    Workload("strstr_16k_aligned", 2_000, ("16384", "0"), "strstr_matrix"),
    Workload("strstr_16k_unaligned", 2_000, ("16384", "3"), "strstr_matrix"),
    Workload("strstr_256k_aligned", 125, ("262144", "0"), "strstr_matrix"),
    Workload("strstr_256k_unaligned", 125, ("262144", "3"), "strstr_matrix"),
    Workload("memmem_64_aligned", 500_000, ("64", "0"), "memmem_matrix"),
    Workload("memmem_64_unaligned", 500_000, ("64", "3"), "memmem_matrix"),
    Workload("memmem_16k_aligned", 2_000, ("16384", "0"), "memmem_matrix"),
    Workload("memmem_16k_unaligned", 2_000, ("16384", "3"), "memmem_matrix"),
    Workload("memmem_256k_aligned", 125, ("262144", "0"), "memmem_matrix"),
    Workload("memmem_256k_unaligned", 125, ("262144", "3"), "memmem_matrix"),
    Workload("memcpy_128m_aligned", 4, ("memcpy", str(CACHE_SPAN_BYTES), "0"), "span_matrix"),
    Workload("memcpy_128m_unaligned", 4, ("memcpy", str(CACHE_SPAN_BYTES), "3"), "span_matrix"),
    Workload("memset_128m_aligned", 4, ("memset", str(CACHE_SPAN_BYTES), "0"), "span_matrix"),
    Workload("memset_128m_unaligned", 4, ("memset", str(CACHE_SPAN_BYTES), "3"), "span_matrix"),
    Workload("strlen_128m_aligned", 4, ("strlen", str(CACHE_SPAN_BYTES), "0"), "span_matrix"),
    Workload("strlen_128m_unaligned", 4, ("strlen", str(CACHE_SPAN_BYTES), "3"), "span_matrix"),
    Workload("memchr_128m_aligned", 4, ("memchr", str(CACHE_SPAN_BYTES), "0"), "span_matrix"),
    Workload("memchr_128m_unaligned", 4, ("memchr", str(CACHE_SPAN_BYTES), "3"), "span_matrix"),
    Workload("strstr_128m_aligned", 4, ("strstr", str(CACHE_SPAN_BYTES), "0"), "span_matrix"),
    Workload("strstr_128m_unaligned", 4, ("strstr", str(CACHE_SPAN_BYTES), "3"), "span_matrix"),
    Workload("memmem_128m_aligned", 4, ("memmem", str(CACHE_SPAN_BYTES), "0"), "span_matrix"),
    Workload("memmem_128m_unaligned", 4, ("memmem", str(CACHE_SPAN_BYTES), "3"), "span_matrix"),
    Workload("allocator_64", 100_000),
    Workload("allocator_4k", 50_000),
    # Dynamic-loader lookup needs a longer hot loop than syscall and string
    # probes: 5,000 lookups left fresh-process setup in the CPU median.
    Workload("dlsym_1", 100_000),
    Workload("dlsym_128", 100_000),
    Workload("dlsym_1024", 100_000),
    Workload("dlopen_graph", 1),
)


class RunnerError(Exception):
    """A setup or contract error, distinct from a measured runtime failure."""


@dataclass(frozen=True)
class CgroupMemoryPeakLeaf:
    """A fresh cgroup-v2 leaf containing exactly one live-memory probe child."""

    path: Path

    def enter_self(self) -> None:
        """Move the calling child into the empty leaf before it runs the fixture."""

        (self.path / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="ascii")

    def read_peak_bytes(self) -> int:
        """Read the cgroup high-water mark after the child has exited."""

        value = (self.path / "memory.peak").read_text(encoding="ascii").strip()
        if not value.isdecimal():
            raise ValueError(f"unexpected cgroup memory.peak value: {value!r}")
        return int(value)


def paired_sample_plan(samples: int, seed: int) -> list[tuple[str, int]]:
    """Interleave paired lane samples in a deterministic, recorded order."""

    if samples <= 0:
        raise ValueError("samples must be positive")
    random_source = random.Random(seed)
    indices = list(range(samples))
    random_source.shuffle(indices)
    plan: list[tuple[str, int]] = []
    for index in indices:
        first = "musl" if random_source.getrandbits(1) == 0 else "crabc"
        second = "crabc" if first == "musl" else "musl"
        plan.extend(((first, index), (second, index)))
    return plan


def select_workloads(requested: list[str] | None) -> tuple[Workload, ...]:
    """Return a declared subset without allowing a report key to repeat."""

    if not requested:
        return WORKLOADS
    available = {workload.name for workload in WORKLOADS}
    unknown = sorted(set(requested) - available)
    if unknown:
        raise ValueError(f"unknown workload selection: {', '.join(unknown)}")
    if len(set(requested)) != len(requested):
        raise ValueError("workload selection contains a duplicate name")
    return tuple(workload for workload in WORKLOADS if workload.name in requested)


def parse_cache_size_bytes(value: str) -> int:
    """Parse Linux sysfs cache sizes such as `128K` without accepting guesses."""

    match = re.fullmatch(r"([1-9][0-9]*)([KMG])?", value.strip())
    if match is None:
        raise ValueError(f"unexpected cache size: {value!r}")
    multiplier = {None: 1, "K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}
    return int(match.group(1)) * multiplier[match.group(2)]


def benchmark_cpu_cache_topology(cpu: int, sysfs_root: Path = Path("/sys/devices/system/cpu")) -> dict[str, Any]:
    """Record data/unified cache facts needed to classify scalar input sizes."""

    cache_root = sysfs_root / f"cpu{cpu}" / "cache"
    if not cache_root.is_dir():
        return {"status": "unsupported", "reason": f"cache sysfs is unavailable: {cache_root}"}
    caches: list[dict[str, Any]] = []
    try:
        for cache_dir in sorted(cache_root.glob("index*"), key=lambda path: path.name):
            if not cache_dir.is_dir():
                continue
            index_text = cache_dir.name.removeprefix("index")
            if not index_text.isdecimal():
                continue
            level_text = (cache_dir / "level").read_text(encoding="ascii").strip()
            line_text = (cache_dir / "coherency_line_size").read_text(encoding="ascii").strip()
            cache_type = (cache_dir / "type").read_text(encoding="ascii").strip()
            if not level_text.isdecimal() or not line_text.isdecimal():
                raise ValueError(f"invalid cache topology in {cache_dir}")
            caches.append(
                {
                    "index": int(index_text),
                    "level": int(level_text),
                    "type": cache_type,
                    "size_bytes": parse_cache_size_bytes((cache_dir / "size").read_text(encoding="ascii")),
                    "line_bytes": int(line_text),
                    "shared_cpu_list": (cache_dir / "shared_cpu_list").read_text(encoding="ascii").strip(),
                }
            )
    except (OSError, ValueError) as error:
        return {"status": "unsupported", "reason": str(error)}
    data_caches = [cache for cache in caches if cache["type"] in ("Data", "Unified")]
    if not data_caches:
        return {"status": "unsupported", "reason": "no data or unified cache entries"}
    def classify_size(size: int) -> dict[str, Any]:
        fitting = [cache for cache in data_caches if cache["size_bytes"] >= size]
        if fitting:
            cache = min(fitting, key=lambda item: (item["level"], item["size_bytes"], item["index"]))
            return {
                "bytes": size,
                "classification": "fits-reported-cache",
                "cache_index": cache["index"],
                "cache_level": cache["level"],
                "cache_type": cache["type"],
            }
        return {
            "bytes": size,
            "classification": "exceeds-largest-reported-data-cache",
        }

    return {
        "status": "ok",
        "cpu": cpu,
        "caches": caches,
        "scalar_matrix_size_classes": {str(size): classify_size(size) for size in SCALAR_MATRIX_SIZES},
        "cache_span_size_class": classify_size(CACHE_SPAN_BYTES),
    }


def bootstrap_cpu_ratio(
    reference: list[int],
    candidate: list[int],
    *,
    seed: int,
    resamples: int = 10_000,
) -> dict[str, float | int]:
    """Return a deterministic paired bootstrap upper bound for CPU medians."""

    if len(reference) == 0 or len(reference) != len(candidate):
        raise ValueError("paired CPU samples must be non-empty and equally sized")
    if resamples <= 0:
        raise ValueError("resamples must be positive")
    if any(value < 0 for value in reference) or any(value < 0 for value in candidate):
        raise ValueError("CPU samples must be non-negative")

    reference_median = statistics.median(reference)
    if reference_median == 0:
        raise ValueError("reference CPU median is below timer resolution")
    candidate_median = statistics.median(candidate)
    random_source = random.Random(seed)
    ratios: list[float] = []
    for _ in range(resamples):
        indices = [random_source.randrange(len(reference)) for _ in reference]
        sampled_reference = statistics.median(reference[index] for index in indices)
        if sampled_reference == 0:
            raise ValueError("bootstrap reference CPU median is below timer resolution")
        sampled_candidate = statistics.median(candidate[index] for index in indices)
        ratios.append(sampled_candidate / sampled_reference)
    ratios.sort()
    upper_index = (95 * resamples + 99) // 100 - 1
    return {
        "median_ratio": candidate_median / reference_median,
        "one_sided_95_upper": ratios[upper_index],
        "resamples": resamples,
        "seed": seed,
    }


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
        default=31,
        help="timed samples per lane/workload after warm-up (default: %(default)s)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        help="untimed warm-up processes per lane/workload (default: %(default)s)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0x4352_4142,
        help="base seed for interleaved sample pairs and bootstrap resampling (default: %(default)s)",
    )
    parser.add_argument(
        "--cpu",
        type=int,
        default=None,
        help="Linux CPU to pin the runner and every child to (default: lowest allowed CPU)",
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
    parser.add_argument(
        "--workload",
        action="append",
        metavar="NAME",
        help="measure only this named workload; repeat to select a matrix subset",
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


def stage_cache_span_source(path: Path, *, span_bytes: int, offset: int) -> None:
    """Write one deterministic C-string/search input without materializing it in Python memory."""

    if span_bytes < len(CACHE_SPAN_NEEDLE) or offset < 0 or offset > 15:
        raise ValueError("invalid cache-spanning fixture dimensions")
    storage_bytes = offset + span_bytes + CACHE_SPAN_PADDING_BYTES
    chunk = b"a" * CACHE_SPAN_WRITE_CHUNK_BYTES
    with path.open("wb") as output:
        remaining = storage_bytes
        while remaining:
            written = min(remaining, len(chunk))
            output.write(chunk[:written])
            remaining -= written
    with path.open("r+b") as output:
        output.seek(offset + span_bytes - len(CACHE_SPAN_NEEDLE))
        output.write(CACHE_SPAN_NEEDLE)
        output.seek(offset + span_bytes)
        output.write(b"\0")


def stage_lane_cache_span_inputs(runtime: Path, lane_name: str) -> dict[str, Path]:
    """Stage private, equal byte inputs for a selected cache-spanning lane."""

    aligned_source = runtime / f"{lane_name}-span-aligned.bin"
    unaligned_source = runtime / f"{lane_name}-span-unaligned.bin"
    destination = runtime / f"{lane_name}-span-destination.bin"
    stage_cache_span_source(aligned_source, span_bytes=CACHE_SPAN_BYTES, offset=0)
    stage_cache_span_source(unaligned_source, span_bytes=CACHE_SPAN_BYTES, offset=3)
    with destination.open("wb") as output:
        output.truncate(3 + CACHE_SPAN_BYTES + CACHE_SPAN_PADDING_BYTES)
    return {
        "span_source_aligned": aligned_source,
        "span_source_unaligned": unaligned_source,
        "span_destination": destination,
    }


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


def clean_environment(library_dir: Path, *additional_library_dirs: Path) -> dict[str, str]:
    """Avoid host loader variables while retaining an executable search PATH."""

    path = os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    return {
        "PATH": path,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "LD_LIBRARY_PATH": ":".join(str(path) for path in (library_dir, *additional_library_dirs)),
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


def diagnostic_marker_pattern(marker_fd: int, marker: str) -> re.Pattern[str]:
    """Match one successful marker write in either supported strace PID layout."""

    prefix = r"(?:\[pid\s+\d+\]\s+)?(?:\d+\s+)?"
    return re.compile(
        rf"^{prefix}write\({marker_fd},\s*\"{re.escape(marker)}\",\s*{len(marker)}\)\s+=\s+{len(marker)}$"
    )


def non_marker_syscall_summary(trace: str, marker_fd: int) -> dict[str, Any]:
    """Keep diagnostic-only writes out of whole-process syscall accounting."""

    begin_pattern = diagnostic_marker_pattern(marker_fd, DIAGNOSTIC_MARKER_BEGIN)
    end_pattern = diagnostic_marker_pattern(marker_fd, DIAGNOSTIC_MARKER_END)
    return syscall_summary(
        "\n".join(
            line for line in trace.splitlines()
            if not begin_pattern.match(line) and not end_pattern.match(line)
        )
    )


def marked_syscall_summary(trace: str, marker_fd: int) -> dict[str, Any]:
    """Summarize only the syscalls strictly between one fixture marker pair."""

    lines = trace.splitlines()
    begin_pattern = diagnostic_marker_pattern(marker_fd, DIAGNOSTIC_MARKER_BEGIN)
    end_pattern = diagnostic_marker_pattern(marker_fd, DIAGNOSTIC_MARKER_END)
    begins = [index for index, line in enumerate(lines) if begin_pattern.match(line)]
    ends = [index for index, line in enumerate(lines) if end_pattern.match(line)]
    if len(begins) != 1 or len(ends) != 1:
        return {
            "status": "failed",
            "reason": f"expected one begin and one end marker, found {len(begins)} begin and {len(ends)} end",
            "marker_fd": marker_fd,
        }
    begin, end = begins[0], ends[0]
    if end <= begin:
        return {
            "status": "failed",
            "reason": "end marker does not follow begin marker",
            "marker_fd": marker_fd,
        }
    return {
        "status": "ok",
        "marker_fd": marker_fd,
        "begin_trace_line": begin + 1,
        "end_trace_line": end + 1,
        **syscall_summary("\n".join(lines[begin + 1:end])),
    }


def syscall_rate_per_operation(summary: dict[str, Any], completed_operations: int) -> dict[str, Any]:
    """Preserve exact diagnostic call rates instead of hiding loop work in totals."""

    if completed_operations <= 0:
        raise ValueError("completed operations must be positive")
    calls = summary["calls"]
    return {
        "completed_operations": completed_operations,
        "calls": {
            name: {
                "calls": entry["calls"] / completed_operations,
                "errors": entry["errors"] / completed_operations,
            }
            for name, entry in calls.items()
        },
        "total_calls": summary["total_calls"] / completed_operations,
        "total_errors": summary["total_errors"] / completed_operations,
    }


def syscall_diagnostic(
    binary: Path,
    arguments: list[str],
    environment: dict[str, str],
    cwd: Path,
    trace_path: Path,
    timeout: float,
    completed_operations: int,
) -> dict[str, Any]:
    if shutil.which("strace") is None:
        return {"status": "unsupported", "reason": "strace is unavailable", "diagnostic": True, "timing": False}
    marker_path = trace_path.with_suffix(".markers")
    marker_fd = os.open(marker_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    diagnostic_environment = {**environment, DIAGNOSTIC_MARKER_ENV: str(marker_fd)}
    command = ["strace", "-f", "-qq", "-o", str(trace_path), str(binary), *arguments]
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=diagnostic_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            pass_fds=(marker_fd,),
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "diagnostic": True, "timing": False}
    finally:
        os.close(marker_fd)
    trace = trace_path.read_text(encoding="utf-8", errors="replace") if trace_path.exists() else ""
    whole_process = non_marker_syscall_summary(trace, marker_fd)
    marked_region = marked_syscall_summary(trace, marker_fd)
    if marked_region["status"] == "ok":
        marked_region["per_completed_operation"] = syscall_rate_per_operation(
            marked_region, completed_operations,
        )
    return {
        "status": (
            "ok"
            if result.returncode == 0 and result.stdout == EXPECTED_STDOUT and not result.stderr
            and marked_region["status"] == "ok"
            else "failed"
        ),
        "diagnostic": True,
        "timing": False,
        "command": command,
        "exit_code": result.returncode,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_preview": result.stderr[:512].decode("utf-8", errors="replace"),
        "trace_sha256": hashlib.sha256(trace.encode("utf-8")).hexdigest(),
        "marker_protocol": {
            "environment_variable": DIAGNOSTIC_MARKER_ENV,
            "begin": DIAGNOSTIC_MARKER_BEGIN,
            "end": DIAGNOSTIC_MARKER_END,
            "marker_writes_excluded_from_whole_process": True,
        },
        **whole_process,
        "whole_process_per_completed_operation": syscall_rate_per_operation(
            whole_process, completed_operations,
        ),
        "marked_region": marked_region,
    }


def cgroup_v2_parent_path(mountinfo: str, cgroup: str) -> Path:
    """Resolve this process's cgroup-v2 directory from procfs records."""

    mount_root: Path | None = None
    mount_point: Path | None = None
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        if separator == "" or after.split(maxsplit=1)[0] != "cgroup2":
            continue
        fields = before.split()
        if len(fields) < 5:
            continue
        mount_root = Path(fields[3])
        mount_point = Path(fields[4])
        break
    if mount_root is None or mount_point is None:
        raise ValueError("cgroup-v2 mount is unavailable")

    parts = cgroup.split("::", maxsplit=1)
    if len(parts) != 2 or parts[0] != "0":
        raise ValueError(f"invalid unified cgroup record: {cgroup!r}")
    current = Path(parts[1])
    try:
        relative = current.relative_to(mount_root)
    except ValueError as error:
        raise ValueError(f"cgroup {current} is outside cgroup-v2 mount root {mount_root}") from error
    return mount_point / relative


def fresh_cgroup_memory_peak_leaf() -> tuple[CgroupMemoryPeakLeaf | None, str | None]:
    """Create a child cgroup for one probe, or retain the precise unsupported reason."""

    try:
        parent = cgroup_v2_parent_path(
            Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace"),
            next(
                line
                for line in Path("/proc/self/cgroup").read_text(encoding="utf-8", errors="replace").splitlines()
                if line.startswith("0::")
            ),
        )
        leaf_path = parent / f"crabc-perf-{os.getpid()}-{secrets.token_hex(8)}"
        leaf_path.mkdir(mode=0o700)
        leaf = CgroupMemoryPeakLeaf(leaf_path)
        if not (leaf.path / "memory.peak").is_file():
            leaf.path.rmdir()
            return None, "fresh cgroup-v2 leaf does not expose memory.peak"
        return leaf, None
    except (OSError, StopIteration, ValueError) as error:
        return None, f"fresh delegated cgroup-v2 memory.peak is unavailable: {error}"


SMAPS_RESIDENT_METRICS = {
    "Rss": "rss_kib",
    "Pss": "pss_kib",
    "Private_Clean": "private_clean_kib",
    "Private_Dirty": "private_dirty_kib",
}


def smaps_mapping_name(header: str) -> str:
    """Return a stable, report-safe label for one /proc/<pid>/smaps mapping."""

    fields = header.split(maxsplit=5)
    if len(fields) < 5:
        raise ValueError(f"invalid smaps mapping header: {header!r}")
    if len(fields) == 5:
        return "[anonymous]"
    pathname = fields[5]
    if pathname.startswith("/"):
        deleted_suffix = " (deleted)"
        deleted = pathname.endswith(deleted_suffix)
        if deleted:
            pathname = pathname[: -len(deleted_suffix)]
        name = Path(pathname).name
        return f"file:{name}" + (" (deleted)" if deleted else "")
    return pathname


def smaps_mapping_summary(smaps: str) -> dict[str, dict[str, int]]:
    """Aggregate resident metrics by mapping kind from one stable smaps snapshot."""

    mappings: dict[str, dict[str, int]] = {}
    current: dict[str, int] | None = None
    for line in smaps.splitlines():
        if re.match(r"^[0-9a-fA-F]+-[0-9a-fA-F]+\s", line) is not None:
            current = mappings.setdefault(
                smaps_mapping_name(line),
                {metric: 0 for metric in SMAPS_RESIDENT_METRICS.values()},
            )
            continue
        if current is None:
            continue
        match = re.match(r"^(Rss|Pss|Private_Clean|Private_Dirty):\s+(\d+)\s+kB$", line)
        if match is not None:
            current[SMAPS_RESIDENT_METRICS[match.group(1)]] += int(match.group(2))
    return {name: mappings[name] for name in sorted(mappings)}


def proc_memory_snapshot(pid: int) -> dict[str, Any]:
    """Capture Linux RSS/PSS and mapping attribution while allocations are retained."""

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
    smaps = Path(f"/proc/{pid}/smaps")
    if smaps.is_file():
        result["mapping_attribution"] = smaps_mapping_summary(
            smaps.read_text(encoding="utf-8", errors="replace")
        )
    return result


def remove_cgroup_memory_peak_leaf(leaf: CgroupMemoryPeakLeaf) -> str | None:
    """Remove the exact fresh leaf after its only child has exited."""

    try:
        leaf.path.rmdir()
    except OSError as error:
        return f"could not remove fresh cgroup-v2 leaf: {error}"
    return None


def cgroup_memory_peak_after_ready_self_test(
    binary: Path,
    environment: dict[str, str],
    cwd: Path,
    output_root: Path,
    timeout: float,
) -> dict[str, Any]:
    """Prove that a fresh leaf records the fixture allocation after its ready barrier."""

    leaf, reason = fresh_cgroup_memory_peak_leaf()
    if leaf is None:
        return {"status": "unsupported", "reason": reason}

    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    stdout_path = output_root / "cgroup-after-ready.stdout"
    stderr_path = output_root / "cgroup-after-ready.stderr"
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
            leaf.enter_self()
            os.chdir(cwd)
            os.execve(
                str(binary),
                [str(binary), "allocator_after_ready", "128", "262144", "97", "98"],
                environment,
            )
        except BaseException as error:
            os.write(2, f"cgroup after-ready probe failure: {error}\n".encode("utf-8", errors="replace"))
            os._exit(127)
    os.close(ready_write)
    os.close(continue_read)
    status: int | None = None
    usage: resource.struct_rusage | None = None
    timed_out = False
    before_peak: int | None = None
    failure: str | None = None
    try:
        ready, _, _ = select.select([ready_read], [], [], timeout)
        if not ready or os.read(ready_read, 1) != b"R":
            failure = "after-ready fixture failed before its ready barrier"
        else:
            before_peak = leaf.read_peak_bytes()
            os.write(continue_write, b"C")
            status, usage, timed_out = wait_with_rusage(pid, timeout)
    except (OSError, ValueError) as error:
        failure = str(error)
    finally:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status, usage = os.wait4(pid, 0)
        os.close(ready_read)
        os.close(continue_write)

    stdout = stdout_path.read_bytes() if stdout_path.exists() else b""
    stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
    try:
        after_peak = leaf.read_peak_bytes()
    except (OSError, ValueError) as error:
        after_peak = None
        failure = failure or str(error)
    cleanup_error = remove_cgroup_memory_peak_leaf(leaf)
    if cleanup_error is not None:
        failure = failure or cleanup_error
    child_ok = (
        status is not None
        and usage is not None
        and not timed_out
        and os.WIFEXITED(status)
        and os.WEXITSTATUS(status) == 0
        and stdout == EXPECTED_STDOUT
        and not stderr
    )
    if before_peak is None or after_peak is None or after_peak <= before_peak:
        failure = failure or "memory.peak did not increase after the ready-barrier allocation"
    return {
        "status": "ok" if child_ok and failure is None else "failed",
        "live_allocation_bytes": 128 * 262144,
        "memory_peak_before_ready_bytes": before_peak,
        "memory_peak_after_ready_bytes": after_peak,
        "child": status_record(status, timed_out) if status is not None else {"status": "not-waited"},
        "resources": rusage_record(usage) if usage is not None else {},
        "stderr_preview": stderr[:512].decode("utf-8", errors="replace"),
        **({"reason": failure} if failure is not None else {}),
    }


def live_memory_diagnostic(
    binary: Path,
    environment: dict[str, str],
    cwd: Path,
    output_root: Path,
    timeout: float,
) -> dict[str, Any]:
    """Measure a 32-MiB live set with PSS and an isolated cgroup high-water mark."""

    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    stdout_path = output_root / "live.stdout"
    stderr_path = output_root / "live.stderr"
    cgroup_leaf, cgroup_reason = fresh_cgroup_memory_peak_leaf()
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
            if cgroup_leaf is not None:
                cgroup_leaf.enter_self()
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
    memory: dict[str, Any] = {}
    status: int | None = None
    usage: resource.struct_rusage | None = None
    timed_out = False
    failed_before_ready = False
    try:
        ready, _, _ = select.select([ready_read], [], [], timeout)
        if not ready or os.read(ready_read, 1) != b"R":
            os.kill(pid, signal.SIGKILL)
            _, status, usage = os.wait4(pid, 0)
            failed_before_ready = True
        else:
            memory = proc_memory_snapshot(pid)
            os.write(continue_write, b"C")
            status, usage, timed_out = wait_with_rusage(pid, timeout)
    finally:
        os.close(ready_read)
        os.close(continue_write)
    stdout = stdout_path.read_bytes() if stdout_path.exists() else b""
    stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
    cgroup_memory: dict[str, Any]
    if cgroup_leaf is None:
        cgroup_memory = {"status": "unsupported", "reason": cgroup_reason}
    else:
        try:
            cgroup_memory = {"status": "ok", "memory_peak_bytes": cgroup_leaf.read_peak_bytes()}
        except (OSError, ValueError) as error:
            cgroup_memory = {"status": "failed", "reason": str(error)}
        cleanup_error = remove_cgroup_memory_peak_leaf(cgroup_leaf)
        if cleanup_error is not None:
            cgroup_memory = {"status": "failed", "reason": cleanup_error}
    child_ok = (
        status is not None
        and usage is not None
        and not timed_out
        and os.WIFEXITED(status)
        and os.WEXITSTATUS(status) == 0
        and stdout == EXPECTED_STDOUT
        and not stderr
    )
    if child_ok and cgroup_memory["status"] == "ok":
        after_ready_self_test = cgroup_memory_peak_after_ready_self_test(
            binary, environment, cwd, output_root, timeout,
        )
        cgroup_memory["after_ready_self_test"] = after_ready_self_test
        if after_ready_self_test["status"] != "ok":
            cgroup_memory["status"] = after_ready_self_test["status"]
    diagnostic_status = "ok" if child_ok and cgroup_memory["status"] == "ok" else "failed"
    if child_ok and cgroup_memory["status"] == "unsupported":
        diagnostic_status = "unsupported"
    if failed_before_ready:
        diagnostic_status = "failed-before-ready"
    return {
        "status": diagnostic_status,
        "live_allocation_bytes": 128 * 262144,
        "memory": memory,
        "cgroup_memory": cgroup_memory,
        "child": status_record(status, timed_out) if status is not None else {"status": "not-waited"},
        "resources": rusage_record(usage) if usage is not None else {},
        "stderr_preview": stderr[:512].decode("utf-8", errors="replace"),
    }


def workload_arguments(
    workload: Workload,
    dso_1: Path,
    dso_128: Path,
    dso_1024: Path,
    graph_root: Path,
    io_file: Path | None = None,
    span_source_aligned: Path | None = None,
    span_source_unaligned: Path | None = None,
    span_destination: Path | None = None,
    tls_growth_directory: Path | None = None,
) -> list[str]:
    arguments = [workload.fixture_mode or workload.name, str(workload.iterations), *workload.extra_arguments]
    if workload.name == "dlsym_1":
        arguments.extend((str(dso_1), "bench_symbol_0"))
    elif workload.name == "dlsym_128":
        arguments.extend((str(dso_128), "bench_symbol_7f"))
    elif workload.name == "dlsym_1024":
        arguments.extend((str(dso_1024), "bench_symbol_1024"))
    elif workload.name == "dlopen_graph":
        arguments.append(str(graph_root))
    elif workload.name in ("fd_file_4k", "stdio_file_4k", "stdio_format_parse"):
        if io_file is None:
            raise ValueError(f"{workload.name} requires a deterministic file input")
        arguments.append(str(io_file))
    elif workload.name == "loader_dynamic_tls_growth":
        if tls_growth_directory is None:
            raise ValueError("loader_dynamic_tls_growth requires staged TLS DSOs")
        arguments.append(str(tls_growth_directory))
    elif workload.fixture_mode == "span_matrix":
        if span_source_aligned is None or span_source_unaligned is None or span_destination is None:
            raise ValueError(f"{workload.name} requires staged cache-spanning inputs")
        source = span_source_unaligned if workload.name.endswith("_unaligned") else span_source_aligned
        arguments.extend((str(source), str(span_destination)))
    return arguments


def workload_arguments_for_lane(workload: Workload, lane: dict[str, Any]) -> list[str]:
    return workload_arguments(
        workload,
        lane["dso_1"],
        lane["dso_128"],
        lane["dso_1024"],
        lane["graph_root"],
        lane["io_file"],
        lane.get("span_source_aligned"),
        lane.get("span_source_unaligned"),
        lane.get("span_destination"),
        lane.get("tls_growth_directory"),
    )


def workload_binary_for_lane(workload: Workload, lane: dict[str, Any]) -> Path:
    """Select the separately compiled fixture required by this workload's contract."""

    if workload.binary == "workload":
        return lane["binary"]
    if workload.binary == "constructor":
        return lane["constructor_binary"]
    if workload.binary == "graph":
        return lane["graph_binary"]
    raise ValueError(f"unknown fixture binary: {workload.binary}")


def measure_workload_pair(
    reference: dict[str, Any],
    candidate: dict[str, Any],
    workload: Workload,
    samples: int,
    warmup: int,
    timeout: float,
    output_root: Path,
    collect_syscalls: bool,
    seed: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Measure paired lanes in one deterministic interleaved execution plan."""

    lanes = {"musl": reference, "crabc": candidate}
    arguments = {name: workload_arguments_for_lane(workload, lane) for name, lane in lanes.items()}
    binaries = {name: workload_binary_for_lane(workload, lane) for name, lane in lanes.items()}
    for lane_name, lane in lanes.items():
        for index in range(warmup):
            warmup_result = run_measured(
                binaries[lane_name], arguments[lane_name], lane["environment"], lane["runtime"],
                output_root / f"warmup-{lane_name}-{workload.name}-{index}", timeout,
            )
            if not valid_sample(warmup_result):
                failed = {"status": "warmup-failed", "warmup": warmup_result}
                skipped = {"status": "skipped", "reason": f"{lane_name} warm-up failed"}
                return (failed, skipped, {"status": "warmup-failed", "seed": seed}) if lane_name == "musl" else (skipped, failed, {"status": "warmup-failed", "seed": seed})

    plan = paired_sample_plan(samples, seed)
    observed: dict[str, list[dict[str, Any] | None]] = {
        "musl": [None] * samples,
        "crabc": [None] * samples,
    }
    for execution_order, (lane_name, sample_index) in enumerate(plan):
        lane = lanes[lane_name]
        sample = run_measured(
            binaries[lane_name], arguments[lane_name], lane["environment"], lane["runtime"],
            output_root / f"sample-{lane_name}-{workload.name}-{sample_index}", timeout,
        )
        sample["sample_index"] = sample_index
        sample["execution_order"] = execution_order
        if not valid_sample(sample):
            prior = [item for item in observed[lane_name] if item is not None]
            failed = {"status": "sample-failed", "samples": prior, "failure": sample}
            skipped = {"status": "skipped", "reason": f"{lane_name} sample failed"}
            return (failed, skipped, {"status": "sample-failed", "seed": seed, "sample_plan": plan}) if lane_name == "musl" else (skipped, failed, {"status": "sample-failed", "seed": seed, "sample_plan": plan})
        observed[lane_name][sample_index] = sample

    completed: dict[str, list[dict[str, Any]]] = {
        name: [item for item in items if item is not None]
        for name, items in observed.items()
    }
    results: dict[str, dict[str, Any]] = {}
    for lane_name, lane in lanes.items():
        lane_samples = completed[lane_name]
        result: dict[str, Any] = {
            "status": "ok",
            "iterations_per_process": workload.iterations,
            "warmup_processes": warmup,
            "sample_count": samples,
            "samples": lane_samples,
            "summary": summarize_samples(lane_samples),
        }
        if collect_syscalls:
            result["syscalls"] = syscall_diagnostic(
                binaries[lane_name], arguments[lane_name], lane["environment"], lane["runtime"],
                output_root / f"{lane_name}-{workload.name}.strace", timeout, workload.iterations,
            )
        results[lane_name] = result

    reference_cpu = [
        sample["resources"]["user_cpu_ns"] + sample["resources"]["system_cpu_ns"]
        for sample in completed["musl"]
    ]
    candidate_cpu = [
        sample["resources"]["user_cpu_ns"] + sample["resources"]["system_cpu_ns"]
        for sample in completed["crabc"]
    ]
    comparison: dict[str, Any] = {
        "status": "ok",
        "seed": seed,
        "sample_plan": [{"lane": lane_name, "sample_index": sample_index} for lane_name, sample_index in plan],
    }
    try:
        cpu = bootstrap_cpu_ratio(reference_cpu, candidate_cpu, seed=seed)
        comparison["cpu"] = {
            **cpu,
            "release_gate": "pass" if cpu["one_sided_95_upper"] <= 0.90 else "fail",
        }
    except ValueError as error:
        comparison["status"] = "cpu-unsupported"
        comparison["cpu"] = {"release_gate": "unsupported", "reason": str(error)}
    return results["musl"], results["crabc"], comparison


def stage_lanes(
    root: Path,
    compiler: str,
    musl_root: Path,
    target_dir: Path,
    temporary: Path,
    workloads: tuple[Workload, ...],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Compile once, then stage two runtime byte sets under short PT_INTERP paths."""

    source = root / "compat/perf/fixtures/workload.c"
    pthread_create_join_tls_contract = root / "compat/perf/fixtures/pthread_create_join_tls_contract.h"
    pthread_mutex_cond_ping_pong_contract = root / "compat/perf/fixtures/pthread_mutex_cond_ping_pong_contract.h"
    pthread_mutex_uncontended_contract = root / "compat/perf/fixtures/pthread_mutex_uncontended_contract.h"
    tls_growth_source = root / "compat/perf/fixtures/tls_growth_dso.c"
    tls_growth_contract = root / "compat/perf/fixtures/tls_growth_contract.h"
    constructor_source = root / "compat/perf/fixtures/startup_constructor.c"
    graph_startup_source = root / "compat/perf/fixtures/startup_graph.c"
    symbols_128 = root / "compat/perf/fixtures/symbols.c"
    original = temporary / "workload"
    constructor_original = temporary / "constructor"
    graph_startup_original = temporary / "graph-startup"
    symbols_1 = temporary / "symbols_1.c"
    dso_1 = temporary / "libsymbols_1.so"
    dso_128 = temporary / "libsymbols_128.so"
    symbols_1024 = temporary / "symbols_1024.c"
    dso_1024 = temporary / "libsymbols_1024.so"
    io_fixture = temporary / "io-fixture.bin"
    tls_growth_paths = [temporary / f"libbench_tls_growth_{index}.so" for index in range(8)]
    graph_sources = {
        "libbench_graph_leaf_left.so": "int bench_graph_leaf_left(void) { return 7; }\n",
        "libbench_graph_leaf_right.so": "int bench_graph_leaf_right(void) { return 11; }\n",
        "libbench_graph_mid_left.so": "extern int bench_graph_leaf_left(void); int bench_graph_mid_left(void) { return bench_graph_leaf_left() + 3; }\n",
        "libbench_graph_mid_right.so": "extern int bench_graph_leaf_right(void); int bench_graph_mid_right(void) { return bench_graph_leaf_right() + 4; }\n",
        "libbench_graph_root.so": "extern int bench_graph_mid_left(void); extern int bench_graph_mid_right(void); int bench_graph_root_value(void) { return bench_graph_mid_left() + bench_graph_mid_right() + 6; }\n",
    }
    compile_checked([compiler, "-O3", "-fPIE", "-pie", "-fno-builtin", str(source), "-o", str(original)], root)
    compile_checked([compiler, "-O3", "-fPIE", "-pie", "-fno-builtin", str(constructor_source), "-o", str(constructor_original)], root)
    symbols_1.write_text(
        "__attribute__((visibility(\"default\"))) int bench_symbol_0(void) { return 0; }\n",
        encoding="utf-8",
    )
    compile_checked([compiler, "-O3", "-fPIC", "-shared", "-fno-builtin", str(symbols_1), "-o", str(dso_1)], root)
    compile_checked([compiler, "-O3", "-fPIC", "-shared", "-fno-builtin", str(symbols_128), "-o", str(dso_128)], root)
    symbols_1024.write_text(
        "\n".join(
            f"__attribute__((visibility(\"default\"))) int bench_symbol_{index}(void) {{ return {index}; }}"
            for index in range(1025)
        )
        + "\n",
        encoding="utf-8",
    )
    compile_checked([compiler, "-O3", "-fPIC", "-shared", "-fno-builtin", str(symbols_1024), "-o", str(dso_1024)], root)
    io_fixture.write_bytes(bytes(range(256)) * 16)
    for index, path in enumerate(tls_growth_paths):
        compile_checked(
            [compiler, "-O3", "-fPIC", "-shared", "-fno-builtin", f"-DTLS_GROWTH_INDEX={index}",
             str(tls_growth_source), "-o", str(path)],
            root,
        )
    graph_paths = {name: temporary / name for name in graph_sources}
    for name, source_text in graph_sources.items():
        source_path = temporary / f"{name}.c"
        source_path.write_text(source_text, encoding="utf-8")
        command = [
            compiler, "-O3", "-fPIC", "-shared", "-fno-builtin", str(source_path),
            f"-Wl,-soname,{name}", "-Wl,-rpath,$ORIGIN", "-o", str(graph_paths[name]),
        ]
        if name == "libbench_graph_mid_left.so":
            command.extend(("-L", str(temporary), "-lbench_graph_leaf_left"))
        elif name == "libbench_graph_mid_right.so":
            command.extend(("-L", str(temporary), "-lbench_graph_leaf_right"))
        elif name == "libbench_graph_root.so":
            command.extend(("-L", str(temporary), "-lbench_graph_mid_left", "-lbench_graph_mid_right"))
        compile_checked(command, root)
    compile_checked(
        [
            compiler, "-O3", "-fPIE", "-pie", "-fno-builtin", str(graph_startup_source),
            "-L", str(temporary), "-lbench_graph_root", "-Wl,-rpath,$ORIGIN/graph-lib",
            "-o", str(graph_startup_original),
        ],
        root,
    )
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
    reference_constructor_binary = runtime / "reference-constructor"
    candidate_constructor_binary = runtime / "candidate-constructor"
    reference_graph_binary = runtime / "reference-graph"
    candidate_graph_binary = runtime / "candidate-graph"
    patch_interpreter(original, reference_binary, reference_loader)
    patch_interpreter(original, candidate_binary, candidate_loader)
    patch_interpreter(constructor_original, reference_constructor_binary, reference_loader)
    patch_interpreter(constructor_original, candidate_constructor_binary, candidate_loader)
    patch_interpreter(graph_startup_original, reference_graph_binary, reference_loader)
    patch_interpreter(graph_startup_original, candidate_graph_binary, candidate_loader)
    reference_dso_1 = reference_library / "libsymbols_1.so"
    candidate_dso_1 = candidate_library / "libsymbols_1.so"
    reference_dso_128 = reference_library / "libsymbols_128.so"
    candidate_dso_128 = candidate_library / "libsymbols_128.so"
    reference_dso_1024 = reference_library / "libsymbols_1024.so"
    candidate_dso_1024 = candidate_library / "libsymbols_1024.so"
    reference_io_file = runtime / "musl-io-fixture.bin"
    candidate_io_file = runtime / "crabc-io-fixture.bin"
    graph_library = runtime / "graph-lib"
    graph_library.mkdir()
    shutil.copy2(dso_1, reference_dso_1)
    shutil.copy2(dso_1, candidate_dso_1)
    shutil.copy2(dso_128, reference_dso_128)
    shutil.copy2(dso_128, candidate_dso_128)
    shutil.copy2(dso_1024, reference_dso_1024)
    shutil.copy2(dso_1024, candidate_dso_1024)
    shutil.copy2(io_fixture, reference_io_file)
    shutil.copy2(io_fixture, candidate_io_file)
    for path in tls_growth_paths:
        shutil.copy2(path, reference_library / path.name)
        shutil.copy2(path, candidate_library / path.name)
    for name, graph_path in graph_paths.items():
        shutil.copy2(graph_path, reference_library / name)
        shutil.copy2(graph_path, candidate_library / name)
        shutil.copy2(graph_path, graph_library / name)
    shutil.copy2(musl_root / "lib/libc.so", reference_library / "libc.musl-aarch64.so.1")
    shutil.copy2(musl_root / "lib/libc.so", reference_library / "libc.so")
    reference = {
        "name": "musl",
        "binary": reference_binary,
        "runtime": runtime,
        "environment": clean_environment(reference_library, graph_library),
        "constructor_binary": reference_constructor_binary,
        "graph_binary": reference_graph_binary,
        "dso_1": reference_dso_1,
        "dso_128": reference_dso_128,
        "dso_1024": reference_dso_1024,
        "graph_root": reference_library / "libbench_graph_root.so",
        "io_file": reference_io_file,
        "tls_growth_directory": reference_library,
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
        "environment": clean_environment(candidate_library, graph_library),
        "constructor_binary": candidate_constructor_binary,
        "graph_binary": candidate_graph_binary,
        "dso_1": candidate_dso_1,
        "dso_128": candidate_dso_128,
        "dso_1024": candidate_dso_1024,
        "graph_root": candidate_library / "libbench_graph_root.so",
        "io_file": candidate_io_file,
        "tls_growth_directory": candidate_library,
        "loader_sha256": sha256_file(candidate_loader),
        "libc_sha256": candidate_library_sha,
    }
    cache_span_inputs: dict[str, dict[str, Path]] = {}
    if any(workload.fixture_mode == "span_matrix" for workload in workloads):
        cache_span_inputs = {
            "musl": stage_lane_cache_span_inputs(runtime, "musl"),
            "crabc": stage_lane_cache_span_inputs(runtime, "crabc"),
        }
        reference.update(cache_span_inputs["musl"])
        candidate.update(cache_span_inputs["crabc"])
    provenance = {
        "application_sha256": sha256_file(original),
        "application_path": str(original),
        "pthread_create_join_tls_contract_sha256": sha256_file(pthread_create_join_tls_contract),
        "pthread_mutex_cond_ping_pong_contract_sha256": sha256_file(pthread_mutex_cond_ping_pong_contract),
        "pthread_mutex_uncontended_contract_sha256": sha256_file(pthread_mutex_uncontended_contract),
        "tls_growth_contract_sha256": sha256_file(tls_growth_contract),
        "tls_growth_dso_sha256": [sha256_file(path) for path in tls_growth_paths],
        "tls_growth_dso_count": len(tls_growth_paths),
        "symbols_1_dso_sha256": sha256_file(dso_1),
        "symbols_1_dso_export_count": 1,
        "symbols_128_dso_sha256": sha256_file(dso_128),
        "symbols_128_dso_export_count": 128,
        "symbols_1024_dso_sha256": sha256_file(dso_1024),
        "symbols_1024_dso_export_count": 1025,
        "graph_dso_sha256": {name: sha256_file(path) for name, path in graph_paths.items()},
        "graph_dso_count": len(graph_paths),
        "io_fixture_sha256": sha256_file(io_fixture),
        "io_fixture_bytes": io_fixture.stat().st_size,
        "reference_binary_sha256": sha256_file(reference_binary),
        "candidate_binary_sha256": sha256_file(candidate_binary),
        "constructor_application_sha256": sha256_file(constructor_original),
        "graph_startup_application_sha256": sha256_file(graph_startup_original),
        "reference_constructor_binary_sha256": sha256_file(reference_constructor_binary),
        "candidate_constructor_binary_sha256": sha256_file(candidate_constructor_binary),
        "reference_graph_binary_sha256": sha256_file(reference_graph_binary),
        "candidate_graph_binary_sha256": sha256_file(candidate_graph_binary),
    }
    if cache_span_inputs:
        provenance["cache_span_inputs"] = {
            "window_bytes": CACHE_SPAN_BYTES,
            "source_padding_bytes": CACHE_SPAN_PADDING_BYTES,
            "tail_needle_hex": CACHE_SPAN_NEEDLE.hex(),
            "lane_isolation": "each lane has distinct immutable source files and a distinct MAP_PRIVATE destination backing file",
            "lanes": {
                lane_name: {
                    name: {
                        "bytes": path.stat().st_size,
                        "sha256": sha256_file(path),
                    }
                    for name, path in paths.items()
                }
                for lane_name, paths in cache_span_inputs.items()
            },
        }
    return reference, candidate, provenance


def validate_inputs(args: argparse.Namespace, root: Path) -> tuple[Path, Path, str]:
    if platform.machine() != "aarch64":
        raise fail(f"requires native Linux/AArch64; platform.machine() was {platform.machine()}")
    if sys.platform != "linux":
        raise fail(f"requires Linux; sys.platform was {sys.platform}")
    if args.samples <= 0 or args.warmup < 0 or args.timeout <= 0 or args.seed < 0:
        raise fail("--samples must be positive; --warmup and --seed must be non-negative; --timeout must be positive")
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
    if not (root / "compat/perf/fixtures/pthread_create_join_tls_contract.h").is_file():
        raise fail("pthread create/join TLS contract source is unavailable")
    if not (root / "compat/perf/fixtures/pthread_mutex_cond_ping_pong_contract.h").is_file():
        raise fail("pthread mutex condition ping-pong contract source is unavailable")
    if not (root / "compat/perf/fixtures/pthread_mutex_uncontended_contract.h").is_file():
        raise fail("pthread mutex uncontended contract source is unavailable")
    if not (root / "compat/perf/fixtures/tls_growth_dso.c").is_file():
        raise fail("dynamic TLS growth DSO source is unavailable")
    if not (root / "compat/perf/fixtures/tls_growth_contract.h").is_file():
        raise fail("dynamic TLS growth contract source is unavailable")
    return musl_root, target_dir, compiler


def pin_benchmark_cpu(requested_cpu: int | None) -> int:
    """Pin the runner before staging so every benchmark child inherits one CPU."""

    if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
        raise fail("Linux CPU affinity APIs are unavailable")
    allowed = os.sched_getaffinity(0)
    if not allowed:
        raise fail("the runner has no allowed CPUs")
    cpu = min(allowed) if requested_cpu is None else requested_cpu
    if cpu not in allowed:
        raise fail(f"requested CPU {cpu} is not in the allowed affinity set {sorted(allowed)}")
    try:
        os.sched_setaffinity(0, {cpu})
    except OSError as error:
        raise fail(f"cannot pin the runner to CPU {cpu}: {error}") from error
    if os.sched_getaffinity(0) != {cpu}:
        raise fail(f"runner affinity did not remain pinned to CPU {cpu}")
    return cpu


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
        selected_workloads = select_workloads(args.workload)
        musl_root, target_dir, compiler = validate_inputs(args, root)
        benchmark_cpu = pin_benchmark_cpu(args.cpu)
    except (RunnerError, ValueError) as error:
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
            "resident_memory": "Linux /proc/<pid>/status, smaps_rollup, and grouped smaps attribution while 32 MiB is live",
            "syscalls": "separate strace diagnostic; never a timing sample; descriptor markers delimit the hot region and are excluded from whole-process totals",
            "comparison": "same musl-compiled application bytes and inputs; PT_INTERP and runtime library bytes vary",
            "sample_order": "paired musl/crabc child processes interleave from a recorded deterministic seed",
            "cpu_decision": "10,000-resample paired bootstrap one-sided 95% upper bound of the median CPU ratio",
        },
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
            "cpuinfo_sha256": sha256_file(Path("/proc/cpuinfo")) if Path("/proc/cpuinfo").is_file() else None,
            "benchmark_cpu": benchmark_cpu,
            "cache_topology": benchmark_cpu_cache_topology(benchmark_cpu),
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
            "seed": args.seed,
            "requested_cpu": args.cpu,
            "timeout_seconds": args.timeout,
            "selected_workloads": [workload.name for workload in selected_workloads],
        },
        "workloads": [
            {"name": workload.name, "iterations_per_process": workload.iterations}
            for workload in selected_workloads
        ],
        "lanes": {},
        "comparisons": {},
    }
    temporary = Path(tempfile.mkdtemp(prefix="crabc-perf-", dir="/tmp"))
    runtime: Path | None = None
    try:
        reference, candidate, provenance = stage_lanes(
            root, compiler, musl_root, target_dir, temporary, selected_workloads,
        )
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
            if lane_report["live_allocator_memory"]["status"] != "ok":
                report["status"] = "partial"
        for workload_index, workload in enumerate(selected_workloads):
            workload_seed = args.seed + workload_index
            reference_result, candidate_result, comparison = measure_workload_pair(
                reference, candidate, workload, args.samples, args.warmup,
                args.timeout, output_root, not args.skip_syscalls, workload_seed,
            )
            report["lanes"]["musl"]["workloads"][workload.name] = reference_result
            report["lanes"]["crabc"]["workloads"][workload.name] = candidate_result
            report["comparisons"][workload.name] = comparison
            if reference_result["status"] != "ok" or candidate_result["status"] != "ok":
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
