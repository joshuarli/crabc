#!/usr/bin/env python3
"""Native x86-64 private-adapter performance and memory evidence.

This runner compares exactly two disposable, native Linux/x86-64 fixture
executables:

* the verified pinned mimalloc v3.5.0 C source, and
* the prefixed ``crabc_test_*`` adapter over the bounded Rust engine.

It deliberately does not build or stage ``crabc-libc`` or ``crabc-ldso``.
The result is evidence for the current single-thread private adapter boundary,
not public ``mi_*`` support, a libc allocator backend, whole-mimalloc
performance qualification, or x86 crabc platform support.
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
import select
import shutil
import signal
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
ALLOCATOR_ROOT = ROOT / "compat/allocator"
FIXTURE_ROOT = ALLOCATOR_ROOT / "perf-x86_64"
REPORT_ROOT = ROOT / "compat/reports/allocator/x86_64/perf"
UPSTREAMS = ROOT / "compat/upstreams.toml"
CACHE = ALLOCATOR_ROOT / ".cache"
TEST_ADAPTER_ROOT = ALLOCATOR_ROOT / "test-adapter"
TEST_ADAPTER_HEADER = TEST_ADAPTER_ROOT / "crabc-mimalloc-test-adapter.h"

SCHEMA = 1
KIND = "crabc-mimalloc-x86_64-private-adapter-performance"
ARCHITECTURE = "x86_64"
RUST_TARGET = "x86_64-unknown-linux-musl"
INTERPRETER = "ld-musl-x86_64.so.1"
MUSL_COMPILER = "musl-gcc"
EXPECTED_ELF = {
    "class": "ELF64",
    "endianness": "little",
    "machine": "Advanced Micro Devices X86-64",
}
RELEASE_FLAGS = (
    "-O3",
    "-DNDEBUG",
    "-DMI_BUILD_RELEASE=1",
    "-DMI_DEBUG=0",
    "-DMI_STAT=0",
    "-DMI_SECURE=0",
    "-DMI_GUARDED=0",
)
ORACLE_SOURCES = (
    "src/alloc.c",
    "src/alloc-aligned.c",
    "src/alloc-posix.c",
    "src/arena.c",
    "src/bitmap.c",
    "src/heap.c",
    "src/init.c",
    "src/libc.c",
    "src/options.c",
    "src/os.c",
    "src/page.c",
    "src/page-map.c",
    "src/random.c",
    "src/stats.c",
    "src/subproc.c",
    "src/theap.c",
    "src/threadlocal.c",
    "src/prim/prim.c",
    "src/prim/prim-tls.c",
)
EXPECTED_RUST_NATIVE_STATIC_LIBRARIES = ("-lgcc_s", "-lc")


@dataclass(frozen=True)
class Workload:
    """One bounded current-engine allocation/free workload."""

    name: str
    request_bytes: int
    batches_per_process: int
    iterations_per_batch: int


# These use only the private adapter's existing ordinary allocation/free slice.
# The batch counts make clock reads amortized while keeping a full 31-sample
# run suitable for a native development machine rather than a promotion gate.
BATCH_WORKLOADS = (
    Workload("alloc_free_64", 64, 32, 20_000),
    Workload("alloc_free_4096", 4096, 32, 5_000),
)
MEMORY_LIVE_BYTES = 8 * 1024 * 1024
MEMORY_BLOCK_BYTES = 4096


class HarnessError(RuntimeError):
    """An evidence-boundary or fixture-contract failure."""


def relative(path: Path) -> str:
    """Use repository-relative paths where possible in durable reports."""

    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise HarnessError(f"required evidence input is missing: {path}")
    return {
        "bytes": path.stat().st_size,
        "path": relative(path),
        "sha256": sha256_file(path),
    }


def artifact_record(path: Path) -> dict[str, Any]:
    """Record a disposable built artifact without retaining a temp path."""

    if not path.is_file():
        raise HarnessError(f"required built artifact is missing: {path}")
    return {
        "bytes": path.stat().st_size,
        "filename": path.name,
        "sha256": sha256_file(path),
    }


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
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


def require_native_x86_64() -> dict[str, str]:
    """Require the canonical host attestation as well as the Docker guest."""

    execution_mode = os.environ.get("CRABC_EXECUTION_MODE")
    host_architecture = os.environ.get("CRABC_HOST_ARCH")
    if execution_mode != "native" or host_architecture not in {"x86_64", "amd64"}:
        raise HarnessError(
            "native x86-64 allocator performance evidence requires canonical native provenance: "
            "CRABC_EXECUTION_MODE=native and CRABC_HOST_ARCH=x86_64 (or amd64)"
        )
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise HarnessError(
            "native x86-64 allocator performance evidence requires the native Linux/x86-64 "
            f"development image; observed {platform.system()}/{platform.machine()}"
        )
    return {"execution_mode": "native", "host_architecture": host_architecture}


def validate_label(label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", label):
        raise HarnessError("label may contain only letters, digits, dot, underscore, and dash")
    return label


def default_report_path(root: Path, label: str) -> Path:
    """Namespace x86 allocator reports away from public-runtime evidence."""

    return root / "compat/reports/allocator/x86_64/perf" / f"{validate_label(label)}.json"


def command_record(command: Sequence[str], *, cwd: Path) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise HarnessError(f"could not execute {command[0]}: {error}") from error
    return {
        "command": list(command),
        "status": completed.returncode,
        "stderr": completed.stderr,
        "stdout": completed.stdout,
    }


def require_success(record: Mapping[str, Any], description: str) -> None:
    if record.get("status") != 0:
        detail = str(record.get("stderr", "")).strip() or str(record.get("stdout", "")).strip()
        raise HarnessError(f"{description} failed ({record.get('status')}): {detail}")


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise HarnessError(f"required tool is unavailable: {name}")
    return path


def load_pin(path: Path = UPSTREAMS) -> dict[str, str]:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HarnessError(f"cannot read mimalloc pin: {error}") from error
    pin = raw.get("mimalloc")
    required = (
        "version",
        "repository",
        "tag",
        "source",
        "sha256",
        "tag_object",
        "revision",
        "archive_root",
    )
    if not isinstance(pin, dict):
        raise HarnessError("compat/upstreams.toml lacks a [mimalloc] pin")
    normalized: dict[str, str] = {}
    for key in required:
        value = pin.get(key)
        if not isinstance(value, str) or not value:
            raise HarnessError(f"mimalloc.{key} must be a non-empty string")
        normalized[key] = value
    if normalized["version"] != "3.5.0" or normalized["tag"] != "v3.5.0":
        raise HarnessError("the private performance oracle is fixed to mimalloc v3.5.0")
    if not re.fullmatch(r"[0-9a-f]{64}", normalized["sha256"]):
        raise HarnessError("mimalloc archive SHA-256 is invalid")
    if not all(re.fullmatch(r"[0-9a-f]{40}", normalized[key]) for key in ("tag_object", "revision")):
        raise HarnessError("mimalloc tag or revision pin is invalid")
    if normalized["archive_root"] != "mimalloc-3.5.0":
        raise HarnessError("mimalloc archive root is not the pinned v3.5.0 root")
    return normalized


def archive_path(pin: Mapping[str, str]) -> Path:
    return CACHE / f"mimalloc-{pin['version']}.tar.gz"


def fetch_archive(pin: Mapping[str, str], *, offline: bool) -> Path:
    """Use only the SHA-256-verified pinned C archive as the C oracle."""

    archive = archive_path(pin)
    if archive.is_file():
        observed = sha256_file(archive)
        if observed != pin["sha256"]:
            raise HarnessError(
                f"cached mimalloc archive digest differs from the pin: expected {pin['sha256']}, observed {observed}"
            )
        return archive
    if offline:
        raise HarnessError(f"verified mimalloc archive is absent from offline cache: {archive}")
    CACHE.mkdir(parents=True, exist_ok=True)
    partial = archive.with_name(f".{archive.name}.part")
    try:
        with urllib.request.urlopen(pin["source"], timeout=60) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output)
    except (OSError, urllib.error.URLError) as error:
        try:
            partial.unlink()
        except FileNotFoundError:
            pass
        raise HarnessError(f"could not download pinned mimalloc archive: {error}") from error
    observed = sha256_file(partial)
    if observed != pin["sha256"]:
        partial.unlink()
        raise HarnessError(
            f"downloaded mimalloc archive digest differs from the pin: expected {pin['sha256']}, observed {observed}"
        )
    os.replace(partial, archive)
    return archive


def safe_extract(archive: Path, destination: Path, archive_root: str) -> Path:
    """Extract only ordinary files beneath the one pinned archive root."""

    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        prefix = f"{archive_root}/"
        for member in members:
            member_path = Path(member.name)
            if (
                (member.name != archive_root and not member.name.startswith(prefix))
                or member_path.is_absolute()
                or ".." in member_path.parts
                or member.issym()
                or member.islnk()
                or member.isdev()
            ):
                raise HarnessError(f"pinned mimalloc archive contains an unsafe member: {member.name}")
        stream.extractall(destination, members, filter="data")
    source = destination / archive_root
    if not (source / "include/mimalloc.h").is_file():
        raise HarnessError("pinned mimalloc archive lacks include/mimalloc.h")
    if any(not (source / item).is_file() for item in ORACLE_SOURCES):
        raise HarnessError("pinned mimalloc archive lacks a required C oracle source unit")
    return source


def source_file_records(source: Path, paths: Sequence[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in paths:
        path = source / item
        if not path.is_file():
            raise HarnessError(f"pinned mimalloc source lacks {item}")
        result.append({"bytes": path.stat().st_size, "path": item, "sha256": sha256_file(path)})
    return result


def parse_elf_identity(output: str) -> dict[str, str]:
    class_match = re.search(r"(?m)^\s*Class:\s*(\S+)\s*$", output)
    data_match = re.search(r"(?m)^\s*Data:\s*(.+?)\s*$", output)
    machine_match = re.search(r"(?m)^\s*Machine:\s*(.+?)\s*$", output)
    if (
        class_match is None
        or class_match.group(1) != EXPECTED_ELF["class"]
        or data_match is None
        or "little endian" not in data_match.group(1)
        or machine_match is None
        or machine_match.group(1) != EXPECTED_ELF["machine"]
    ):
        raise HarnessError("fixture artifact is not Linux/x86-64 little-endian ELF64")
    return dict(EXPECTED_ELF)


def dynamic_dependencies(readelf: str, artifact: Path) -> list[str]:
    record = command_record((readelf, "-d", str(artifact)), cwd=ROOT)
    require_success(record, "fixture dynamic dependency inspection")
    dependencies = re.findall(r"\(NEEDED\).*?\[(.+?)\]", str(record["stdout"]))
    return sorted(set(dependencies))


def executable_interpreter(readelf: str, artifact: Path) -> str:
    record = command_record((readelf, "-l", str(artifact)), cwd=ROOT)
    require_success(record, "fixture PT_INTERP inspection")
    match = re.search(r"Requesting program interpreter:\s*(.+?)\]", str(record["stdout"]))
    if match is None:
        raise HarnessError("fixture has no PT_INTERP")
    interpreter = match.group(1).strip().lstrip("[")
    if Path(interpreter).name != INTERPRETER:
        raise HarnessError(
            f"fixture interpreter differs from the native x86-64 musl contract: {interpreter}"
        )
    return interpreter


def audit_executable(readelf: str, artifact: Path) -> dict[str, Any]:
    header = command_record((readelf, "-h", str(artifact)), cwd=ROOT)
    require_success(header, "fixture ELF header inspection")
    return {
        "artifact": artifact_record(artifact),
        "dynamic_dependencies": dynamic_dependencies(readelf, artifact),
        "elf": parse_elf_identity(str(header["stdout"])),
        "interpreter": executable_interpreter(readelf, artifact),
    }


def adapter_header_symbols() -> list[str]:
    header = TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
    names = re.findall(r"(?m)^[^#\n;]*\b(crabc_test_[A-Za-z0-9_]+)\s*\([^;{]*\)\s*;", header)
    names = sorted(set(names))
    if len(names) != 16:
        raise HarnessError("private adapter header does not retain its 16-symbol boundary")
    return names


def archive_prefixed_symbols(nm: str, artifact: Path) -> list[str]:
    record = command_record((nm, "-g", "--defined-only", str(artifact)), cwd=ROOT)
    require_success(record, "Rust adapter static archive symbol inspection")
    names: set[str] = set()
    for line in str(record["stdout"]).splitlines():
        fields = line.split()
        if len(fields) < 2 or line.endswith(":"):
            continue
        name = fields[-1]
        if name.startswith("crabc_test_"):
            names.add(name)
    return sorted(names)


def parse_native_static_libraries(output: str) -> list[str]:
    matches = re.findall(r"(?m)^\s*(?:note:\s*)?native-static-libs:\s*(.*?)\s*$", output)
    if len(matches) != 1:
        raise HarnessError("Rust adapter native-static-libs output is absent or ambiguous")
    libraries = matches[0].split()
    if not libraries:
        raise HarnessError("Rust adapter native-static-libs output is empty")
    return libraries


def build_pinned_c_fixture(
    compiler: str, readelf: str, source: Path, build_root: Path
) -> tuple[Path, dict[str, Any]]:
    binary = build_root / "pinned-c-fixture"
    command = [
        compiler,
        "-std=c11",
        "-fPIE",
        "-pie",
        "-fno-builtin",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        *RELEASE_FLAGS,
        "-I",
        str(FIXTURE_ROOT),
        "-I",
        str(source / "include"),
        str(FIXTURE_ROOT / "fixture.c"),
        str(FIXTURE_ROOT / "c-backend.c"),
        *(str(source / item) for item in ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C private-adapter fixture build")
    return binary, {
        "build_command": command,
        "configuration_flags": list(RELEASE_FLAGS),
        "executable": audit_executable(readelf, binary),
    }


def build_rust_fixture(
    compiler: str, readelf: str, nm: str, build_root: Path
) -> tuple[Path, dict[str, Any]]:
    cargo_target = build_root / "rust-target"
    cargo_command = [
        "cargo",
        "rustc",
        "--locked",
        "--package",
        "crabc-mimalloc-test-adapter",
        "--lib",
        "--features",
        "test-adapter",
        "--target",
        RUST_TARGET,
        "--release",
        "--target-dir",
        str(cargo_target),
        "--",
        "--print=native-static-libs",
    ]
    cargo = command_record(cargo_command, cwd=ROOT)
    require_success(cargo, "Rust private test-adapter static library build")
    native_libraries = parse_native_static_libraries(str(cargo["stdout"]) + "\n" + str(cargo["stderr"]))
    if native_libraries != list(EXPECTED_RUST_NATIVE_STATIC_LIBRARIES):
        raise HarnessError("Rust adapter native static library contract changed")
    static_library = cargo_target / RUST_TARGET / "release/libcrabc_mimalloc_test_adapter.a"
    expected_symbols = adapter_header_symbols()
    observed_symbols = archive_prefixed_symbols(nm, static_library)
    if observed_symbols != expected_symbols:
        raise HarnessError("Rust adapter static archive no longer exposes exactly the private prefixed symbols")
    binary = build_root / "rust-private-adapter-fixture"
    fixture_command = [
        compiler,
        "-std=c11",
        "-fPIE",
        "-pie",
        "-fno-builtin",
        "-ftls-model=initial-exec",
        "-I",
        str(FIXTURE_ROOT),
        "-I",
        str(TEST_ADAPTER_ROOT),
        str(FIXTURE_ROOT / "fixture.c"),
        str(FIXTURE_ROOT / "rust-backend.c"),
        str(static_library),
        "-L/usr/lib",
        *native_libraries,
        "-pthread",
        "-o",
        str(binary),
    ]
    fixture = command_record(fixture_command, cwd=ROOT)
    require_success(fixture, "Rust private-adapter fixture build")
    return binary, {
        "adapter_header": file_record(TEST_ADAPTER_HEADER),
        "cargo_command": cargo_command,
        "executable": audit_executable(readelf, binary),
        "native_static_libraries": native_libraries,
        "static_archive": artifact_record(static_library),
        "static_archive_prefixed_symbols": observed_symbols,
        "fixture_build_command": fixture_command,
    }


def clean_environment() -> dict[str, str]:
    """Do not let host loader overrides change either fixture lane."""

    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "TZ": "UTC",
    }


def rusage_record(value: resource.struct_rusage) -> dict[str, int]:
    return {
        "involuntary_context_switches": value.ru_nivcsw,
        "major_faults": value.ru_majflt,
        "max_rss_kib": value.ru_maxrss,
        "minor_faults": value.ru_minflt,
        "system_cpu_ns": round(value.ru_stime * 1_000_000_000),
        "user_cpu_ns": round(value.ru_utime * 1_000_000_000),
        "voluntary_context_switches": value.ru_nvcsw,
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


def status_record(status: int, timed_out: bool) -> dict[str, int | str]:
    if timed_out:
        return {"kind": "timeout"}
    if os.WIFEXITED(status):
        return {"code": os.WEXITSTATUS(status), "kind": "exit"}
    if os.WIFSIGNALED(status):
        return {"kind": "signal", "signal": os.WTERMSIG(status)}
    return {"kind": "unknown", "wait_status": status}


def parse_batch_output(output: str, *, expected_batches: int) -> list[int]:
    """Accept exactly the fixture's address-free batch result grammar."""

    values: list[int] = []
    lines = output.splitlines()
    if not lines or lines[-1] != "ok":
        raise HarnessError("fixture batch output lacks its terminal ok record")
    for line in lines[:-1]:
        match = re.fullmatch(r"batch_ns=([1-9][0-9]*)", line)
        if match is None:
            raise HarnessError(f"fixture batch output contains an unexpected record: {line!r}")
        values.append(int(match.group(1)))
    if len(values) != expected_batches:
        raise HarnessError(f"fixture batch output expected {expected_batches} batch records, found {len(values)}")
    return values


def batch_sample_record(
    process: Mapping[str, Any], output: str, *, expected_batches: int
) -> dict[str, Any]:
    """Keep process resource evidence distinct from fixture batch timings."""

    return {
        "batch_ns": parse_batch_output(output, expected_batches=expected_batches),
        "process": dict(process),
    }


def run_batch_sample(
    binary: Path,
    workload: Workload,
    *,
    output_root: Path,
    sample_name: str,
    timeout: float,
) -> dict[str, Any]:
    """Run one fresh fixture process and retain timing-free rusage separately."""

    output_root.mkdir(parents=True, exist_ok=True)
    stdout_path = output_root / f"{sample_name}.stdout"
    stderr_path = output_root / f"{sample_name}.stderr"
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
            os.execve(
                str(binary),
                [
                    str(binary),
                    "batch",
                    str(workload.request_bytes),
                    str(workload.batches_per_process),
                    str(workload.iterations_per_batch),
                ],
                clean_environment(),
            )
        except BaseException as error:
            os.write(2, f"fixture exec failure: {error}\n".encode("utf-8", errors="replace"))
            os._exit(127)
    status, usage, timed_out = wait_with_rusage(pid, timeout)
    stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
    result = {
        "elapsed_wall_ns": time.monotonic_ns() - started,
        "resources": rusage_record(usage),
        "status": status_record(status, timed_out),
        "stderr_bytes": len(stderr.encode("utf-8")),
        "stdout_sha256": sha256_file(stdout_path) if stdout_path.exists() else None,
        "stderr_sha256": sha256_file(stderr_path) if stderr_path.exists() else None,
    }
    if result["status"] != {"code": 0, "kind": "exit"} or stderr:
        raise HarnessError(
            f"fixture batch child failed: status={result['status']} stderr={stderr[:512]!r} stdout={stdout[:512]!r}"
        )
    return batch_sample_record(result, stdout, expected_batches=workload.batches_per_process)


def read_protocol_line(descriptor: int, *, expected: bytes, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    received = bytearray()
    while b"\n" not in received:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HarnessError(f"memory fixture timed out waiting for {expected!r}")
        ready, _, _ = select.select([descriptor], [], [], remaining)
        if not ready:
            continue
        chunk = os.read(descriptor, 128)
        if not chunk:
            raise HarnessError(f"memory fixture closed its readiness pipe before {expected!r}")
        received.extend(chunk)
    line, _, trailing = bytes(received).partition(b"\n")
    if trailing:
        raise HarnessError("memory fixture emitted multiple readiness records before parent release")
    if line + b"\n" != expected:
        raise HarnessError(f"memory fixture expected {expected!r}, observed {line + b'\\n'!r}")


def parse_status_memory(text: str) -> dict[str, int]:
    fields = {"VmRSS": "vm_rss_kib", "VmSize": "vm_size_kib"}
    result: dict[str, int] = {}
    for source, destination in fields.items():
        match = re.search(rf"(?m)^{source}:\s+([0-9]+)\s+kB$", text)
        if match is None:
            raise HarnessError(f"/proc status lacks {source}")
        result[destination] = int(match.group(1))
    return result


def parse_smaps_rollup(text: str) -> dict[str, int]:
    fields = {
        "Rss": "rss_kib",
        "Pss": "pss_kib",
        "Private_Clean": "private_clean_kib",
        "Private_Dirty": "private_dirty_kib",
    }
    result: dict[str, int] = {}
    for source, destination in fields.items():
        match = re.search(rf"(?m)^{source}:\s+([0-9]+)\s+kB$", text)
        if match is None:
            raise HarnessError(f"/proc smaps_rollup lacks {source}")
        result[destination] = int(match.group(1))
    return result


def maps_record(text: str) -> dict[str, int | str]:
    mapping_count = 0
    virtual_bytes = 0
    for line in text.splitlines():
        match = re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s", line)
        if match is None:
            raise HarnessError(f"invalid /proc maps record: {line!r}")
        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        if end <= start:
            raise HarnessError(f"invalid /proc maps range: {line!r}")
        mapping_count += 1
        virtual_bytes += end - start
    if mapping_count == 0:
        raise HarnessError("/proc maps is empty for live fixture")
    return {
        "mapping_count": mapping_count,
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "virtual_bytes": virtual_bytes,
    }


def process_memory_snapshot(pid: int) -> dict[str, Any]:
    proc = Path("/proc") / str(pid)
    try:
        status = (proc / "status").read_text(encoding="utf-8")
        smaps_rollup = (proc / "smaps_rollup").read_text(encoding="utf-8")
        maps = (proc / "maps").read_text(encoding="utf-8")
    except OSError as error:
        raise HarnessError(f"cannot capture live fixture memory from {proc}: {error}") from error
    return {
        "maps": maps_record(maps),
        "smaps_rollup": parse_smaps_rollup(smaps_rollup),
        "status": "ok",
        "status_memory": parse_status_memory(status),
    }


def memory_delta(before: Mapping[str, Any], live: Mapping[str, Any]) -> dict[str, int]:
    """Compare only matching post-init and live numeric observations."""

    if before.get("status") != "ok" or live.get("status") != "ok":
        raise HarnessError("memory delta requires successful post-init and live snapshots")
    result: dict[str, int] = {}
    for group in ("maps", "smaps_rollup", "status_memory"):
        before_group = before.get(group)
        live_group = live.get(group)
        if not isinstance(before_group, Mapping) or not isinstance(live_group, Mapping):
            raise HarnessError(f"memory snapshot lacks {group}")
        for key, before_value in before_group.items():
            live_value = live_group.get(key)
            if type(before_value) is int and type(live_value) is int:
                result[f"{group}.{key}"] = live_value - before_value
    if not result:
        raise HarnessError("memory snapshots have no comparable numeric observations")
    return dict(sorted(result.items()))


def run_memory_sample(
    binary: Path,
    *,
    output_root: Path,
    sample_name: str,
    timeout: float,
) -> dict[str, Any]:
    """Capture baseline-after-init and live-set memory under parent barriers."""

    output_root.mkdir(parents=True, exist_ok=True)
    stdout_path = output_root / f"{sample_name}.stdout"
    stderr_path = output_root / f"{sample_name}.stderr"
    ready_read, ready_write = os.pipe()
    control_read, control_write = os.pipe()
    os.set_inheritable(ready_write, True)
    os.set_inheritable(control_read, True)
    started = time.monotonic_ns()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_read)
            os.close(control_write)
            stdout = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            stderr = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(stdout, 1)
            os.dup2(stderr, 2)
            os.close(stdout)
            os.close(stderr)
            os.execve(
                str(binary),
                [
                    str(binary),
                    "memory",
                    str(MEMORY_LIVE_BYTES),
                    str(MEMORY_BLOCK_BYTES),
                    str(ready_write),
                    str(control_read),
                ],
                clean_environment(),
            )
        except BaseException as error:
            os.write(2, f"memory fixture exec failure: {error}\n".encode("utf-8", errors="replace"))
            os._exit(127)
    os.close(ready_write)
    os.close(control_read)
    reaped = False
    try:
        read_protocol_line(ready_read, expected=b"READY_INIT\n", timeout=timeout)
        post_init = process_memory_snapshot(pid)
        os.write(control_write, b"1")
        read_protocol_line(ready_read, expected=b"READY_LIVE\n", timeout=timeout)
        live = process_memory_snapshot(pid)
        os.write(control_write, b"1")
        status, usage, timed_out = wait_with_rusage(pid, timeout)
        reaped = True
    finally:
        os.close(ready_read)
        os.close(control_write)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.wait4(pid, 0)
            except ChildProcessError:
                pass
    stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
    process = {
        "elapsed_wall_ns": time.monotonic_ns() - started,
        "resources": rusage_record(usage),
        "status": status_record(status, timed_out),
        "stderr_bytes": len(stderr.encode("utf-8")),
        "stdout_sha256": sha256_file(stdout_path) if stdout_path.exists() else None,
        "stderr_sha256": sha256_file(stderr_path) if stderr_path.exists() else None,
    }
    if process["status"] != {"code": 0, "kind": "exit"} or stderr or stdout != "ok\n":
        raise HarnessError(
            f"memory fixture child failed: status={process['status']} stderr={stderr[:512]!r} stdout={stdout[:512]!r}"
        )
    return {
        "live": live,
        "post_initialization": post_init,
        "post_initialization_to_live_delta": memory_delta(post_init, live),
        "process": process,
    }


def percentile(values: Sequence[int], fraction: float) -> int:
    if not values:
        raise HarnessError("cannot summarize an empty measurement")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction + 0.5)))
    return ordered[index]


def numeric_summary(values: Sequence[int]) -> dict[str, int]:
    if not values:
        raise HarnessError("cannot summarize an empty measurement")
    return {
        "max": max(values),
        "median": round(statistics.median(values)),
        "min": min(values),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
    }


def bootstrap_ratio(reference: Sequence[int], candidate: Sequence[int], *, seed: int) -> dict[str, float | int]:
    """One-sided bootstrap evidence, intentionally without a pass threshold."""

    if len(reference) == 0 or len(reference) != len(candidate) or any(value <= 0 for value in reference):
        raise HarnessError("bootstrap ratio requires equal positive reference and candidate samples")
    reference_median = statistics.median(reference)
    candidate_median = statistics.median(candidate)
    random_source = random.Random(seed)
    resamples = 10_000
    ratios: list[float] = []
    for _ in range(resamples):
        indices = [random_source.randrange(len(reference)) for _ in reference]
        sampled_reference = statistics.median(reference[index] for index in indices)
        sampled_candidate = statistics.median(candidate[index] for index in indices)
        ratios.append(sampled_candidate / sampled_reference)
    ratios.sort()
    return {
        "median_ratio_rust_over_c": candidate_median / reference_median,
        "one_sided_95_upper_rust_over_c": ratios[(95 * resamples + 99) // 100 - 1],
        "resamples": resamples,
        "seed": seed,
    }


def paired_sample_plan(samples: int, *, seed: int) -> list[tuple[str, int]]:
    if samples <= 0:
        raise HarnessError("sample count must be positive")
    random_source = random.Random(seed)
    indices = list(range(samples))
    random_source.shuffle(indices)
    plan: list[tuple[str, int]] = []
    for index in indices:
        first = "pinned_c" if random_source.getrandbits(1) == 0 else "rust_private_adapter"
        second = "rust_private_adapter" if first == "pinned_c" else "pinned_c"
        plan.extend(((first, index), (second, index)))
    return plan


def summarize_batch_samples(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    flattened: list[int] = []
    medians: list[int] = []
    p99_values: list[int] = []
    process_cpu: list[int] = []
    for sample in samples:
        batches = sample.get("batch_ns")
        process = sample.get("process")
        if not isinstance(batches, list) or not all(type(value) is int and value > 0 for value in batches):
            raise HarnessError("batch sample lacks positive batch measurements")
        if not isinstance(process, Mapping) or not isinstance(process.get("resources"), Mapping):
            raise HarnessError("batch sample lacks process resource measurements")
        flattened.extend(batches)
        medians.append(round(statistics.median(batches)))
        p99_values.append(percentile(batches, 0.99))
        resources = process["resources"]
        user = resources.get("user_cpu_ns")
        system = resources.get("system_cpu_ns")
        if type(user) is not int or type(system) is not int:
            raise HarnessError("batch sample lacks CPU resource measurements")
        process_cpu.append(user + system)
    return {
        "batch_ns": numeric_summary(flattened),
        "per_process_batch_median_ns": numeric_summary(medians),
        "per_process_batch_p99_ns": numeric_summary(p99_values),
        "process_cpu_ns": numeric_summary(process_cpu),
    }


def measure_batch_workload(
    binaries: Mapping[str, Path],
    workload: Workload,
    *,
    samples: int,
    warmup: int,
    seed: int,
    timeout: float,
    output_root: Path,
) -> dict[str, Any]:
    lanes = ("pinned_c", "rust_private_adapter")
    for lane in lanes:
        for warmup_index in range(warmup):
            run_batch_sample(
                binaries[lane],
                workload,
                output_root=output_root,
                sample_name=f"warmup-{workload.name}-{lane}-{warmup_index}",
                timeout=timeout,
            )
    by_lane: dict[str, list[dict[str, Any] | None]] = {lane: [None] * samples for lane in lanes}
    plan = paired_sample_plan(samples, seed=seed)
    for lane, sample_index in plan:
        record = run_batch_sample(
            binaries[lane],
            workload,
            output_root=output_root,
            sample_name=f"sample-{workload.name}-{lane}-{sample_index}",
            timeout=timeout,
        )
        record["sample_index"] = sample_index
        by_lane[lane][sample_index] = record
    completed: dict[str, list[dict[str, Any]]] = {}
    for lane, records in by_lane.items():
        if any(record is None for record in records):
            raise HarnessError(f"batch measurement did not complete every {lane} sample")
        completed[lane] = [record for record in records if record is not None]
    c_medians = [round(statistics.median(record["batch_ns"])) for record in completed["pinned_c"]]
    rust_medians = [round(statistics.median(record["batch_ns"])) for record in completed["rust_private_adapter"]]
    c_p99 = [percentile(record["batch_ns"], 0.99) for record in completed["pinned_c"]]
    rust_p99 = [percentile(record["batch_ns"], 0.99) for record in completed["rust_private_adapter"]]
    return {
        "comparison": {
            "batch_median_ns": bootstrap_ratio(c_medians, rust_medians, seed=seed),
            "batch_p99_ns": bootstrap_ratio(c_p99, rust_p99, seed=seed ^ 0x5EED),
            "status": "measured-no-promotion-threshold",
        },
        "lanes": {
            lane: {"samples": records, "summary": summarize_batch_samples(records)}
            for lane, records in completed.items()
        },
        "request_bytes": workload.request_bytes,
        "batches_per_process": workload.batches_per_process,
        "iterations_per_batch": workload.iterations_per_batch,
        "sample_plan": [{"lane": lane, "sample_index": index} for lane, index in plan],
        "warmup_processes_per_lane": warmup,
    }


def summarize_memory_samples(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    fields: dict[str, list[int]] = {}
    for sample in samples:
        delta = sample.get("post_initialization_to_live_delta")
        if not isinstance(delta, Mapping):
            raise HarnessError("memory sample lacks its post-init delta")
        for name, value in delta.items():
            if type(value) is not int:
                raise HarnessError("memory sample delta contains a non-integer")
            fields.setdefault(name, []).append(value)
    return {name: numeric_summary(values) for name, values in sorted(fields.items())}


def measure_memory(
    binaries: Mapping[str, Path],
    *,
    samples: int,
    warmup: int,
    seed: int,
    timeout: float,
    output_root: Path,
) -> dict[str, Any]:
    lanes = ("pinned_c", "rust_private_adapter")
    for lane in lanes:
        for warmup_index in range(warmup):
            run_memory_sample(
                binaries[lane],
                output_root=output_root,
                sample_name=f"warmup-live-memory-{lane}-{warmup_index}",
                timeout=timeout,
            )
    by_lane: dict[str, list[dict[str, Any] | None]] = {lane: [None] * samples for lane in lanes}
    plan = paired_sample_plan(samples, seed=seed)
    for lane, sample_index in plan:
        record = run_memory_sample(
            binaries[lane],
            output_root=output_root,
            sample_name=f"sample-live-memory-{lane}-{sample_index}",
            timeout=timeout,
        )
        record["sample_index"] = sample_index
        by_lane[lane][sample_index] = record
    completed: dict[str, list[dict[str, Any]]] = {}
    for lane, records in by_lane.items():
        if any(record is None for record in records):
            raise HarnessError(f"memory measurement did not complete every {lane} sample")
        completed[lane] = [record for record in records if record is not None]
    differences: dict[str, list[int]] = {}
    for c_record, rust_record in zip(completed["pinned_c"], completed["rust_private_adapter"], strict=True):
        c_delta = c_record["post_initialization_to_live_delta"]
        rust_delta = rust_record["post_initialization_to_live_delta"]
        assert isinstance(c_delta, Mapping) and isinstance(rust_delta, Mapping)
        for field in sorted(set(c_delta).intersection(rust_delta)):
            c_value = c_delta[field]
            rust_value = rust_delta[field]
            if type(c_value) is int and type(rust_value) is int:
                differences.setdefault(field, []).append(rust_value - c_value)
    return {
        "block_bytes": MEMORY_BLOCK_BYTES,
        "comparison": {
            "paired_post_initialization_delta_rust_minus_c": {
                name: numeric_summary(values) for name, values in sorted(differences.items())
            },
            "status": "observational-no-memory-parity-threshold",
        },
        "lanes": {
            lane: {"samples": records, "post_initialization_to_live_delta_summary": summarize_memory_samples(records)}
            for lane, records in completed.items()
        },
        "live_bytes": MEMORY_LIVE_BYTES,
        "sample_plan": [{"lane": lane, "sample_index": index} for lane, index in plan],
        "warmup_processes_per_lane": warmup,
    }


def pin_benchmark_cpu(requested: int | None) -> int:
    if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
        raise HarnessError("Linux CPU affinity APIs are unavailable")
    allowed = os.sched_getaffinity(0)
    if not allowed:
        raise HarnessError("the performance runner has no allowed CPUs")
    cpu = min(allowed) if requested is None else requested
    if cpu not in allowed:
        raise HarnessError(f"requested CPU {cpu} is not in the allowed affinity set {sorted(allowed)}")
    try:
        os.sched_setaffinity(0, {cpu})
    except OSError as error:
        raise HarnessError(f"cannot pin the native benchmark runner to CPU {cpu}: {error}") from error
    if os.sched_getaffinity(0) != {cpu}:
        raise HarnessError(f"benchmark runner affinity did not remain pinned to CPU {cpu}")
    return cpu


def release_profile(root: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    in_release = False
    for raw_line in (root / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("["):
            in_release = line == "[profile.release]"
        elif in_release and "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            entries[key.strip()] = value.strip()
    return entries


def tool_version(tool: str) -> str:
    record = command_record((tool, "--version"), cwd=ROOT)
    require_success(record, f"{tool} version probe")
    lines = str(record["stdout"]).splitlines()
    if not lines:
        raise HarnessError(f"{tool} version probe emitted no output")
    return lines[0]


def empty_report(*, label: str, native_execution_provenance: Mapping[str, str]) -> dict[str, Any]:
    """Return the narrow report skeleton that tests can validate without tools."""

    return {
        "architecture": ARCHITECTURE,
        "comparison_scope": "same native Linux/x86-64 host and shared fixture source; never compare across architectures",
        "interpreter": INTERPRETER,
        "kind": KIND,
        "label": validate_label(label),
        "native_execution_provenance": dict(native_execution_provenance),
        "schema": SCHEMA,
        "scope": {
            "claim": "bounded single-thread private-adapter C/Rust performance and post-init live-memory evidence",
            "performance_qualification": False,
            "profile": "linux-x86_64-private-test-adapter",
            "public_crabc_allocator_integration": False,
            "public_mi_api": False,
            "public_support": False,
        },
        "status": "pending",
        "target": RUST_TARGET,
    }


def validate_report_contract(report: Mapping[str, Any]) -> None:
    """Fail closed if a report drifts into a public or promotion claim."""

    if report.get("schema") != SCHEMA or report.get("kind") != KIND:
        raise HarnessError("private-adapter performance report schema changed")
    if report.get("architecture") != ARCHITECTURE or report.get("target") != RUST_TARGET:
        raise HarnessError("private-adapter performance report target changed")
    if report.get("interpreter") != INTERPRETER:
        raise HarnessError("private-adapter performance report interpreter changed")
    validate_label(str(report.get("label", "")))
    provenance = report.get("native_execution_provenance")
    if provenance != {"execution_mode": "native", "host_architecture": "x86_64"} and provenance != {
        "execution_mode": "native",
        "host_architecture": "amd64",
    }:
        raise HarnessError("private-adapter performance report lacks canonical native provenance")
    scope = report.get("scope")
    if not isinstance(scope, Mapping) or scope.get("profile") != "linux-x86_64-private-test-adapter":
        raise HarnessError("private-adapter performance report scope changed")
    for field in (
        "performance_qualification",
        "public_crabc_allocator_integration",
        "public_mi_api",
        "public_support",
    ):
        if scope.get(field) is not False:
            raise HarnessError("private-adapter performance report attempted a public or promotion claim")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--smoke", action="store_true", help="run 3 native samples per lane/workload")
    mode.add_argument("--full", action="store_true", help="run 31 native samples per lane/workload")
    parser.add_argument("--cpu", type=int, default=None, help="allowed Linux CPU to pin (default: lowest allowed)")
    parser.add_argument("--label", default="baseline", help="namespaced report label")
    parser.add_argument("--offline", action="store_true", help="require the pinned C archive in the local cache")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-process timeout in seconds")
    arguments = parser.parse_args()
    validate_label(arguments.label)
    if arguments.timeout <= 0:
        parser.error("--timeout must be positive")
    return arguments


def run(arguments: argparse.Namespace) -> Path:
    native_execution_provenance = require_native_x86_64()
    label = validate_label(arguments.label)
    samples = 3 if arguments.smoke else 31
    warmup = 1 if arguments.smoke else 3
    report_path = default_report_path(ROOT, label)
    report = empty_report(label=label, native_execution_provenance=native_execution_provenance)
    report["mode"] = "smoke" if arguments.smoke else "full"
    report["measurement_contract"] = {
        "batch_timing": "one CLOCK_MONOTONIC pair around each fixed allocation/free batch; never one timer read per operation",
        "comparison": "same C fixture source and workload inputs; only a disposable pinned-C or private Rust-adapter backend shim varies",
        "memory": "post-initialization and touched-live-set /proc snapshots; absolute process memory is not allocator parity because contexts differ",
        "process_resources": "fresh child process wait4(2) rusage outside the timed batches",
        "scope": "single creating-thread private adapter only; no public mi_* or crabc libc allocator ABI",
        "sample_order": "native C/Rust pairs interleave from a recorded deterministic seed",
    }
    benchmark_cpu = pin_benchmark_cpu(arguments.cpu)
    report["host"] = {
        "benchmark_cpu": benchmark_cpu,
        "cpuinfo_sha256": sha256_file(Path("/proc/cpuinfo")) if Path("/proc/cpuinfo").is_file() else None,
        "machine": platform.machine(),
        "release": platform.release(),
        "system": platform.system(),
    }
    compiler = require_tool(MUSL_COMPILER)
    readelf = require_tool("readelf")
    nm = require_tool("nm")
    pin = load_pin()
    archive = fetch_archive(pin, offline=arguments.offline)
    report["inputs"] = {
        "c_release_flags": list(RELEASE_FLAGS),
        "cargo_lock": file_record(ROOT / "Cargo.lock"),
        "cargo_release_profile": release_profile(ROOT),
        "fixture": {
            "c_backend": file_record(FIXTURE_ROOT / "c-backend.c"),
            "header": file_record(FIXTURE_ROOT / "perf-api.h"),
            "rust_backend": file_record(FIXTURE_ROOT / "rust-backend.c"),
            "source": file_record(FIXTURE_ROOT / "fixture.c"),
        },
        "mimalloc": {
            "archive": file_record(archive),
            "archive_root": pin["archive_root"],
            "repository": pin["repository"],
            "revision": pin["revision"],
            "source": pin["source"],
            "tag": pin["tag"],
            "tag_object": pin["tag_object"],
            "version": pin["version"],
        },
        "musl_compiler": {"path": compiler, "version": tool_version(compiler)},
        "rustc_version": tool_version("rustc"),
        "test_adapter_header": file_record(TEST_ADAPTER_HEADER),
    }
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-perf-x86_64-") as temporary_name:
        temporary = Path(temporary_name)
        source = safe_extract(archive, temporary / "source", pin["archive_root"])
        build_root = temporary / "build"
        build_root.mkdir()
        c_binary, c_build = build_pinned_c_fixture(compiler, readelf, source, build_root)
        rust_binary, rust_build = build_rust_fixture(compiler, readelf, nm, build_root)
        binaries = {"pinned_c": c_binary, "rust_private_adapter": rust_binary}
        report["inputs"]["pinned_c_source_units"] = source_file_records(source, ORACLE_SOURCES)
        report["lanes"] = {
            "pinned_c": c_build,
            "rust_private_adapter": rust_build,
        }
        output_root = temporary / "output"
        report["workloads"] = {
            workload.name: measure_batch_workload(
                binaries,
                workload,
                samples=samples,
                warmup=warmup,
                seed=0x4352_4142 + index,
                timeout=arguments.timeout,
                output_root=output_root,
            )
            for index, workload in enumerate(BATCH_WORKLOADS)
        }
        report["memory"] = {
            "live_8m_4096": measure_memory(
                binaries,
                samples=samples,
                warmup=warmup,
                seed=0x4D45_4D31,
                timeout=arguments.timeout,
                output_root=output_root,
            )
        }
    report["status"] = "ok"
    validate_report_contract(report)
    atomic_write_json(report_path, report)
    return report_path


def main() -> int:
    arguments = parse_arguments()
    try:
        report_path = run(arguments)
    except (HarnessError, OSError, tarfile.TarError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
