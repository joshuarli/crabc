#!/usr/bin/env python3
"""Native Linux/AArch64 local allocation/free scaling smoke.

This is separate from the public runtime performance runner and from the
single-thread private Rust adapter. It compiles a disposable fixture against
the exact pinned C mimalloc v3.5.0 source and measures independent local
allocation/free loops at 1/2/4/8 workers where the qualified host allows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[3]
SUITE = Path(__file__).resolve().parent
CACHE = ROOT / "compat" / "allocator" / ".cache"
UPSTREAMS = ROOT / "compat" / "upstreams.toml"
REPORT_ROOT = ROOT / "compat" / "reports" / "allocator" / "aarch64" / "multithread-local"
SCHEMA = 1
KIND = "crabc-mimalloc-aarch64-local-multithread-performance"
TARGET = "aarch64-unknown-linux-musl"
WORKER_SCALES = (1, 2, 4, 8)
EXPECTED_ELF = {"class": "ELF64", "machine": "AArch64"}
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
C_ORACLE_FLAGS = (
    "-DMI_SHARED_LIB",
    "-DMI_SHARED_LIB_EXPORT",
    "-DMI_LIBC_MUSL=1",
    "-DMI_BUILD_RELEASE=1",
    "-DMI_DEBUG=0",
    "-DMI_STAT=0",
    "-DMI_SECURE=0",
    "-DMI_GUARDED=0",
)


class HarnessError(RuntimeError):
    """A setup, fixture, or report-contract violation."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise HarnessError(f"required file is missing: {path}")
    return {"path": relative(path), "bytes": path.stat().st_size, "sha256": sha256_file(path)}


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
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


def validate_label(label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", label):
        raise HarnessError("label may contain only letters, digits, dot, underscore, and dash")
    return label


def default_report_path(label: str) -> Path:
    return REPORT_ROOT / f"{validate_label(label)}.json"


def host_record() -> dict[str, Any]:
    cpuinfo = Path("/proc/cpuinfo")
    return {
        "machine": platform.machine(),
        "release": platform.release(),
        "system": platform.system(),
        "cpuinfo_sha256": sha256_file(cpuinfo) if cpuinfo.is_file() else None,
        "execution_mode": os.environ.get("CRABC_EXECUTION_MODE"),
        "host_architecture": os.environ.get("CRABC_HOST_ARCH"),
    }


def native_aarch64_qualification(host: Mapping[str, Any]) -> tuple[bool, str | None]:
    host_architecture = str(host.get("host_architecture") or "").lower()
    machine = str(host.get("machine") or "").lower()
    if host.get("execution_mode") != "native" or host_architecture not in {"aarch64", "arm64"}:
        return False, "requires CRABC_EXECUTION_MODE=native and CRABC_HOST_ARCH=aarch64 (or arm64)"
    if host.get("system") != "Linux" or machine not in {"aarch64", "arm64"}:
        return False, "requires a native Linux/AArch64 execution environment"
    return True, None


def allowed_cpus() -> list[int]:
    if not hasattr(os, "sched_getaffinity"):
        raise HarnessError("Linux sched_getaffinity is unavailable")
    cpus = sorted(os.sched_getaffinity(0))
    if not cpus:
        raise HarnessError("the process has no allowed benchmark CPUs")
    return cpus


def selected_worker_scales(cpu_count: int) -> list[int]:
    if cpu_count < 1:
        raise HarnessError("at least one allowed CPU is required")
    return [workers for workers in WORKER_SCALES if workers <= cpu_count]


def pin_runner(cpus: Sequence[int]) -> dict[str, list[int]]:
    if not hasattr(os, "sched_setaffinity"):
        raise HarnessError("Linux sched_setaffinity is unavailable")
    before = sorted(os.sched_getaffinity(0))
    requested = sorted(set(cpus))
    try:
        os.sched_setaffinity(0, requested)
    except OSError as error:
        raise HarnessError(f"cannot pin the benchmark runner: {error}") from error
    observed = sorted(os.sched_getaffinity(0))
    if observed != requested:
        raise HarnessError(f"runner affinity mismatch: requested {requested}, observed {observed}")
    return {"before": before, "requested": requested, "observed": observed}


def command_record(command: Sequence[str], *, timeout: float) -> dict[str, Any]:
    started = time.monotonic_ns()
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
                "TZ": "UTC",
            },
        )
    except subprocess.TimeoutExpired as error:
        return {
            "command": list(command),
            "status": "timeout",
            "stdout": error.stdout or "",
            "stderr": error.stderr or "",
            "elapsed_wall_ns": time.monotonic_ns() - started,
        }
    return {
        "command": list(command),
        "status": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "elapsed_wall_ns": time.monotonic_ns() - started,
    }


def require_success(record: Mapping[str, Any], description: str) -> None:
    if record.get("status") != 0:
        detail = str(record.get("stderr") or record.get("stdout") or "").strip()
        raise HarnessError(f"{description} failed ({record.get('status')}): {detail}")


def require_tool(name: str) -> str:
    tool = shutil.which(name)
    if tool is None:
        raise HarnessError(f"required tool is unavailable: {name}")
    return tool


def load_pin() -> dict[str, str]:
    try:
        with UPSTREAMS.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HarnessError(f"cannot read mimalloc pin: {error}") from error
    pin = raw.get("mimalloc")
    required = ("version", "source", "sha256", "archive_root", "revision", "tag", "tag_object")
    if not isinstance(pin, dict):
        raise HarnessError("compat/upstreams.toml lacks [mimalloc]")
    normalized: dict[str, str] = {}
    for key in required:
        value = pin.get(key)
        if not isinstance(value, str) or not value:
            raise HarnessError(f"mimalloc.{key} must be a non-empty string")
        normalized[key] = value
    if (
        normalized["version"] != "3.5.0"
        or normalized["tag"] != "v3.5.0"
        or normalized["archive_root"] != "mimalloc-3.5.0"
        or not re.fullmatch(r"[0-9a-f]{64}", normalized["sha256"])
    ):
        raise HarnessError("the C oracle must remain the pinned mimalloc v3.5.0 archive")
    return normalized


def fetch_archive(pin: Mapping[str, str], *, offline: bool) -> Path:
    archive = CACHE / f"mimalloc-{pin['version']}.tar.gz"
    if archive.is_file():
        if sha256_file(archive) != pin["sha256"]:
            raise HarnessError("cached mimalloc archive digest differs from compat/upstreams.toml")
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
    if sha256_file(partial) != pin["sha256"]:
        partial.unlink()
        raise HarnessError("downloaded mimalloc archive digest differs from compat/upstreams.toml")
    os.replace(partial, archive)
    return archive


def safe_extract(archive: Path, destination: Path, archive_root: str) -> Path:
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
    if not (source / "include" / "mimalloc.h").is_file() or any(not (source / item).is_file() for item in ORACLE_SOURCES):
        raise HarnessError("pinned mimalloc archive lacks the required C oracle sources")
    return source


def fixture_compile_command(compiler: str, source: Path, binary: Path) -> list[str]:
    return [
        compiler,
        "-std=c11",
        "-O3",
        "-DNDEBUG",
        "-fPIE",
        "-pie",
        "-fno-builtin",
        "-D_GNU_SOURCE",
        *C_ORACLE_FLAGS,
        "-I",
        str(source / "include"),
        str(SUITE / "fixture.c"),
        *(str(source / unit) for unit in ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(binary),
    ]


def rust_engine_cargo_command(cargo: str, target_directory: Path) -> list[str]:
    return [
        cargo,
        "build",
        "--locked",
        "--package",
        "crabc-mimalloc",
        "--target",
        TARGET,
        "--release",
        "--target-dir",
        str(target_directory),
    ]


def exact_rlib(target_directory: Path, crate: str) -> Path:
    candidates = sorted((target_directory / TARGET / "release" / "deps").glob(f"lib{crate}-*.rlib"))
    if len(candidates) != 1:
        raise HarnessError(f"Rust fixture needs exactly one {crate} rlib, found {len(candidates)}")
    return candidates[0]


def rust_fixture_rustc_command(rustc: str, target_directory: Path, binary: Path) -> list[str]:
    dependency_directory = target_directory / TARGET / "release" / "deps"
    return [
        rustc,
        "--edition",
        "2024",
        "--target",
        TARGET,
        "--crate-name",
        "rust_local_scaling",
        str(SUITE / "rust-local-scaling.rs"),
        "-L",
        f"dependency={dependency_directory}",
        "--extern",
        f"crabc_core={exact_rlib(target_directory, 'crabc_core')}",
        "--extern",
        f"crabc_mimalloc={exact_rlib(target_directory, 'crabc_mimalloc')}",
        "-C",
        "opt-level=3",
        "-C",
        "lto=fat",
        "-C",
        "codegen-units=1",
        "-C",
        "panic=abort",
        "-o",
        str(binary),
    ]


def parse_aarch64_elf_header(output: str) -> dict[str, str]:
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
        raise HarnessError("pinned C fixture is not a Linux/AArch64 little-endian ELF64 executable")
    return {"class": EXPECTED_ELF["class"], "endianness": "little", "machine": EXPECTED_ELF["machine"]}


def audit_aarch64_fixture(readelf: str, binary: Path, *, timeout: float) -> dict[str, str]:
    header = command_record([readelf, "-h", str(binary)], timeout=timeout)
    require_success(header, "pinned C fixture ELF header inspection")
    return parse_aarch64_elf_header(str(header["stdout"]))


def parse_fixture_output(output: str, *, workers: int, iterations: int, cpus: Sequence[int]) -> dict[str, int | str]:
    expected_affinity = ",".join(str(cpu) for cpu in cpus)
    records: dict[str, str] = {}
    lines = output.splitlines()
    if not lines or lines[-1] != "ok":
        raise HarnessError("fixture output lacks its terminal ok record")
    for line in lines[:-1]:
        match = re.fullmatch(r"(workers|iterations|operations|max_worker_ns|sum_worker_ns|checksum|affinity)=([0-9,]+)", line)
        if match is None or match.group(1) in records:
            raise HarnessError(f"fixture output contains an unexpected record: {line!r}")
        if match.group(1) != "affinity" and "," in match.group(2):
            raise HarnessError(f"fixture output contains a non-numeric value: {line!r}")
        records[match.group(1)] = match.group(2)
    required = {"workers", "iterations", "operations", "max_worker_ns", "sum_worker_ns", "checksum", "affinity"}
    if set(records) != required:
        raise HarnessError("fixture output does not contain the complete measurement grammar")
    if records["affinity"] != expected_affinity:
        raise HarnessError("fixture output affinity differs from the requested worker CPUs")
    numeric = {name: int(records[name]) for name in required - {"affinity"}}
    if numeric["workers"] != workers or numeric["iterations"] != iterations:
        raise HarnessError("fixture output workers or iterations differs from the requested workload")
    if numeric["operations"] != workers * iterations or numeric["max_worker_ns"] <= 0:
        raise HarnessError("fixture output has invalid operation or timing values")
    if numeric["sum_worker_ns"] < numeric["max_worker_ns"]:
        raise HarnessError("fixture output has an impossible worker timing sum")
    return {**numeric, "affinity": records["affinity"]}


def run_fixture(binary: Path, *, workers: int, iterations: int, cpus: Sequence[int], timeout: float) -> dict[str, Any]:
    record = command_record(
        [str(binary), "--workers", str(workers), "--iterations", str(iterations), "--cpus", ",".join(str(cpu) for cpu in cpus)],
        timeout=timeout,
    )
    require_success(record, f"{binary.name} {workers}-worker fixture")
    parsed = parse_fixture_output(str(record["stdout"]), workers=workers, iterations=iterations, cpus=cpus)
    elapsed_ns = int(parsed["max_worker_ns"])
    return {
        "fixture": parsed,
        "elapsed_wall_ns": record["elapsed_wall_ns"],
        "throughput_operations_per_second": int(parsed["operations"]) * 1_000_000_000 / elapsed_ns,
    }


def summarize_samples(samples: Sequence[Mapping[str, Any]]) -> dict[str, float | int]:
    throughput = [float(sample["throughput_operations_per_second"]) for sample in samples]
    elapsed = [int(sample["fixture"]["max_worker_ns"]) for sample in samples]
    return {
        "max_worker_ns_median": int(statistics.median(elapsed)),
        "sample_count": len(samples),
        "throughput_operations_per_second_median": statistics.median(throughput),
    }


def measure_lane(binary: Path, *, scales: Sequence[int], cpus: Sequence[int], samples: int, warmup: int, iterations: int, timeout: float) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for workers in scales:
        worker_cpus = list(cpus[:workers])
        for _ in range(warmup):
            run_fixture(binary, workers=workers, iterations=iterations, cpus=worker_cpus, timeout=timeout)
        measured = [
            run_fixture(binary, workers=workers, iterations=iterations, cpus=worker_cpus, timeout=timeout)
            for _ in range(samples)
        ]
        results[str(workers)] = {
            "affinity_cpus": worker_cpus,
            "samples": measured,
            "summary": summarize_samples(measured),
        }
    return results


def serialization_signatures(scales: Mapping[str, Any]) -> dict[str, Any]:
    baseline = float(scales["1"]["summary"]["throughput_operations_per_second_median"])
    if baseline <= 0:
        raise HarnessError("one-worker throughput must be positive")
    per_scale: dict[str, Any] = {}
    for workers_text, measurement in scales.items():
        workers = int(workers_text)
        observed = float(measurement["summary"]["throughput_operations_per_second_median"]) / baseline
        status = "baseline" if workers == 1 else ("flat-throughput-signature" if observed <= 1.25 else "no-flat-throughput-signature")
        per_scale[workers_text] = {
            "global_serialization_signature": status,
            "independent_worker_target_scaling": workers,
            "parallel_efficiency": observed / workers,
            "throughput_scaling_vs_one_worker": observed,
        }
    return {
        "flat_throughput_maximum_scaling": 1.25,
        "meaning": "A flat-throughput signature is a diagnostic for possible process-global serialization; it is not a performance qualification result.",
        "per_scale": per_scale,
    }


def current_friend_boundary_evidence_classification() -> dict[str, Any]:
    """Keep raw direct-engine scaling distinct from production evidence."""

    return {
        "classification": "diagnostic-only",
        "production_scaling_evidence": {
            "reason": "the checked-in Rust fixture calls the documentation-hidden direct-engine friend boundary, not the production crabc-libc allocator ABI",
            "status": "rejected",
        },
    }


def compare_lanes(c_lane: Mapping[str, Any], rust_lane: Mapping[str, Any]) -> dict[str, Any]:
    production_scaling_evidence = current_friend_boundary_evidence_classification()["production_scaling_evidence"]
    if rust_lane.get("status") != "ok":
        return {
            "status": "unavailable",
            "reason": "Rust multithread fixture was not supplied",
            "production_scaling_evidence": production_scaling_evidence,
        }
    scales: dict[str, Any] = {}
    for workers, c_result in c_lane["scales"].items():
        c_throughput = float(c_result["summary"]["throughput_operations_per_second_median"])
        rust_throughput = float(rust_lane["scales"][workers]["summary"]["throughput_operations_per_second_median"])
        scales[workers] = {"rust_to_pinned_c_throughput_ratio": rust_throughput / c_throughput}
    return {"status": "ok", "scales": scales, "production_scaling_evidence": production_scaling_evidence}


def empty_report(*, label: str, host: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "architecture": "aarch64",
        "host": dict(host),
        "kind": KIND,
        "label": validate_label(label),
        "schema": SCHEMA,
        "scope": {
            "claim": "early native Linux/AArch64 local allocation/free scaling smoke",
            "performance_qualification": False,
            "public_crabc_allocator_integration": False,
            "public_mi_api": False,
            "public_support": False,
        },
        "evidence_classification": {
            "current_rust_direct_engine_friend_boundary": current_friend_boundary_evidence_classification(),
        },
        "target": TARGET,
    }


def validate_report_contract(report: Mapping[str, Any]) -> None:
    if report.get("schema") != SCHEMA or report.get("kind") != KIND:
        raise HarnessError("multithread performance report schema changed")
    if report.get("architecture") != "aarch64" or report.get("target") != TARGET:
        raise HarnessError("multithread performance report target changed")
    validate_label(str(report.get("label", "")))
    scope = report.get("scope")
    if not isinstance(scope, Mapping):
        raise HarnessError("multithread performance report has no scope")
    for field in ("performance_qualification", "public_crabc_allocator_integration", "public_mi_api", "public_support"):
        if scope.get(field) is not False:
            raise HarnessError("multithread performance report attempted a public or promotion claim")
    evidence = report.get("evidence_classification")
    if not isinstance(evidence, Mapping):
        raise HarnessError("multithread performance report has no evidence classification")
    friend_boundary = evidence.get("current_rust_direct_engine_friend_boundary")
    if not isinstance(friend_boundary, Mapping) or friend_boundary.get("classification") != "diagnostic-only":
        raise HarnessError("multithread performance report lost its friend-boundary diagnostic classification")
    production = friend_boundary.get("production_scaling_evidence")
    if not isinstance(production, Mapping) or production.get("status") != "rejected":
        raise HarnessError("multithread performance report accepted friend-boundary production scaling evidence")
    comparison = report.get("comparison")
    if comparison is not None:
        if not isinstance(comparison, Mapping):
            raise HarnessError("multithread performance report comparison is malformed")
        comparison_production = comparison.get("production_scaling_evidence")
        if not isinstance(comparison_production, Mapping) or comparison_production.get("status") != "rejected":
            raise HarnessError("multithread performance report accepted comparison production scaling evidence")
    lanes = report.get("lanes")
    if isinstance(lanes, Mapping) and "rust" in lanes:
        rust_lane = lanes["rust"]
        if not isinstance(rust_lane, Mapping):
            raise HarnessError("multithread performance report Rust lane is malformed")
        lane_evidence = rust_lane.get("evidence_classification")
        if not isinstance(lane_evidence, Mapping) or lane_evidence.get("classification") != "diagnostic-only":
            raise HarnessError("multithread performance report Rust lane lost diagnostic-only classification")
        lane_production = lane_evidence.get("production_scaling_evidence")
        if not isinstance(lane_production, Mapping) or lane_production.get("status") != "rejected":
            raise HarnessError("multithread performance report Rust lane accepted production scaling evidence")


def unavailable_report(*, label: str, host: Mapping[str, Any], reason: str) -> dict[str, Any]:
    report = empty_report(label=label, host=host)
    report.update(
        {
            "status": "unavailable",
            "qualification": {
                "status": "unavailable",
                "required": "native Linux/AArch64 with CRABC_EXECUTION_MODE=native and CRABC_HOST_ARCH=aarch64",
                "reason": reason,
            },
        }
    )
    validate_report_contract(report)
    return report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--smoke", action="store_true", help="run three timed samples at each available scale")
    mode.add_argument("--full", action="store_true", help="run 31 timed samples at each available scale")
    parser.add_argument("--compiler", default="musl-gcc", help="pinned musl C compiler (default: %(default)s)")
    parser.add_argument("--iterations", type=int, default=250_000, help="allocation/free pairs per worker sample")
    parser.add_argument("--label", default="baseline", help="report label")
    parser.add_argument("--offline", action="store_true", help="require the verified C oracle archive in the local cache")
    parser.add_argument("--report", type=Path, default=None, help="JSON report path")
    parser.add_argument("--rust-fixture", type=Path, default=None, help="optional external replacement for the checked-in Rust fixture")
    parser.add_argument("--timeout", type=float, default=30.0, help="per fixture process timeout in seconds")
    arguments = parser.parse_args()
    validate_label(arguments.label)
    if arguments.iterations <= 0 or arguments.timeout <= 0:
        parser.error("--iterations and --timeout must be positive")
    return arguments


def run(arguments: argparse.Namespace) -> Path:
    report_path = arguments.report or default_report_path(arguments.label)
    host = host_record()
    qualified, reason = native_aarch64_qualification(host)
    if not qualified:
        atomic_write_json(report_path, unavailable_report(label=arguments.label, host=host, reason=str(reason)))
        return report_path

    allowed = allowed_cpus()
    scales = selected_worker_scales(len(allowed))
    affinity = pin_runner(allowed[: max(scales)])
    samples, warmup = (3, 1) if arguments.smoke else (31, 3)
    report = empty_report(label=arguments.label, host=host)
    report.update(
        {
            "status": "pending",
            "qualification": {"status": "qualified", "required": "native Linux/AArch64 dispatcher and guest attestation"},
            "affinity": affinity,
            "measurement_contract": {
                "comparison": "the pinned C lane and an optional Rust fixture use the same worker/iteration/affinity command and strict result grammar",
                "timing": "each worker times its post-barrier local allocation/free loop; aggregate throughput divides all completed operations by the slowest worker elapsed time",
                "worker_scales": list(WORKER_SCALES),
            },
            "inputs": {
                "iterations_per_worker": arguments.iterations,
                "samples": samples,
                "warmup": warmup,
                "rust_fixture_source": file_record(SUITE / "rust-local-scaling.rs"),
                "manifest": file_record(SUITE / "manifest.json"),
                "fixture": file_record(SUITE / "fixture.c"),
            },
            "lanes": {},
        }
    )
    compiler = require_tool(arguments.compiler)
    readelf = require_tool("readelf")
    cargo = require_tool("cargo") if arguments.rust_fixture is None else None
    rustc = require_tool("rustc") if arguments.rust_fixture is None else None
    pin = load_pin()
    archive = fetch_archive(pin, offline=arguments.offline)
    report["inputs"].update({"compiler": compiler, "mimalloc_archive": file_record(archive), "mimalloc_revision": pin["revision"]})
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-multithread-aarch64-", dir="/tmp") as temporary_name:
        temporary = Path(temporary_name)
        source = safe_extract(archive, temporary / "source", pin["archive_root"])
        c_fixture = temporary / "pinned-c-local-scaling"
        build = command_record(fixture_compile_command(compiler, source, c_fixture), timeout=arguments.timeout)
        require_success(build, "pinned C multithread fixture build")
        c_elf = audit_aarch64_fixture(readelf, c_fixture, timeout=arguments.timeout)
        c_scales = measure_lane(c_fixture, scales=scales, cpus=allowed, samples=samples, warmup=warmup, iterations=arguments.iterations, timeout=arguments.timeout)
        report["lanes"]["pinned_c"] = {
            "artifact": {"filename": c_fixture.name, "sha256": sha256_file(c_fixture), "bytes": c_fixture.stat().st_size},
            "build_command": build["command"],
            "elf": c_elf,
            "scales": c_scales,
            "serialization": serialization_signatures(c_scales),
            "status": "ok",
        }
        if arguments.rust_fixture is None:
            rust_target = temporary / "rust-target"
            engine_build = command_record(rust_engine_cargo_command(str(cargo), rust_target), timeout=arguments.timeout)
            rust_fixture = temporary / "rust-local-scaling"
            rust_provenance: dict[str, Any] = {"engine_build_command": engine_build["command"]}
            if engine_build["status"] != 0:
                report["lanes"]["rust"] = {
                    **rust_provenance,
                    "evidence_classification": current_friend_boundary_evidence_classification(),
                    "reason": "checked-in direct-engine fixture dependencies did not build: " + str(engine_build["stderr"]).strip(),
                    "status": "unavailable",
                }
            else:
                try:
                    fixture_build = command_record(rust_fixture_rustc_command(str(rustc), rust_target, rust_fixture), timeout=arguments.timeout)
                    require_success(fixture_build, "checked-in direct-engine Rust fixture build")
                    rust_provenance["fixture_build_command"] = fixture_build["command"]
                    rust_provenance["elf"] = audit_aarch64_fixture(readelf, rust_fixture, timeout=arguments.timeout)
                    rust_scales = measure_lane(rust_fixture, scales=scales, cpus=allowed, samples=samples, warmup=warmup, iterations=arguments.iterations, timeout=arguments.timeout)
                except HarnessError as error:
                    report["lanes"]["rust"] = {
                        **rust_provenance,
                        "evidence_classification": current_friend_boundary_evidence_classification(),
                        "reason": "checked-in direct-engine fixture could not complete the current local-worker smoke: " + str(error),
                        "status": "unavailable",
                    }
                else:
                    report["lanes"]["rust"] = {
                        **rust_provenance,
                        "artifact": file_record(rust_fixture),
                        "evidence_classification": current_friend_boundary_evidence_classification(),
                        "scales": rust_scales,
                        "serialization": serialization_signatures(rust_scales),
                        "status": "ok",
                    }
        else:
            rust_fixture = arguments.rust_fixture.resolve()
            if not rust_fixture.is_file() or not os.access(rust_fixture, os.X_OK):
                raise HarnessError(f"Rust fixture is not an executable file: {rust_fixture}")
            rust_scales = measure_lane(rust_fixture, scales=scales, cpus=allowed, samples=samples, warmup=warmup, iterations=arguments.iterations, timeout=arguments.timeout)
            report["lanes"]["rust"] = {
                "artifact": file_record(rust_fixture),
                "elf": audit_aarch64_fixture(readelf, rust_fixture, timeout=arguments.timeout),
                "evidence_classification": {
                    "classification": "diagnostic-only",
                    "production_scaling_evidence": {
                        "reason": "an externally supplied fixture has not established the production crabc-libc allocator ABI boundary",
                        "status": "rejected",
                    },
                },
                "scales": rust_scales,
                "serialization": serialization_signatures(rust_scales),
                "status": "ok",
            }
    report["comparison"] = compare_lanes(report["lanes"]["pinned_c"], report["lanes"]["rust"])
    report["status"] = "ok" if report["comparison"]["status"] == "ok" else "partial"
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
