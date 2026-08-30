#!/usr/bin/env python3
"""Linux/AArch64 local Rust-native versus pinned-C allocation/free smoke.

This is intentionally a development architecture ratchet, not a replacement
for the qualified AArch64 final-promotion performance suite.  The two lanes
execute one identical C fixture and differ only behind an opaque private
init/malloc/free/shutdown boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = Path(__file__).resolve().parent
MANIFEST = FIXTURE_ROOT / "perf-local-aarch64-v3.5.0.json"
UPSTREAMS = ROOT / "compat/upstreams.toml"
TEST_ADAPTER_ROOT = ROOT / "compat/allocator/test-adapter"
TEST_ADAPTER_HEADER = TEST_ADAPTER_ROOT / "crabc-mimalloc-test-adapter.h"
CACHE = FIXTURE_ROOT / ".cache"

SCHEMA = 1
KIND = "crabc-mimalloc-aarch64-local-allocation-performance-smoke"
ARCHITECTURE = "aarch64"
RUST_TARGET = "aarch64-unknown-linux-musl"
MUSL_COMPILER = "musl-gcc"
RUST_SHADOW_BACKEND_IDENTITY = "rust-native-shadow-crabc-test-free-v1"
RUST_SHADOW_FREE_ROUTE = "crabc_test_free"
PINNED_C_BACKEND_IDENTITY = "pinned-c-mimalloc-v3.5.0"
REJECTED_C_FREE_ROUTE = "mi_free"
MEASUREMENT_BOUNDARY_KIND = "direct-engine-friend-boundary"
FIXTURE_RELEASE_FLAGS = ("-O3", "-DNDEBUG")
PINNED_C_SOURCE_CONFIGURATION_FLAGS = (
    "-DMI_SHARED_LIB",
    "-DMI_SHARED_LIB_EXPORT",
    "-DMI_LIBC_MUSL=1",
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


class HarnessError(RuntimeError):
    """A malformed evidence input, unsupported host, or failed fixture."""


@dataclass(frozen=True)
class Workload:
    name: str
    request_bytes: int
    batches_per_process: int
    iterations_per_batch: int


def relative(path: Path) -> str:
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
        raise HarnessError(f"required input is missing: {path}")
    return {"bytes": path.stat().st_size, "path": relative(path), "sha256": sha256_file(path)}


def artifact_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise HarnessError(f"required built artifact is missing: {path}")
    return {"bytes": path.stat().st_size, "filename": path.name, "sha256": sha256_file(path)}


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


def default_report_path(root: Path, label: str) -> Path:
    return root / "compat/reports/allocator/aarch64/local-perf" / f"{validate_label(label)}.json"


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
    return {"command": list(command), "status": completed.returncode, "stderr": completed.stderr, "stdout": completed.stdout}


def require_success(record: Mapping[str, Any], description: str) -> None:
    if record.get("status") != 0:
        detail = str(record.get("stderr", "")).strip() or str(record.get("stdout", "")).strip()
        raise HarnessError(f"{description} failed ({record.get('status')}): {detail}")


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise HarnessError(f"required tool is unavailable: {name}")
    return path


def require_linux_aarch64() -> dict[str, Any]:
    """Accept only the development Linux/AArch64 guest, never a final claim."""

    observed_system = platform.system()
    observed_machine = platform.machine().lower()
    if observed_system != "Linux" or observed_machine not in {"aarch64", "arm64"}:
        raise HarnessError(
            "local allocator performance smoke requires Linux/AArch64; "
            f"observed {observed_system}/{platform.machine()}"
        )
    if sys.byteorder != "little":
        raise HarnessError("local allocator performance smoke requires little-endian AArch64")
    return {
        "architecture": ARCHITECTURE,
        "final_promotion_qualified": False,
        "observed_machine": observed_machine,
        "observed_release": platform.release(),
        "observed_system": observed_system,
        "qualification": "linux-aarch64-development-smoke-only",
        "reason": "This local lane is never final promotion qualification; Docker is development smoke evidence only.",
        "smoke_eligible": True,
    }


def load_manifest(path: Path = MANIFEST) -> tuple[dict[str, Any], tuple[Workload, ...]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessError(f"cannot read local AArch64 performance manifest: {error}") from error
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA or raw.get("kind") != KIND:
        raise HarnessError("local AArch64 performance manifest schema changed")
    if raw.get("architecture") != ARCHITECTURE or raw.get("profile") != "linux-aarch64-local-private-shadow":
        raise HarnessError("local AArch64 performance manifest target changed")
    upstream = raw.get("upstream")
    fixture = raw.get("fixture")
    if not isinstance(upstream, Mapping) or upstream.get("version") != "3.5.0" or upstream.get("revision") != "18b08671c9302247bfb682286e6bf3cc1773f801":
        raise HarnessError("local AArch64 performance manifest upstream changed")
    if not isinstance(fixture, Mapping) or fixture.get("single_thread_only") is not True:
        raise HarnessError("local AArch64 performance manifest no longer describes a single-thread fixture")
    attestation = fixture.get("selected_artifact_attestation")
    if attestation != {
        "backend_identity": RUST_SHADOW_BACKEND_IDENTITY,
        "free_route": RUST_SHADOW_FREE_ROUTE,
        "rejected_c_free_route": REJECTED_C_FREE_ROUTE,
    }:
        raise HarnessError("local AArch64 performance manifest selected-artifact attestation changed")
    measurement_boundary = raw.get("measurement_boundary")
    if measurement_boundary != {
        "final_promotion_qualification_eligible": False,
        "kind": MEASUREMENT_BOUNDARY_KIND,
        "production_libc_measurement": False,
        "reason": "The prefixed crabc_test_* adapter directly enters the Rust engine. It does not measure the production crabc-libc allocator ABI or backend selection.",
    }:
        raise HarnessError("local AArch64 performance manifest measurement boundary changed")
    scope = raw.get("scope")
    if not isinstance(scope, Mapping) or any(
        scope.get(field) is not False
        for field in ("final_promotion_qualification", "public_crabc_allocator_integration", "public_mi_api")
    ):
        raise HarnessError("local AArch64 performance manifest attempted a public or promotion claim")
    smoke = raw.get("architecture_smoke")
    mode = raw.get("mode")
    workloads = raw.get("workloads")
    if not isinstance(smoke, Mapping) or smoke.get("minimum_rust_over_pinned_c_throughput_ratio") != 0.25:
        raise HarnessError("local AArch64 performance manifest lost the architecture smoke ratchet")
    if not isinstance(mode, Mapping) or mode.get("samples_per_lane_and_workload") != 5 or mode.get("warmup_processes_per_lane_and_workload") != 2:
        raise HarnessError("local AArch64 performance manifest mode changed")
    if not isinstance(workloads, list) or not workloads:
        raise HarnessError("local AArch64 performance manifest has no workloads")
    parsed: list[Workload] = []
    names: set[str] = set()
    for item in workloads:
        if not isinstance(item, Mapping):
            raise HarnessError("local AArch64 workload is not an object")
        name = item.get("name")
        fields = ("request_bytes", "batches_per_process", "iterations_per_batch")
        if not isinstance(name, str) or not name or name in names or any(type(item.get(field)) is not int or item[field] <= 0 for field in fields):
            raise HarnessError("local AArch64 workload is invalid")
        names.add(name)
        parsed.append(Workload(name, item["request_bytes"], item["batches_per_process"], item["iterations_per_batch"]))
    return raw, tuple(parsed)


def load_pin(path: Path = UPSTREAMS) -> dict[str, str]:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HarnessError(f"cannot read mimalloc pin: {error}") from error
    pin = raw.get("mimalloc")
    required = ("version", "repository", "tag", "source", "sha256", "tag_object", "revision", "archive_root")
    if not isinstance(pin, dict):
        raise HarnessError("compat/upstreams.toml lacks a [mimalloc] pin")
    normalized: dict[str, str] = {}
    for key in required:
        value = pin.get(key)
        if not isinstance(value, str) or not value:
            raise HarnessError(f"mimalloc.{key} must be a non-empty string")
        normalized[key] = value
    if normalized["version"] != "3.5.0" or normalized["revision"] != "18b08671c9302247bfb682286e6bf3cc1773f801":
        raise HarnessError("local AArch64 performance oracle is fixed to pinned mimalloc v3.5.0")
    if not re.fullmatch(r"[0-9a-f]{64}", normalized["sha256"]):
        raise HarnessError("mimalloc archive SHA-256 is invalid")
    return normalized


def archive_path(pin: Mapping[str, str]) -> Path:
    return CACHE / f"mimalloc-{pin['version']}-{pin['sha256'][:16]}.tar.gz"


def fetch_archive(pin: Mapping[str, str], *, offline: bool) -> Path:
    archive = archive_path(pin)
    if archive.is_file() and sha256_file(archive) == pin["sha256"]:
        return archive
    if offline:
        raise HarnessError(f"pinned mimalloc archive is absent or invalid in offline mode: {archive}")
    archive.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(pin["source"], timeout=60) as response:
            payload = response.read()
    except urllib.error.URLError as error:
        raise HarnessError(f"could not fetch pinned mimalloc archive: {error}") from error
    temporary = archive.with_suffix(".download")
    try:
        temporary.write_bytes(payload)
        if sha256_file(temporary) != pin["sha256"]:
            raise HarnessError("downloaded mimalloc archive SHA-256 differs from compat/upstreams.toml")
        os.replace(temporary, archive)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return archive


def safe_extract(archive: Path, destination: Path, archive_root: str) -> Path:
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            expected_prefix = f"{archive_root}/"
            if not members or any(
                member.name != archive_root and not member.name.startswith(expected_prefix)
                or member.issym() or member.islnk() or member.name.startswith("/") or ".." in Path(member.name).parts
                for member in members
            ):
                raise HarnessError("pinned mimalloc archive has an unsafe or unexpected member")
            bundle.extractall(destination, members=members, filter="data")
    except (OSError, tarfile.TarError) as error:
        raise HarnessError(f"cannot extract pinned mimalloc archive: {error}") from error
    source = destination / archive_root
    if not source.is_dir():
        raise HarnessError("pinned mimalloc archive root was not extracted")
    return source


def parse_native_static_libraries(output: str) -> list[str]:
    matches = re.findall(r"(?m)^\s*(?:note:\s*)?native-static-libs:\s*(.*?)\s*$", output)
    if len(matches) != 1:
        raise HarnessError("Rust shadow adapter native-static-libs output is absent or ambiguous")
    libraries = matches[0].split()
    if not libraries or not all(item.startswith("-") for item in libraries):
        raise HarnessError("Rust shadow adapter native-static-libs output is invalid")
    return libraries


def fixture_link_libraries(native_static_libraries: Sequence[str]) -> list[str]:
    """Keep Cargo's host-link hint out of the musl fixture's final link.

    The pinned AArch64 Rust staticlib currently reports ``-lgcc_s -lc``.
    Alpine's musl toolchain has no shared ``gcc_s`` archive, and its driver
    already supplies the C and compiler runtime for the C fixture.  The
    fixture has no additional Rust-native library requirement (the AArch64
    staticlib includes its compiler-builtins/unwind support), as proved by
    this exact closed input.  Fail closed if Cargo's requirement changes.
    """

    if list(native_static_libraries) != ["-lgcc_s", "-lc"]:
        raise HarnessError("Rust shadow adapter native static library contract changed")
    return []


def adapter_header_symbols() -> list[str]:
    header = TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
    names = re.findall(r"(?m)^[^#\n;]*\b(crabc_test_[A-Za-z0-9_]+)\s*\([^;{]*\)\s*;", header)
    names = sorted(set(names))
    if len(names) != 16:
        raise HarnessError("private adapter header does not retain its 16-symbol boundary")
    return names


def archive_prefixed_symbols(nm: str, artifact: Path) -> list[str]:
    record = command_record((nm, "-g", "--defined-only", str(artifact)), cwd=ROOT)
    require_success(record, "Rust shadow archive symbol inspection")
    names = {line.split()[-1] for line in str(record["stdout"]).splitlines() if len(line.split()) >= 2 and line.split()[-1].startswith("crabc_test_")}
    return sorted(names)


def rust_target_self_contained_search_path() -> str:
    rustc = require_tool("rustc")
    record = command_record((rustc, "--print", "sysroot"), cwd=ROOT)
    require_success(record, "Rust sysroot discovery")
    lines = [line.strip() for line in str(record["stdout"]).splitlines() if line.strip()]
    if len(lines) != 1:
        raise HarnessError("Rust sysroot discovery is absent or ambiguous")
    path = Path(lines[0]) / "lib/rustlib" / RUST_TARGET / "lib/self-contained"
    if not (path / "libunwind.a").is_file():
        raise HarnessError(f"Rust target self-contained libunwind is absent: {path / 'libunwind.a'}")
    return str(path)


def fixture_compiler_prefix(compiler: str) -> list[str]:
    return [compiler, "-std=c11", "-fPIE", "-pie", "-fno-builtin", *FIXTURE_RELEASE_FLAGS]


def pinned_c_fixture_command(compiler: str, source: Path, binary: Path) -> list[str]:
    return [
        *fixture_compiler_prefix(compiler),
        *PINNED_C_SOURCE_CONFIGURATION_FLAGS,
        "-I", str(FIXTURE_ROOT), "-I", str(source / "include"),
        str(FIXTURE_ROOT / "fixture.c"), str(FIXTURE_ROOT / "c-pinned-backend.c"),
        *(str(source / item) for item in ORACLE_SOURCES), "-pthread", "-o", str(binary),
    ]


def rust_adapter_cargo_command(cargo_target: Path) -> list[str]:
    return [
        "cargo", "rustc", "--locked", "--package", "crabc-mimalloc-test-adapter", "--lib",
        "--features", "test-adapter", "--target", RUST_TARGET, "--release", "--target-dir", str(cargo_target),
        "--", "--print=native-static-libs",
    ]


def rust_fixture_command(compiler: str, static_library: Path, native_search_path: str, native_libraries: Sequence[str], binary: Path) -> list[str]:
    return [
        *fixture_compiler_prefix(compiler),
        "-I", str(FIXTURE_ROOT), "-I", str(TEST_ADAPTER_ROOT),
        str(FIXTURE_ROOT / "fixture.c"), str(FIXTURE_ROOT / "rust-native-shadow-backend.c"),
        str(static_library), f"-L{native_search_path}", *native_libraries, "-pthread", "-o", str(binary),
    ]


def parse_elf_identity(output: str) -> dict[str, str]:
    class_match = re.search(r"(?m)^\s*Class:\s*(\S+)\s*$", output)
    data_match = re.search(r"(?m)^\s*Data:\s*(.+?)\s*$", output)
    machine_match = re.search(r"(?m)^\s*Machine:\s*(.+?)\s*$", output)
    if class_match is None or class_match.group(1) != "ELF64" or data_match is None or "little endian" not in data_match.group(1) or machine_match is None or machine_match.group(1) != "AArch64":
        raise HarnessError("fixture artifact is not Linux/AArch64 little-endian ELF64")
    return {"class": "ELF64", "endianness": "little", "machine": "AArch64"}


def audit_executable(readelf: str, artifact: Path) -> dict[str, Any]:
    header = command_record((readelf, "-h", str(artifact)), cwd=ROOT)
    require_success(header, "fixture ELF header inspection")
    return {"artifact": artifact_record(artifact), "elf": parse_elf_identity(str(header["stdout"]))}


def executable_defined_symbols(nm: str, artifact: Path) -> set[str]:
    record = command_record((nm, "-g", "--defined-only", str(artifact)), cwd=ROOT)
    require_success(record, "fixture executable symbol inspection")
    return {
        fields[-1]
        for line in str(record["stdout"]).splitlines()
        if (fields := line.split()) and not line.endswith(":")
    }


def verify_rust_shadow_free_symbols(symbols: set[str]) -> dict[str, Any]:
    """Prove the selected executable retains Rust-shadow free, not C free."""

    if RUST_SHADOW_FREE_ROUTE not in symbols:
        raise HarnessError("Rust shadow executable does not define crabc_test_free")
    if REJECTED_C_FREE_ROUTE in symbols:
        raise HarnessError("Rust shadow executable defines the rejected pinned-C mi_free route")
    return {
        "required_rust_shadow_symbol": RUST_SHADOW_FREE_ROUTE,
        "required_rust_shadow_symbol_defined": True,
        "rejected_c_symbol": REJECTED_C_FREE_ROUTE,
        "rejected_c_symbol_defined": False,
    }


def parse_attestation_output(
    output: str, *, expected_identity: str, expected_free_route: str
) -> dict[str, str]:
    """Accept the fixture-private attestation grammar and no incidental text."""

    expected = [
        f"backend_identity={expected_identity}",
        f"free_route={expected_free_route}",
        "ok",
    ]
    observed = output.splitlines()
    if observed != expected:
        raise HarnessError("fixture selected-artifact attestation output is absent or changed")
    return {"backend_identity": expected_identity, "free_route": expected_free_route}


def run_fixture_attestation(
    binary: Path, *, expected_identity: str, expected_free_route: str, timeout: float = 30.0
) -> dict[str, str]:
    """Run the fixture's build-selected backend attestation at a fixed route."""

    try:
        completed = subprocess.run(
            [str(binary), "attest", expected_identity, expected_free_route],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=clean_environment(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise HarnessError("fixture selected-artifact attestation timed out") from error
    if completed.returncode != 0 or completed.stderr:
        raise HarnessError(
            "fixture selected-artifact attestation failed: "
            f"status={completed.returncode} stderr={completed.stderr[:512]!r} stdout={completed.stdout[:512]!r}"
        )
    return parse_attestation_output(
        completed.stdout,
        expected_identity=expected_identity,
        expected_free_route=expected_free_route,
    )


def run_selected_artifact_attestation(binary: Path, *, timeout: float = 30.0) -> dict[str, str]:
    """Reject an executable whose private boundary is not the Rust shadow."""

    return run_fixture_attestation(
        binary,
        expected_identity=RUST_SHADOW_BACKEND_IDENTITY,
        expected_free_route=RUST_SHADOW_FREE_ROUTE,
        timeout=timeout,
    )


def selected_artifact_build_identity(
    *, backend_source: Mapping[str, Any], static_archive: Mapping[str, Any], executable: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind the attested route to the exact source/archive/executable hashes."""

    components = {
        "backend_identity": RUST_SHADOW_BACKEND_IDENTITY,
        "backend_source_sha256": backend_source.get("sha256"),
        "executable_sha256": executable.get("sha256"),
        "free_route": RUST_SHADOW_FREE_ROUTE,
        "static_archive_sha256": static_archive.get("sha256"),
    }
    if not all(isinstance(value, str) and value for value in components.values()):
        raise HarnessError("Rust shadow selected-artifact identity lacks a component hash")
    canonical = json.dumps(components, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {"algorithm": "sha256-canonical-json", "components": components, "sha256": hashlib.sha256(canonical).hexdigest()}


def attest_rust_shadow_artifact(
    nm: str, binary: Path, *, backend_source: Mapping[str, Any], static_archive: Mapping[str, Any], executable: Mapping[str, Any]
) -> dict[str, Any]:
    """Perform all pre-timing checks for the selected Rust-shadow fixture."""

    return {
        "build_identity": selected_artifact_build_identity(
            backend_source=backend_source,
            static_archive=static_archive,
            executable=executable,
        ),
        "runtime": run_selected_artifact_attestation(binary),
        "symbol_attestation": verify_rust_shadow_free_symbols(executable_defined_symbols(nm, binary)),
    }


def assert_c_backend_rejects_rust_shadow_attestation(binary: Path) -> dict[str, Any]:
    """Prove the same check does not accept the pinned-C fixture by mistake."""

    observed = run_fixture_attestation(
        binary,
        expected_identity=PINNED_C_BACKEND_IDENTITY,
        expected_free_route=REJECTED_C_FREE_ROUTE,
    )
    if observed != {"backend_identity": PINNED_C_BACKEND_IDENTITY, "free_route": REJECTED_C_FREE_ROUTE}:
        raise HarnessError("pinned C fixture selected-artifact attestation changed")
    return {
        "accepted_as_rust_shadow": False,
        "observed_backend_identity": PINNED_C_BACKEND_IDENTITY,
        "observed_free_route": REJECTED_C_FREE_ROUTE,
        "required_rust_shadow_identity": RUST_SHADOW_BACKEND_IDENTITY,
        "required_rust_shadow_free_route": RUST_SHADOW_FREE_ROUTE,
    }


def build_pinned_c_fixture(compiler: str, readelf: str, source: Path, build_root: Path) -> tuple[Path, dict[str, Any]]:
    binary = build_root / "pinned-c-fixture"
    command = pinned_c_fixture_command(compiler, source, binary)
    result = command_record(command, cwd=source)
    require_success(result, "pinned C fixture build")
    return binary, {
        "build_command": command,
        "executable": audit_executable(readelf, binary),
        "rust_shadow_attestation_rejection": assert_c_backend_rejects_rust_shadow_attestation(binary),
    }


def build_rust_fixture(compiler: str, readelf: str, nm: str, build_root: Path) -> tuple[Path, dict[str, Any]]:
    cargo_target = build_root / "rust-target"
    cargo_command = rust_adapter_cargo_command(cargo_target)
    cargo = command_record(cargo_command, cwd=ROOT)
    require_success(cargo, "Rust native shadow static library build")
    native_libraries = parse_native_static_libraries(str(cargo["stdout"]) + "\n" + str(cargo["stderr"]))
    fixture_libraries = fixture_link_libraries(native_libraries)
    static_library = cargo_target / RUST_TARGET / "release/libcrabc_mimalloc_test_adapter.a"
    expected_symbols = adapter_header_symbols()
    observed_symbols = archive_prefixed_symbols(nm, static_library)
    if observed_symbols != expected_symbols:
        raise HarnessError("Rust shadow static archive no longer exposes exactly the private prefixed symbols")
    binary = build_root / "rust-native-shadow-fixture"
    search_path = rust_target_self_contained_search_path()
    fixture_command = rust_fixture_command(compiler, static_library, search_path, fixture_libraries, binary)
    fixture = command_record(fixture_command, cwd=ROOT)
    require_success(fixture, "Rust native shadow fixture build")
    backend_source = file_record(FIXTURE_ROOT / "rust-native-shadow-backend.c")
    archive = artifact_record(static_library)
    executable = audit_executable(readelf, binary)
    return binary, {
        "cargo_command": cargo_command,
        "executable": executable,
        "fixture_build_command": fixture_command,
        "native_library_search_path": search_path,
        "fixture_link_libraries": fixture_libraries,
        "native_static_libraries_reported_by_rustc": native_libraries,
        "selected_artifact_attestation": attest_rust_shadow_artifact(
            nm,
            binary,
            backend_source=backend_source,
            static_archive=archive,
            executable=executable["artifact"],
        ),
        "static_archive": archive,
        "static_archive_prefixed_symbols": observed_symbols,
    }


def clean_environment() -> dict[str, str]:
    return {"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"), "TZ": "UTC"}


def parse_batch_output(output: str, *, expected_batches: int) -> list[int]:
    lines = output.splitlines()
    if not lines or lines[-1] != "ok":
        raise HarnessError("fixture batch output lacks its terminal ok record")
    values: list[int] = []
    for line in lines[:-1]:
        match = re.fullmatch(r"batch_ns=([1-9][0-9]*)", line)
        if match is None:
            raise HarnessError(f"fixture batch output contains an unexpected record: {line!r}")
        values.append(int(match.group(1)))
    if len(values) != expected_batches:
        raise HarnessError(f"fixture batch output expected {expected_batches} batch records, found {len(values)}")
    return values


def run_batch_sample(binary: Path, workload: Workload, *, timeout: float) -> dict[str, Any]:
    started = time.monotonic_ns()
    try:
        child = subprocess.run(
            [str(binary), str(workload.request_bytes), str(workload.batches_per_process), str(workload.iterations_per_batch)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=clean_environment(), timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise HarnessError(f"fixture batch child timed out after {timeout}s") from error
    elapsed_wall_ns = time.monotonic_ns() - started
    if child.returncode != 0 or child.stderr:
        raise HarnessError(f"fixture batch child failed: status={child.returncode} stderr={child.stderr[:512]!r} stdout={child.stdout[:512]!r}")
    batch_ns = parse_batch_output(child.stdout, expected_batches=workload.batches_per_process)
    return {"batch_ns": batch_ns, "elapsed_wall_ns": elapsed_wall_ns}


def paired_sample_plan(samples: int, *, seed: int) -> list[tuple[str, int]]:
    if samples <= 0:
        raise HarnessError("sample count must be positive")
    random_source = random.Random(seed)
    indices = list(range(samples))
    random_source.shuffle(indices)
    plan: list[tuple[str, int]] = []
    for index in indices:
        first = "pinned_c" if random_source.getrandbits(1) == 0 else "rust_native_shadow"
        second = "rust_native_shadow" if first == "pinned_c" else "pinned_c"
        plan.extend(((first, index), (second, index)))
    return plan


def percentile(values: Sequence[int], fraction: float) -> int:
    if not values:
        raise HarnessError("cannot summarize an empty measurement")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction + 0.5)))
    return ordered[index]


def numeric_summary(values: Sequence[int]) -> dict[str, int]:
    if not values:
        raise HarnessError("cannot summarize an empty measurement")
    return {"max": max(values), "median": round(statistics.median(values)), "min": min(values), "p95": percentile(values, 0.95)}


def throughput_pairs_per_second(batch_ns: int, iterations_per_batch: int) -> float:
    if batch_ns <= 0 or iterations_per_batch <= 0:
        raise HarnessError("throughput requires a positive batch duration and iteration count")
    return iterations_per_batch * 1_000_000_000 / batch_ns


def throughput_ratio(pinned_c: Sequence[float], rust_native_shadow: Sequence[float], *, seed: int) -> dict[str, float | int]:
    if len(pinned_c) == 0 or len(pinned_c) != len(rust_native_shadow) or any(value <= 0 for value in (*pinned_c, *rust_native_shadow)):
        raise HarnessError("throughput ratio requires equal positive C and Rust samples")
    c_median = statistics.median(pinned_c)
    rust_median = statistics.median(rust_native_shadow)
    random_source = random.Random(seed)
    resamples = 10_000
    ratios: list[float] = []
    for _ in range(resamples):
        indices = [random_source.randrange(len(pinned_c)) for _ in pinned_c]
        ratios.append(statistics.median(rust_native_shadow[index] for index in indices) / statistics.median(pinned_c[index] for index in indices))
    ratios.sort()
    return {
        "median_rust_over_pinned_c": rust_median / c_median,
        "one_sided_95_lower_rust_over_pinned_c": ratios[(5 * resamples) // 100],
        "resamples": resamples,
        "seed": seed,
    }


def summarize_lane(samples: Sequence[Mapping[str, Any]], workload: Workload) -> dict[str, Any]:
    median_batch_ns = [round(statistics.median(record["batch_ns"])) for record in samples]
    throughputs = [throughput_pairs_per_second(value, workload.iterations_per_batch) for value in median_batch_ns]
    return {
        "per_process_batch_median_ns": numeric_summary(median_batch_ns),
        "per_process_throughput_pairs_per_second": {
            "max": max(throughputs), "median": statistics.median(throughputs), "min": min(throughputs),
        },
        "sample_count": len(samples),
    }


def measure_workload(binaries: Mapping[str, Path], workload: Workload, *, samples: int, warmup: int, seed: int, timeout: float) -> dict[str, Any]:
    lanes = ("pinned_c", "rust_native_shadow")
    for lane in lanes:
        for _ in range(warmup):
            run_batch_sample(binaries[lane], workload, timeout=timeout)
    by_lane: dict[str, list[dict[str, Any] | None]] = {lane: [None] * samples for lane in lanes}
    plan = paired_sample_plan(samples, seed=seed)
    for lane, sample_index in plan:
        sample = run_batch_sample(binaries[lane], workload, timeout=timeout)
        sample["sample_index"] = sample_index
        by_lane[lane][sample_index] = sample
    completed: dict[str, list[dict[str, Any]]] = {}
    for lane, records in by_lane.items():
        if any(record is None for record in records):
            raise HarnessError(f"measurement did not complete every {lane} sample")
        completed[lane] = [record for record in records if record is not None]
    c_throughputs = [throughput_pairs_per_second(round(statistics.median(record["batch_ns"])), workload.iterations_per_batch) for record in completed["pinned_c"]]
    rust_throughputs = [throughput_pairs_per_second(round(statistics.median(record["batch_ns"])), workload.iterations_per_batch) for record in completed["rust_native_shadow"]]
    return {
        "allocation_sizes_bytes": [workload.request_bytes],
        "batches_per_process": workload.batches_per_process,
        "iterations_per_batch": workload.iterations_per_batch,
        "lanes": {lane: {"samples": records, "summary": summarize_lane(records, workload)} for lane, records in completed.items()},
        "sample_plan": [{"lane": lane, "sample_index": index} for lane, index in plan],
        "throughput_ratio": throughput_ratio(c_throughputs, rust_throughputs, seed=seed ^ 0xA64C_0001),
        "warmup_processes_per_lane": warmup,
    }


def pin_benchmark_cpu(requested: int | None) -> int:
    if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
        raise HarnessError("Linux CPU affinity APIs are unavailable")
    allowed = os.sched_getaffinity(0)
    if not allowed:
        raise HarnessError("performance runner has no allowed CPUs")
    cpu = min(allowed) if requested is None else requested
    if cpu not in allowed:
        raise HarnessError(f"requested CPU {cpu} is not in allowed affinity {sorted(allowed)}")
    try:
        os.sched_setaffinity(0, {cpu})
    except OSError as error:
        raise HarnessError(f"cannot pin benchmark runner to CPU {cpu}: {error}") from error
    if os.sched_getaffinity(0) != {cpu}:
        raise HarnessError(f"benchmark runner affinity did not remain pinned to CPU {cpu}")
    return cpu


def tool_version(tool: str) -> str:
    record = command_record((tool, "--version"), cwd=ROOT)
    require_success(record, f"{tool} version probe")
    lines = str(record["stdout"]).splitlines()
    if not lines:
        raise HarnessError(f"{tool} version probe emitted no output")
    return lines[0]


def empty_report(*, label: str, host_qualification: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "architecture": ARCHITECTURE,
        "comparison_scope": "same Linux/AArch64 host and shared fixture source; only opaque private backend shims vary",
        "host_qualification": dict(host_qualification),
        "kind": KIND,
        "label": validate_label(label),
        "measurement_boundary": {
            "final_promotion_qualification_eligible": False,
            "kind": MEASUREMENT_BOUNDARY_KIND,
            "production_libc_measurement": False,
            "reason": "The prefixed crabc_test_* adapter directly enters the Rust engine. It does not measure the production crabc-libc allocator ABI or backend selection.",
        },
        "schema": SCHEMA,
        "scope": {
            "final_promotion_qualified": False,
            "public_crabc_allocator_integration": False,
            "public_mi_api": False,
            "statement": "single-thread local architecture smoke only",
        },
        "status": "pending",
        "target": RUST_TARGET,
    }


def validate_report_contract(report: Mapping[str, Any]) -> None:
    if report.get("schema") != SCHEMA or report.get("kind") != KIND or report.get("architecture") != ARCHITECTURE or report.get("target") != RUST_TARGET:
        raise HarnessError("local AArch64 performance report schema changed")
    validate_label(str(report.get("label", "")))
    host = report.get("host_qualification")
    if not isinstance(host, Mapping) or host.get("qualification") != "linux-aarch64-development-smoke-only" or host.get("final_promotion_qualified") is not False:
        raise HarnessError("local AArch64 performance report made an unsupported host claim")
    scope = report.get("scope")
    if not isinstance(scope, Mapping) or any(scope.get(field) is not False for field in ("final_promotion_qualified", "public_crabc_allocator_integration", "public_mi_api")):
        raise HarnessError("local AArch64 performance report attempted a public or promotion claim")
    measurement_boundary = report.get("measurement_boundary")
    if not isinstance(measurement_boundary, Mapping) or measurement_boundary.get("kind") != MEASUREMENT_BOUNDARY_KIND:
        raise HarnessError("local AArch64 performance report has an unexpected measurement boundary")
    if measurement_boundary.get("production_libc_measurement") is not False:
        raise HarnessError("direct-engine friend-boundary report cannot claim production libc measurement")
    if measurement_boundary.get("final_promotion_qualification_eligible") is not False:
        raise HarnessError("direct-engine friend-boundary report cannot qualify for final promotion")
    status = report.get("status")
    if status == "pending":
        return
    if status not in {"measured-architecture-pass", "measured-architecture-blocked"}:
        raise HarnessError("local AArch64 performance report has an invalid status")
    command = report.get("reproducible_command")
    measurement = report.get("measurement_contract")
    workloads = report.get("workloads")
    lanes = report.get("lanes")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise HarnessError("measured local AArch64 performance report lacks its reproducible command")
    if not isinstance(measurement, Mapping) or not measurement.get("timing") or not measurement.get("warmup"):
        raise HarnessError("measured local AArch64 performance report lacks its timing and warmup contract")
    if not isinstance(workloads, Mapping) or not workloads:
        raise HarnessError("measured local AArch64 performance report lacks workloads")
    if not isinstance(lanes, Mapping) or not isinstance(lanes.get("rust_native_shadow"), Mapping):
        raise HarnessError("measured local AArch64 performance report lacks the Rust shadow lane")
    attestation = lanes["rust_native_shadow"].get("selected_artifact_attestation")
    if not isinstance(attestation, Mapping):
        raise HarnessError("measured local AArch64 performance report lacks selected-artifact attestation")
    runtime = attestation.get("runtime")
    symbols = attestation.get("symbol_attestation")
    build_identity = attestation.get("build_identity")
    if runtime != {"backend_identity": RUST_SHADOW_BACKEND_IDENTITY, "free_route": RUST_SHADOW_FREE_ROUTE}:
        raise HarnessError("measured local AArch64 performance report selected an unexpected Rust shadow route")
    if not isinstance(symbols, Mapping) or symbols.get("required_rust_shadow_symbol_defined") is not True or symbols.get("rejected_c_symbol_defined") is not False:
        raise HarnessError("measured local AArch64 performance report did not prove the Rust shadow free symbol")
    if not isinstance(build_identity, Mapping) or build_identity.get("algorithm") != "sha256-canonical-json" or not re.fullmatch(r"[0-9a-f]{64}", str(build_identity.get("sha256", ""))):
        raise HarnessError("measured local AArch64 performance report lacks selected-artifact build identity")
    for workload in workloads.values():
        if not isinstance(workload, Mapping):
            raise HarnessError("measured local AArch64 workload is invalid")
        sizes = workload.get("allocation_sizes_bytes")
        warmup = workload.get("warmup_processes_per_lane")
        ratio = workload.get("throughput_ratio")
        if not isinstance(sizes, list) or not sizes or not all(type(size) is int and size > 0 for size in sizes):
            raise HarnessError("measured local AArch64 workload lacks allocation sizes")
        if type(warmup) is not int or warmup <= 0:
            raise HarnessError("measured local AArch64 workload lacks warmup")
        if not isinstance(ratio, Mapping) or type(ratio.get("median_rust_over_pinned_c")) not in {int, float}:
            raise HarnessError("measured local AArch64 workload lacks throughput ratio")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="run the fixed local architecture smoke")
    parser.add_argument("--label", default="local", help="namespaced output label")
    parser.add_argument("--cpu", type=int, default=None, help="allowed Linux CPU to pin; defaults to the lowest")
    parser.add_argument("--offline", action="store_true", help="require the pinned archive in the local fixture cache")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-process timeout in seconds")
    arguments = parser.parse_args()
    if not arguments.smoke:
        parser.error("only --smoke is supported by this local evidence lane")
    validate_label(arguments.label)
    if arguments.timeout <= 0:
        parser.error("--timeout must be positive")
    return arguments


def run(arguments: argparse.Namespace) -> tuple[Path, bool]:
    manifest, workloads = load_manifest()
    host_qualification = require_linux_aarch64()
    label = validate_label(arguments.label)
    report = empty_report(label=label, host_qualification=host_qualification)
    report_path = default_report_path(ROOT, label)
    report["mode"] = "smoke"
    report["reproducible_command"] = ["python3", relative(Path(__file__)), "--smoke", "--label", label, "--timeout", str(arguments.timeout)] + ([] if arguments.cpu is None else ["--cpu", str(arguments.cpu)]) + ([] if not arguments.offline else ["--offline"])
    report["measurement_contract"] = {
        "comparison": "one shared fixture source; opaque direct-engine friend boundary varies only by pinned-C versus prefixed Rust-native shadow backend",
        "measurement_boundary": "direct-engine-friend-boundary; never production crabc-libc allocator ABI or backend selection",
        "fresh_processes": True,
        "timing": "one CLOCK_MONOTONIC pair around each fixed allocation/free batch; never a clock read per allocation",
        "warmup": "unreported fresh fixture processes run before randomized paired samples",
    }
    report["host"] = {
        "benchmark_cpu": pin_benchmark_cpu(arguments.cpu),
        "cpuinfo_sha256": sha256_file(Path("/proc/cpuinfo")) if Path("/proc/cpuinfo").is_file() else None,
    }
    compiler = require_tool(MUSL_COMPILER)
    readelf = require_tool("readelf")
    nm = require_tool("nm")
    pin = load_pin()
    archive = fetch_archive(pin, offline=arguments.offline)
    report["inputs"] = {
        "cargo_lock": file_record(ROOT / "Cargo.lock"),
        "fixture": {name: file_record(FIXTURE_ROOT / name) for name in ("fixture.c", "perf-api.h", "c-pinned-backend.c", "rust-native-shadow-backend.c")},
        "fixture_release_flags": list(FIXTURE_RELEASE_FLAGS),
        "manifest": file_record(MANIFEST),
        "mimalloc": {"archive": file_record(archive), **pin},
        "musl_compiler": {"path": compiler, "version": tool_version(compiler)},
        "pinned_c_source_configuration_flags": list(PINNED_C_SOURCE_CONFIGURATION_FLAGS),
        "rustc_version": tool_version("rustc"),
        "test_adapter_header": file_record(TEST_ADAPTER_HEADER),
    }
    samples = manifest["mode"]["samples_per_lane_and_workload"]
    warmup = manifest["mode"]["warmup_processes_per_lane_and_workload"]
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-local-perf-aarch64-") as temporary_name:
        temporary = Path(temporary_name)
        source = safe_extract(archive, temporary / "source", pin["archive_root"])
        build_root = temporary / "build"
        build_root.mkdir()
        c_binary, c_build = build_pinned_c_fixture(compiler, readelf, source, build_root)
        rust_binary, rust_build = build_rust_fixture(compiler, readelf, nm, build_root)
        report["inputs"]["pinned_c_source_units"] = [file_record(source / item) for item in ORACLE_SOURCES]
        report["lanes"] = {"pinned_c": c_build, "rust_native_shadow": rust_build}
        report["workloads"] = {
            workload.name: measure_workload(
                {"pinned_c": c_binary, "rust_native_shadow": rust_binary}, workload,
                samples=samples, warmup=warmup, seed=0x4352_4142 + index, timeout=arguments.timeout,
            )
            for index, workload in enumerate(workloads)
        }
    threshold = manifest["architecture_smoke"]["minimum_rust_over_pinned_c_throughput_ratio"]
    blocked = [
        name for name, workload in report["workloads"].items()
        if workload["throughput_ratio"]["median_rust_over_pinned_c"] < threshold
    ]
    report["architecture_smoke_gate"] = {
        "blocked_workloads": blocked,
        "minimum_rust_over_pinned_c_throughput_ratio": threshold,
        "status": "blocked" if blocked else "passed",
    }
    report["status"] = "measured-architecture-blocked" if blocked else "measured-architecture-pass"
    validate_report_contract(report)
    atomic_write_json(report_path, report)
    return report_path, not blocked


def main() -> int:
    arguments = parse_arguments()
    try:
        report_path, passed = run(arguments)
    except HarnessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(report_path)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
