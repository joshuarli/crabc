#!/usr/bin/env python3
"""Linux/AArch64 local-worker Rust-shadow versus pinned-C smoke.

This development architecture ratchet runs one source-shared C fixture at
1, 2, 4, and 8 ordinary pthread workers. The pinned-C lane enters the pinned
v3.5.0 source through a private shim. The Rust lane links one exact,
compile-time-selected ``native-mimalloc-shadow`` libc.so and reaches it only
through the same fixture-private malloc/free shim. It is never final
performance qualification.
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
CACHE = FIXTURE_ROOT / ".cache"

SCHEMA = 2
KIND = "crabc-mimalloc-aarch64-local-allocation-performance-smoke"
ARCHITECTURE = "aarch64"
RUST_TARGET = "aarch64-unknown-linux-musl"
MUSL_COMPILER = "musl-gcc"
RUST_SHADOW_BACKEND_IDENTITY = "rust-native-shadow-selected-c-abi-v1"
RUST_SHADOW_FREE_ROUTE = "free"
RUST_SHADOW_FEATURE = "native-mimalloc-shadow"
PINNED_C_BACKEND_IDENTITY = "pinned-c-mimalloc-v3.5.0"
REJECTED_C_FREE_ROUTE = "mi_free"
MEASUREMENT_BOUNDARY_KIND = "selected-native-shadow-c-abi"
CANONICAL_LOADER = Path("/lib/ld-crabc-aarch64.so.1")
SELECTED_LIBC_LINK_FLAG = "-l:libc.so"
WORKER_SCALES = (1, 2, 4, 8)
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
    if raw.get("architecture") != ARCHITECTURE or raw.get("profile") != "linux-aarch64-local-selected-native-shadow":
        raise HarnessError("local AArch64 performance manifest target changed")
    upstream = raw.get("upstream")
    fixture = raw.get("fixture")
    if not isinstance(upstream, Mapping) or upstream.get("version") != "3.5.0" or upstream.get("revision") != "18b08671c9302247bfb682286e6bf3cc1773f801":
        raise HarnessError("local AArch64 performance manifest upstream changed")
    if not isinstance(fixture, Mapping) or fixture.get("single_thread_only") is not False:
        raise HarnessError("local AArch64 performance manifest lost its multi-worker fixture")
    if fixture.get("local_worker_scales") != list(WORKER_SCALES):
        raise HarnessError("local AArch64 performance manifest worker scales changed")
    attestation = fixture.get("selected_artifact_attestation")
    if attestation != {
        "backend_identity": RUST_SHADOW_BACKEND_IDENTITY,
        "cargo_feature": RUST_SHADOW_FEATURE,
        "free_route": RUST_SHADOW_FREE_ROUTE,
        "rejected_c_free_route": REJECTED_C_FREE_ROUTE,
    }:
        raise HarnessError("local AArch64 performance manifest selected-artifact attestation changed")
    measurement_boundary = raw.get("measurement_boundary")
    if measurement_boundary != {
        "final_promotion_qualification_eligible": False,
        "kind": MEASUREMENT_BOUNDARY_KIND,
        "production_libc_measurement": False,
        "reason": "The Rust lane links one compile-time-selected nondefault shadow libc.so. It does not measure the default production allocator selection or a qualified final-promotion environment.",
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
    if (
        not isinstance(mode, Mapping)
        or mode.get("samples_per_lane_and_workload_and_worker_scale") != 5
        or mode.get("warmup_processes_per_lane_and_workload_and_worker_scale") != 2
    ):
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


def rust_shadow_cargo_command(cargo_target: Path) -> list[str]:
    return [
        "cargo", "build", "--locked", "--package", "crabc-libc",
        "--features", RUST_SHADOW_FEATURE, "--release", "--target-dir", str(cargo_target),
    ]


def rust_shadow_fixture_command(
    compiler: Path, selected_libc: Path, builtins: Path, binary: Path
) -> list[str]:
    return [
        *fixture_compiler_prefix(str(compiler)),
        "-nodefaultlibs",
        "-I", str(ROOT / "include"), "-I", str(FIXTURE_ROOT),
        "-L", str(selected_libc.parent),
        "-Wl,--allow-shlib-undefined",
        str(FIXTURE_ROOT / "fixture.c"), str(FIXTURE_ROOT / "rust-native-shadow-backend.c"),
        SELECTED_LIBC_LINK_FLAG, str(builtins), "-Wl,--trace", "-o", str(binary),
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


def parse_dynamic_dependencies(output: str) -> list[str]:
    return re.findall(r"Shared library: \[([^\]]+)\]", output)


def parse_dynamic_search_paths(output: str) -> list[str]:
    return re.findall(r"\((?:RPATH|RUNPATH)\).*?\[([^\]]+)\]", output)


def parse_interpreter(output: str) -> str:
    interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)", output)
    if len(interpreters) != 1:
        raise HarnessError("fixture has an ambiguous PT_INTERP")
    return interpreters[0]


def audit_selected_shadow_fixture(readelf: str, artifact: Path) -> dict[str, Any]:
    """Prove this executable needs only the exact selected shadow libc name."""

    executable = audit_executable(readelf, artifact)
    dynamic = command_record((readelf, "--wide", "--dynamic", str(artifact)), cwd=ROOT)
    require_success(dynamic, "selected Rust shadow fixture DT_NEEDED inspection")
    dependencies = parse_dynamic_dependencies(str(dynamic["stdout"]))
    search_paths = parse_dynamic_search_paths(str(dynamic["stdout"]))
    if dependencies != ["libc.so"] or search_paths:
        raise HarnessError("selected Rust shadow fixture has an ambiguous runtime library selection")
    program_headers = command_record((readelf, "--wide", "--program-headers", str(artifact)), cwd=ROOT)
    require_success(program_headers, "selected Rust shadow fixture PT_INTERP inspection")
    interpreter = parse_interpreter(str(program_headers["stdout"]))
    if interpreter != str(CANONICAL_LOADER):
        raise HarnessError("selected Rust shadow fixture lost the canonical owned loader")
    return {
        **executable,
        "dynamic_dependencies": dependencies,
        "dynamic_search_paths": search_paths,
        "interpreter": interpreter,
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
    binary: Path,
    *,
    expected_identity: str,
    expected_free_route: str,
    environment: Mapping[str, str] | None = None,
    timeout: float = 30.0,
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
            env=clean_environment() if environment is None else dict(environment),
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


def selected_artifact_build_identity(
    *,
    backend_source: Mapping[str, Any],
    selected_libc: Mapping[str, Any],
    cargo_fingerprint: Mapping[str, Any],
    executable: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the selected feature, shared object, shim, and executable hashes."""

    components = {
        "backend_identity": RUST_SHADOW_BACKEND_IDENTITY,
        "backend_source_sha256": backend_source.get("sha256"),
        "cargo_fingerprint_sha256": cargo_fingerprint.get("sha256"),
        "executable_sha256": executable.get("sha256"),
        "free_route": RUST_SHADOW_FREE_ROUTE,
        "selected_libc_sha256": selected_libc.get("sha256"),
    }
    if not all(isinstance(value, str) and value for value in components.values()):
        raise HarnessError("Rust shadow selected-artifact identity lacks a component hash")
    canonical = json.dumps(components, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {"algorithm": "sha256-canonical-json", "components": components, "sha256": hashlib.sha256(canonical).hexdigest()}


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


def cargo_fingerprint_features(path: Path) -> list[str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        features = json.loads(str(raw["features"]))
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise HarnessError("selected Rust shadow Cargo fingerprint is malformed") from error
    if not isinstance(features, list) or not all(isinstance(feature, str) and feature for feature in features):
        raise HarnessError("selected Rust shadow Cargo fingerprint feature list is invalid")
    return features


def selected_shadow_cargo_fingerprint(cargo_target: Path) -> dict[str, Any]:
    candidates = sorted((cargo_target / "release/.fingerprint").glob("crabc-libc-*/lib-c.json"))
    selected = [path for path in candidates if RUST_SHADOW_FEATURE in cargo_fingerprint_features(path)]
    if len(selected) != 1:
        raise HarnessError("selected Rust shadow Cargo build has an ambiguous feature fingerprint")
    fingerprint = selected[0]
    features = cargo_fingerprint_features(fingerprint)
    if set(features) != {"default", RUST_SHADOW_FEATURE}:
        raise HarnessError("selected Rust shadow Cargo features changed")
    return {"cargo_features": features, "fingerprint": file_record(fingerprint), "required_feature": RUST_SHADOW_FEATURE}


def dynamic_function_exports(readelf: str, artifact: Path) -> set[str]:
    record = command_record((readelf, "-W", "--dyn-syms", str(artifact)), cwd=ROOT)
    require_success(record, "selected Rust shadow dynamic-symbol inspection")
    exports: set[str] = set()
    for line in str(record["stdout"]).splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[3] != "FUNC" or fields[6] == "UND":
            continue
        if fields[4] not in {"GLOBAL", "WEAK"} or fields[5] != "DEFAULT":
            continue
        exports.add(fields[-1].split("@", 1)[0])
    return exports


def direct_mimalloc_targets(objdump: str, artifact: Path, symbol: str) -> list[str]:
    record = command_record((objdump, "-d", f"--disassemble={symbol}", str(artifact)), cwd=ROOT)
    require_success(record, f"selected Rust shadow {symbol} transfer inspection")
    return sorted(set(re.findall(r"<(mi_[^>]+)>", str(record["stdout"]))))


def attest_selected_shadow_libc(
    readelf: str, objdump: str, artifact: Path, cargo_target: Path
) -> dict[str, Any]:
    """Reject a selected artifact that can route timed malloc/free to C mimalloc."""

    fingerprint = selected_shadow_cargo_fingerprint(cargo_target)
    exports = dynamic_function_exports(readelf, artifact)
    required_exports = {"malloc", "free"}
    if not required_exports.issubset(exports):
        raise HarnessError("selected Rust shadow libc lacks public malloc/free exports")
    relocations = command_record((readelf, "-W", "--relocs", str(artifact)), cwd=ROOT)
    require_success(relocations, "selected Rust shadow C-backend relocation inspection")
    c_backend_relocations = sorted(set(re.findall(r"(?<![A-Za-z0-9_])(mi_[A-Za-z0-9_.$@]+)", str(relocations["stdout"]))))
    if c_backend_relocations:
        raise HarnessError("selected Rust shadow libc retains a C mimalloc relocation")
    entrypoint_targets = {symbol: direct_mimalloc_targets(objdump, artifact, symbol) for symbol in sorted(required_exports)}
    if any(entrypoint_targets.values()):
        raise HarnessError("selected Rust shadow malloc/free transfers directly to C mimalloc")
    return {
        "artifact": file_record(artifact),
        "cargo_feature_attestation": fingerprint,
        "c_backend_relocations": c_backend_relocations,
        "public_malloc_free_exports": sorted(required_exports),
        "public_malloc_free_direct_mimalloc_targets": entrypoint_targets,
    }


def require_runtime_inputs() -> tuple[Path, Path, Path]:
    raw_sysroot = os.environ.get("CRABC_TEST_SYSROOT")
    if not raw_sysroot:
        raise HarnessError("local multi-worker smoke requires CRABC_TEST_SYSROOT from scripts/run_owned_test_suite.py")
    sysroot = Path(raw_sysroot).expanduser().resolve()
    compiler = sysroot / "bin/crabc-cc"
    builtins = sysroot / "usr/lib/libcrabc-builtins.a"
    if not compiler.is_file() or not builtins.is_file():
        raise HarnessError("local multi-worker smoke requires a complete owned crabc sysroot")
    if not CANONICAL_LOADER.is_file() or CANONICAL_LOADER.is_symlink():
        raise HarnessError("local multi-worker smoke requires the staged canonical owned loader")
    return sysroot, compiler, builtins


def printed_driver_link_plan(compiler: Path, command: Sequence[str]) -> dict[str, Any]:
    record = command_record((str(compiler), "--crabc-print-link-plan", *command[1:]), cwd=ROOT)
    require_success(record, "selected Rust shadow fixture driver link-plan inspection")
    try:
        plan = json.loads(str(record["stdout"]))
    except json.JSONDecodeError as error:
        raise HarnessError("selected Rust shadow fixture driver did not emit JSON") from error
    if not isinstance(plan, dict):
        raise HarnessError("selected Rust shadow fixture driver link plan is invalid")
    return plan


def link_plan_search_paths(command: Sequence[str]) -> list[str]:
    paths: list[str] = []
    index = 0
    while index < len(command):
        argument = command[index]
        if argument == "-L":
            if index + 1 == len(command):
                raise HarnessError("selected Rust shadow fixture link plan has a dangling -L")
            paths.append(command[index + 1])
            index += 2
            continue
        if argument.startswith("-L") and len(argument) > 2:
            paths.append(argument[2:])
        index += 1
    return paths


def audit_selected_shadow_link_plan(
    plan: Mapping[str, Any], sysroot: Path, selected_libc: Path, builtins: Path
) -> dict[str, Any]:
    command = plan.get("command")
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise HarnessError("selected Rust shadow fixture link plan command is invalid")
    if plan.get("default_libraries") != [] or command.count("-nodefaultlibs") != 1 or "-lc" in command:
        raise HarnessError("selected Rust shadow fixture link plan retained a default C library")
    if command.count(SELECTED_LIBC_LINK_FLAG) != 1 or link_plan_search_paths(command) != [str(selected_libc.parent)]:
        raise HarnessError("selected Rust shadow fixture link plan has an ambiguous libc search root")
    if command.count(str(builtins)) != 1 or command.index(SELECTED_LIBC_LINK_FLAG) >= command.index(str(builtins)):
        raise HarnessError("selected Rust shadow fixture link plan lost its selected libc/builtins ordering")
    if selected_libc.parent.resolve() == (sysroot / "usr/lib").resolve():
        raise HarnessError("selected Rust shadow libc aliases the ordinary sysroot libc")
    return {
        "default_libraries": [],
        "driver_opt_out": "-nodefaultlibs",
        "selected_library_flag": SELECTED_LIBC_LINK_FLAG,
        "selected_library_root": relative(selected_libc.parent),
        "owned_builtins": file_record(builtins),
    }


def audit_selected_shadow_linker_trace(
    build: Mapping[str, Any], selected_libc: Path, sysroot: Path
) -> dict[str, Any]:
    trace = str(build.get("stdout", "")) + "\n" + str(build.get("stderr", ""))
    selected = str(selected_libc.resolve())
    ordinary = str((sysroot / "usr/lib/libc.so").resolve())
    if selected not in trace or ordinary in trace:
        raise HarnessError("selected Rust shadow fixture linker trace did not resolve only the selected libc")
    return {
        "selected_libc": file_record(selected_libc),
        "selected_libc_seen": True,
        "sysroot_libc_seen": False,
        "trace_sha256": hashlib.sha256(trace.encode("utf-8")).hexdigest(),
    }


def build_pinned_c_fixture(compiler: str, readelf: str, source: Path, build_root: Path) -> tuple[Path, dict[str, Any], dict[str, str]]:
    binary = build_root / "pinned-c-fixture"
    command = pinned_c_fixture_command(compiler, source, binary)
    result = command_record(command, cwd=source)
    require_success(result, "pinned C fixture build")
    return binary, {
        "build_command": command,
        "executable": audit_executable(readelf, binary),
        "rust_shadow_attestation_rejection": assert_c_backend_rejects_rust_shadow_attestation(binary),
    }, clean_environment()


def build_rust_fixture(
    readelf: str,
    objdump: str,
    sysroot: Path,
    compiler: Path,
    builtins: Path,
    build_root: Path,
) -> tuple[Path, dict[str, Any], dict[str, str]]:
    cargo_target = build_root / "rust-shadow-target"
    cargo_command = rust_shadow_cargo_command(cargo_target)
    cargo = command_record(cargo_command, cwd=ROOT)
    require_success(cargo, "selected Rust native-shadow libc build")
    selected_libc = cargo_target / "release/libc.so"
    if not selected_libc.is_file():
        raise HarnessError("selected Rust native-shadow Cargo build did not emit libc.so")
    selected_libc_attestation = attest_selected_shadow_libc(readelf, objdump, selected_libc, cargo_target)
    binary = build_root / "rust-native-shadow-fixture"
    fixture_command = rust_shadow_fixture_command(compiler, selected_libc, builtins, binary)
    driver_plan = printed_driver_link_plan(compiler, fixture_command)
    link_plan = audit_selected_shadow_link_plan(driver_plan, sysroot, selected_libc, builtins)
    fixture = command_record(fixture_command, cwd=ROOT)
    require_success(fixture, "selected Rust native-shadow fixture build")
    linker_trace = audit_selected_shadow_linker_trace(fixture, selected_libc, sysroot)
    backend_source = file_record(FIXTURE_ROOT / "rust-native-shadow-backend.c")
    executable = audit_selected_shadow_fixture(readelf, binary)
    runtime_environment = clean_environment(runtime_library=selected_libc.parent)
    runtime = run_fixture_attestation(
        binary,
        expected_identity=RUST_SHADOW_BACKEND_IDENTITY,
        expected_free_route=RUST_SHADOW_FREE_ROUTE,
        environment=runtime_environment,
    )
    build_identity = selected_artifact_build_identity(
        backend_source=backend_source,
        selected_libc=selected_libc_attestation["artifact"],
        cargo_fingerprint=selected_libc_attestation["cargo_feature_attestation"]["fingerprint"],
        executable=executable["artifact"],
    )
    return binary, {
        "cargo_command": cargo_command,
        "executable": executable,
        "fixture_build_command": fixture_command,
        "selected_artifact_attestation": {
            "build_identity": build_identity,
            "runtime": runtime,
            "selected_shadow_libc": selected_libc_attestation,
        },
        "selected_link_provenance": {
            "driver_plan": link_plan,
            "linker_trace": linker_trace,
        },
    }, runtime_environment


def clean_environment(*, runtime_library: Path | None = None) -> dict[str, str]:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "TZ": "UTC",
    }
    if runtime_library is not None:
        environment["LD_LIBRARY_PATH"] = str(runtime_library)
    return environment


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


def run_batch_sample(
    binary: Path,
    workload: Workload,
    worker_count: int,
    *,
    environment: Mapping[str, str],
    timeout: float,
) -> dict[str, Any]:
    started = time.monotonic_ns()
    try:
        child = subprocess.run(
            [
                str(binary),
                str(workload.request_bytes),
                str(worker_count),
                str(workload.batches_per_process),
                str(workload.iterations_per_batch),
            ],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=dict(environment), timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise HarnessError(f"fixture batch child timed out after {timeout}s") from error
    elapsed_wall_ns = time.monotonic_ns() - started
    if child.returncode != 0 or child.stderr:
        raise HarnessError(f"fixture batch child failed: status={child.returncode} stderr={child.stderr[:512]!r} stdout={child.stdout[:512]!r}")
    batch_ns = parse_batch_output(child.stdout, expected_batches=workload.batches_per_process)
    return {
        "batch_ns": batch_ns,
        "elapsed_wall_ns": elapsed_wall_ns,
        "operations_per_batch": worker_count * workload.iterations_per_batch,
        "worker_count": worker_count,
    }


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


def throughput_pairs_per_second(batch_ns: int, iterations_per_worker_per_batch: int, worker_count: int) -> float:
    if batch_ns <= 0 or iterations_per_worker_per_batch <= 0 or worker_count <= 0:
        raise HarnessError("throughput requires positive batch duration, iteration count, and worker count")
    return worker_count * iterations_per_worker_per_batch * 1_000_000_000 / batch_ns


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


def summarize_lane(samples: Sequence[Mapping[str, Any]], workload: Workload, worker_count: int) -> dict[str, Any]:
    median_batch_ns = [round(statistics.median(record["batch_ns"])) for record in samples]
    throughputs = [
        throughput_pairs_per_second(value, workload.iterations_per_batch, worker_count)
        for value in median_batch_ns
    ]
    return {
        "per_process_batch_median_ns": numeric_summary(median_batch_ns),
        "per_process_throughput_all_workers_pairs_per_second": {
            "max": max(throughputs), "median": statistics.median(throughputs), "min": min(throughputs),
        },
        "sample_count": len(samples),
    }


def measure_worker_scale(
    binaries: Mapping[str, tuple[Path, Mapping[str, str]]],
    workload: Workload,
    worker_count: int,
    *,
    samples: int,
    warmup: int,
    seed: int,
    timeout: float,
) -> dict[str, Any]:
    lanes = ("pinned_c", "rust_native_shadow")
    for lane in lanes:
        for _ in range(warmup):
            binary, environment = binaries[lane]
            run_batch_sample(binary, workload, worker_count, environment=environment, timeout=timeout)
    by_lane: dict[str, list[dict[str, Any] | None]] = {lane: [None] * samples for lane in lanes}
    plan = paired_sample_plan(samples, seed=seed)
    for lane, sample_index in plan:
        binary, environment = binaries[lane]
        sample = run_batch_sample(binary, workload, worker_count, environment=environment, timeout=timeout)
        sample["sample_index"] = sample_index
        by_lane[lane][sample_index] = sample
    completed: dict[str, list[dict[str, Any]]] = {}
    for lane, records in by_lane.items():
        if any(record is None for record in records):
            raise HarnessError(f"measurement did not complete every {lane} sample")
        completed[lane] = [record for record in records if record is not None]
    c_throughputs = [
        throughput_pairs_per_second(
            round(statistics.median(record["batch_ns"])), workload.iterations_per_batch, worker_count
        )
        for record in completed["pinned_c"]
    ]
    rust_throughputs = [
        throughput_pairs_per_second(
            round(statistics.median(record["batch_ns"])), workload.iterations_per_batch, worker_count
        )
        for record in completed["rust_native_shadow"]
    ]
    return {
        "allocation_sizes_bytes": [workload.request_bytes],
        "batches_per_process": workload.batches_per_process,
        "iterations_per_worker_per_batch": workload.iterations_per_batch,
        "local_allocation_free_pairs_per_batch": worker_count * workload.iterations_per_batch,
        "lanes": {
            lane: {"raw_samples": records, "summary": summarize_lane(records, workload, worker_count)}
            for lane, records in completed.items()
        },
        "sample_plan": [{"lane": lane, "sample_index": index} for lane, index in plan],
        "throughput_ratio": throughput_ratio(c_throughputs, rust_throughputs, seed=seed ^ 0xA64C_0001),
        "worker_count": worker_count,
        "warmup_processes_per_lane": warmup,
    }


def measure_workload(
    binaries: Mapping[str, tuple[Path, Mapping[str, str]]],
    workload: Workload,
    *,
    samples: int,
    warmup: int,
    seed: int,
    timeout: float,
) -> dict[str, Any]:
    return {
        "allocation_sizes_bytes": [workload.request_bytes],
        "worker_scales": {
            f"workers_{worker_count}": measure_worker_scale(
                binaries,
                workload,
                worker_count,
                samples=samples,
                warmup=warmup,
                seed=seed ^ worker_count,
                timeout=timeout,
            )
            for worker_count in WORKER_SCALES
        },
    }


def benchmark_affinity() -> dict[str, Any]:
    if not hasattr(os, "sched_getaffinity"):
        raise HarnessError("Linux CPU affinity APIs are unavailable")
    allowed = sorted(os.sched_getaffinity(0))
    if not allowed:
        raise HarnessError("performance runner has no allowed CPUs")
    return {
        "allowed_cpu_ids": allowed,
        "allowed_cpu_count": len(allowed),
        "oversubscribed_worker_scales": [scale for scale in WORKER_SCALES if scale > len(allowed)],
        "preserves_caller_affinity": True,
        "single_cpu_pinning": False,
    }


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
        "comparison_scope": "same Linux/AArch64 host, worker scales, and shared fixture source; only the pinned-C versus selected native-shadow allocation boundary varies",
        "host_qualification": dict(host_qualification),
        "kind": KIND,
        "label": validate_label(label),
        "measurement_boundary": {
            "final_promotion_qualification_eligible": False,
            "kind": MEASUREMENT_BOUNDARY_KIND,
            "production_libc_measurement": False,
            "reason": "The Rust lane links one compile-time-selected nondefault shadow libc.so. It does not measure the default production allocator selection or a qualified final-promotion environment.",
        },
        "schema": SCHEMA,
        "scope": {
            "final_promotion_qualified": False,
            "public_crabc_allocator_integration": False,
            "public_mi_api": False,
            "statement": "multi-worker local selected-shadow architecture smoke only",
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
        raise HarnessError("selected native-shadow report cannot claim production libc measurement")
    if measurement_boundary.get("final_promotion_qualification_eligible") is not False:
        raise HarnessError("selected native-shadow report cannot qualify for final promotion")
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
    if (
        not isinstance(measurement, Mapping)
        or not measurement.get("timing")
        or not measurement.get("warmup")
        or not measurement.get("worker_lifecycle")
        or measurement.get("raw_samples") is not True
    ):
        raise HarnessError("measured local AArch64 performance report lacks its worker/raw-sample contract")
    if not isinstance(workloads, Mapping) or not workloads:
        raise HarnessError("measured local AArch64 performance report lacks workloads")
    if not isinstance(lanes, Mapping) or not isinstance(lanes.get("rust_native_shadow"), Mapping):
        raise HarnessError("measured local AArch64 performance report lacks the Rust shadow lane")
    attestation = lanes["rust_native_shadow"].get("selected_artifact_attestation")
    if not isinstance(attestation, Mapping):
        raise HarnessError("measured local AArch64 performance report lacks selected-artifact attestation")
    runtime = attestation.get("runtime")
    selected_libc = attestation.get("selected_shadow_libc")
    build_identity = attestation.get("build_identity")
    if runtime != {"backend_identity": RUST_SHADOW_BACKEND_IDENTITY, "free_route": RUST_SHADOW_FREE_ROUTE}:
        raise HarnessError("measured local AArch64 performance report selected an unexpected Rust shadow route")
    if not isinstance(selected_libc, Mapping):
        raise HarnessError("measured local AArch64 performance report lacks selected shadow libc attestation")
    feature = selected_libc.get("cargo_feature_attestation")
    direct_targets = selected_libc.get("public_malloc_free_direct_mimalloc_targets")
    if (
        not isinstance(feature, Mapping)
        or feature.get("required_feature") != RUST_SHADOW_FEATURE
        or not isinstance(feature.get("fingerprint"), Mapping)
        or not re.fullmatch(r"[0-9a-f]{64}", str(feature["fingerprint"].get("sha256", "")))
        or not isinstance(direct_targets, Mapping)
        or any(direct_targets.get(symbol) != [] for symbol in ("malloc", "free"))
        or selected_libc.get("c_backend_relocations") != []
    ):
        raise HarnessError("measured local AArch64 performance report did not prove selected native shadow routing")
    if not isinstance(build_identity, Mapping) or build_identity.get("algorithm") != "sha256-canonical-json" or not re.fullmatch(r"[0-9a-f]{64}", str(build_identity.get("sha256", ""))):
        raise HarnessError("measured local AArch64 performance report lacks selected-artifact build identity")
    for workload in workloads.values():
        if not isinstance(workload, Mapping):
            raise HarnessError("measured local AArch64 workload is invalid")
        sizes = workload.get("allocation_sizes_bytes")
        if not isinstance(sizes, list) or not sizes or not all(type(size) is int and size > 0 for size in sizes):
            raise HarnessError("measured local AArch64 workload lacks allocation sizes")
        scales = workload.get("worker_scales")
        if not isinstance(scales, Mapping) or set(scales) != {f"workers_{scale}" for scale in WORKER_SCALES}:
            raise HarnessError("measured local AArch64 workload lacks required worker scales")
        for worker_count in WORKER_SCALES:
            scale = scales[f"workers_{worker_count}"]
            if not isinstance(scale, Mapping) or scale.get("worker_count") != worker_count:
                raise HarnessError("measured local AArch64 worker scale is invalid")
            warmup = scale.get("warmup_processes_per_lane")
            ratio = scale.get("throughput_ratio")
            lanes_for_scale = scale.get("lanes")
            if type(warmup) is not int or warmup <= 0:
                raise HarnessError("measured local AArch64 worker scale lacks warmup")
            if not isinstance(ratio, Mapping) or type(ratio.get("median_rust_over_pinned_c")) not in {int, float}:
                raise HarnessError("measured local AArch64 worker scale lacks throughput ratio")
            if not isinstance(lanes_for_scale, Mapping):
                raise HarnessError("measured local AArch64 worker scale lacks lanes")
            for lane in ("pinned_c", "rust_native_shadow"):
                lane_record = lanes_for_scale.get(lane)
                raw_samples = lane_record.get("raw_samples") if isinstance(lane_record, Mapping) else None
                if not isinstance(raw_samples, list) or not raw_samples:
                    raise HarnessError("measured local AArch64 worker scale lacks raw samples")
                if any(
                    not isinstance(sample, Mapping)
                    or sample.get("worker_count") != worker_count
                    or not isinstance(sample.get("batch_ns"), list)
                    or not sample["batch_ns"]
                    for sample in raw_samples
                ):
                    raise HarnessError("measured local AArch64 raw worker sample is invalid")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="run the fixed local architecture smoke")
    parser.add_argument("--label", default="local", help="namespaced output label")
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
    report["reproducible_command"] = ["python3", relative(Path(__file__)), "--smoke", "--label", label, "--timeout", str(arguments.timeout)] + ([] if not arguments.offline else ["--offline"])
    report["measurement_contract"] = {
        "comparison": "one shared fixture source and worker lifecycle; only pinned-C versus exact selected native-shadow C-ABI malloc/free boundary varies",
        "measurement_boundary": "selected-native-shadow-c-abi; nondefault shadow only, never default allocator or final promotion evidence",
        "fresh_processes": True,
        "raw_samples": True,
        "timing": "one CLOCK_MONOTONIC pair around each ready/start/finish all-worker allocation/free batch; never a clock read per allocation",
        "warmup": "unreported fresh fixture processes run before randomized paired samples",
        "worker_lifecycle": "1/2/4/8 ordinary pthread workers allocate/free only their own blocks, return normally, and are joined before backend shutdown",
    }
    report["host"] = {
        "affinity": benchmark_affinity(),
        "cpuinfo_sha256": sha256_file(Path("/proc/cpuinfo")) if Path("/proc/cpuinfo").is_file() else None,
    }
    compiler = require_tool(MUSL_COMPILER)
    readelf = require_tool("readelf")
    objdump = require_tool("objdump")
    sysroot, selected_compiler, builtins = require_runtime_inputs()
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
        "selected_shadow_cargo_feature": RUST_SHADOW_FEATURE,
        "selected_shadow_cargo_profile": "release",
        "selected_shadow_runtime": {
            "compiler": file_record(selected_compiler),
            "owned_builtins": file_record(builtins),
            "sysroot": relative(sysroot),
        },
    }
    samples = manifest["mode"]["samples_per_lane_and_workload_and_worker_scale"]
    warmup = manifest["mode"]["warmup_processes_per_lane_and_workload_and_worker_scale"]
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-local-perf-aarch64-") as temporary_name:
        temporary = Path(temporary_name)
        source = safe_extract(archive, temporary / "source", pin["archive_root"])
        build_root = temporary / "build"
        build_root.mkdir()
        c_binary, c_build, c_environment = build_pinned_c_fixture(compiler, readelf, source, build_root)
        rust_binary, rust_build, rust_environment = build_rust_fixture(
            readelf, objdump, sysroot, selected_compiler, builtins, build_root
        )
        report["inputs"]["pinned_c_source_units"] = [file_record(source / item) for item in ORACLE_SOURCES]
        report["lanes"] = {"pinned_c": c_build, "rust_native_shadow": rust_build}
        report["workloads"] = {
            workload.name: measure_workload(
                {
                    "pinned_c": (c_binary, c_environment),
                    "rust_native_shadow": (rust_binary, rust_environment),
                }, workload,
                samples=samples, warmup=warmup, seed=0x4352_4142 + index, timeout=arguments.timeout,
            )
            for index, workload in enumerate(workloads)
        }
    threshold = manifest["architecture_smoke"]["minimum_rust_over_pinned_c_throughput_ratio"]
    blocked = [
        f"{name}/{scale_name}"
        for name, workload in report["workloads"].items()
        for scale_name, scale in workload["worker_scales"].items()
        if scale["throughput_ratio"]["median_rust_over_pinned_c"] < threshold
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
