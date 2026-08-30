#!/usr/bin/env python3
"""Run the deterministic native-mimalloc selected-shadow churn/RSS smoke.

The fixture is intentionally standalone rather than another option in
``compat/allocator/run.py``.  Invoke this harness inside the canonical owned
loader boundary, after building the debug libc with ``native-mimalloc-shadow``:

    python3 scripts/run_owned_test_suite.py \
      --sysroot target/crabc-sysroot \
      --loader target/debug/libldso.so -- \
      python3 compat/allocator/native_churn_rss_smoke.py

It builds one C11 fixture through the installed ``crabc-cc`` driver.  The
fixture calls only standard production C allocation APIs, verifies one
cross-thread free while the source owner remains live, and then has the
initial thread free each worker-owned allocation after that worker has exited.
The report distinguishes observable RSS and workload liveness from allocator
metadata, which is deliberately not exposed through the production shadow C
ABI and therefore is never inferred from private test hooks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat/allocator/native-churn-rss-smoke-v3.5.0.json"
FIXTURE_SCHEMA = "crabc-mimalloc-native-churn-rss-smoke-fixture-v1"
REPORT_SCHEMA = "crabc-mimalloc-native-churn-rss-smoke-report-v1"
CANONICAL_LOADER = Path("/lib/ld-crabc-aarch64.so.1")
DEFAULT_REPORT = ROOT / "compat/reports/allocator/native-churn-rss-smoke-latest.json"
NEEDED_LIBRARY = re.compile(r"Shared library: \[(?P<name>[^]]+)\]")


class SmokeError(RuntimeError):
    """A violated selected-shadow evidence precondition or fixture result."""


class ArtifactAttestationError(SmokeError):
    """The selected libc artifact cannot prove its native-shadow identity."""


class AllocatorLivenessError(SmokeError):
    """The fixture did not complete its required allocation ownership lifecycle."""


class RssThresholdError(SmokeError):
    """A completed fixture process exceeded the reviewed RSS ceiling."""

    def __init__(self, *, observed_bytes: int, threshold_bytes: int) -> None:
        self.observed_bytes = observed_bytes
        self.threshold_bytes = threshold_bytes
        super().__init__(
            "fixture RSS high-water exceeded the configured threshold: "
            f"observed {observed_bytes} bytes, threshold {threshold_bytes} bytes"
        )


def relative(path: Path) -> str:
    """Return a durable repository-relative spelling when possible."""

    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    """Hash one regular evidence input."""

    if not path.is_file():
        raise SmokeError(f"required input is not a regular file: {relative(path)}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Mapping[str, Any]:
    """Load one JSON object without silently accepting another shape."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SmokeError(f"could not read JSON object {relative(path)}: {error}") from error
    if not isinstance(value, dict):
        raise SmokeError(f"JSON root must be an object: {relative(path)}")
    return value


def require_string(value: Mapping[str, Any], key: str) -> str:
    """Read one required nonempty string field."""

    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise SmokeError(f"contract field {key!r} must be a nonempty string")
    return result


def require_positive_int(value: Mapping[str, Any], key: str) -> int:
    """Read one positive integer field without treating booleans as numbers."""

    result = value.get(key)
    if isinstance(result, bool) or not isinstance(result, int) or result <= 0:
        raise SmokeError(f"contract field {key!r} must be a positive integer")
    return result


def require_string_list(value: Mapping[str, Any], key: str) -> list[str]:
    """Read one list of nonempty strings."""

    result = value.get(key)
    if not isinstance(result, list) or not all(isinstance(item, str) and item for item in result):
        raise SmokeError(f"contract field {key!r} must be a list of nonempty strings")
    return list(result)


def require_object(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """Read one required JSON object without accepting a mutable shape."""

    result = value.get(key)
    if not isinstance(result, dict):
        raise SmokeError(f"contract field {key!r} must be an object")
    return result


def validate_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the fixed native-shadow workload and its honest boundaries."""

    if contract.get("format") != 1 or contract.get("schema") != "crabc-mimalloc-native-churn-rss-smoke":
        raise SmokeError("unsupported native churn/RSS smoke contract")

    fixture = contract.get("fixture")
    execution = contract.get("execution")
    boundary = contract.get("production_shadow_boundary")
    observation = contract.get("state_observation")
    attestation = contract.get("selected_shadow_artifact_attestation")
    if not isinstance(fixture, dict) or not isinstance(execution, dict):
        raise SmokeError("contract must contain fixture and execution objects")
    if not isinstance(boundary, dict) or not isinstance(observation, dict):
        raise SmokeError("contract must contain production boundary and observation objects")
    if not isinstance(attestation, dict):
        raise SmokeError("contract must contain a selected-shadow artifact attestation object")

    fixture_path = ROOT / require_string(fixture, "path")
    if fixture_path != ROOT / "compat/allocator/native-churn-rss-smoke.c":
        raise SmokeError("fixture path changed from the reviewed native smoke source")
    fixture_sha256 = require_string(fixture, "sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", fixture_sha256):
        raise SmokeError("fixture sha256 must be a lowercase SHA-256 digest")
    if sha256_file(fixture_path) != fixture_sha256:
        raise SmokeError("fixture source differs from the reviewed contract hash")
    if fixture.get("license") != "crabc-authored C11 evidence fixture":
        raise SmokeError("fixture provenance license changed")

    if execution.get("allocator_feature") != "native-mimalloc-shadow":
        raise SmokeError("execution must name the native-mimalloc shadow feature")
    if require_string(execution, "compiler") != "crabc-cc from CRABC_TEST_SYSROOT/bin":
        raise SmokeError("execution compiler boundary changed")
    if require_string(execution, "language") != "C11":
        raise SmokeError("execution language changed")
    if require_string(execution, "canonical_loader") != str(CANONICAL_LOADER):
        raise SmokeError("canonical loader boundary changed")
    if require_string_list(execution, "compile_flags") != [
        "-O2",
        "-DNDEBUG",
        "-fPIE",
        "-pie",
        "-ftls-model=initial-exec",
        "-pthread",
    ]:
        raise SmokeError("compile flags changed")
    if require_string_list(execution, "link_flags") != ["-Wl,--allow-shlib-undefined"]:
        raise SmokeError("link flags changed")
    if require_string_list(execution, "link_libraries") != ["-lc"]:
        raise SmokeError("link libraries changed")
    if require_string_list(execution, "expected_dynamic_dependencies") != ["libc.so"]:
        raise SmokeError("dynamic dependency boundary changed")
    for key in ("seed", "cycles", "process_epochs", "watchdog_seconds", "rss_threshold_bytes"):
        require_positive_int(execution, key)

    fingerprint = require_object(attestation, "cargo_fingerprint")
    if require_string(fingerprint, "directory") != "target/debug/.fingerprint":
        raise SmokeError("selected-shadow cargo fingerprint directory changed")
    if require_string(fingerprint, "package_prefix") != "crabc-libc-":
        raise SmokeError("selected-shadow cargo fingerprint package changed")
    if require_string(fingerprint, "file") != "lib-c.json":
        raise SmokeError("selected-shadow cargo fingerprint file changed")
    if require_string_list(fingerprint, "exact_features") != [
        "default",
        "native-mimalloc-shadow",
    ]:
        raise SmokeError("selected-shadow cargo fingerprint feature identity changed")

    exported_free = require_object(attestation, "exported_free_route")
    if require_string(exported_free, "symbol") != "free":
        raise SmokeError("selected-shadow exported free symbol changed")
    if require_string(exported_free, "required_callee_suffix") != "native_free>":
        raise SmokeError("selected-shadow exported free route changed")
    if require_string(exported_free, "forbidden_callee_suffix") != "mi_free>":
        raise SmokeError("selected-shadow exported free fallback exclusion changed")

    rust_cleanup = require_object(attestation, "rust_cleanup_free_route")
    if require_string(rust_cleanup, "helper_symbol") != "__crabc_interposable_free":
        raise SmokeError("selected-shadow Rust cleanup helper changed")
    if require_string(rust_cleanup, "required_branch_target") != "free@plt>":
        raise SmokeError("selected-shadow Rust cleanup free route changed")
    if require_string(rust_cleanup, "required_relocation") != "R_AARCH64_JUMP_SLOT":
        raise SmokeError("selected-shadow Rust cleanup relocation changed")

    required_api = ["malloc", "free", "posix_memalign", "malloc_usable_size"]
    if require_string_list(boundary, "allowed_allocation_apis") != required_api:
        raise SmokeError("production allocation API boundary changed")
    if require_string_list(boundary, "forbidden_allocator_identifiers") != [
        "mi_",
        "libmimalloc",
        "native_allocate",
        "native_free",
        "__crabc_runtime",
    ]:
        raise SmokeError("forbidden allocator identifier boundary changed")
    if boundary.get("allocator_private_hooks") is not False:
        raise SmokeError("allocator private hook exclusion changed")
    if boundary.get("c_backend_fallback") is not False:
        raise SmokeError("C-backend fallback exclusion changed")

    if observation.get("rss") != "sampled-from-/proc/self/status-VmRSS":
        raise SmokeError("RSS observation method changed")
    if observation.get("allocator_metadata") != "not-exposed-by-production-shadow-c-api":
        raise SmokeError("allocator metadata boundary changed")
    if observation.get("metadata_high_water_bytes") is not None:
        raise SmokeError("metadata high-water must remain unavailable without a production API")

    source = fixture_path.read_text(encoding="utf-8")
    for identifier in boundary["forbidden_allocator_identifiers"]:
        if identifier in source:
            raise SmokeError(f"fixture contains forbidden allocator identifier: {identifier}")
    for identifier in required_api:
        if identifier not in source:
            raise SmokeError(f"fixture omits required production allocation API: {identifier}")
    required_semantics = [
        "owner_exits_with_live_blocks",
        "successful_cross_thread_handoffs",
        "post_exit_initial_thread_frees",
        "not-exposed-by-production-shadow-c-api",
    ]
    if any(marker not in source for marker in required_semantics):
        raise SmokeError("fixture no longer records the required legal-C lifecycle semantics")

    return {
        "fixture": fixture_path,
        "fixture_sha256": fixture_sha256,
        "seed": require_positive_int(execution, "seed"),
        "cycles": require_positive_int(execution, "cycles"),
        "process_epochs": require_positive_int(execution, "process_epochs"),
        "watchdog_seconds": require_positive_int(execution, "watchdog_seconds"),
        "rss_threshold_bytes": require_positive_int(execution, "rss_threshold_bytes"),
        "compile_flags": require_string_list(execution, "compile_flags"),
        "link_flags": require_string_list(execution, "link_flags"),
        "link_libraries": require_string_list(execution, "link_libraries"),
        "selected_shadow_artifact_attestation": attestation,
    }


def command_record(command: Sequence[str], **kwargs: Any) -> dict[str, Any]:
    """Run one bounded command and retain output for a failure report."""

    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            **kwargs,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "command": list(command),
            "status": None,
            "stdout": error.stdout or "",
            "stderr": error.stderr or "",
            "timed_out": True,
        }
    return {
        "command": list(command),
        "status": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "timed_out": False,
    }


def require_success(record: Mapping[str, Any], subject: str) -> None:
    """Raise an actionable error for a failed compile or execution record."""

    if record.get("timed_out"):
        raise SmokeError(f"{subject} exceeded the configured watchdog")
    if record.get("status") != 0:
        raise SmokeError(
            f"{subject} failed with status {record.get('status')}: "
            f"stdout={record.get('stdout')!r} stderr={record.get('stderr')!r}"
        )


def dynamic_dependencies(binary: Path) -> list[str]:
    """Read the exact NEEDED-library set of one selected-shadow fixture."""

    record = command_record(["readelf", "-d", str(binary)])
    require_success(record, "readelf dynamic dependency inspection")
    return NEEDED_LIBRARY.findall(str(record["stdout"]))


def sha256_text(value: str) -> str:
    """Hash a textual tool observation without retaining its unstable addresses."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def cargo_fingerprint_features(value: Mapping[str, Any]) -> list[str]:
    """Decode Cargo's JSON-encoded enabled-feature list exactly once."""

    encoded = value.get("features")
    if not isinstance(encoded, str):
        raise ArtifactAttestationError("crabc-libc Cargo fingerprint omits its enabled features")
    try:
        features = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise ArtifactAttestationError(
            "crabc-libc Cargo fingerprint has malformed enabled features"
        ) from error
    if (
        not isinstance(features, list)
        or not all(isinstance(feature, str) and feature for feature in features)
        or len(features) != len(set(features))
    ):
        raise ArtifactAttestationError(
            "crabc-libc Cargo fingerprint enabled features are not a unique string list"
        )
    return features


def selected_shadow_fingerprint(
    runtime: Path,
    expectation: Mapping[str, Any],
) -> dict[str, Any]:
    """Select the one libc fingerprint with the reviewed native feature set."""

    fingerprint = require_object(expectation, "cargo_fingerprint")
    exact_features = require_string_list(fingerprint, "exact_features")
    fingerprint_root = runtime / ".fingerprint"
    candidates = sorted(
        fingerprint_root.glob(f"{require_string(fingerprint, 'package_prefix')}*/{require_string(fingerprint, 'file')}")
    )
    matches: list[tuple[Path, Mapping[str, Any], list[str]]] = []
    for candidate in candidates:
        try:
            value = read_json(candidate)
            features = cargo_fingerprint_features(value)
        except SmokeError:
            continue
        if sorted(features) == sorted(exact_features):
            matches.append((candidate, value, features))
    if len(matches) != 1:
        raise ArtifactAttestationError(
            "selected-shadow libc build identity is ambiguous: expected exactly one "
            f"Cargo fingerprint with features {exact_features!r}, found {len(matches)}"
        )
    path, value, features = matches[0]
    return {
        "path": relative(path),
        "sha256": sha256_file(path),
        "features": features,
        "declared_features": value.get("declared_features"),
    }


def require_attestation_success(record: Mapping[str, Any], subject: str) -> str:
    """Turn an ELF-inspection failure into an explicit selected-artifact failure."""

    if record.get("timed_out"):
        raise ArtifactAttestationError(f"{subject} exceeded its inspection watchdog")
    if record.get("status") != 0:
        raise ArtifactAttestationError(
            f"{subject} failed with status {record.get('status')}: "
            f"stdout={record.get('stdout')!r} stderr={record.get('stderr')!r}"
        )
    stdout = record.get("stdout")
    if not isinstance(stdout, str):
        raise ArtifactAttestationError(f"{subject} omitted textual inspection output")
    return stdout


def attested_free_symbol(stdout: str, symbol: str) -> dict[str, str]:
    """Require a default-visible, defined dynamic C allocation entry point."""

    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        name = fields[-1].split("@@", 1)[0]
        symbol_type, binding, visibility, section = fields[3:7]
        if name != symbol:
            continue
        if (
            symbol_type == "FUNC"
            and binding in {"GLOBAL", "WEAK"}
            and visibility == "DEFAULT"
            and section != "UND"
        ):
            return {"binding": binding, "visibility": visibility, "section": section}
    raise ArtifactAttestationError(
        f"selected-shadow libc does not define default-visible dynamic {symbol}"
    )


def require_branch_target(stdout: str, target_suffix: str, subject: str) -> None:
    """Require an AArch64 branch to one named disassembly target suffix."""

    if not re.search(rf"\b(?:b|bl)\s+[^<]*<[^>]*{re.escape(target_suffix)}", stdout):
        raise ArtifactAttestationError(f"{subject} does not branch to <{target_suffix}")


def require_no_branch_target(stdout: str, target_suffix: str, subject: str) -> None:
    """Reject a named allocator backend branch in one reviewed function body."""

    if re.search(rf"\b(?:b|bl)\s+[^<]*<[^>]*{re.escape(target_suffix)}", stdout):
        raise ArtifactAttestationError(f"{subject} branches to forbidden <{target_suffix}")


def selected_shadow_artifact_attestation(
    runtime: Path,
    expectation: Mapping[str, Any],
) -> dict[str, Any]:
    """Attest the selected libc build and both Rust-to-C ``free`` routes.

    The fixture's dynamic dependency check alone only proves that it loaded a
    file named ``libc.so``.  This adds the selected Cargo feature identity, the
    exported native-shadow ``free`` route, and the separate Rust cleanup thunk
    that deliberately branches through ``free@plt`` for foreign C allocations.
    """

    libc = runtime / "libc.so"
    if not libc.is_file():
        raise ArtifactAttestationError("selected-shadow libc artifact is missing")
    exported_free = require_object(expectation, "exported_free_route")
    rust_cleanup = require_object(expectation, "rust_cleanup_free_route")

    dyn_symbols_record = command_record(["readelf", "-W", "--dyn-syms", str(libc)])
    dyn_symbols = require_attestation_success(
        dyn_symbols_record, "selected-shadow libc dynamic symbol inspection"
    )
    exported_route_record = command_record(
        ["objdump", "-d", f"--disassemble={require_string(exported_free, 'symbol')}", str(libc)]
    )
    exported_route = require_attestation_success(
        exported_route_record, "selected-shadow exported free route inspection"
    )
    cleanup_route_record = command_record(
        [
            "objdump",
            "-d",
            f"--disassemble={require_string(rust_cleanup, 'helper_symbol')}",
            str(libc),
        ]
    )
    cleanup_route = require_attestation_success(
        cleanup_route_record, "selected-shadow Rust cleanup free route inspection"
    )
    relocation_record = command_record(["readelf", "-Wr", str(libc)])
    relocations = require_attestation_success(
        relocation_record, "selected-shadow Rust cleanup relocation inspection"
    )

    exported_symbol = attested_free_symbol(dyn_symbols, require_string(exported_free, "symbol"))
    require_branch_target(
        exported_route,
        require_string(exported_free, "required_callee_suffix"),
        "selected-shadow exported free",
    )
    require_no_branch_target(
        exported_route,
        require_string(exported_free, "forbidden_callee_suffix"),
        "selected-shadow exported free",
    )
    helper_symbol = require_string(rust_cleanup, "helper_symbol")
    require_branch_target(
        cleanup_route,
        require_string(rust_cleanup, "required_branch_target"),
        f"selected-shadow {helper_symbol}",
    )
    required_relocation = require_string(rust_cleanup, "required_relocation")
    if not re.search(rf"{re.escape(required_relocation)}.*\bfree(?:\s|\+|$)", relocations):
        raise ArtifactAttestationError(
            "selected-shadow Rust cleanup free route lacks its required free PLT relocation"
        )

    return {
        "status": "passed",
        "build_identity": {
            "libc": {"path": relative(libc), "sha256": sha256_file(libc), "size_bytes": libc.stat().st_size},
            "cargo_fingerprint": selected_shadow_fingerprint(runtime, expectation),
        },
        "routes": {
            "exported_free": {
                "symbol": require_string(exported_free, "symbol"),
                **exported_symbol,
                "required_callee_suffix": require_string(exported_free, "required_callee_suffix"),
                "forbidden_callee_suffix": require_string(exported_free, "forbidden_callee_suffix"),
                "disassembly_sha256": sha256_text(exported_route),
            },
            "rust_cleanup_free": {
                "helper_symbol": helper_symbol,
                "required_branch_target": require_string(rust_cleanup, "required_branch_target"),
                "required_relocation": required_relocation,
                "disassembly_sha256": sha256_text(cleanup_route),
                "relocations_sha256": sha256_text(relocations),
            },
        },
    }


def retain_selected_shadow_context(
    error: SmokeError,
    *,
    binary: Path,
    dependencies: Sequence[str],
    attestation: Mapping[str, Any],
) -> None:
    """Keep completed artifact proof visible when a later fixture check fails."""

    error.selected_shadow_artifact_attestation = dict(attestation)
    error.artifact = {
        "sha256": sha256_file(binary),
        "size_bytes": binary.stat().st_size,
    }
    error.dynamic_dependencies = list(dependencies)


def require_owned_shadow_environment() -> tuple[Path, Path, Path]:
    """Require the launcher-staged owned sysroot, loader, and debug runtime."""

    raw_sysroot = os.environ.get("CRABC_TEST_SYSROOT")
    if not raw_sysroot:
        raise SmokeError(
            "native churn/RSS smoke requires CRABC_TEST_SYSROOT from scripts/run_owned_test_suite.py"
        )
    sysroot = Path(raw_sysroot).expanduser().resolve()
    compiler = sysroot / "bin/crabc-cc"
    manifest = sysroot / "share/crabc/manifest.json"
    runtime = ROOT / "target/debug"
    if not compiler.is_file() or not manifest.is_file():
        raise SmokeError("native churn/RSS smoke requires a complete owned crabc sysroot")
    if not (runtime / "libc.so").is_file() or not (runtime / "libldso.so").is_file():
        raise SmokeError("native churn/RSS smoke requires target/debug libc.so and libldso.so")
    if not CANONICAL_LOADER.is_file() or CANONICAL_LOADER.is_symlink():
        raise SmokeError(
            "native churn/RSS smoke must run under scripts/run_owned_test_suite.py canonical-loader staging"
        )
    return sysroot, compiler, runtime


def parse_fixture_output(
    stdout: str,
    *,
    seed: int,
    cycles: int,
) -> dict[str, Any]:
    """Validate one compact machine-readable fixture result."""

    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise AllocatorLivenessError(f"fixture stdout is not one JSON result: {stdout!r}") from error
    if not isinstance(value, dict) or value.get("schema") != FIXTURE_SCHEMA:
        raise AllocatorLivenessError("fixture JSON schema changed")
    expected = {
        "seed": seed,
        "cycles": cycles,
        "owner_exits_with_live_blocks": cycles,
        "successful_cross_thread_handoffs": cycles,
        "post_exit_initial_thread_frees": cycles * 6,
        "requested_bytes_live_final": 0,
        "usable_bytes_live_final": 0,
        "live_blocks_final": 0,
        "allocator_metadata_high_water_bytes": None,
        "allocator_metadata_observation": "not-exposed-by-production-shadow-c-api",
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise AllocatorLivenessError(
                f"fixture result field {key!r} differs: expected {expected_value!r}, got {value.get(key)!r}"
            )
    positive_fields = [
        "requested_bytes_total",
        "requested_bytes_live_high_water",
        "usable_bytes_live_high_water",
        "live_blocks_high_water",
        "rss_samples",
    ]
    for key in positive_fields:
        result = value.get(key)
        if isinstance(result, bool) or not isinstance(result, int) or result <= 0:
            raise AllocatorLivenessError(f"fixture result field {key!r} must be a positive integer")
    for key in ("rss_initial_bytes", "rss_final_bytes", "rss_high_water_bytes"):
        result = value.get(key)
        if isinstance(result, bool) or not isinstance(result, int) or result < 0:
            raise AllocatorLivenessError(f"fixture result field {key!r} must be a nonnegative integer")
    if value["rss_high_water_bytes"] < max(value["rss_initial_bytes"], value["rss_final_bytes"]):
        raise AllocatorLivenessError("fixture RSS high-water is below an observed RSS sample")
    return value


def run_smoke(
    contract: Mapping[str, Any],
    *,
    seed: int,
    cycles: int,
    epochs: int,
    watchdog_seconds: int,
    rss_threshold_bytes: int,
) -> dict[str, Any]:
    """Build then run fresh selected-shadow fixture processes deterministically."""

    validated = validate_contract(contract)
    if min(seed, cycles, epochs, watchdog_seconds, rss_threshold_bytes) <= 0:
        raise SmokeError(
            "seed, cycles, epochs, watchdog seconds, and RSS threshold bytes must all be positive"
        )
    _sysroot, compiler, runtime = require_owned_shadow_environment()
    fixture = validated["fixture"]
    assert isinstance(fixture, Path)

    with tempfile.TemporaryDirectory(prefix="crabc-native-churn-rss-smoke-") as temporary:
        artifact_root = Path(temporary)
        binary = artifact_root / "native-churn-rss-smoke"
        build_command = [
            str(compiler),
            "-std=c11",
            *validated["compile_flags"],
            "-L",
            str(runtime),
            str(fixture),
            *validated["link_flags"],
            *validated["link_libraries"],
            "-o",
            str(binary),
        ]
        build = command_record(build_command, cwd=ROOT)
        require_success(build, "native churn/RSS smoke fixture build")
        dependencies = dynamic_dependencies(binary)
        if dependencies != ["libc.so"]:
            raise ArtifactAttestationError(
                "selected-shadow fixture dynamic dependency set differs from the production boundary: "
                f"{dependencies!r}"
            )
        attestation = selected_shadow_artifact_attestation(
            runtime, validated["selected_shadow_artifact_attestation"]
        )
        environment = dict(os.environ)
        for key in ("LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"):
            environment.pop(key, None)
        environment["LD_LIBRARY_PATH"] = str(runtime)
        executions: list[dict[str, Any]] = []
        try:
            for epoch in range(epochs):
                epoch_seed = seed + epoch
                run_command = [str(binary), str(epoch_seed), str(cycles)]
                record = command_record(
                    run_command,
                    cwd=ROOT,
                    env=environment,
                    timeout=watchdog_seconds,
                )
                try:
                    require_success(
                        record, f"native churn/RSS smoke process epoch {epoch + 1}/{epochs}"
                    )
                except SmokeError as error:
                    raise AllocatorLivenessError(str(error)) from error
                if record["stderr"]:
                    raise AllocatorLivenessError(
                        f"fixture emitted unexpected stderr at epoch {epoch + 1}/{epochs}: "
                        f"{record['stderr']!r}"
                    )
                fixture_result = parse_fixture_output(
                    str(record["stdout"]), seed=epoch_seed, cycles=cycles
                )
                executions.append(
                    {
                        "epoch": epoch + 1,
                        "seed": epoch_seed,
                        "fixture": fixture_result,
                        "watchdog": {"seconds": watchdog_seconds, "status": "passed"},
                    }
                )
        except AllocatorLivenessError as error:
            # The worker lifecycle can fail after all artifact proof has
            # succeeded. Retain that proof in the failed JSON rather than
            # making a liveness failure look like an unselected libc.
            retain_selected_shadow_context(
                error,
                binary=binary,
                dependencies=dependencies,
                attestation=attestation,
            )
            raise
        observed_rss = high_water(executions)["rss_bytes"]
        if not isinstance(observed_rss, int):
            raise SmokeError("RSS high-water aggregation did not produce an integer")
        if observed_rss > rss_threshold_bytes:
            error = RssThresholdError(
                observed_bytes=observed_rss, threshold_bytes=rss_threshold_bytes
            )
            retain_selected_shadow_context(
                error,
                binary=binary,
                dependencies=dependencies,
                attestation=attestation,
            )
            raise error
        return {
            "artifact": {
                "sha256": sha256_file(binary),
                "size_bytes": binary.stat().st_size,
            },
            "build": {
                "command": build_command,
                "dynamic_dependencies": dependencies,
                "selected_shadow_artifact_attestation": attestation,
            },
            "executions": executions,
        }


def high_water(executions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate observables without turning unavailable metadata into a proxy."""

    if not executions:
        raise SmokeError("no successful fixture executions to aggregate")
    fixture_results = [entry["fixture"] for entry in executions]
    if not all(isinstance(result, dict) for result in fixture_results):
        raise SmokeError("execution result shape changed")
    typed_results = [result for result in fixture_results if isinstance(result, dict)]
    return {
        "rss_bytes": max(result["rss_high_water_bytes"] for result in typed_results),
        "requested_live_bytes": max(
            result["requested_bytes_live_high_water"] for result in typed_results
        ),
        "usable_live_bytes": max(result["usable_bytes_live_high_water"] for result in typed_results),
        "live_blocks": max(result["live_blocks_high_water"] for result in typed_results),
        "allocator_metadata": {
            "available": False,
            "high_water_bytes": None,
            "reason": "not exposed by the production shadow C API",
        },
    }


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    """Publish one complete report without exposing a partial JSON document."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def report_for_success(
    contract: Mapping[str, Any],
    run: Mapping[str, Any],
    *,
    seed: int,
    cycles: int,
    epochs: int,
    watchdog_seconds: int,
    rss_threshold_bytes: int,
) -> dict[str, Any]:
    """Create the durable report that a CI caller can consume directly."""

    executions = run.get("executions")
    if not isinstance(executions, list):
        raise SmokeError("successful run omitted execution records")
    return {
        "schema": REPORT_SCHEMA,
        "status": "passed",
        "contract": {
            "path": relative(CONTRACT_PATH),
            "sha256": sha256_file(CONTRACT_PATH),
            "fixture_sha256": contract["fixture"]["sha256"],
        },
        "configuration": {
            "seed": seed,
            "cycles_per_process": cycles,
            "fresh_process_epochs": epochs,
            "watchdog_seconds": watchdog_seconds,
            "rss_threshold_bytes": rss_threshold_bytes,
        },
        "production_shadow_boundary": {
            "allocator_feature": "native-mimalloc-shadow",
            "allocation_apis": contract["production_shadow_boundary"]["allowed_allocation_apis"],
            "allocator_private_hooks": False,
            "c_backend_fallback": False,
            "dynamic_dependencies": run["build"]["dynamic_dependencies"],
            "selected_shadow_artifact_attestation": run["build"][
                "selected_shadow_artifact_attestation"
            ],
        },
        "artifact": run["artifact"],
        "executions": executions,
        "high_water": high_water(executions),
    }


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the bounded, reproducible smoke controls."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, help="nonzero base seed (default: manifest)")
    parser.add_argument("--cycles", type=int, help="owner/handoff churn cycles per process")
    parser.add_argument("--epochs", type=int, help="fresh process epochs")
    parser.add_argument("--watchdog-seconds", type=int, help="per-process watchdog")
    parser.add_argument(
        "--rss-threshold-bytes",
        type=int,
        help="maximum completed-process RSS high-water (default: manifest)",
    )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT, help="JSON report path")
    return parser.parse_args(arguments)


def failure_report(error: SmokeError) -> dict[str, Any]:
    """Record a machine-readable failure class without losing the diagnosis."""

    failure: dict[str, Any] = {"kind": "harness", "message": str(error)}
    if isinstance(error, AllocatorLivenessError):
        failure["kind"] = "allocator_liveness"
    elif isinstance(error, RssThresholdError):
        failure["kind"] = "rss_threshold"
        failure["rss"] = {
            "observed_high_water_bytes": error.observed_bytes,
            "threshold_bytes": error.threshold_bytes,
        }
    elif isinstance(error, ArtifactAttestationError):
        failure["kind"] = "selected_shadow_attestation"
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "failed",
        "contract": {"path": relative(CONTRACT_PATH)},
        "failure": failure,
        "error": str(error),
    }
    attestation = getattr(error, "selected_shadow_artifact_attestation", None)
    if isinstance(attestation, dict):
        report["production_shadow_boundary"] = {
            "dynamic_dependencies": getattr(error, "dynamic_dependencies", None),
            "selected_shadow_artifact_attestation": attestation,
        }
        report["artifact"] = getattr(error, "artifact", None)
    return report


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the smoke and write a passed or failed machine-readable report."""

    args = parse_arguments(arguments)
    report_path = args.report.expanduser().resolve()
    try:
        contract = read_json(CONTRACT_PATH)
        validated = validate_contract(contract)
        seed = validated["seed"] if args.seed is None else args.seed
        cycles = validated["cycles"] if args.cycles is None else args.cycles
        epochs = validated["process_epochs"] if args.epochs is None else args.epochs
        watchdog_seconds = (
            validated["watchdog_seconds"]
            if args.watchdog_seconds is None
            else args.watchdog_seconds
        )
        rss_threshold_bytes = (
            validated["rss_threshold_bytes"]
            if args.rss_threshold_bytes is None
            else args.rss_threshold_bytes
        )
        run = run_smoke(
            contract,
            seed=seed,
            cycles=cycles,
            epochs=epochs,
            watchdog_seconds=watchdog_seconds,
            rss_threshold_bytes=rss_threshold_bytes,
        )
        report = report_for_success(
            contract,
            run,
            seed=seed,
            cycles=cycles,
            epochs=epochs,
            watchdog_seconds=watchdog_seconds,
            rss_threshold_bytes=rss_threshold_bytes,
        )
    except SmokeError as error:
        report = failure_report(error)
        atomic_write_json(report_path, report)
        print(f"native-churn-rss-smoke: {error}", file=sys.stderr)
        return 1
    atomic_write_json(report_path, report)
    print(json.dumps({"report": str(report_path), "status": "passed"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
