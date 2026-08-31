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
internal state, which is deliberately not exposed through the production
shadow C ABI and therefore is never inferred from private test hooks.  An
unavailable registry, ledger, PageMap, metadata, arena, TLD, or Theap
observation keeps the general-production state qualification incomplete even
when the C workload itself passes.
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
FIXTURE_SCHEMA = "crabc-mimalloc-native-churn-rss-smoke-fixture-v2"
REPORT_SCHEMA = "crabc-mimalloc-native-churn-rss-smoke-report-v3"
CANONICAL_LOADER = Path("/lib/ld-crabc-aarch64.so.1")
DEFAULT_REPORT = ROOT / "compat/reports/allocator/native-churn-rss-smoke-latest.json"
NEEDED_LIBRARY = re.compile(r"Shared library: \[(?P<name>[^]]+)\]")
UINT64_MAX = (1 << 64) - 1
FIXTURE_RANDOM_UPDATES_PER_EPOCH = 6
THREAD_FANOUT = {
    "initial_threads": 1,
    "owner_workers_per_epoch": 1,
    "handoff_workers_per_epoch": 1,
    "worker_threads_per_epoch": 2,
    "peak_threads": 3,
}
ALLOCATOR_STATE_FIELDS = {
    "live_owner_registry": (
        "live_owner_registry_high_water_entries",
        "live_owner_registry_plateau_after_warmup",
        "registry_entries",
    ),
    "post_exit_registry": (
        "post_exit_registry_high_water_entries",
        "post_exit_registry_plateau_after_warmup",
        "registry_entries",
    ),
    "client_ledger": (
        "client_ledger_high_water_entries",
        "client_ledger_plateau_after_warmup",
        "ledger_entries",
    ),
    "page_map": (
        "page_map_registered_high_water_entries",
        "page_map_plateau_after_warmup",
        "registered_entries",
    ),
    "metadata": (
        "allocator_metadata_high_water_bytes",
        "allocator_metadata_plateau_after_warmup",
        "bytes",
    ),
    "arena": (
        "arena_registry_high_water_entries",
        "arena_plateau_after_warmup",
        "registry_entries",
    ),
    "abandoned_page": (
        "abandoned_page_high_water_count",
        "abandoned_page_plateau_after_warmup",
        "pages",
    ),
    "tld": (
        "tld_high_water_count",
        "tld_plateau_after_warmup",
        "live_tlds",
    ),
    "theap": (
        "theap_high_water_count",
        "theap_plateau_after_warmup",
        "live_theaps",
    ),
}
ALLOCATOR_PLATEAU_CATEGORIES = tuple(ALLOCATOR_STATE_FIELDS)
ALLOCATOR_STATE_OBSERVATION = "not-exposed-by-production-shadow-c-api"
STATE_AUDITOR_SCOPE = "production-general-churn"
REQUIRED_HIGH_WATER_FIELDS = (
    "rss_bytes",
    "requested_live_bytes",
    "usable_live_bytes",
    "live_blocks",
    "thread_fanout.peak_threads",
    "thread_fanout.total_worker_threads",
    "rss_slopes.within_process_quiescent.minimum_bytes_per_fixture_epoch",
    "rss_slopes.within_process_quiescent.maximum_bytes_per_fixture_epoch",
    "rss_slopes.across_process_high_water.bytes_per_epoch",
    "state_auditor.workload_liveness.snapshot_count",
    "state_auditor.workload_liveness.plateau_after_warmup",
    "allocator_state.live_owner_registry.high_water",
    "allocator_state.live_owner_registry.plateau_after_warmup",
    "allocator_state.post_exit_registry.high_water",
    "allocator_state.post_exit_registry.plateau_after_warmup",
    "allocator_state.client_ledger.high_water",
    "allocator_state.client_ledger.plateau_after_warmup",
    "allocator_state.metadata.high_water",
    "allocator_state.metadata.plateau_after_warmup",
    "allocator_state.page_map.high_water",
    "allocator_state.page_map.plateau_after_warmup",
    "allocator_state.arena.high_water",
    "allocator_state.arena.plateau_after_warmup",
    "allocator_state.abandoned_page.high_water",
    "allocator_state.abandoned_page.plateau_after_warmup",
    "allocator_state.tld.high_water",
    "allocator_state.tld.plateau_after_warmup",
    "allocator_state.theap.high_water",
    "allocator_state.theap.plateau_after_warmup",
)
REQUIRED_ARTIFACT_ATTESTATION_FIELDS = (
    "production_shadow_boundary.fixture_elf_attestation.fixture.sha256",
    "production_shadow_boundary.fixture_elf_attestation.fixture.size_bytes",
    "production_shadow_boundary.fixture_elf_attestation.fixture.identity.class",
    "production_shadow_boundary.fixture_elf_attestation.fixture.identity.data",
    "production_shadow_boundary.fixture_elf_attestation.fixture.identity.os_abi",
    "production_shadow_boundary.fixture_elf_attestation.fixture.identity.abi_version",
    "production_shadow_boundary.fixture_elf_attestation.fixture.identity.type",
    "production_shadow_boundary.fixture_elf_attestation.fixture.identity.machine",
    "production_shadow_boundary.fixture_elf_attestation.fixture.pt_interp",
    "production_shadow_boundary.fixture_elf_attestation.selected_loader.canonical_path",
    "production_shadow_boundary.fixture_elf_attestation.selected_loader.canonical_sha256",
    "production_shadow_boundary.fixture_elf_attestation.selected_loader.runtime_path",
    "production_shadow_boundary.fixture_elf_attestation.selected_loader.runtime_sha256",
    "executions[].executed_fixture_elf.sha256",
    "executions[].executed_fixture_elf.identity",
    "executions[].executed_fixture_elf.pt_interp",
)


class SmokeError(RuntimeError):
    """A violated selected-shadow evidence precondition or fixture result."""


class PrerequisiteError(SmokeError):
    """The owned native execution prerequisites are not available."""


class EvidenceContractError(SmokeError):
    """An executed or selected artifact cannot satisfy a production boundary."""

    def __init__(self, message: str, *, boundary: str) -> None:
        self.boundary = boundary
        super().__init__(message)


class ArtifactAttestationError(EvidenceContractError):
    """The selected libc artifact cannot prove its native-shadow identity."""

    def __init__(self, message: str) -> None:
        super().__init__(message, boundary="selected_shadow_artifact")


class FixtureElfAttestationError(EvidenceContractError):
    """The fixture executable does not match the selected target/loader boundary."""

    def __init__(self, message: str) -> None:
        super().__init__(message, boundary="fixture_elf_identity")


class AllocatorStateEvidenceError(EvidenceContractError):
    """The production workload ran without its required internal audit evidence."""

    def __init__(self, message: str) -> None:
        super().__init__(message, boundary="allocator_internal_state")


class AllocatorLivenessError(SmokeError):
    """The fixture did not complete its required allocation ownership lifecycle."""

    def __init__(
        self,
        message: str,
        *,
        root_failure: Mapping[str, Any] | None = None,
        completed_executions: Sequence[Mapping[str, Any]] = (),
    ) -> None:
        self.root_failure = dict(root_failure) if root_failure is not None else None
        self.completed_executions = [dict(execution) for execution in completed_executions]
        super().__init__(message)


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


def require_int_at_least(value: Mapping[str, Any], key: str, minimum: int) -> int:
    """Read one integer field with the samples needed by a plateau or slope."""

    result = value.get(key)
    if isinstance(result, bool) or not isinstance(result, int) or result < minimum:
        raise SmokeError(f"contract field {key!r} must be an integer at least {minimum}")
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


def next_fixture_random(value: int) -> int:
    """Apply the fixture's wrapping xorshift64 transition exactly."""

    value ^= (value << 13) & UINT64_MAX
    value ^= value >> 7
    value ^= (value << 17) & UINT64_MAX
    return value & UINT64_MAX


def fixture_epoch_seeds(seed: int, cycles: int) -> list[int]:
    """Derive every inner fixture-epoch seed reported by one process run."""

    if seed <= 0 or seed > UINT64_MAX or cycles <= 0:
        raise SmokeError("fixture seed and cycle count are outside their positive u64 range")
    random_state = seed
    result: list[int] = []
    for _cycle in range(cycles):
        random_state = next_fixture_random(random_state)
        result.append(random_state)
        for _shuffle_step in range(FIXTURE_RANDOM_UPDATES_PER_EPOCH - 1):
            random_state = next_fixture_random(random_state)
    return result


def exact_slope(first: int, last: int, intervals: int) -> dict[str, Any]:
    """Report an exact endpoint delta plus its derived per-epoch slope."""

    if intervals <= 0:
        raise SmokeError("RSS slope requires at least one complete epoch interval")
    delta = last - first
    return {
        "first_bytes": first,
        "last_bytes": last,
        "delta_bytes": delta,
        "interval_count": intervals,
        "bytes_per_epoch": delta / intervals,
    }


def fixture_rss_slope(result: Mapping[str, Any]) -> dict[str, Any]:
    """Measure post-warm quiescent RSS growth inside one fixture process."""

    cycles = result.get("cycles")
    first = result.get("rss_warm_quiescent_bytes")
    last = result.get("rss_last_quiescent_bytes")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in (cycles, first, last)):
        raise SmokeError("fixture RSS slope endpoints changed shape")
    assert isinstance(cycles, int) and isinstance(first, int) and isinstance(last, int)
    return exact_slope(first, last, cycles - 1)


def unavailable_allocator_state() -> dict[str, dict[str, Any]]:
    """Describe every required internal state without inventing a proxy."""

    reason = "not exposed by the production shadow C API"
    return {
        category: {
            "available": False,
            "high_water": None,
            "high_water_unit": unit,
            "plateau_after_warmup": None,
            "reason": reason,
        }
        for category, (_high_water_field, _plateau_field, unit) in ALLOCATOR_STATE_FIELDS.items()
    }


def validate_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the fixed native-shadow workload and its honest boundaries."""

    if contract.get("format") != 1 or contract.get("schema") != "crabc-mimalloc-native-churn-rss-smoke":
        raise SmokeError("unsupported native churn/RSS smoke contract")

    fixture = contract.get("fixture")
    execution = contract.get("execution")
    boundary = contract.get("production_shadow_boundary")
    observation = contract.get("state_observation")
    attestation = contract.get("selected_shadow_artifact_attestation")
    failure_contract = contract.get("failure_contract")
    report_contract = contract.get("report")
    if not isinstance(fixture, dict) or not isinstance(execution, dict):
        raise SmokeError("contract must contain fixture and execution objects")
    if not isinstance(boundary, dict) or not isinstance(observation, dict):
        raise SmokeError("contract must contain production boundary and observation objects")
    if not isinstance(attestation, dict):
        raise SmokeError("contract must contain a selected-shadow artifact attestation object")
    if not isinstance(failure_contract, dict):
        raise SmokeError("contract must contain a failure contract object")
    if not isinstance(report_contract, dict):
        raise SmokeError("contract must contain a report object")

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
    if require_object(execution, "fixture_elf_identity") != {
        "class": "ELF64",
        "data": "little-endian",
        "os_abi": "UNIX - System V",
        "abi_version": "0",
        "type": "DYN",
        "machine": "AArch64",
        "pt_interp": str(CANONICAL_LOADER),
    }:
        raise SmokeError("fixture ELF identity boundary changed")
    require_positive_int(execution, "seed")
    require_int_at_least(execution, "cycles", 2)
    require_int_at_least(execution, "process_epochs", 2)
    require_positive_int(execution, "watchdog_seconds")
    require_positive_int(execution, "rss_threshold_bytes")
    if require_object(execution, "thread_fanout") != {
        "initial_threads": 1,
        "owner_workers_per_fixture_epoch": 1,
        "handoff_workers_per_fixture_epoch": 1,
        "peak_threads": 3,
    }:
        raise SmokeError("thread-fanout contract changed")

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
    if observation.get("allocator_state_categories") != list(ALLOCATOR_PLATEAU_CATEGORIES):
        raise SmokeError("allocator state category boundary changed")
    if observation.get("allocator_plateau_observation") != ALLOCATOR_STATE_OBSERVATION:
        raise SmokeError("allocator plateau observation boundary changed")
    if observation.get("production_liveness_state_auditor") != STATE_AUDITOR_SCOPE:
        raise SmokeError("production liveness state-auditor scope changed")
    if observation.get("general_production_state_qualification") != "incomplete-when-unavailable":
        raise SmokeError("general-production state qualification changed")
    if require_string_list(failure_contract, "kinds") != [
        "harness",
        "prerequisite",
        "runtime",
        "evidence",
    ]:
        raise SmokeError("failure classification contract changed")
    if failure_contract.get("exit_68_root_failure_required") is not True:
        raise SmokeError("exit-68 root-failure requirement changed")
    if require_string(report_contract, "path") != relative(DEFAULT_REPORT):
        raise SmokeError("report path changed")
    if require_string(report_contract, "schema") != REPORT_SCHEMA:
        raise SmokeError("report schema changed")
    if require_string_list(report_contract, "required_high_water") != list(
        REQUIRED_HIGH_WATER_FIELDS
    ):
        raise SmokeError("required high-water report fields changed")
    if require_string_list(
        report_contract, "required_artifact_attestation"
    ) != list(REQUIRED_ARTIFACT_ATTESTATION_FIELDS):
        raise SmokeError("required artifact-attestation report fields changed")

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
        "process_epochs": require_int_at_least(execution, "process_epochs", 2),
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
    except OSError as error:
        return {
            "command": list(command),
            "status": None,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "launch_error": str(error),
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

    if record.get("launch_error"):
        raise PrerequisiteError(f"{subject} could not launch: {record['launch_error']}")
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
    stdout = require_fixture_inspection_success(
        record, "fixture dynamic dependency inspection"
    )
    return NEEDED_LIBRARY.findall(stdout)


def require_fixture_inspection_success(record: Mapping[str, Any], subject: str) -> str:
    """Distinguish a missing inspection tool from a wrong fixture artifact."""

    if record.get("launch_error"):
        raise PrerequisiteError(f"{subject} could not launch: {record['launch_error']}")
    if record.get("timed_out"):
        raise PrerequisiteError(f"{subject} exceeded its inspection watchdog")
    if record.get("status") != 0:
        raise FixtureElfAttestationError(
            f"{subject} failed with status {record.get('status')}: "
            f"stdout={record.get('stdout')!r} stderr={record.get('stderr')!r}"
        )
    stdout = record.get("stdout")
    if not isinstance(stdout, str):
        raise FixtureElfAttestationError(f"{subject} omitted textual inspection output")
    return stdout


def attested_elf_identity(stdout: str) -> dict[str, str]:
    """Require the executed fixture to be the reviewed Linux/AArch64 PIE ELF."""

    fields: dict[str, str] = {}
    for line in stdout.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        fields[key] = value.strip()
    elf_type = fields.get("Type", "").split(maxsplit=1)[0]
    data = fields.get("Data", "")
    identity = {
        "class": fields.get("Class", ""),
        "data": "little-endian" if "little endian" in data else data,
        "os_abi": fields.get("OS/ABI", ""),
        "abi_version": fields.get("ABI Version", ""),
        "type": elf_type,
        "machine": fields.get("Machine", ""),
    }
    expected = {
        "class": "ELF64",
        "data": "little-endian",
        "os_abi": "UNIX - System V",
        "abi_version": "0",
        "type": "DYN",
        "machine": "AArch64",
    }
    if identity != expected:
        raise FixtureElfAttestationError(
            f"fixture ELF identity differs: expected {expected!r}, got {identity!r}"
        )
    return identity


def attested_program_interpreter(stdout: str, expected: Path) -> str:
    """Require exactly one PT_INTERP naming the selected canonical loader."""

    interpreters = re.findall(r"\[Requesting program interpreter:\s*([^]]+)\]", stdout)
    expected_text = str(expected)
    if interpreters != [expected_text]:
        raise FixtureElfAttestationError(
            "fixture program interpreter differs: "
            f"expected exactly {expected_text!r}, got {interpreters!r}"
        )
    return interpreters[0]


def fixture_elf_attestation(binary: Path, runtime: Path) -> dict[str, Any]:
    """Attest the exact fixture bytes and loader selected for their execution."""

    header_record = command_record(["readelf", "-h", str(binary)])
    header = require_fixture_inspection_success(
        header_record, "fixture ELF header inspection"
    )
    program_header_record = command_record(["readelf", "-l", str(binary)])
    program_headers = require_fixture_inspection_success(
        program_header_record, "fixture program-header inspection"
    )
    identity = attested_elf_identity(header)
    interpreter = attested_program_interpreter(program_headers, CANONICAL_LOADER)

    selected_loader = runtime / "libldso.so"
    canonical_loader_hash = sha256_file(CANONICAL_LOADER)
    selected_loader_hash = sha256_file(selected_loader)
    if canonical_loader_hash != selected_loader_hash:
        raise FixtureElfAttestationError(
            "canonical PT_INTERP loader differs from target/debug/libldso.so"
        )
    return {
        "status": "passed",
        "fixture": {
            "path": str(binary),
            "sha256": sha256_file(binary),
            "size_bytes": binary.stat().st_size,
            "identity": identity,
            "pt_interp": interpreter,
            "elf_header_sha256": sha256_text(header),
            "program_headers_sha256": sha256_text(program_headers),
        },
        "selected_loader": {
            "canonical_path": interpreter,
            "canonical_sha256": canonical_loader_hash,
            "canonical_size_bytes": CANONICAL_LOADER.stat().st_size,
            "runtime_path": relative(selected_loader),
            "runtime_sha256": selected_loader_hash,
            "runtime_size_bytes": selected_loader.stat().st_size,
        },
    }


def require_fixture_elf_unchanged(
    binary: Path, attestation: Mapping[str, Any]
) -> dict[str, Any]:
    """Prove the file about to execute is the exact attested fixture ELF."""

    fixture = attestation.get("fixture")
    if not isinstance(fixture, dict):
        raise FixtureElfAttestationError("fixture ELF attestation changed shape")
    if (
        fixture.get("sha256") != sha256_file(binary)
        or fixture.get("size_bytes") != binary.stat().st_size
    ):
        raise FixtureElfAttestationError(
            "fixture ELF changed after attestation and before execution"
        )
    return {
        "sha256": fixture["sha256"],
        "size_bytes": fixture["size_bytes"],
        "identity": fixture["identity"],
        "pt_interp": fixture["pt_interp"],
    }


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

    if record.get("launch_error"):
        raise PrerequisiteError(f"{subject} could not launch: {record['launch_error']}")
    if record.get("timed_out"):
        raise PrerequisiteError(f"{subject} exceeded its inspection watchdog")
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
    fixture_attestation: Mapping[str, Any],
) -> None:
    """Keep completed artifact proof visible when a later fixture check fails."""

    error.selected_shadow_artifact_attestation = dict(attestation)
    error.artifact = {
        "sha256": sha256_file(binary),
        "size_bytes": binary.stat().st_size,
    }
    error.dynamic_dependencies = list(dependencies)
    error.fixture_elf_attestation = dict(fixture_attestation)


def require_owned_shadow_environment() -> tuple[Path, Path, Path]:
    """Require the launcher-staged owned sysroot, loader, and debug runtime."""

    raw_sysroot = os.environ.get("CRABC_TEST_SYSROOT")
    if not raw_sysroot:
        raise PrerequisiteError(
            "native churn/RSS smoke requires CRABC_TEST_SYSROOT from scripts/run_owned_test_suite.py"
        )
    sysroot = Path(raw_sysroot).expanduser().resolve()
    compiler = sysroot / "bin/crabc-cc"
    manifest = sysroot / "share/crabc/manifest.json"
    runtime = ROOT / "target/debug"
    if not compiler.is_file() or not manifest.is_file():
        raise PrerequisiteError("native churn/RSS smoke requires a complete owned crabc sysroot")
    if not (runtime / "libc.so").is_file() or not (runtime / "libldso.so").is_file():
        raise PrerequisiteError(
            "native churn/RSS smoke requires target/debug libc.so and libldso.so"
        )
    if not CANONICAL_LOADER.is_file() or CANONICAL_LOADER.is_symlink():
        raise PrerequisiteError(
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
    inner_seeds = fixture_epoch_seeds(seed, cycles)
    expected = {
        "status": "passed",
        "seed": seed,
        "cycles": cycles,
        "completed_epochs": cycles,
        "first_fixture_epoch_seed": inner_seeds[0],
        "last_fixture_epoch_seed": inner_seeds[-1],
        "owner_exits_with_live_blocks": cycles,
        "successful_cross_thread_handoffs": cycles,
        "post_exit_initial_thread_frees": cycles * 6,
        "requested_bytes_live_final": 0,
        "usable_bytes_live_final": 0,
        "live_blocks_final": 0,
        "allocator_metadata_observation": ALLOCATOR_STATE_OBSERVATION,
    }
    for high_water_field, plateau_field, _unit in ALLOCATOR_STATE_FIELDS.values():
        expected[high_water_field] = None
        expected[plateau_field] = None
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
    for key in (
        "rss_initial_bytes",
        "rss_final_bytes",
        "rss_high_water_bytes",
        "rss_warm_quiescent_bytes",
        "rss_last_quiescent_bytes",
    ):
        result = value.get(key)
        if isinstance(result, bool) or not isinstance(result, int) or result < 0:
            raise AllocatorLivenessError(f"fixture result field {key!r} must be a nonnegative integer")
    if any(
        value[key] == 0
        for key in (
            "rss_initial_bytes",
            "rss_high_water_bytes",
            "rss_warm_quiescent_bytes",
            "rss_last_quiescent_bytes",
        )
    ):
        raise PrerequisiteError(
            "fixture could not observe a positive VmRSS value from /proc/self/status"
        )
    if value["rss_high_water_bytes"] < max(
        value["rss_initial_bytes"],
        value["rss_final_bytes"],
        value["rss_warm_quiescent_bytes"],
        value["rss_last_quiescent_bytes"],
    ):
        raise AllocatorLivenessError("fixture RSS high-water is below an observed RSS sample")
    if value.get("thread_fanout") != {
        **THREAD_FANOUT,
        "worker_threads_created": cycles * THREAD_FANOUT["worker_threads_per_epoch"],
    }:
        raise AllocatorLivenessError("fixture thread-fanout record changed")
    state_auditor = value.get("state_auditor")
    expected_auditor = {
        "status": "incomplete",
        "scope": STATE_AUDITOR_SCOPE,
        "workload_liveness": {
            "status": "passed",
            "snapshot_count": cycles,
            "warmup_epoch": 1,
            "post_warm_snapshot_count": cycles - 1,
            "plateau_after_warmup": True,
        },
        "allocator_state": {
            "status": "unavailable",
            "observation": ALLOCATOR_STATE_OBSERVATION,
        },
    }
    if state_auditor != expected_auditor:
        raise AllocatorLivenessError(
            "fixture state-auditor record differs: "
            f"expected {expected_auditor!r}, got {state_auditor!r}"
        )
    fixture_rss_slope(value)
    return value


def parse_fixture_failure(
    stdout: str,
    *,
    status: int,
    process_epoch: int,
    seed: int,
    cycles: int,
) -> AllocatorLivenessError:
    """Decode exit 68 without ever losing its runtime root classification."""

    opaque_root = {
        "process_epoch": process_epoch,
        "process_seed": seed,
        "exit_status": status,
        "structured": False,
        "stdout": stdout,
    }

    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        return AllocatorLivenessError(
            f"exit-68 runtime failure did not emit one structured root: {stdout!r}",
            root_failure=opaque_root,
        )
    if not isinstance(value, dict) or value.get("schema") != FIXTURE_SCHEMA:
        return AllocatorLivenessError(
            "exit-68 runtime root used an unknown fixture schema",
            root_failure=opaque_root,
        )
    if value.get("status") != "failed" or value.get("seed") != seed or value.get("cycles") != cycles:
        return AllocatorLivenessError(
            "exit-68 structured fixture failure identity changed",
            root_failure=opaque_root,
        )
    completed_epochs = value.get("completed_epochs")
    failure = value.get("root_failure")
    state_auditor = value.get("state_auditor")
    if (
        isinstance(completed_epochs, bool)
        or not isinstance(completed_epochs, int)
        or completed_epochs < 0
        or completed_epochs >= cycles
        or not isinstance(failure, dict)
        or not isinstance(state_auditor, dict)
    ):
        return AllocatorLivenessError(
            "exit-68 structured fixture failure shape changed",
            root_failure=opaque_root,
        )
    fixture_epoch = failure.get("epoch")
    fixture_epoch_seed = failure.get("epoch_seed")
    transition_name = failure.get("transition")
    code = failure.get("code")
    subject_index = failure.get("subject_index")
    domain = failure.get("domain")
    if (
        failure.get("exit_status") != status
        or status != 68
        or isinstance(fixture_epoch, bool)
        or not isinstance(fixture_epoch, int)
        or fixture_epoch != completed_epochs + 1
        or isinstance(fixture_epoch_seed, bool)
        or not isinstance(fixture_epoch_seed, int)
        or fixture_epoch_seed < 0
        or not isinstance(transition_name, str)
        or not transition_name
        or domain not in {"allocator_runtime", "thread_runtime", "fixture_invariant"}
        or isinstance(code, bool)
        or not isinstance(code, int)
        or code <= 0
        or (
            subject_index is not None
            and (
                isinstance(subject_index, bool)
                or not isinstance(subject_index, int)
                or subject_index < 0
            )
        )
        or state_auditor.get("status") != "failed"
        or state_auditor.get("scope") != STATE_AUDITOR_SCOPE
        or state_auditor.get("snapshot_count") != completed_epochs
    ):
        return AllocatorLivenessError(
            "exit-68 structured fixture failure fields changed",
            root_failure=opaque_root,
        )
    root_failure = {
        "process_epoch": process_epoch,
        "process_seed": seed,
        "fixture_epoch": fixture_epoch,
        "fixture_epoch_seed": fixture_epoch_seed,
        "completed_fixture_epochs": completed_epochs,
        "name": transition_name,
        "code": code,
        "subject_index": subject_index,
        "exit_status": status,
        "domain": domain,
        "structured": True,
    }
    return AllocatorLivenessError(
        "native churn/RSS smoke ownership transition failed: "
        f"process epoch {process_epoch}, seed {seed}, fixture epoch {fixture_epoch}, "
        f"epoch seed {fixture_epoch_seed}, transition {transition_name}, code {code}, "
        f"subject index {subject_index!r}",
        root_failure=root_failure,
    )


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
    if min(seed, watchdog_seconds, rss_threshold_bytes) <= 0 or cycles < 2 or epochs < 2:
        raise SmokeError(
            "seed, watchdog seconds, and RSS threshold bytes must be positive; "
            "cycles and epochs must each be at least two"
        )
    if seed > UINT64_MAX or seed + epochs - 1 > UINT64_MAX:
        raise SmokeError("process-epoch seed schedule exceeds the fixture's u64 range")
    configuration = report_configuration(
        seed=seed,
        cycles=cycles,
        epochs=epochs,
        watchdog_seconds=watchdog_seconds,
        rss_threshold_bytes=rss_threshold_bytes,
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
        try:
            elf_attestation = fixture_elf_attestation(binary, runtime)
        except EvidenceContractError as error:
            error.selected_shadow_artifact_attestation = dict(attestation)
            error.artifact = {
                "sha256": sha256_file(binary),
                "size_bytes": binary.stat().st_size,
            }
            error.dynamic_dependencies = list(dependencies)
            error.configuration = configuration
            raise
        environment = dict(os.environ)
        for key in ("LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"):
            environment.pop(key, None)
        environment["LD_LIBRARY_PATH"] = str(runtime)
        executions: list[dict[str, Any]] = []
        try:
            for epoch in range(epochs):
                epoch_seed = seed + epoch
                run_command = [str(binary), str(epoch_seed), str(cycles)]
                executed_fixture = require_fixture_elf_unchanged(
                    binary, elf_attestation
                )
                record = command_record(
                    run_command,
                    cwd=ROOT,
                    env=environment,
                    timeout=watchdog_seconds,
                )
                if record.get("timed_out"):
                    raise AllocatorLivenessError(
                        f"native churn/RSS smoke process epoch {epoch + 1}/{epochs} "
                        "exceeded the configured watchdog",
                        root_failure={
                            "process_epoch": epoch + 1,
                            "process_seed": epoch_seed,
                            "name": "watchdog_timeout",
                            "domain": "thread_runtime",
                            "structured": False,
                        },
                        completed_executions=executions,
                    )
                status = record.get("status")
                if status == 68:
                    error = parse_fixture_failure(
                        str(record["stdout"]),
                        status=status,
                        process_epoch=epoch + 1,
                        seed=epoch_seed,
                        cycles=cycles,
                    )
                    error.completed_executions = [dict(execution) for execution in executions]
                    raise error
                if status != 0:
                    raise AllocatorLivenessError(
                        f"native churn/RSS smoke process epoch {epoch + 1}/{epochs} "
                        f"failed with status {status}: stdout={record.get('stdout')!r} "
                        f"stderr={record.get('stderr')!r}",
                        root_failure={
                            "process_epoch": epoch + 1,
                            "process_seed": epoch_seed,
                            "name": "fixture_process_exit",
                            "exit_status": status,
                            "domain": "allocator_runtime",
                            "structured": False,
                        },
                        completed_executions=executions,
                    )
                if record["stderr"]:
                    raise AllocatorLivenessError(
                        f"fixture emitted unexpected stderr at epoch {epoch + 1}/{epochs}: "
                        f"{record['stderr']!r}",
                        root_failure={
                            "process_epoch": epoch + 1,
                            "process_seed": epoch_seed,
                            "name": "unexpected_fixture_stderr",
                            "domain": "fixture_invariant",
                            "structured": False,
                        },
                        completed_executions=executions,
                    )
                fixture_result = parse_fixture_output(
                    str(record["stdout"]), seed=epoch_seed, cycles=cycles
                )
                inner_seeds = fixture_epoch_seeds(epoch_seed, cycles)
                executions.append(
                    {
                        "epoch": epoch + 1,
                        "seed": epoch_seed,
                        "fixture_epoch_count": cycles,
                        "fixture_epoch_seeds": inner_seeds,
                        "executed_fixture_elf": executed_fixture,
                        "thread_fanout": fixture_result["thread_fanout"],
                        "rss_slope": fixture_rss_slope(fixture_result),
                        "fixture": fixture_result,
                        "watchdog": {"seconds": watchdog_seconds, "status": "passed"},
                    }
                )
        except SmokeError as error:
            # The worker lifecycle can fail after all artifact proof has
            # succeeded. Retain that proof in the failed JSON rather than
            # making a liveness failure look like an unselected libc.
            retain_selected_shadow_context(
                error,
                binary=binary,
                dependencies=dependencies,
                attestation=attestation,
                fixture_attestation=elf_attestation,
            )
            error.configuration = configuration
            raise
        observed_rss = high_water(executions)["rss_bytes"]
        if not isinstance(observed_rss, int):
            raise SmokeError("RSS high-water aggregation did not produce an integer")
        if observed_rss > rss_threshold_bytes:
            error = RssThresholdError(
                observed_bytes=observed_rss, threshold_bytes=rss_threshold_bytes
            )
            error.completed_executions = [dict(execution) for execution in executions]
            retain_selected_shadow_context(
                error,
                binary=binary,
                dependencies=dependencies,
                attestation=attestation,
                fixture_attestation=elf_attestation,
            )
            error.configuration = configuration
            raise error
        try:
            require_general_production_state(executions)
        except AllocatorStateEvidenceError as error:
            retain_selected_shadow_context(
                error,
                binary=binary,
                dependencies=dependencies,
                attestation=attestation,
                fixture_attestation=elf_attestation,
            )
            error.configuration = configuration
            raise
        return {
            "artifact": {
                "sha256": sha256_file(binary),
                "size_bytes": binary.stat().st_size,
            },
            "build": {
                "command": build_command,
                "dynamic_dependencies": dependencies,
                "fixture_elf_attestation": elf_attestation,
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
    state_auditors = [result.get("state_auditor") for result in typed_results]
    if not all(isinstance(auditor, dict) for auditor in state_auditors):
        raise SmokeError("fixture state-auditor result shape changed")
    typed_auditors = [auditor for auditor in state_auditors if isinstance(auditor, dict)]
    workload_audits = [auditor.get("workload_liveness") for auditor in typed_auditors]
    if not all(isinstance(audit, dict) for audit in workload_audits):
        raise SmokeError("fixture workload-liveness audit shape changed")
    typed_workload_audits = [audit for audit in workload_audits if isinstance(audit, dict)]
    within_process_slopes = [fixture_rss_slope(result) for result in typed_results]
    high_water_samples = [result["rss_high_water_bytes"] for result in typed_results]
    across_process_slope = exact_slope(
        high_water_samples[0], high_water_samples[-1], len(high_water_samples) - 1
    )
    return {
        "rss_bytes": max(result["rss_high_water_bytes"] for result in typed_results),
        "requested_live_bytes": max(
            result["requested_bytes_live_high_water"] for result in typed_results
        ),
        "usable_live_bytes": max(result["usable_bytes_live_high_water"] for result in typed_results),
        "live_blocks": max(result["live_blocks_high_water"] for result in typed_results),
        "state_auditor": {
            "status": "incomplete",
            "scope": STATE_AUDITOR_SCOPE,
            "workload_liveness": {
                "status": "passed",
                "process_epoch_count": len(typed_results),
                "snapshot_count": sum(
                    audit["snapshot_count"] for audit in typed_workload_audits
                ),
                "post_warm_snapshot_count": sum(
                    audit["post_warm_snapshot_count"] for audit in typed_workload_audits
                ),
                "plateau_after_warmup": all(
                    audit["plateau_after_warmup"] is True
                    for audit in typed_workload_audits
                ),
            },
            "allocator_state": {
                "status": "unavailable",
                "observation": ALLOCATOR_STATE_OBSERVATION,
                "general_production_qualified": False,
            },
        },
        "thread_fanout": {
            **THREAD_FANOUT,
            "total_worker_threads": sum(
                result["thread_fanout"]["worker_threads_created"] for result in typed_results
            ),
        },
        "rss_slopes": {
            "unit": "bytes_per_epoch",
            "within_process_quiescent": {
                "measurements": within_process_slopes,
                "minimum_bytes_per_fixture_epoch": min(
                    slope["bytes_per_epoch"] for slope in within_process_slopes
                ),
                "maximum_bytes_per_fixture_epoch": max(
                    slope["bytes_per_epoch"] for slope in within_process_slopes
                ),
            },
            "across_process_high_water": across_process_slope,
        },
        "allocator_state": unavailable_allocator_state(),
    }


def require_general_production_state(
    executions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Fail closed until every required allocator-internal category is auditable."""

    summary = high_water(executions)
    state_auditor = summary.get("state_auditor")
    if not isinstance(state_auditor, dict):
        raise SmokeError("aggregated state-auditor result changed shape")
    allocator_audit = state_auditor.get("allocator_state")
    if not isinstance(allocator_audit, dict):
        raise SmokeError("aggregated allocator-state result changed shape")
    if allocator_audit.get("general_production_qualified") is not True:
        error = AllocatorStateEvidenceError(
            "general-production churn audit requires registry, ledger, PageMap, "
            "metadata, arena, abandoned-page, TLD, and Theap high-water and "
            "post-warm plateau observations"
        )
        error.high_water = summary
        error.completed_executions = [dict(execution) for execution in executions]
        raise error
    return summary


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


def report_configuration(
    *,
    seed: int,
    cycles: int,
    epochs: int,
    watchdog_seconds: int,
    rss_threshold_bytes: int,
) -> dict[str, Any]:
    """Describe every deterministic seed, epoch, and thread-fanout control."""

    return {
        "seed": seed,
        "process_epoch_seeds": [seed + epoch for epoch in range(epochs)],
        "fixture_epochs_per_process": cycles,
        "fresh_process_epochs": epochs,
        "total_fixture_epochs": cycles * epochs,
        "thread_fanout": {
            **THREAD_FANOUT,
            "total_worker_threads": (
                cycles * epochs * THREAD_FANOUT["worker_threads_per_epoch"]
            ),
        },
        "watchdog_seconds": watchdog_seconds,
        "rss_threshold_bytes": rss_threshold_bytes,
    }


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
    summary = require_general_production_state(executions)
    return {
        "schema": REPORT_SCHEMA,
        "status": "passed",
        "contract": {
            "path": relative(CONTRACT_PATH),
            "sha256": sha256_file(CONTRACT_PATH),
            "fixture_sha256": contract["fixture"]["sha256"],
        },
        "configuration": report_configuration(
            seed=seed,
            cycles=cycles,
            epochs=epochs,
            watchdog_seconds=watchdog_seconds,
            rss_threshold_bytes=rss_threshold_bytes,
        ),
        "qualification": {
            "general_production_workload": "passed",
            "allocator_internal_state": "passed",
            "general_production_churn_audit": "passed",
        },
        "production_shadow_boundary": {
            "allocator_feature": "native-mimalloc-shadow",
            "allocation_apis": contract["production_shadow_boundary"]["allowed_allocation_apis"],
            "allocator_private_hooks": False,
            "c_backend_fallback": False,
            "dynamic_dependencies": run["build"]["dynamic_dependencies"],
            "fixture_elf_attestation": run["build"]["fixture_elf_attestation"],
            "selected_shadow_artifact_attestation": run["build"][
                "selected_shadow_artifact_attestation"
            ],
        },
        "artifact": run["artifact"],
        "executions": executions,
        "high_water": summary,
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

    failure: dict[str, Any] = {
        "kind": "harness",
        "subtype": "contract_or_harness",
        "message": str(error),
    }
    if isinstance(error, AllocatorLivenessError):
        failure["kind"] = "runtime"
        failure["subtype"] = "allocator_liveness"
        if error.root_failure is not None:
            failure["root_failure"] = error.root_failure
    elif isinstance(error, RssThresholdError):
        failure["kind"] = "runtime"
        failure["subtype"] = "rss_threshold"
        failure["rss"] = {
            "observed_high_water_bytes": error.observed_bytes,
            "threshold_bytes": error.threshold_bytes,
        }
    elif isinstance(error, EvidenceContractError):
        failure["kind"] = "evidence"
        failure["subtype"] = "production_boundary"
        failure["boundary"] = error.boundary
    elif isinstance(error, PrerequisiteError):
        failure["kind"] = "prerequisite"
        failure["subtype"] = "owned_native_environment"
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
            "fixture_elf_attestation": getattr(error, "fixture_elf_attestation", None),
            "selected_shadow_artifact_attestation": attestation,
        }
        report["artifact"] = getattr(error, "artifact", None)
    completed_executions = getattr(error, "completed_executions", None)
    if isinstance(completed_executions, list) and completed_executions:
        report["executions"] = completed_executions
    configuration = getattr(error, "configuration", None)
    if isinstance(configuration, dict):
        report["configuration"] = configuration
    observed_high_water = getattr(error, "high_water", None)
    if isinstance(observed_high_water, dict):
        report["high_water"] = observed_high_water
    return report


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the smoke and write a passed or failed machine-readable report."""

    args = parse_arguments(arguments)
    report_path = args.report.expanduser().resolve()
    configuration: dict[str, Any] | None = None
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
        if (
            seed > 0
            and cycles >= 2
            and epochs >= 2
            and watchdog_seconds > 0
            and rss_threshold_bytes > 0
            and seed <= UINT64_MAX
            and seed + epochs - 1 <= UINT64_MAX
        ):
            configuration = report_configuration(
                seed=seed,
                cycles=cycles,
                epochs=epochs,
                watchdog_seconds=watchdog_seconds,
                rss_threshold_bytes=rss_threshold_bytes,
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
        if configuration is not None and not isinstance(
            getattr(error, "configuration", None), dict
        ):
            error.configuration = configuration
        report = failure_report(error)
        atomic_write_json(report_path, report)
        print(f"native-churn-rss-smoke: {error}", file=sys.stderr)
        return 1
    atomic_write_json(report_path, report)
    print(json.dumps({"report": str(report_path), "status": "passed"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
