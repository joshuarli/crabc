#!/usr/bin/env python3
"""Bounded native x86-64 M2 VM-primitives evidence producer.

This module owns neither milestone aggregation nor source-map promotion.  It
checks the target-local fragment's complete source-policy matrix, compiles a
fresh direct-include C oracle from the pinned archive, and compares its fixed
regular-VM lifecycle record with one already-built Rust exact test.  The
fragment deliberately remains partial: passing this producer is evidence for
the fixed no-option owner slice, not a claim for huge pages, hints, THP policy,
or allocator lifecycle integration.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_suffix(".c")
SCHEMA = "crabc-mimalloc-x86_64-m2-component-evidence"
TRACE_BEGIN = "CRABC_MI_M2_VM_TRACE_BEGIN"
TRACE_END = "CRABC_MI_M2_VM_TRACE_END"
EXPECTED_RUST_TEST_COUNT = 1

CHECKS = (
    (
        "native-vm-fixed-lifecycle-differential",
        "c-rust-vm-primitives-fixed-lifecycle",
        "os::tests::emit_m2_vm_primitives_c_rust_trace",
    ),
    (
        "aligned-map-direct-cleanup-owner",
        "rust-unit",
        "os::tests::aligned_mapping_retains_the_direct_candidate_when_its_cleanup_fails",
    ),
    (
        "aligned-map-prefix-cleanup-owner",
        "rust-unit",
        "os::tests::aligned_mapping_retains_the_untrimmed_overmap_when_prefix_release_fails",
    ),
    (
        "aligned-map-suffix-cleanup-owner",
        "rust-unit",
        "os::tests::aligned_mapping_retains_only_the_live_suffix_when_suffix_release_fails",
    ),
    (
        "aligned-map-complete-trim-sequence",
        "rust-unit",
        "os::tests::forced_aligned_mapping_exercises_all_three_release_edges_before_returning_the_exact_range",
    ),
    (
        "reset-advice-retry-snapshot",
        "rust-unit",
        "os::tests::reset_retries_the_initial_advice_after_a_concurrent_global_fallback",
    ),
    (
        "aligned-map-os-page-claim-owner",
        "rust-unit",
        "os_page::tests::aligned_map_prefix_cleanup_failure_transfers_the_live_claim_owner",
    ),
    (
        "aligned-map-metadata-owner",
        "rust-unit",
        "meta::tests::aligned_map_prefix_cleanup_failure_retains_metadata_before_private_backing_publication",
    ),
    (
        "aligned-map-process-arena-owner",
        "rust-unit",
        "process_arena::tests::explicit_os_reservation_retains_an_aligned_map_cleanup_failure_before_setup",
    ),
    (
        "normal-os-offset-full-provenance-and-release-retry",
        "rust-unit",
        "os::tests::normal_offset_os_allocation_retains_full_provenance_and_retries_release",
    ),
    (
        "normal-os-good-size-and-base-provenance",
        "rust-unit",
        "os::tests::normal_os_allocation_uses_good_size_and_base_provenance",
    ),
    (
        "normal-os-offset-zero-delegation-and-geometry",
        "rust-unit",
        "os::tests::normal_offset_os_allocation_delegates_zero_and_rejects_invalid_geometry",
    ),
    (
        "normal-os-aligned-failure-owner",
        "rust-unit",
        "os::tests::normal_os_allocation_preserves_a_failed_aligned_map_owner",
    ),
    (
        "normal-os-source-reservation-caller",
        "rust-unit",
        "process_arena::tests::explicit_os_reservation_publishes_one_os_arena_for_reserved_and_committed_requests",
    ),
    (
        "linux-os-reuse-contained-range-noop",
        "rust-unit",
        "os::tests::reuse_is_a_contained_range_noop_on_linux",
    ),
    (
        "fixed-no-option-numa-cache-and-current-node-normalization",
        "rust-unit",
        "os::tests::os_numa_wrapper_caches_and_normalizes_the_raw_primitives",
    ),
    (
        "native-protection-owner-and-retry",
        "rust-unit",
        "os::tests::native_protection_failures_preserve_mapping_owner_and_retry",
    ),
)
CHECK_IDS = tuple(check[0] for check in CHECKS)
TRACE_CHECK_ID = CHECKS[0][0]
TRACE_TARGET = CHECKS[0][2]

TRACE_KEYS = (
    "m2.vm.config.page_size",
    "m2.vm.config.large_page_size",
    "m2.vm.config.alloc_granularity",
    "m2.vm.config.has_overcommit",
    "m2.vm.config.has_partial_free",
    "m2.vm.config.has_virtual_reserve",
    "m2.vm.config.has_transparent_huge_pages",
    "m2.vm.reserved.initially_zero",
    "m2.vm.reserved.initially_committed",
    "m2.vm.reserved.commit_not_known_zero",
    "m2.vm.reserved.decommit_no_recommit",
    "m2.vm.reserved.reset_success",
    "m2.vm.reserved.reuse_linux_noop",
    "m2.vm.reserved.protect_success",
    "m2.vm.reserved.unprotect_success",
    "m2.vm.reserved.release_success",
    "m2.vm.normal.client_is_base",
    "m2.vm.normal.good_size",
    "m2.vm.normal.memid_base_and_size",
    "m2.vm.normal.initially_committed",
    "m2.vm.normal.initially_zero",
    "m2.vm.normal.release_success",
    "m2.vm.aligned.alignment",
    "m2.vm.aligned.client_is_aligned",
    "m2.vm.aligned.good_size",
    "m2.vm.aligned.memid_base_and_size",
    "m2.vm.aligned.release_success",
    "m2.vm.offset.client_offset_nonzero",
    "m2.vm.offset.client_plus_offset_is_aligned",
    "m2.vm.offset.good_size",
    "m2.vm.offset.memid_base_and_size",
    "m2.vm.offset.release_full_mapping_success",
    "m2.vm.numa.count_at_least_one",
    "m2.vm.numa.current_lt_count",
)
TRACE_TRUE_KEYS = frozenset(TRACE_KEYS).difference(
    {
        "m2.vm.config.page_size",
        "m2.vm.config.large_page_size",
        "m2.vm.config.alloc_granularity",
        "m2.vm.config.has_overcommit",
        "m2.vm.config.has_partial_free",
        "m2.vm.config.has_virtual_reserve",
        "m2.vm.config.has_transparent_huge_pages",
        "m2.vm.reserved.initially_committed",
        "m2.vm.normal.good_size",
        "m2.vm.aligned.alignment",
        "m2.vm.aligned.good_size",
        "m2.vm.offset.good_size",
    }
)
TRACE_FALSE_KEYS = frozenset({"m2.vm.reserved.initially_committed"})

BRANCH_IDS = (
    "unix-platform-primitive-dispatch",
    "os-configuration-and-good-size",
    "unix-configuration-and-thp-process-policy",
    "os-free-and-statistics-events",
    "os-primitive-regular-and-aligned-allocation",
    "os-normal-aligned-and-offset-allocation",
    "os-range-transition-policy-and-failure-owners",
    "aligned-hint-random-state",
    "unix-regular-map-large-page-and-thp-routing",
    "unix-free-primitive",
    "unix-commit-decommit-reset-reuse-and-protect",
    "huge-page-and-numa-placement",
    "primitive-interface-declaration-frontier",
)
SOURCE_UNITS = (
    "include/mimalloc/prim.h",
    "src/os.c",
    "src/prim/prim.c",
    "src/prim/unix/prim.c",
)


def _error(message: str) -> ValueError:
    return ValueError(f"native x86 M2 VM fragment {message}")


def _require_string_list(value: object, description: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise _error(f"{description} must be a list of nonempty strings")
    if not allow_empty and not value:
        raise _error(f"{description} must not be empty")
    if len(set(value)) != len(value):
        raise _error(f"{description} contains duplicate values")
    return list(value)


def load_fragment(path: Path) -> dict[str, Any]:
    """Load and validate the immutable component fragment before execution."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise _error(f"cannot read {path}: {error}") from error
    if not isinstance(raw, dict):
        raise _error("root must be an object")
    if set(raw) != {"component", "format", "schema", "target", "upstream"}:
        raise _error("root keys changed")
    if raw.get("format") != 1 or raw.get("schema") != SCHEMA:
        raise _error("schema identity changed")
    upstream = raw.get("upstream")
    if not isinstance(upstream, dict) or set(upstream) != {
        "archive_sha256", "revision", "version"
    }:
        raise _error("upstream identity changed")
    if upstream.get("version") != "3.5.0":
        raise _error("upstream version changed")
    target = raw.get("target")
    if not isinstance(target, dict) or target != {
        "architecture": "x86_64",
        "endianness": "little",
        "kernel_baseline": "5.10",
        "os": "linux",
        "rust_target": "x86_64-unknown-linux-musl",
    }:
        raise _error("target changed")
    component = raw.get("component")
    if not isinstance(component, dict) or set(component) != {
        "bounded_source_definitions",
        "branch_matrix",
        "checks",
        "completion_status",
        "id",
        "remaining_conditions",
        "source_map_records",
        "source_units",
        "unqualified_failure_matrix",
    }:
        raise _error("component keys changed")
    if component.get("id") != "vm-primitives" or component.get("completion_status") != "partial":
        raise _error("must remain the partial vm-primitives component")
    if component.get("source_units") != list(SOURCE_UNITS):
        raise _error("source units changed")
    remaining = _require_string_list(
        component.get("remaining_conditions"), "remaining conditions", allow_empty=False
    )
    if not any("huge" in condition.lower() for condition in remaining):
        raise _error("remaining conditions lost the huge-page frontier")
    if not any("hint" in condition.lower() for condition in remaining):
        raise _error("remaining conditions lost the aligned-hint frontier")
    if not any("numa" in condition.lower() for condition in remaining):
        raise _error("remaining conditions lost the NUMA frontier")
    if not any("failure" in condition.lower() for condition in remaining):
        raise _error("remaining conditions lost failure ownership")

    source_map = component.get("source_map_records")
    expected_source_map = [
        {"unit_id": "os-allocation-policy", "required_status": "partial"},
        {"unit_id": "linux-unix-primitives", "required_status": "partial"},
        {"unit_id": "primitive-interface", "required_status": "partial"},
    ]
    if source_map != expected_source_map:
        raise _error("source-map boundary changed")

    raw_checks = component.get("checks")
    if not isinstance(raw_checks, list) or len(raw_checks) != len(CHECKS):
        raise _error("check inventory changed")
    expected_checks = [
        {
            "id": check_id,
            "kind": kind,
            "target": target_name,
            "expected_passed_test_count": 1,
        }
        for check_id, kind, target_name in CHECKS
    ]
    if raw_checks != expected_checks:
        raise _error("check inventory or exact test target changed")

    definitions = component.get("bounded_source_definitions")
    if not isinstance(definitions, list) or not definitions:
        raise _error("bounded source definitions are absent")
    definition_ids: set[str] = set()
    for definition in definitions:
        if not isinstance(definition, dict) or set(definition) != {
            "evidence_check_ids", "id", "required_definitions", "source_anchor"
        }:
            raise _error("bounded source definition shape changed")
        definition_id = definition.get("id")
        if not isinstance(definition_id, str) or not definition_id or definition_id in definition_ids:
            raise _error("bounded source definition identity changed")
        definition_ids.add(definition_id)
        _require_string_list(
            definition.get("required_definitions"),
            f"bounded source definition {definition_id} required definitions",
            allow_empty=False,
        )
        evidence_ids = _require_string_list(
            definition.get("evidence_check_ids"),
            f"bounded source definition {definition_id} evidence checks",
            allow_empty=False,
        )
        if any(check_id not in CHECK_IDS for check_id in evidence_ids):
            raise _error(f"bounded source definition {definition_id} has an unknown evidence check")
        _validate_anchor(definition.get("source_anchor"), f"bounded source definition {definition_id}")

    branches = component.get("branch_matrix")
    if not isinstance(branches, list) or [branch.get("id") if isinstance(branch, dict) else None for branch in branches] != list(BRANCH_IDS):
        raise _error("branch matrix identity or order changed")
    branch_anchor_keys: set[tuple[str, int, int]] = set()
    for branch in branches:
        if not isinstance(branch, dict) or set(branch) != {
            "disposition", "evidence_check_ids", "id", "missing_conditions", "source_anchors", "source_scope"
        }:
            raise _error("branch matrix entry shape changed")
        disposition = branch.get("disposition")
        if disposition not in {"qualified-fixed-profile", "partial-fixed-profile", "unqualified"}:
            raise _error(f"branch {branch['id']} has an invalid disposition")
        if not isinstance(branch.get("source_scope"), str) or not branch["source_scope"]:
            raise _error(f"branch {branch['id']} source scope is invalid")
        evidence_ids = _require_string_list(
            branch.get("evidence_check_ids"), f"branch {branch['id']} evidence checks", allow_empty=True
        )
        if any(check_id not in CHECK_IDS for check_id in evidence_ids):
            raise _error(f"branch {branch['id']} has an unknown evidence check")
        missing_conditions = _require_string_list(
            branch.get("missing_conditions"), f"branch {branch['id']} missing conditions", allow_empty=True
        )
        if disposition == "qualified-fixed-profile":
            if not evidence_ids or missing_conditions:
                raise _error(f"qualified branch {branch['id']} has incomplete evidence accounting")
        elif not missing_conditions:
            raise _error(f"open branch {branch['id']} lost its exact missing condition")
        if disposition == "unqualified" and evidence_ids:
            raise _error(f"unqualified branch {branch['id']} borrows evidence it does not execute")
        anchors = branch.get("source_anchors")
        if not isinstance(anchors, list) or not anchors:
            raise _error(f"branch {branch['id']} source anchors are absent")
        for anchor in anchors:
            validated = _validate_anchor(anchor, f"branch {branch['id']}")
            key = (validated["member"], validated["start_line"], validated["end_line"])
            if key in branch_anchor_keys:
                raise _error(f"branch {branch['id']} repeats a source anchor")
            branch_anchor_keys.add(key)

    unqualified = component.get("unqualified_failure_matrix")
    if not isinstance(unqualified, list) or not unqualified:
        raise _error("unqualified failure matrix is absent")
    for entry in unqualified:
        if not isinstance(entry, dict) or set(entry) != {"id", "required_evidence", "source_scope"}:
            raise _error("unqualified failure matrix entry changed")
        if not isinstance(entry["id"], str) or not entry["id"] or not isinstance(entry["source_scope"], str):
            raise _error("unqualified failure matrix identity changed")
        _require_string_list(entry["required_evidence"], "unqualified failure evidence", allow_empty=False)
    return raw


def _validate_anchor(value: object, description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"end_line", "member", "sha256", "start_line"}:
        raise _error(f"{description} source anchor changed")
    member = value.get("member")
    start = value.get("start_line")
    end = value.get("end_line")
    digest = value.get("sha256")
    if (
        not isinstance(member, str)
        or member not in SOURCE_UNITS
        or type(start) is not int
        or type(end) is not int
        or start < 1
        or end < start
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise _error(f"{description} source anchor is invalid")
    return dict(value)


def validate_source_anchor_matrix(fragment: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    """Hash every branch anchor, including known-unqualified policy paths."""

    component = fragment["component"]
    raw_anchors = [
        definition["source_anchor"] for definition in component["bounded_source_definitions"]
    ]
    raw_anchors.extend(
        anchor for branch in component["branch_matrix"] for anchor in branch["source_anchors"]
    )
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    for raw_anchor in raw_anchors:
        anchor = _validate_anchor(raw_anchor, "source matrix")
        identity = (anchor["member"], anchor["start_line"], anchor["end_line"])
        if identity in seen:
            continue
        seen.add(identity)
        path = source / anchor["member"]
        try:
            lines = path.read_bytes().splitlines(keepends=True)
        except OSError as error:
            raise _error(f"cannot read pinned source anchor {anchor['member']}: {error}") from error
        if anchor["end_line"] > len(lines):
            raise _error(f"source anchor exceeds pinned source: {anchor['member']}")
        payload = b"".join(lines[anchor["start_line"] - 1 : anchor["end_line"]])
        actual = hashlib.sha256(payload).hexdigest()
        if actual != anchor["sha256"]:
            raise _error(
                "source anchor digest changed: "
                f"{anchor['member']}:{anchor['start_line']}-{anchor['end_line']}"
            )
        records.append(
            {
                "bytes": len(payload),
                "end_line": anchor["end_line"],
                "member": anchor["member"],
                "sha256": actual,
                "start_line": anchor["start_line"],
            }
        )
    return records


def parse_trace(output: str, *, source: str) -> dict[str, int]:
    """Parse and validate the finite, address-free VM lifecycle record."""

    if output.count(TRACE_BEGIN) != 1 or output.count(TRACE_END) != 1:
        raise ValueError(f"{source} M2 VM trace did not emit exactly one marker pair")
    start = output.index(TRACE_BEGIN) + len(TRACE_BEGIN)
    end = output.index(TRACE_END)
    if end <= start:
        raise ValueError(f"{source} M2 VM trace markers are reversed")
    values: dict[str, int] = {}
    for line in output[start:end].strip().splitlines():
        if line.count("=") != 1:
            raise ValueError(f"{source} M2 VM trace has a malformed observation")
        key, raw_value = line.split("=", 1)
        if key in values or key not in TRACE_KEYS or not raw_value.isascii() or not raw_value.isdecimal():
            raise ValueError(f"{source} M2 VM trace has an invalid observation: {line}")
        values[key] = int(raw_value)
    missing = sorted(set(TRACE_KEYS).difference(values))
    unexpected = sorted(set(values).difference(TRACE_KEYS))
    if missing or unexpected:
        raise ValueError(
            f"{source} M2 VM trace schema changed: missing {missing}; unexpected {unexpected}"
        )
    _validate_trace_values(values, source=source)
    return values


def _validate_trace_values(trace: Mapping[str, int], *, source: str) -> None:
    page = trace["m2.vm.config.page_size"]
    large = trace["m2.vm.config.large_page_size"]
    granularity = trace["m2.vm.config.alloc_granularity"]
    if page == 0 or page & (page - 1) or large < page or large % page or granularity != page:
        raise ValueError(f"{source} M2 VM trace has invalid configuration geometry")
    for key in (
        "m2.vm.config.has_overcommit",
        "m2.vm.config.has_partial_free",
        "m2.vm.config.has_virtual_reserve",
        "m2.vm.config.has_transparent_huge_pages",
    ):
        if trace[key] not in {0, 1}:
            raise ValueError(f"{source} M2 VM trace has a nonboolean configuration field: {key}")
    if trace["m2.vm.aligned.alignment"] < page or (
        trace["m2.vm.aligned.alignment"] & (trace["m2.vm.aligned.alignment"] - 1)
    ):
        raise ValueError(f"{source} M2 VM trace has invalid aligned-map geometry")
    for key in TRACE_TRUE_KEYS:
        if trace[key] != 1:
            raise ValueError(f"{source} M2 VM trace has an unmet lifecycle relation: {key}")
    for key in TRACE_FALSE_KEYS:
        if trace[key] != 0:
            raise ValueError(f"{source} M2 VM trace has an invalid initial reservation relation: {key}")
    for key in (
        "m2.vm.normal.good_size",
        "m2.vm.aligned.good_size",
        "m2.vm.offset.good_size",
    ):
        if trace[key] == 0 or trace[key] % page:
            raise ValueError(f"{source} M2 VM trace has invalid allocation extent: {key}")


def _compare(c_trace: Mapping[str, int], rust_trace: Mapping[str, int], harness: Any) -> dict[str, Any]:
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise harness.HarnessError("native x86 M2 VM lifecycle differs from pinned C: " + "; ".join(mismatches))
    return {"compared_value_count": len(TRACE_KEYS), "status": "matched"}


def _trace_check(fragment: Mapping[str, Any], test_program: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(test_program, Mapping) or not isinstance(test_program.get("path"), Path):
        raise _error("aggregate did not supply its prepared native Rust test program")
    check = next(
        check for check in fragment["component"]["checks"] if check["id"] == TRACE_CHECK_ID
    )
    if check["target"] != TRACE_TARGET or check["expected_passed_test_count"] != EXPECTED_RUST_TEST_COUNT:
        raise _error("fixed lifecycle trace check changed")
    return check


def run_evidence(
    harness: Any,
    *,
    offline: bool,
    test_program: Mapping[str, Any],
    contract_fragment: Path,
) -> dict[str, Any]:
    """Run the bounded native VM C/Rust differential from the aggregate gate.

    The aggregate passes a single already-built no-default-feature native test
    binary.  This producer never substitutes a local Cargo rebuild: that keeps
    the M2 gate's exact-test accounting batched and its artifact identity clear.
    """

    harness.require_native_x86_64()
    fragment = load_fragment(contract_fragment)
    check = _trace_check(fragment, test_program)
    pin = harness.load_pin()
    upstream = fragment["upstream"]
    if upstream["revision"] != pin["revision"] or upstream["archive_sha256"] != pin["sha256"]:
        raise harness.HarnessError("native x86 M2 VM fragment pin differs from the allocator pin")
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-vm-primitives"
    artifacts.mkdir(parents=True, exist_ok=True)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-vm-source-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        source_anchors = validate_source_anchor_matrix(fragment, source)
        binary = artifacts / "m2-vm-primitives-oracle"
        command = [
            compiler,
            "-std=c11",
            "-fPIC",
            "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB",
            "-DMI_SHARED_LIB_EXPORT",
            "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I",
            str(source / "include"),
            "-I",
            str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE),
            *(str(source / item) for item in harness.M1_RAW_PRIMITIVE_ORACLE_SOURCES),
            "-pthread",
            "-o",
            str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C native x86 M2 VM oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=180)
        harness.require_success(c_run, "pinned C native x86 M2 VM oracle")
        c_trace = parse_trace(str(c_run["stdout"]), source="pinned C")
        source_files = harness.source_file_records(source, SOURCE_UNITS)

    rust, rust_output = harness._x86_64_run_exact_program_check(
        test_program,
        check,
        nocapture=True,
        gate_name="native x86 M2 VM",
    )
    rust_command = rust["command"]
    rust_count = rust["passed_test_count"]
    rust_trace = parse_trace(rust_output, source="Rust")
    comparison = _compare(c_trace, rust_trace, harness)
    trace_payload = json.dumps(c_trace, separators=(",", ":"), sort_keys=True).encode("utf-8")
    report = {
        "architecture": "x86_64",
        "c_command": command,
        "c_source_files": source_files,
        "compared_value_count": comparison["compared_value_count"],
        "comparison": comparison,
        "fixture": harness.artifact_record(FIXTURE),
        "format": 1,
        "profile": "release-no-default-features-fixed-regular-vm",
        "rust_build_command": list(test_program.get("build_command", [])),
        "rust_command": rust_command,
        "rust_passed_test_count": rust_count,
        "schema": "crabc-mimalloc-x86_64-m2-vm-primitives-evidence",
        "source_anchors": source_anchors,
        "status": "passed",
        "trace_sha256": hashlib.sha256(trace_payload).hexdigest(),
        "upstream": {"archive_sha256": pin["sha256"], "revision": pin["revision"]},
        "nonclaims": list(fragment["component"]["remaining_conditions"]),
    }
    evidence_path = artifacts / "evidence.json"
    harness.write_json(evidence_path, report)
    evidence_path.chmod(0o644)
    return report
