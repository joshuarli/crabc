#!/usr/bin/env python3
"""Closed native x86-64 admission inventory for allocator OS fault seams.

This is deliberately a reader for one fixed source-bound receipt, not a
second fault injector.  ``m2_vm_x86_64.c`` keeps the C bodies direct-included
and ``os::tests::emit_m2_fault_seam_inventory_c_rust_trace`` keeps Rust
injection behind its existing test-only ``FaultPlan``.  This module names the
complete set of source groups the receipt must account for, including the two
receivers that current authority deliberately stops.  A passing receipt is
therefore bounded evidence for selected OS paths; it does not complete M2.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence


SCHEMA = "crabc-mimalloc-x86_64-fault-seam-inventory-evidence"
FORMAT = 1
ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_vm_x86_64.c"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/fault-seam-inventory.json"
FAULT_PROFILE_DEFINE = "-DCRABC_M2_FAULT_SEAM_INVENTORY_PROFILE=1"
HUGE_RETRY_HELPER_TEST_DEFINE = "-DCRABC_M2_FAULT_SEAM_RETRY_HELPER_TEST=1"
MBIND_BOUNDARY_TEST_DEFINE = "-DCRABC_M2_FAULT_SEAM_MBIND_BOUNDARY_TEST=1"
HUGE_RETRY_HELPER_SCHEMA = "crabc-mimalloc-x86_64-fault-seam-retry-helper-regression"
MBIND_BOUNDARY_SCHEMA = "crabc-mimalloc-x86_64-fault-seam-mbind-boundary-regression"
C_TRACE_BEGIN = "CRABC_MI_M2_FAULT_SEAM_INVENTORY_C_TRACE_BEGIN"
C_TRACE_END = "CRABC_MI_M2_FAULT_SEAM_INVENTORY_C_TRACE_END"
RUST_TRACE_BEGIN = "CRABC_MI_M2_FAULT_SEAM_INVENTORY_RUST_TRACE_BEGIN"
RUST_TRACE_END = "CRABC_MI_M2_FAULT_SEAM_INVENTORY_RUST_TRACE_END"
C_TRACE_KEYS = (
    "m2.fault.c.huge.partial_primitive_failure_retains_one_os_huge_owner_and_stats",
    "m2.fault.c.huge.timeout_after_progress_retains_one_os_huge_owner_and_stats",
    "m2.fault.c.huge.noncontiguous_adjustment_rejects_owner_after_source_cleanup",
    "m2.fault.c.huge.placement_failure_is_best_effort_and_retains_one_os_huge_owner",
    "m2.fault.c.huge.free_continues_after_failed_page_and_applies_source_stats",
)
RUST_TRACE_KEYS = (
    "m2.fault.rust.huge.partial_primitive_failure_retains_one_os_huge_owner_and_stats",
    "m2.fault.rust.huge.timeout_after_progress_retains_one_os_huge_owner_and_stats",
    "m2.fault.rust.huge.noncontiguous_adjustment_retains_rejected_cleanup_owner",
    "m2.fault.rust.huge.placement_failure_is_best_effort_and_retains_mapping_owner",
    "m2.fault.rust.huge.free_continues_after_failed_page_and_records_retry_bits",
)
RUST_TARGET = "os::tests::emit_m2_fault_seam_inventory_c_rust_trace"
SOURCE_UNITS = (
    "include/mimalloc/prim.h",
    "src/arena.c",
    "src/init.c",
    "src/os.c",
    "src/page.c",
    "src/prim/prim.c",
    "src/prim/unix/prim.c",
)

PINNED_C_SOURCE_FILES = (
    {"path": "include/mimalloc/prim.h", "bytes": 6403, "sha256": "1987e8e2eedc07bb181bf2a11a27bec80a5309c32cfa66a56900fb4cbb64b172"},
    {"path": "src/arena.c", "bytes": 115645, "sha256": "5d9aa2dc06fa6e942d6a46eb4748b0c10c81f96c2ed50042412a9e66fd6f4d7a"},
    {"path": "src/init.c", "bytes": 25096, "sha256": "e22486042ba132e002822315ccd4b24738fc3a151fc14172e5e45426e8add299"},
    {"path": "src/os.c", "bytes": 39093, "sha256": "8410b04c2d5b37e59fff1854364fed1fba873133b064cfe02083277038388548"},
    {"path": "src/page.c", "bytes": 44473, "sha256": "f7b1c3c0725b425516e22cf49d3ff7e03b708732fdba4bd1f4c759484d52593c"},
    {"path": "src/prim/prim.c", "bytes": 2449, "sha256": "241b1087a0e22609de71b2deba6c771135dd37e756ea89ba79b5900165b4f229"},
    {"path": "src/prim/unix/prim.c", "bytes": 36822, "sha256": "8efeac14a9952aa7c3117ce2d9d801f93692bda6cd80e09a51ddca398d7ac774"},
)
MBIND_PROFILE_SOURCE_UNITS = (
    "src/prim/prim.c",
    "src/prim/unix/prim.c",
)
MBIND_PROFILE_ORIGINAL_EXPRESSION = (
    "return syscall(SYS_mbind, start, len, mode, nmask, maxnode, flags);"
)
MBIND_PROFILE_REPLACEMENT_EXPRESSION = (
    "return m2_fault_inventory_mbind_syscall(start, len, mode, nmask, maxnode, flags);"
)
MBIND_PROFILE_SINGLE_REPLACEMENT = {
    "source_member": "src/prim/unix/prim.c",
    "source_expression": MBIND_PROFILE_ORIGINAL_EXPRESSION,
    "replacement_expression": MBIND_PROFILE_REPLACEMENT_EXPRESSION,
    "match_count": 1,
}
MBIND_PROFILE_DERIVED_FILES = (
    {
        "path": "prim.c",
        "bytes": 2449,
        "sha256": "241b1087a0e22609de71b2deba6c771135dd37e756ea89ba79b5900165b4f229",
    },
    {
        "path": "unix/prim.c",
        "bytes": 36836,
        "sha256": "7748ea6e69890f2b8e7f81fa9411ae19c4862f2fc7ad1d87d63df5d39e41fa00",
    },
)
DIRECT_FIXTURE_SOURCE_UNITS = (
    "src/os.c", "src/arena.c", "src/init.c", "src/page.c", "src/prim/prim.c",
)
RESOLVED_DIRECT_PRIMITIVE = "src/prim/unix/prim.c"
RUST_TRACE_SOURCE = "crabc-mimalloc/src/os.rs"
DIAGNOSTIC_OWNER_BOUNDARY = {
    "c_output_registration": "src/options.c:415-433 mi_out_get_default/mi_register_output",
    "c_warning_emission": "src/options.c:540-550 _mi_warning_message",
    "initialization_order": "src/init.c:537-548 mi_process_init_once/_mi_options_init",
    "rust_source_map_unit": "option-processing",
    "rust_source_map_status": "not-started",
    "rust_owner": None,
}
FRAGMENT_PATH = ROOT / "compat/allocator/m2-fault-seam-inventory-x86_64-v3.5.0.fragment.json"
FAULT_COMPONENT_CHECK_ID = "source-indexed-fault-seam-inventory"
FAULT_COMPONENT_SOURCE_MAP_RECORDS = [
    {"unit_id": "page-map-lifecycle", "required_status": "partial"},
    {"unit_id": "os-allocation-policy", "required_status": "partial"},
]
FAULT_COMPONENT_SOURCE_UNITS = [
    "src/os.c", "src/page-map.c", "src/prim/unix/prim.c", "src/options.c",
]
FAULT_COMPONENT_UNQUALIFIED_IDS = (
    "stopped-metadata-and-os-aligned-publication",
    "unmapped-rust-output-owner",
    "remaining-ambient-and-hardware-fault-receivers",
)
SOURCE_ANCHORS = (
    {"member": "src/os.c", "start_line": 240, "end_line": 294, "sha256": "b90d71dbe1a3bdee02095502ca799cdea2cd4c1f42983b6117d932c47b931c02"},
    {"member": "src/os.c", "start_line": 303, "end_line": 430, "sha256": "e5ba5306a96cc2ccc54041ef1b7158b93cf6ae6db10e2d4bcecbc62741e6225b"},
    {"member": "src/os.c", "start_line": 438, "end_line": 527, "sha256": "fc4e177b6d6c35be7372e641d8d0209f03cdc84f2f87099dfcf1a00eb0ad1b89"},
    {"member": "src/os.c", "start_line": 534, "end_line": 712, "sha256": "dc9c44664aa3348206cdfe456b3a1eff19ffed26192d64ad314baf0b4d014feb"},
    {"member": "src/os.c", "start_line": 771, "end_line": 841, "sha256": "7b83053ca4b7d273cb420e60ab993b9bc54d933f87774485caf86ec877024b70"},
    {"member": "src/page-map.c", "start_line": 214, "end_line": 515, "sha256": "b0218dd17e7a38ed3018fcb3f2941f5421fd72afb05c02023ce49bf21734edd3"},
)
SOURCE_REQUIRED_DEFINITIONS = (
    ("void mi_os_prim_free", "void _mi_os_free_ex", "void _mi_os_free"),
    ("static int mi_os_prim_alloc_at", "static int mi_os_prim_alloc_aligned"),
    ("void* _mi_os_alloc", "void* _mi_os_alloc_aligned_at_offset"),
    ("int _mi_os_commit_ex", "bool _mi_os_decommit", "bool _mi_os_purge_ex", "bool _mi_os_protect"),
    ("void* _mi_os_alloc_huge_os_pages", "static void mi_os_free_huge_os_pages"),
    ("static bool mi_page_map_init_once", "bool _mi_page_map_register"),
)
BRANCH_OPEN_CONDITION = "The named source relation is bounded; it does not promote an unselected receiver."
FAULT_COMPONENT_UNQUALIFIED_MATRIX = [
    {
        "id": "stopped-metadata-and-os-aligned-publication",
        "source_scope": "PageMetadataMapping/meta and OsAlignedPage claim-to-publication receivers.",
        "required_evidence": [
            "lifted metadata/OsAligned-publication authority boundary",
            "native typed publication and rollback owner matrix",
        ],
    },
    {
        "id": "unmapped-rust-output-owner",
        "source_scope": "src/options.c:415-433 mi_register_output and 540-550 _mi_warning_message after src/init.c:537-548 option initialization.",
        "required_evidence": [
            "Rust allocator output registration owner",
            "source-faithful warning delivery/ordering evidence",
        ],
    },
    {
        "id": "remaining-ambient-and-hardware-fault-receivers",
        "source_scope": "Ambient option/detection, hardware huge-page success, physical NUMA placement, generic callbacks/statistics, and unselected OS/PageMap callers.",
        "required_evidence": [
            "typed owner-specific fault rows",
            "native current-source receiver evidence",
        ],
    },
]
FAULT_COMPONENT_REMAINING_CONDITIONS = [
    "Metadata-map publication and OsAligned claim-to-publication receivers remain stopped and unadmitted.",
    "The C output callback warning is bounded, but Rust output registration/delivery remains the not-started option-processing source-map prerequisite.",
    "Ambient hardware huge-page success, physical NUMA placement, unselected callers, and general callback/statistics owners remain unqualified.",
    "The fault-injection component and M2 remain partial.",
]


@dataclass(frozen=True)
class SourceRow:
    """One closed source family and its current Rust receiver boundary."""

    identifier: str
    c_anchor: str
    rust_receivers: tuple[str, ...]
    required_branch_ids: tuple[str, ...]


@dataclass(frozen=True)
class BranchRow:
    """One admissible source branch with its fixed injected observation."""

    identifier: str
    source_row: str
    c_branch: str
    rust_receiver: str
    point: str
    ordinal: int
    errno: str
    owner_statistics: str
    outcome: str


@dataclass(frozen=True)
class StoppedReceiver:
    """A named route that the current receipt must retain but cannot admit."""

    identifier: str
    reason: str


# Keep these six source groups in source order.  The branch rows below are
# deliberately more granular: one anchor must not turn an unrelated source
# receiver into an admitted fault result merely because it shares os.c.
SOURCE_ROWS = (
    SourceRow(
        "os-full-release-owner",
        "src/os.c:240-294",
        ("os.rs:2766-2889 unmap and partial-release owners",),
        ("full-release-unmap-failure-retry", "huge-free-continues-after-failure"),
    ),
    SourceRow(
        "os-regular-aligned-map-and-cleanup",
        "src/os.c:303-430",
        ("os.rs:1849-2009 map_for_process/map_aligned_for_process",),
        ("regular-map-commit-failure", "aligned-cleanup-retained-owner"),
    ),
    SourceRow(
        "os-normal-offset-allocation-owner",
        "src/os.c:438-527",
        ("os.rs NormalOsAllocation paths",),
        ("normal-offset-full-owner",),
    ),
    SourceRow(
        "os-range-transition-fault-owners",
        "src/os.c:534-712",
        ("os.rs:656-675, 1645-1668, 2518-2652, 2905-2912",),
        (
            "commit-failure-owner-retry",
            "decommit-failure-owner-retry",
            "purge-reset-fallback-owner",
            "protect-failure-owner-retry",
            "unprotect-failure-owner-retry",
            "external-callback-statistics-receiver",
        ),
    ),
    SourceRow(
        "os-huge-branch-fault-owners",
        "src/os.c:771-841",
        ("os.rs:2013-2057 and huge allocation/release owners",),
        (
            "huge-terminal-large-map-failure",
            "huge-partial-progress-primitive-failure",
            "huge-timeout-after-progress",
            "huge-noncontiguous-adjustment-cleanup",
            "huge-placement-warning-preserves-owner",
        ),
    ),
    SourceRow(
        "page-map-completed-dependency",
        "src/page-map.c:214-515",
        ("page_map.rs and process_page_map.rs completed M2 matrix",),
        ("page-map-completed-check-dependency",),
    ),
)


# This is a finite *admission* domain, not a claim to enumerate Linux errors
# or every allocator failure.  Error spellings identify the injected primitive
# observation; upper C void continuation and Rust retained-owner outcomes stay
# in the explicit ``outcome`` field.
BRANCH_ROWS = (
    BranchRow(
        "full-release-unmap-failure-retry",
        "os-full-release-owner",
        "_mi_os_free_ex -> mi_os_prim_free",
        "NormalOsAllocation raw release retry owner",
        "Unmap", 1, "ENOMEM",
        "full MemoryId remains live after the failed primitive; source accounting is not replayed by retry",
        "retry-owner",
    ),
    BranchRow(
        "huge-free-continues-after-failure",
        "os-full-release-owner",
        "mi_os_free_huge_os_pages page loop",
        "HugeOsRawReleaseRetry failed-page tracker",
        "Unmap", 1, "ENOMEM",
        "every selected source page receives one free and source current bytes decrease once per page",
        "terminal-continued-free",
    ),
    BranchRow(
        "regular-map-commit-failure",
        "os-regular-aligned-map-and-cleanup",
        "mi_os_prim_alloc_at commit transition",
        "Mapping and NormalOsAllocation owner",
        "Commit", 1, "ENOMEM",
        "failed commit leaves the mapping owner intact and counters unchanged until explicit retry",
        "retry-owner",
    ),
    BranchRow(
        "aligned-cleanup-retained-owner",
        "os-regular-aligned-map-and-cleanup",
        "mi_os_prim_alloc_aligned direct/prefix/suffix cleanup",
        "AlignedMappingFailure retained live range",
        "Unmap", 1, "ENOMEM",
        "C continues its best-effort cleanup accounting; Rust exposes the exact still-live cleanup owner",
        "modeled-owner-divergence",
    ),
    BranchRow(
        "normal-offset-full-owner",
        "os-normal-offset-allocation-owner",
        "_mi_os_alloc_aligned_at_offset full provenance release",
        "NormalOsAllocation full MemoryId",
        "Unmap", 1, "ENOMEM",
        "interior client offset never replaces the full source mapping owner",
        "retry-owner",
    ),
    BranchRow(
        "commit-failure-owner-retry",
        "os-range-transition-fault-owners",
        "_mi_os_commit_ex",
        "VmProcess commit owner",
        "Commit", 1, "ENOMEM",
        "one failed primitive does not publish committed bytes and the retained mapping retries once",
        "retry-owner",
    ),
    BranchRow(
        "decommit-failure-owner-retry",
        "os-range-transition-fault-owners",
        "_mi_os_decommit",
        "VmProcess decommit owner",
        "Decommit", 1, "ENOMEM",
        "failure keeps the source-selected recommit state; retry is explicit",
        "retry-owner",
    ),
    BranchRow(
        "purge-reset-fallback-owner",
        "os-range-transition-fault-owners",
        "_mi_os_reset and _mi_os_purge_ex advice fallback",
        "VmProcess purge owner",
        "Purge", 1, "EAGAIN",
        "the source retry/fallback consumes the selected advice failure without replacing the mapping owner",
        "source-fallback",
    ),
    BranchRow(
        "protect-failure-owner-retry",
        "os-range-transition-fault-owners",
        "_mi_os_protect",
        "VmProcess protection owner",
        "Protect", 1, "ENOMEM",
        "failed protection retains the exact mapping for its explicit retry",
        "retry-owner",
    ),
    BranchRow(
        "unprotect-failure-owner-retry",
        "os-range-transition-fault-owners",
        "_mi_os_unprotect",
        "VmProcess protection owner",
        "Unprotect", 1, "ENOMEM",
        "failed unprotection retains the exact mapping for its explicit retry",
        "retry-owner",
    ),
    BranchRow(
        "external-callback-statistics-receiver",
        "os-range-transition-fault-owners",
        "_mi_os_purge_ex external arena callback branch",
        "VmProcess external backing and subprocess statistics",
        "Purge", 1, "ENOMEM",
        "fixed callback transitions preserve its published backing and only source-selected statistics change",
        "source-callback-terminal",
    ),
    BranchRow(
        "huge-terminal-large-map-failure",
        "os-huge-branch-fault-owners",
        "_mi_os_alloc_huge_os_pages -> unix_mmap large-only",
        "HugeOsAllocation unavailable terminal result",
        "LargeMap", 1, "ENOMEM",
        "no regular map, owner, or huge statistics are published after the selected huge primitive failure",
        "terminal-unavailable",
    ),
    BranchRow(
        "huge-partial-progress-primitive-failure",
        "os-huge-branch-fault-owners",
        "_mi_os_alloc_huge_os_pages loop after one simulated huge primitive success",
        "HugeOsAllocation contiguous prefix owner",
        "HugeMap", 2, "ENOMEM",
        "one completed source huge page remains OsHuge-owned and accounted; later primitive failure terminates the loop",
        "terminal-prefix-owner",
    ),
    BranchRow(
        "huge-timeout-after-progress",
        "os-huge-branch-fault-owners",
        "_mi_os_alloc_huge_os_pages timeout estimate",
        "HugeOsAllocation timed-out prefix owner",
        "Clock", 1, "ETIMEDOUT",
        "timeout follows one completed source page; it does not erase its owner or accounting",
        "terminal-prefix-owner",
    ),
    BranchRow(
        "huge-noncontiguous-adjustment-cleanup",
        "os-huge-branch-fault-owners",
        "_mi_os_alloc_huge_os_pages noncontiguous primitive adjustment",
        "HugeOsRejectedPrimitive cleanup owner",
        "HugeMap", 1, "EINVAL",
        "a primitive result at a different address cannot become OsHuge; its adjustment cleanup stays explicit",
        "terminal-rejected-owner",
    ),
    BranchRow(
        "huge-placement-warning-preserves-owner",
        "os-huge-branch-fault-owners",
        "_mi_prim_alloc_huge_os_pages best-effort mbind",
        "apply_huge_page_numa_preference mapping owner",
        "NumaBind", 1, "EPERM",
        "the fixed mbind failure is ignored after its exact one-word source argument tuple and leaves the live mapping owner and statistics unchanged",
        "terminal-owner",
    ),
    BranchRow(
        "page-map-completed-check-dependency",
        "page-map-completed-dependency",
        "PageMap completed 11-check matrix",
        "PageMap source owners",
        "Map", 1, "ENOMEM",
        "existing completed PageMap evidence is required input only; stopped metadata publication is not admitted here",
        "completed-dependency",
    ),
)

UNQUALIFIED_BRANCHES: tuple[dict[str, str], ...] = ()

STOPPED_RECEIVERS = (
    StoppedReceiver(
        "metadata-map-commit-publication",
        "PageMetadataMapping/meta allocation and publication authority is stopped.",
    ),
    StoppedReceiver(
        "os-aligned-page-publication",
        "OsAlignedPageClaim claim-to-publication transactions are stopped.",
    ),
)


def _exact_strings(values: object, *, label: str) -> list[str]:
    if not isinstance(values, list) or not all(type(value) is str and value for value in values):
        raise ValueError(f"{label} must be a nonempty string list")
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not contain duplicates")
    return list(values)


def _branch_map() -> dict[str, BranchRow]:
    return {row.identifier: row for row in BRANCH_ROWS}


def validate_inventory_definition(definition: Mapping[str, Any]) -> dict[str, Any]:
    """Reject a renamed, omitted, or broadened finite inventory definition."""

    expected_keys = {"branch_rows", "source_rows", "stopped_receivers"}
    if set(definition) != expected_keys:
        raise ValueError("fault inventory definition fields changed")
    source_ids = _exact_strings(definition.get("source_rows"), label="source_rows")
    stopped_ids = _exact_strings(definition.get("stopped_receivers"), label="stopped_receivers")
    branch_ids = _exact_strings(definition.get("branch_rows"), label="branch_rows")
    if source_ids != [row.identifier for row in SOURCE_ROWS]:
        raise ValueError("fault inventory source-row roster changed")
    if stopped_ids != [row.identifier for row in STOPPED_RECEIVERS]:
        raise ValueError("fault inventory stopped-receiver roster changed")
    if branch_ids != [row.identifier for row in BRANCH_ROWS]:
        raise ValueError("fault inventory branch-row roster changed")
    return {
        "branch_rows": branch_ids,
        "source_rows": source_ids,
        "stopped_receivers": stopped_ids,
    }


def inventory_definition() -> dict[str, list[str]]:
    """Return the exact fixed names that a receipt must repeat verbatim."""

    return {
        "branch_rows": [row.identifier for row in BRANCH_ROWS],
        "source_rows": [row.identifier for row in SOURCE_ROWS],
        "stopped_receivers": [row.identifier for row in STOPPED_RECEIVERS],
    }


def load_fragment(path: Path = FRAGMENT_PATH) -> dict[str, Any]:
    """Load the one fixed partial-M2 fragment without widening its receiver set."""

    try:
        fragment = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("fault inventory M2 fragment is unreadable") from error
    runner = _load_runner()
    pin = runner.load_pin()
    expected_keys = {"component", "format", "schema", "target", "upstream"}
    expected_target = {
        "architecture": "x86_64", "endianness": "little", "kernel_baseline": "5.10",
        "os": "linux", "rust_target": "x86_64-unknown-linux-musl",
    }
    if (
        not isinstance(fragment, Mapping)
        or set(fragment) != expected_keys
        or fragment.get("schema") != "crabc-mimalloc-x86_64-m2-component-evidence"
        or fragment.get("format") != 1
        or fragment.get("target") != expected_target
        or fragment.get("upstream") != {
            "version": pin["version"], "revision": pin["revision"],
            "archive_sha256": pin["sha256"],
        }
    ):
        raise EvidenceError("fault inventory M2 fragment identity changed")
    component = fragment.get("component")
    expected_component_keys = {
        "branch_matrix", "bounded_source_definitions", "checks", "completion_status", "id",
        "remaining_conditions", "source_map_records", "source_units", "unqualified_failure_matrix",
    }
    if (
        not isinstance(component, Mapping)
        or set(component) != expected_component_keys
        or component.get("id") != "fault-injection"
        or component.get("completion_status") != "partial"
        or component.get("source_units") != FAULT_COMPONENT_SOURCE_UNITS
        or component.get("source_map_records") != FAULT_COMPONENT_SOURCE_MAP_RECORDS
    ):
        raise EvidenceError("fault inventory M2 component boundary changed")
    checks = component.get("checks")
    if checks != [{
        "id": FAULT_COMPONENT_CHECK_ID,
        "kind": "c-rust-fault-seam-inventory",
        "target": RUST_TARGET,
        "expected_passed_test_count": 1,
    }]:
        raise EvidenceError("fault inventory M2 check roster changed")
    definitions = component.get("bounded_source_definitions")
    if not isinstance(definitions, list) or [item.get("id") if isinstance(item, Mapping) else None for item in definitions] != [
        row.identifier for row in SOURCE_ROWS
    ]:
        raise EvidenceError("fault inventory M2 source-definition roster changed")
    for row, definition, anchor, required_definitions in zip(
        SOURCE_ROWS, definitions, SOURCE_ANCHORS, SOURCE_REQUIRED_DEFINITIONS
    ):
        if (
            not isinstance(definition, Mapping)
            or set(definition) != {"evidence_check_ids", "id", "required_definitions", "source_anchor"}
            or definition.get("evidence_check_ids") != [FAULT_COMPONENT_CHECK_ID]
            or definition.get("required_definitions") != list(required_definitions)
            or definition.get("source_anchor") != anchor
        ):
            raise EvidenceError("fault inventory M2 source definition changed")
    matrix = component.get("branch_matrix")
    if not isinstance(matrix, list) or [item.get("id") if isinstance(item, Mapping) else None for item in matrix] != [
        row.identifier for row in BRANCH_ROWS
    ]:
        raise EvidenceError("fault inventory M2 branch-matrix roster changed")
    anchors_by_source_row = {
        source_row.identifier: anchor for source_row, anchor in zip(SOURCE_ROWS, SOURCE_ANCHORS)
    }
    for row, branch in zip(BRANCH_ROWS, matrix):
        if (
            not isinstance(branch, Mapping)
            or set(branch) != {"disposition", "evidence_check_ids", "id", "missing_conditions", "source_anchors", "source_scope"}
            or branch.get("disposition") != "admitted-current-source-c-rust-relation"
            or branch.get("source_scope") != row.c_branch
            or branch.get("evidence_check_ids") != [FAULT_COMPONENT_CHECK_ID]
            or branch.get("source_anchors") != [anchors_by_source_row[row.source_row]]
            or branch.get("missing_conditions") != [BRANCH_OPEN_CONDITION]
        ):
            raise EvidenceError("fault inventory M2 branch matrix changed")
    unqualified = component.get("unqualified_failure_matrix")
    if unqualified != FAULT_COMPONENT_UNQUALIFIED_MATRIX:
        raise EvidenceError("fault inventory M2 unqualified receiver roster changed")
    remaining = component.get("remaining_conditions")
    if remaining != FAULT_COMPONENT_REMAINING_CONDITIONS:
        raise EvidenceError("fault inventory M2 remaining-condition boundary changed")
    return dict(fragment)


def validate_branch_records(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Validate every fixed C/Rust branch binding before M2 may consume it."""

    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise ValueError("fault inventory branch records must be a list")
    if len(records) != len(BRANCH_ROWS):
        raise ValueError("fault inventory branch record count changed")
    expected = _branch_map()
    materialized: list[dict[str, Any]] = []
    for index, raw in enumerate(records):
        if not isinstance(raw, Mapping):
            raise ValueError("fault inventory branch record is not an object")
        row = expected.get(raw.get("id"))
        if row is None or raw.get("id") != BRANCH_ROWS[index].identifier:
            raise ValueError("fault inventory branch record order or identity changed")
        expected_record = {
            "c_branch": row.c_branch,
            "errno": row.errno,
            "id": row.identifier,
            "ordinal": row.ordinal,
            "outcome": row.outcome,
            "owner_statistics": row.owner_statistics,
            "point": row.point,
            "rust_receiver": row.rust_receiver,
            "source_row": row.source_row,
            "status": "admitted",
        }
        if dict(raw) != expected_record:
            raise ValueError(f"fault inventory branch record changed: {row.identifier}")
        materialized.append(expected_record)
    return materialized


def _local_file_record(path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    return {
        "bytes": len(payload),
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _combined_output(record: Mapping[str, Any]) -> str:
    return str(record["stdout"]) + "\n" + str(record["stderr"])


def _validate_process_record(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "command", "cwd", "status", "stderr", "stdout",
    }:
        raise ValueError(f"{label} process record changed")
    command = value.get("command")
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(argument, str) and argument for argument in command)
        or not isinstance(value.get("cwd"), str)
        or not value["cwd"]
        or type(value.get("status")) is not int
        or value["status"] != 0
        or not isinstance(value.get("stderr"), str)
        or not isinstance(value.get("stdout"), str)
    ):
        raise ValueError(f"{label} process result changed")
    return dict(value)


def _validate_huge_branch_receipt(receipt: object, runner: Any) -> dict[str, Any]:
    """Reconstruct the two traces from retained fixed-profile process streams."""

    expected_keys = {
        "c_build", "c_compiled_source_closure", "c_mbind_direct_include_profile", "c_run", "c_source_files",
        "fixture", "rust_build", "rust_passed_test_count", "rust_run",
        "rust_source_files",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != expected_keys:
        raise ValueError("fault inventory huge branch receipt changed")
    c_build = _validate_process_record(receipt.get("c_build"), label="fault inventory C build")
    c_run = _validate_process_record(receipt.get("c_run"), label="fault inventory C run")
    direct_include = _validate_mbind_profile_record(receipt.get("c_mbind_direct_include_profile"))
    source = Path(c_build["cwd"])
    command = c_build["command"]
    if (
        source.name != "mimalloc-3.5.0"
        or Path(command[0]).name != "musl-gcc"
        or len(command) < 3
        or command[-2] != "-o"
    ):
        raise ValueError("fault inventory C profile tool or working directory changed")
    binary = Path(command[-1])
    if command != _huge_branch_c_command(
        runner, command[0], source, binary, direct_include=direct_include
    ):
        raise ValueError("fault inventory C command or source closure changed")
    if c_run["cwd"] != c_build["cwd"] or c_run["command"] != [str(binary)]:
        raise ValueError("fault inventory C run command changed")
    if receipt.get("c_source_files") != list(PINNED_C_SOURCE_FILES):
        raise ValueError("fault inventory C source-file provenance changed")
    if receipt.get("c_compiled_source_closure") != {
        "direct_fixture_source_units": list(DIRECT_FIXTURE_SOURCE_UNITS),
        "mbind_direct_include_profile": _mbind_profile_record(direct_include),
        "resolved_direct_primitive": RESOLVED_DIRECT_PRIMITIVE,
        "translation_units": list(runner.M2_X86_64_VM_C_ORACLE_SOURCES),
    }:
        raise ValueError("fault inventory C compiled source closure changed")
    if receipt.get("fixture") != _local_file_record(FIXTURE):
        raise ValueError("fault inventory generated fixture provenance changed")
    _parse_fixed_trace(
        _combined_output(c_run), begin=C_TRACE_BEGIN, end=C_TRACE_END,
        keys=C_TRACE_KEYS, source="retained pinned C stream",
    )

    rust_build = _validate_process_record(receipt.get("rust_build"), label="fault inventory Rust build")
    rust_run = _validate_process_record(receipt.get("rust_run"), label="fault inventory Rust run")
    expected_build = runner._m2_x86_64_vm_rust_build_command()
    if (
        Path(rust_build["command"][0]).name != "cargo"
        or rust_build["command"][1:] != expected_build[1:]
        or rust_build["cwd"] != str(ROOT)
    ):
        raise ValueError("fault inventory Rust build command changed")
    run_command = rust_run["command"]
    if (
        rust_run["cwd"] != str(ROOT)
        or len(run_command) != 5
        or run_command[1:] != [RUST_TARGET, "--exact", "--test-threads=1", "--nocapture"]
        or not runner._m2_x86_64_vm_rust_binary_path_is_bound(run_command[0])
    ):
        raise ValueError("fault inventory Rust target/filter command changed")
    output = _combined_output(rust_run)
    try:
        passed_test_count = runner.parse_rust_test_count(output)
    except runner.HarnessError as error:
        raise EvidenceError("retained Rust stream has no exact test summary") from error
    if passed_test_count != 1 or receipt.get("rust_passed_test_count") != 1:
        raise ValueError("fault inventory Rust test count changed")
    if receipt.get("rust_source_files") != [_local_file_record(ROOT / RUST_TRACE_SOURCE)]:
        raise ValueError("fault inventory Rust trace source changed")
    _parse_fixed_trace(
        output, begin=RUST_TRACE_BEGIN, end=RUST_TRACE_END,
        keys=RUST_TRACE_KEYS, source="retained Rust stream",
    )
    return dict(receipt)


def validate_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the immutable, current-source fault admission receipt shape."""

    expected_keys = {
        "architecture", "branch_records", "diagnostic_owner_boundary", "format",
        "huge_branch_receipt", "inventory", "nonclaims", "schema", "status",
        "stopped_receivers", "source_state_after", "source_state_before", "upstream",
        "unqualified_branches", "vm_receipt",
    }
    if set(report) != expected_keys:
        raise ValueError("fault inventory receipt fields changed")
    if report.get("schema") != SCHEMA or report.get("format") != FORMAT:
        raise ValueError("fault inventory receipt schema changed")
    if report.get("architecture") != "x86_64" or report.get("status") != "passed":
        raise ValueError("fault inventory receipt target/status changed")
    if not isinstance(report.get("inventory"), Mapping):
        raise ValueError("fault inventory receipt has no inventory")
    inventory = validate_inventory_definition(report["inventory"])
    records = validate_branch_records(report.get("branch_records"))
    stopped = _exact_strings(report.get("stopped_receivers"), label="stopped_receivers")
    if stopped != inventory["stopped_receivers"]:
        raise ValueError("fault inventory receipt stopped receivers changed")
    if report.get("unqualified_branches") != list(UNQUALIFIED_BRANCHES):
        raise ValueError("fault inventory unqualified branch boundary changed")
    if report.get("diagnostic_owner_boundary") != DIAGNOSTIC_OWNER_BOUNDARY:
        raise ValueError("fault inventory diagnostic owner boundary changed")

    runner = _load_runner()
    huge_receipt = _validate_huge_branch_receipt(report.get("huge_branch_receipt"), runner)
    pin = runner.load_pin()
    if report.get("upstream") != {
        "archive_sha256": pin["sha256"], "revision": pin["revision"],
    }:
        raise ValueError("fault inventory receipt upstream identity changed")
    vm_receipt = report.get("vm_receipt")
    if not isinstance(vm_receipt, Mapping) or set(vm_receipt) != {
        "compared_value_count", "schema", "status", "trace_sha256"
    }:
        raise ValueError("fault inventory VM receipt binding changed")
    if (
        vm_receipt.get("schema") != "crabc-mimalloc-x86_64-m2-vm-primitives-evidence"
        or vm_receipt.get("status") != "passed"
        or type(vm_receipt.get("compared_value_count")) is not int
        or vm_receipt["compared_value_count"] <= 0
        or not isinstance(vm_receipt.get("trace_sha256"), str)
        or len(vm_receipt["trace_sha256"]) != 64
    ):
        raise ValueError("fault inventory VM receipt is invalid")
    nonclaims = _exact_strings(report.get("nonclaims"), label="nonclaims")
    try:
        before = runner.validate_runtime_ticket_zero_soak_source_state(
            report.get("source_state_before"), "fault inventory source before"
        )
        after = runner.validate_runtime_ticket_zero_soak_source_state(
            report.get("source_state_after"), "fault inventory source after"
        )
    except runner.HarnessError as error:
        raise ValueError("fault inventory source attestation changed") from error
    if not before["worktree_clean"] or before != after:
        raise ValueError("fault inventory source state is not one clean revision")
    return {
        "branch_records": records,
        "diagnostic_owner_boundary": dict(DIAGNOSTIC_OWNER_BOUNDARY),
        "huge_branch_receipt": huge_receipt,
        "inventory": inventory,
        "nonclaims": nonclaims,
        "stopped_receivers": stopped,
        "unqualified_branches": list(UNQUALIFIED_BRANCHES),
        "upstream": dict(report["upstream"]),
        "vm_receipt": dict(vm_receipt),
    }


class EvidenceError(RuntimeError):
    """A fixed fault-inventory source or receipt boundary changed."""


def _load_runner() -> Any:
    path = ROOT / "compat/allocator/run.py"
    spec = importlib.util.spec_from_file_location("crabc_allocator_fault_inventory_runner", path)
    if spec is None or spec.loader is None:
        raise EvidenceError("allocator native runner is absent")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(spec.name) is module:
            sys.modules.pop(spec.name, None)
        raise
    return module


def _parse_fixed_trace(output: str, *, begin: str, end: str, keys: Sequence[str], source: str) -> dict[str, int]:
    if output.count(begin) != 1 or output.count(end) != 1:
        raise EvidenceError(f"{source} fault trace marker count changed")
    start = output.index(begin) + len(begin)
    finish = output.index(end)
    if finish <= start:
        raise EvidenceError(f"{source} fault trace markers are reversed")
    values: dict[str, int] = {}
    for line in output[start:finish].strip().splitlines():
        if line.count("=") != 1:
            raise EvidenceError(f"{source} fault trace observation is malformed")
        key, raw = line.split("=", 1)
        if key in values or key not in keys or not raw.isascii() or not raw.isdecimal():
            raise EvidenceError(f"{source} fault trace observation changed: {line}")
        values[key] = int(raw)
    if tuple(values) != tuple(keys) or any(value != 1 for value in values.values()):
        raise EvidenceError(f"{source} fault trace relations changed")
    return values


def _digest_trace(trace: Mapping[str, int]) -> str:
    return hashlib.sha256(
        json.dumps(dict(trace), separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _source_files(runner: Any, source: Path) -> list[dict[str, Any]]:
    records_by_path = {
        record["path"]: record
        for record in runner.source_file_records(source, SOURCE_UNITS)
    }
    if set(records_by_path) != set(SOURCE_UNITS):
        raise EvidenceError("fault inventory C source closure changed")
    records = [records_by_path[path] for path in SOURCE_UNITS]
    if records != list(PINNED_C_SOURCE_FILES):
        raise EvidenceError("fault inventory pinned C source bytes changed")
    return records


MBIND_PROFILE_PINNED_SOURCE_FILES = tuple(
    record for record in PINNED_C_SOURCE_FILES if record["path"] in MBIND_PROFILE_SOURCE_UNITS
)


def _profile_file_record(profile: Path, relative: str) -> dict[str, Any]:
    """Record generated direct-include bytes relative to their one profile root."""

    payload = (profile / relative).read_bytes()
    return {
        "bytes": len(payload),
        "path": relative,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _pinned_mbind_profile_source_files(source: Path) -> list[dict[str, Any]]:
    """Fail closed before deriving the sole substituted primitive body."""

    records = []
    for expected in MBIND_PROFILE_PINNED_SOURCE_FILES:
        try:
            payload = (source / expected["path"]).read_bytes()
        except OSError as error:
            raise EvidenceError("fault inventory mbind direct-include source is missing") from error
        records.append({
            "bytes": len(payload),
            "path": expected["path"],
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    if records != list(MBIND_PROFILE_PINNED_SOURCE_FILES):
        raise EvidenceError("fault inventory mbind direct-include source bytes changed")
    return records


def _render_mbind_profile_unix_body(source: bytes) -> bytes:
    """Derive one typed mbind body while preserving every other Unix primitive byte."""

    original = MBIND_PROFILE_ORIGINAL_EXPRESSION.encode("utf-8")
    replacement = MBIND_PROFILE_REPLACEMENT_EXPRESSION.encode("utf-8")
    if source.count(original) != 1 or replacement in source:
        raise EvidenceError("fault inventory mbind direct-include replacement changed")
    derived = source.replace(original, replacement)
    if derived.count(replacement) != 1 or original in derived:
        raise EvidenceError("fault inventory mbind direct-include derivation changed")
    return derived


def _write_mbind_profile(source: Path, profile: Path) -> Path:
    """Write the pinned direct include with one source-indexed substitution.

    The generator verifies both input members against the fixed archive bytes
    before it copies `prim.c` and substitutes the single `mi_prim_mbind`
    expression in its Unix include.  It never intercepts the other upstream
    `syscall` expressions that process initialization uses.
    """

    _pinned_mbind_profile_source_files(source)
    primitive = source / "src/prim/prim.c"
    unix = source / "src/prim/unix/prim.c"
    direct = profile / "prim.c"
    derived_unix = profile / "unix/prim.c"
    derived_unix.parent.mkdir(parents=True, exist_ok=False)
    direct.write_bytes(primitive.read_bytes())
    derived_unix.write_bytes(_render_mbind_profile_unix_body(unix.read_bytes()))
    records = [_profile_file_record(profile, "prim.c"), _profile_file_record(profile, "unix/prim.c")]
    if records != list(MBIND_PROFILE_DERIVED_FILES):
        raise EvidenceError("fault inventory mbind direct-include derived bytes changed")
    return direct


def _mbind_profile_record(direct_include: Path) -> dict[str, Any]:
    """Retain the source binding and exact generated bytes for reader replay."""

    return {
        "derived_files": [dict(record) for record in MBIND_PROFILE_DERIVED_FILES],
        "direct_include": str(direct_include),
        "input_source_files": [dict(record) for record in MBIND_PROFILE_PINNED_SOURCE_FILES],
        "single_replacement": dict(MBIND_PROFILE_SINGLE_REPLACEMENT),
    }


def _validate_mbind_profile_record(value: object) -> Path:
    """Reject a receipt whose direct include is not the one fixed derivation."""

    if not isinstance(value, Mapping) or set(value) != {
        "derived_files", "direct_include", "input_source_files", "single_replacement",
    }:
        raise ValueError("fault inventory mbind direct-include profile changed")
    direct = value.get("direct_include")
    if (
        not isinstance(direct, str)
        or not direct
        or Path(direct).name != "prim.c"
        or value.get("input_source_files") != list(MBIND_PROFILE_PINNED_SOURCE_FILES)
        or value.get("single_replacement") != MBIND_PROFILE_SINGLE_REPLACEMENT
        or value.get("derived_files") != list(MBIND_PROFILE_DERIVED_FILES)
    ):
        raise ValueError("fault inventory mbind direct-include profile bytes changed")
    return Path(direct)


def _branch_records() -> list[dict[str, Any]]:
    return [
        {
            "c_branch": row.c_branch,
            "errno": row.errno,
            "id": row.identifier,
            "ordinal": row.ordinal,
            "outcome": row.outcome,
            "owner_statistics": row.owner_statistics,
            "point": row.point,
            "rust_receiver": row.rust_receiver,
            "source_row": row.source_row,
            "status": "admitted",
        }
        for row in BRANCH_ROWS
    ]


def _huge_branch_c_command(
    runner: Any, compiler: str, source: Path, binary: Path, *, direct_include: Path
) -> list[str]:
    """Compile the fixed profile with its recorded typed-mbind include only."""

    return [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        FAULT_PROFILE_DEFINE,
        f'-DCRABC_M2_FAULT_SEAM_PRIM_PROFILE="{direct_include}"',
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *runner.CONFIGURATION_PROFILES["release"],
        str(FIXTURE),
        *(str(source / item) for item in runner.M2_X86_64_VM_C_ORACLE_SOURCES),
        "-Wl,--wrap=munmap",
        "-Wl,--wrap=mmap",
        "-Wl,--wrap=madvise",
        "-Wl,--wrap=mprotect",
        "-Wl,--wrap=prctl",
        "-Wl,--wrap=clock_gettime",
        "-pthread",
        "-o",
        str(binary),
    ]


def _huge_retry_helper_c_command(
    runner: Any, compiler: str, source: Path, binary: Path, *, direct_include: Path
) -> list[str]:
    """Build the fixture's finite partial-retry predicate as an isolated binary."""

    command = _huge_branch_c_command(
        runner, compiler, source, binary, direct_include=direct_include
    )
    command.insert(command.index(FAULT_PROFILE_DEFINE) + 1, HUGE_RETRY_HELPER_TEST_DEFINE)
    return command


def _mbind_boundary_c_command(
    runner: Any, compiler: str, source: Path, binary: Path, *, direct_include: Path
) -> list[str]:
    """Compile the isolated `mi_prim_mbind` boundary regression."""

    command = _huge_branch_c_command(
        runner, compiler, source, binary, direct_include=direct_include
    )
    command.insert(command.index(FAULT_PROFILE_DEFINE) + 1, MBIND_BOUNDARY_TEST_DEFINE)
    return command


def compile_huge_branch_profile(*, offline: bool) -> dict[str, Any]:
    """Compile the direct-included C profile without collecting a receipt."""

    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        compiler = runner.require_tool("musl-gcc")
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        artifacts.mkdir(parents=True, exist_ok=True)
        with runner.temporary_directory(prefix="crabc-mimalloc-fault-seam-compile-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            _source_files(runner, source)
            direct_include = _write_mbind_profile(source, Path(temporary) / "mbind-direct-include")
            binary = artifacts / "m2-fault-seam-inventory-huge-oracle"
            command = _huge_branch_c_command(
                runner, compiler, source, binary, direct_include=direct_include
            )
            build = runner.command_record(command, cwd=source, timeout_seconds=300)
            runner.require_success(build, "pinned C native x86 fault-seam huge profile build")
            return {
                "command": command,
                "fixture": runner.artifact_record(FIXTURE),
                "mbind_direct_include_profile": _mbind_profile_record(direct_include),
            }
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error


def run_huge_retry_helper_regression(*, offline: bool) -> dict[str, Any]:
    """Execute the fixture's exact 1GiB, 1GiB, 2MiB retry predicate once."""

    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        compiler = runner.require_tool("musl-gcc")
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        artifacts.mkdir(parents=True, exist_ok=True)
        with runner.temporary_directory(prefix="crabc-mimalloc-fault-seam-retry-helper-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            _source_files(runner, source)
            direct_include = _write_mbind_profile(source, Path(temporary) / "mbind-direct-include")
            binary = artifacts / "m2-fault-seam-retry-helper"
            build = runner.command_record(
                _huge_retry_helper_c_command(
                    runner, compiler, source, binary, direct_include=direct_include
                ),
                cwd=source,
                timeout_seconds=300,
            )
            runner.require_success(build, "pinned C partial huge retry helper build")
            run = runner.command_record([str(binary)], cwd=source, timeout_seconds=60)
            runner.require_success(run, "pinned C partial huge retry helper")
            if str(run["stdout"]) != "allocator fault seam partial huge retry helper: PASS\n" or run["stderr"]:
                raise EvidenceError("pinned C partial huge retry helper output changed")
            report = {
                "build": {**build, "cwd": str(source)},
                "fixture": runner.artifact_record(FIXTURE),
                "format": 1,
                "mbind_direct_include_profile": _mbind_profile_record(direct_include),
                "run": {**run, "cwd": str(source)},
                "schema": HUGE_RETRY_HELPER_SCHEMA,
                "upstream": {
                    "archive_sha256": pin["sha256"],
                    "revision": pin["revision"],
                },
            }
            runner.write_json(artifacts / "partial-huge-retry-helper.json", report)
            return report
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error


def run_mbind_boundary_regression(*, offline: bool) -> dict[str, Any]:
    """Prove initialization stays outside the one typed mbind substitution."""

    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        compiler = runner.require_tool("musl-gcc")
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        artifacts.mkdir(parents=True, exist_ok=True)
        with runner.temporary_directory(prefix="crabc-mimalloc-fault-seam-mbind-boundary-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            _source_files(runner, source)
            direct_include = _write_mbind_profile(source, Path(temporary) / "mbind-direct-include")
            binary = artifacts / "m2-fault-seam-mbind-boundary"
            build = runner.command_record(
                _mbind_boundary_c_command(
                    runner, compiler, source, binary, direct_include=direct_include
                ),
                cwd=source,
                timeout_seconds=300,
            )
            runner.require_success(build, "pinned C typed mbind boundary build")
            run = runner.command_record([str(binary)], cwd=source, timeout_seconds=60)
            runner.require_success(run, "pinned C typed mbind boundary")
            if str(run["stdout"]) != "allocator fault seam mbind boundary: PASS\n" or run["stderr"]:
                raise EvidenceError("pinned C typed mbind boundary output changed")
            report = {
                "build": {**build, "cwd": str(source)},
                "fixture": runner.artifact_record(FIXTURE),
                "format": 1,
                "mbind_direct_include_profile": _mbind_profile_record(direct_include),
                "run": {**run, "cwd": str(source)},
                "schema": MBIND_BOUNDARY_SCHEMA,
                "upstream": {
                    "archive_sha256": pin["sha256"],
                    "revision": pin["revision"],
                },
            }
            runner.write_json(artifacts / "mbind-boundary.json", report)
            return report
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error


def _validate_reused_vm_receipt(vm: object) -> dict[str, Any]:
    """Keep one aggregate VM receipt as an input, never a trace-hash substitute."""

    if (
        not isinstance(vm, Mapping)
        or vm.get("schema") != "crabc-mimalloc-x86_64-m2-vm-primitives-evidence"
        or vm.get("status") != "passed"
        or type(vm.get("compared_value_count")) is not int
        or vm["compared_value_count"] <= 0
        or not isinstance(vm.get("trace_sha256"), str)
        or len(vm["trace_sha256"]) != 64
    ):
        raise EvidenceError("fault inventory reused VM receipt is invalid")
    return dict(vm)


def run_evidence(
    *,
    offline: bool,
    report_path: Path = REPORT_DEFAULT,
    test_program: Mapping[str, Any] | None = None,
    vm_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect a fixed huge profile, reusing an aggregate VM receipt when supplied."""

    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        before = runner.m2_memory_substrate_source_state()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        compiler = runner.require_tool("musl-gcc")
        execution = runner._m2_x86_64_vm_rust_execution()
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        if test_program is None:
            # The standalone path hands this product to the fixed VM producer,
            # whose provenance contract accepts only the canonical M2 target.
            test_program = runner._x86_64_unit_test_program(
                execution,
                runner.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET,
                gate_name="native x86 fault seam inventory",
            )
        elif not runner._m2_x86_64_vm_test_program_is_bound(test_program):
            raise EvidenceError("fault inventory Rust test-program provenance changed")
        if vm_evidence is None:
            vm = runner._run_m2_x86_64_vm_evidence(offline=offline, test_program=test_program)
        else:
            vm = _validate_reused_vm_receipt(vm_evidence)
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error

    artifacts.mkdir(parents=True, exist_ok=True)
    try:
        with runner.temporary_directory(prefix="crabc-mimalloc-fault-seam-source-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            c_files = _source_files(runner, source)
            direct_include = _write_mbind_profile(source, Path(temporary) / "mbind-direct-include")
            binary = artifacts / "m2-fault-seam-inventory-huge-oracle"
            c_command = _huge_branch_c_command(
                runner, compiler, source, binary, direct_include=direct_include
            )
            c_build = runner.command_record(c_command, cwd=source, timeout_seconds=300)
            runner.require_success(c_build, "pinned C native x86 fault-seam huge profile build")
            c_run = runner.command_record([str(binary)], cwd=source, timeout_seconds=180)
            runner.require_success(c_run, "pinned C native x86 fault-seam huge profile")
            c_trace = _parse_fixed_trace(
                str(c_run["stdout"]), begin=C_TRACE_BEGIN, end=C_TRACE_END,
                keys=C_TRACE_KEYS, source="pinned C",
            )
            c_mbind_direct_include_profile = _mbind_profile_record(direct_include)
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error

    try:
        execution = test_program["execution"]
        rust_command = runner._x86_64_program_check_command(
            test_program, RUST_TARGET, nocapture=True,
            gate_name="native x86 fault-seam huge profile",
        )
        rust_run = runner.command_record(
            rust_command, cwd=ROOT, timeout_seconds=int(execution["timeout_seconds"])
        )
        runner.require_success(rust_run, "native x86 fault-seam huge profile")
        rust_output = str(rust_run["stdout"]) + "\n" + str(rust_run["stderr"])
        rust_passed_test_count = runner.parse_rust_test_count(rust_output)
        if rust_passed_test_count != 1:
            raise EvidenceError(
                "native x86 fault-seam huge profile did not pass exactly one Rust test"
            )
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error
    rust_trace = _parse_fixed_trace(
        rust_output, begin=RUST_TRACE_BEGIN, end=RUST_TRACE_END,
        keys=RUST_TRACE_KEYS, source="Rust",
    )
    try:
        after = runner.m2_memory_substrate_source_state()
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error
    report = {
        "architecture": "x86_64",
        "branch_records": _branch_records(),
        "format": FORMAT,
        "huge_branch_receipt": {
            "c_build": {**c_build, "cwd": str(source)},
            "c_compiled_source_closure": {
                "direct_fixture_source_units": list(DIRECT_FIXTURE_SOURCE_UNITS),
                "mbind_direct_include_profile": c_mbind_direct_include_profile,
                "resolved_direct_primitive": RESOLVED_DIRECT_PRIMITIVE,
                "translation_units": list(runner.M2_X86_64_VM_C_ORACLE_SOURCES),
            },
            "c_mbind_direct_include_profile": c_mbind_direct_include_profile,
            "c_run": {**c_run, "cwd": str(source)},
            "c_source_files": c_files,
            "fixture": runner.artifact_record(FIXTURE),
            "rust_build": {**test_program["build"], "cwd": str(ROOT)},
            "rust_passed_test_count": rust_passed_test_count,
            "rust_run": {**rust_run, "cwd": str(ROOT)},
            "rust_source_files": [_local_file_record(ROOT / RUST_TRACE_SOURCE)],
        },
        "diagnostic_owner_boundary": DIAGNOSTIC_OWNER_BOUNDARY,
        "inventory": inventory_definition(),
        "nonclaims": [
            "This fixed primitive-response profile does not qualify successful hardware huge pages.",
            "The fixed mbind result proves C output-callback warning control flow and Rust retained ownership, not a Rust diagnostic-output parity contract or ambient NUMA placement.",
            "Metadata and OsAligned publication receivers remain stopped and unadmitted.",
            "This receipt leaves the fault-injection component and M2 partial.",
        ],
        "schema": SCHEMA,
        "source_state_after": after,
        "source_state_before": before,
        "status": "passed",
        "stopped_receivers": [row.identifier for row in STOPPED_RECEIVERS],
        "unqualified_branches": list(UNQUALIFIED_BRANCHES),
        "upstream": {"archive_sha256": pin["sha256"], "revision": pin["revision"]},
        "vm_receipt": {
            "compared_value_count": vm["compared_value_count"],
            "schema": vm["schema"],
            "status": vm["status"],
            "trace_sha256": vm["trace_sha256"],
        },
    }
    validate_report(report)
    runner.write_json(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--compile-only", action="store_true")
    parser.add_argument("--retry-helper-regression", action="store_true")
    parser.add_argument("--mbind-boundary-regression", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        selected_modes = sum((
            arguments.compile_only,
            arguments.retry_helper_regression,
            arguments.mbind_boundary_regression,
        ))
        if selected_modes > 1:
            raise EvidenceError("fault inventory accepts one focused mode")
        if arguments.compile_only:
            compile_huge_branch_profile(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: C profile compile PASS")
            return 0
        if arguments.retry_helper_regression:
            run_huge_retry_helper_regression(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: partial huge retry helper PASS")
            return 0
        if arguments.mbind_boundary_regression:
            run_mbind_boundary_regression(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: typed mbind boundary PASS")
            return 0
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 fault seam inventory: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 fault seam inventory: PASS "
        f"({len(report['branch_records'])} admitted rows; "
        f"{len(report['unqualified_branches'])} unqualified eligible branch; "
        f"report: {report_path_relative(arguments.report)})"
    )
    return 0


def report_path_relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
