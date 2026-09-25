#!/usr/bin/env python3
"""Closed native x86-64 admission inventory for allocator OS fault seams.

This is deliberately a reader for one fixed source-bound receipt, not a
second fault injector.  ``m2_vm_x86_64.c`` keeps the C bodies direct-included
and ``os::tests::emit_m2_fault_seam_inventory_c_rust_trace`` keeps Rust
injection behind its existing test-only ``FaultPlan``.  This module names the
complete set of source groups the receipt must account for, including the
metadata receiver that remains unadmitted. The ordinary OS publication profile
runs independently while the canonical aggregate still requires both profiles.  A passing receipt is
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
import re
import stat
import sys
import tempfile
from typing import Any, Mapping, Sequence


SCHEMA = "crabc-mimalloc-x86_64-fault-seam-inventory-evidence"
# Format 4 requires the metadata-publication receiver beside the ordinary OS
# publication and source diagnostic/huge receivers. Legacy reports cannot
# admit the new rows.
FORMAT = 4
ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_vm_x86_64.c"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/fault-seam-inventory.json"
CANONICAL_M2_VM_FIXTURE = ROOT / "compat/allocator/m2_vm_x86_64.c"
OS_PUBLICATION_PROFILE_DEFINE = "-DCRABC_M2_OS_PUBLICATION_PROFILE=1"
OS_PUBLICATION_CHECK_ID = "os-aligned-page-publication-fault-receiver"
OS_PUBLICATION_TARGET = "os_page::tests::emit_os_publication_fault_receiver_trace"
OS_PUBLICATION_BEGIN = "CRABC_MI_M2_OS_PUBLICATION_TRACE_BEGIN"
OS_PUBLICATION_END = "CRABC_MI_M2_OS_PUBLICATION_TRACE_END"
OS_PUBLICATION_KEYS = tuple(
    f"os_publication.{selected}.{field}" for selected in range(1, 8)
    for field in ("page_result", "commit_branch", "map_branch", "release_once",
                  "cleanup_retention", "unreachable", "raw_retry", "retry_statistics", "map_rollback",
                  "repeat_same_branch", "recovered_page_published")
)
OS_PUBLICATION_BOUNDARY = {
    "source": "src/arena.c:781-1120,1220-1297; src/page-map.c:391-515; src/os.c:240-294",
    "cases": ["map-failure", "metadata-commit-failure", "block-commit-failure",
              "page-map-publication-failure", "metadata-commit-and-cleanup-failure",
              "page-map-and-cleanup-failure", "published-page-release-failure"],
    "requests": "each case's faulted request twice against the state the first failure left, then one fault-free publication and release",
    "c_release": "void upper free; failed range captured only for exact lower primitive fixture cleanup",
    "rust_release": "one typed Claim or Published owner; raw retry never repeats source accounting",
    "excluded": "corrupted-alias provenance refusal, general metadata allocator, hardware huge/NUMA, and complete M2",
}
METADATA_PUBLICATION_PROFILE_DEFINE = "-DCRABC_M2_METADATA_PUBLICATION_PROFILE=1"
METADATA_PUBLICATION_CHECK_ID = "metadata-publication-fault-receiver"
METADATA_PUBLICATION_TARGET = "meta::tests::emit_metadata_publication_fault_receiver_trace"
METADATA_PUBLICATION_BEGIN = "CRABC_MI_M2_METADATA_PUBLICATION_TRACE_BEGIN"
METADATA_PUBLICATION_END = "CRABC_MI_M2_METADATA_PUBLICATION_TRACE_END"
METADATA_PUBLICATION_DELTAS_BEGIN = "CRABC_MI_M2_METADATA_PUBLICATION_DELTAS_BEGIN"
METADATA_PUBLICATION_DELTAS_END = "CRABC_MI_M2_METADATA_PUBLICATION_DELTAS_END"
# Raw primitive counts are mechanism-specific (C sees each wrapped mmap hint
# retry; Rust's FaultPlan sees one transition), so only the committed-byte
# delta, which each failed fresh-page claim changes by its source rollback
# accounting, is a shared value.
METADATA_PUBLICATION_DELTA_KEYS = tuple(
    f"metadata_publication.{selected}.committed_delta" for selected in range(1, 4)
)
METADATA_PUBLICATION_KEYS = tuple(
    f"metadata_publication.{selected}.{field}" for selected in range(1, 4)
    for field in ("request_failed", "no_capability", "fault_reached", "live_owner_intact",
                  "reserved_restored", "committed_recorded", "retry_zeroed_malloc",
                  "retry_page_published")
)
# The detached-Theap metadata request meets one persistently unavailable
# primitive while its fresh page is claimed. Both languages keep their own
# fault mechanism (C link-wrapped imports, Rust's test-only FaultPlan); the
# receipt compares only observed ownership and accounting relations.
METADATA_PUBLICATION_BOUNDARY = {
    "source": "src/subproc.c:29-37; src/page.c:1048-1065; src/arena.c:781-869",
    "cases": ["os-map-failure", "os-commit-failure", "arena-commit-failure"],
    "c_fault": "persistent __wrap_mmap or __wrap_mprotect ENOMEM around one _mi_meta_zalloc",
    "rust_fault": "FaultPlan::every(Map|Commit) around one MetadataEngine::zalloc",
    "excluded": "PageMap submap publication (completed PageMap matrix), huge/NUMA hardware, cleanup-release failure (OS publication receiver)",
}
FAULT_PROFILE_DEFINE = "-DCRABC_M2_FAULT_SEAM_INVENTORY_PROFILE=1"
HUGE_RETRY_HELPER_TEST_DEFINE = "-DCRABC_M2_FAULT_SEAM_RETRY_HELPER_TEST=1"
HUGE_TIMEOUT_CLOCK_HELPER_TEST_DEFINE = "-DCRABC_M2_FAULT_SEAM_TIMEOUT_CLOCK_HELPER_TEST=1"
HUGE_PLACEMENT_WARNING_HELPER_TEST_DEFINE = "-DCRABC_M2_FAULT_SEAM_PLACEMENT_WARNING_HELPER_TEST=1"
MBIND_BOUNDARY_TEST_DEFINE = "-DCRABC_M2_FAULT_SEAM_MBIND_BOUNDARY_TEST=1"
HUGE_BRANCH_DIAGNOSTIC_TEST_DEFINE = "-DCRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST=1"
HUGE_RETRY_HELPER_SCHEMA = "crabc-mimalloc-x86_64-fault-seam-retry-helper-regression"
HUGE_TIMEOUT_CLOCK_HELPER_SCHEMA = "crabc-mimalloc-x86_64-fault-seam-timeout-clock-helper-regression"
HUGE_PLACEMENT_WARNING_HELPER_SCHEMA = "crabc-mimalloc-x86_64-fault-seam-placement-warning-helper-regression"
MBIND_BOUNDARY_SCHEMA = "crabc-mimalloc-x86_64-fault-seam-mbind-boundary-regression"
HUGE_BRANCH_DIAGNOSTIC_SCHEMA = "crabc-mimalloc-x86_64-fault-seam-huge-branch-diagnosis"
CANONICAL_M2_VM_C_COMPILE_REGRESSION_SCHEMA = (
    "crabc-mimalloc-x86_64-fault-seam-canonical-m2-vm-c-compile-regression"
)
C_TRACE_BEGIN = "CRABC_MI_M2_FAULT_SEAM_INVENTORY_C_TRACE_BEGIN"
C_TRACE_END = "CRABC_MI_M2_FAULT_SEAM_INVENTORY_C_TRACE_END"
RUST_TRACE_BEGIN = "CRABC_MI_M2_FAULT_SEAM_INVENTORY_RUST_TRACE_BEGIN"
RUST_TRACE_END = "CRABC_MI_M2_FAULT_SEAM_INVENTORY_RUST_TRACE_END"
FAULT_DIAGNOSTIC_C_TRACE_BEGIN = "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_C_TRACE_BEGIN"
FAULT_DIAGNOSTIC_C_TRACE_END = "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_C_TRACE_END"
FAULT_DIAGNOSTIC_RUST_TRACE_BEGIN = "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_RUST_TRACE_BEGIN"
FAULT_DIAGNOSTIC_RUST_TRACE_END = "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_RUST_TRACE_END"
FAULT_DIAGNOSTIC_DEFAULT_C_BEGIN = "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_C_DEFAULT_BEGIN"
FAULT_DIAGNOSTIC_DEFAULT_C_END = "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_C_DEFAULT_END"
FAULT_DIAGNOSTIC_DEFAULT_RUST_BEGIN = "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_RUST_DEFAULT_BEGIN"
FAULT_DIAGNOSTIC_DEFAULT_RUST_END = "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_RUST_DEFAULT_END"
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
FAULT_DIAGNOSTIC_TRACE_KEYS = (
    "default_mbind", "default_mapping_survives", "default_stats_survive",
    "default_continuation_flush",
    "gate_off_mbind", "gate_off_no_output", "gate_off_mapping_survives",
    "gate_off_stats_survive", "custom_mbind", "custom_fragments",
    "custom_mapping_survives", "custom_stats_survive", "invalid_no_mbind",
    "invalid_no_output", "invalid_mapping_survives", "invalid_stats_survive",
)
FAULT_DIAGNOSTIC_TRACE_TAIL_KEYS = (
    "custom_thread_identity", "default_continuation_hex", "custom_prefix_hex", "custom_body_hex",
)
HUGE_BRANCH_DIAGNOSTIC_BEGIN = "CRABC_MI_M2_FAULT_SEAM_HUGE_DIAG_BEGIN"
HUGE_BRANCH_DIAGNOSTIC_END = "CRABC_MI_M2_FAULT_SEAM_HUGE_DIAG_END"
HUGE_BRANCH_DIAGNOSTIC_CASES = (
    "partial", "timeout", "placement", "noncontiguous", "free",
)
HUGE_BRANCH_DIAGNOSTIC_SELECTED = {
    "partial": 1,
    "timeout": 2,
    "placement": 4,
    "noncontiguous": 3,
    "free": 5,
}
HUGE_BRANCH_DIAGNOSTIC_BOOLEAN_FIELDS = (
    "captured", "complete", "returned", "page_size", "memid", "huge_mmap", "fallback_mmap",
    "reserved_stats", "committed_stats", "clock", "suppressed_options", "suppressed_relation",
    "enabled_options", "mbind_tuple", "diagnostics", "cleanup", "free_initial_owner", "free_tuple",
)
HUGE_BRANCH_DIAGNOSTIC_COUNT_FIELDS = (
    "mmap_calls", "munmap_calls", "clock_calls", "syscall_calls", "diagnostic_calls",
    "diagnostic_first_length", "diagnostic_second_length", "pages", "size",
)
HUGE_BRANCH_DIAGNOSTIC_FRAGMENT_FIELDS = (
    "diagnostic_first_hex", "diagnostic_second_hex",
)
HUGE_BRANCH_DIAGNOSTIC_FIELDS = (
    "case", "selected", *HUGE_BRANCH_DIAGNOSTIC_BOOLEAN_FIELDS, *HUGE_BRANCH_DIAGNOSTIC_COUNT_FIELDS,
    "reserved_delta", "committed_delta", "memkind", "exit_status", *HUGE_BRANCH_DIAGNOSTIC_FRAGMENT_FIELDS,
)
RUST_TARGET = "os::tests::emit_m2_fault_seam_inventory_c_rust_trace"
SOURCE_UNITS = (
    "include/mimalloc/atomic.h",
    "include/mimalloc/prim.h",
    "include/mimalloc/prim-tls.h",
    "src/arena.c",
    "src/init.c",
    "src/os.c",
    "src/options.c",
    "src/page.c",
    "src/page-map.c",
    "src/prim/prim.c",
    "src/prim/unix/prim.c",
)

PINNED_C_SOURCE_FILES = (
    {"path": "include/mimalloc/atomic.h", "bytes": 24497, "sha256": "106b267e98ccc5e01b48252c9742584cd5c914f309e7f4a4413ad85e65063d41"},
    {"path": "include/mimalloc/prim.h", "bytes": 6403, "sha256": "1987e8e2eedc07bb181bf2a11a27bec80a5309c32cfa66a56900fb4cbb64b172"},
    {"path": "include/mimalloc/prim-tls.h", "bytes": 19214, "sha256": "46d871923b38c9463da985c54503cd5cb64bb2c91008f3d35bcbaae2a11c31c2"},
    {"path": "src/arena.c", "bytes": 115645, "sha256": "5d9aa2dc06fa6e942d6a46eb4748b0c10c81f96c2ed50042412a9e66fd6f4d7a"},
    {"path": "src/init.c", "bytes": 25096, "sha256": "e22486042ba132e002822315ccd4b24738fc3a151fc14172e5e45426e8add299"},
    {"path": "src/os.c", "bytes": 39093, "sha256": "8410b04c2d5b37e59fff1854364fed1fba873133b064cfe02083277038388548"},
    {"path": "src/options.c", "bytes": 28585, "sha256": "760c694c7663a18ae9745deb969215544d682c15fedd87ffe2645c6d31d5ba30"},
    {"path": "src/page.c", "bytes": 44473, "sha256": "f7b1c3c0725b425516e22cf49d3ff7e03b708732fdba4bd1f4c759484d52593c"},
    {"path": "src/page-map.c", "bytes": 22024, "sha256": "ff3509ae3d4185e9cb2a95e1f35daba3329e998bac917ac7938f1bf06dba0f78"},
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
MBIND_PROFILE_DIRECTORY_MODE = 0o700
MBIND_PROFILE_FILE_MODE = 0o600
CONTAINER_CHECKOUT_ROOT = Path("/workspace")
CONTAINER_WORK_ROOT = Path("/workspace/.work/allocator-x86_64")
DIRECT_FIXTURE_SOURCE_UNITS = (
    "src/os.c", "src/arena.c", "src/init.c", "src/page.c", "src/prim/prim.c",
)
RESOLVED_DIRECT_PRIMITIVE = "src/prim/unix/prim.c"
RUST_TRACE_SOURCE = "crabc-mimalloc/src/os.rs"
RUST_TRACE_SOURCE_FILES = (
    "Cargo.lock", "Cargo.toml", ".cargo/config.toml", "crabc-core/Cargo.toml",
    "crabc-core/src/error.rs", "crabc-core/src/lib.rs", "crabc-core/src/mm.rs",
    "crabc-core/src/mm_x86_64.rs", "crabc-core/src/param.rs", "crabc-core/src/syscall.rs",
    "crabc-core/src/syscall_x86_64.rs", "crabc-core/src/thread.rs",
    "crabc-mimalloc/Cargo.toml", "crabc-mimalloc/src/config.rs",
    "crabc-mimalloc/src/diagnostic_output.rs", "crabc-mimalloc/src/invariants.rs",
    "crabc-mimalloc/src/lib.rs", "crabc-mimalloc/src/lock.rs",
    "crabc-mimalloc/src/os.rs", "crabc-mimalloc/src/random.rs",
    "crabc-mimalloc/src/subproc.rs", "crabc-mimalloc/src/types.rs",
    "crabc-mimalloc/src/os_page.rs", "crabc-mimalloc/src/page_map.rs",
    "crabc-mimalloc/src/bootstrap.rs", "crabc-mimalloc/src/single_thread.rs",
)
METADATA_PUBLICATION_RUST_SOURCE_FILES = (
    "crabc-mimalloc/src/meta.rs", "crabc-mimalloc/src/process_init.rs",
)
# This receipt reconstructs one selected C/Rust fault receiver and the private
# caller-supplied default sink. The target still does not qualify general FILE
# behavior, recursive output, ambient placement, or M2 as a whole.
DIAGNOSTIC_OWNER_BOUNDARY = {
    "c_output_registration": "src/options.c:415-433 mi_out_get_default/mi_register_output",
    "c_warning_emission": "src/options.c:540-550 _mi_warning_message",
    "initialization_order": "src/init.c:537-548 mi_process_init_once/_mi_options_init",
    "rust_source_map_unit": "option-processing",
    "rust_source_map_status": "partial",
    "rust_owner": "crabc_mimalloc::diagnostic_output",
    "fault_diagnostic_relation": "bounded-current-source-private-receiver",
    "default_stderr_transport": "caller-supplied native musl fputs(stderr) test capability only",
    "unqualified": "general FILE transport, recursive output, and full M2 remain open",
}
NONCLAIMS = (
    "This selected node-62 EPERM receiver proves current-source C/Rust private diagnostic delivery through the stored default sink and custom callback; it does not qualify general FILE short-write/error/buffering parity, recursive output, selected x86 libc startup, or ambient NUMA placement.",
    "This fixed primitive-response profile does not qualify successful hardware huge pages or physical NUMA placement.",
    "The metadata-publication receiver admits only one detached-Theap `_mi_meta_zalloc` under three sustained primitive failures; ordinary OS publication has its own required receiver.",
    "This receipt leaves the fault-injection component and M2 partial.",
)
FRAGMENT_PATH = ROOT / "compat/allocator/m2-fault-seam-inventory-x86_64-v3.5.0.fragment.json"
FAULT_COMPONENT_CHECK_ID = "source-indexed-fault-seam-inventory"
FAULT_COMPONENT_SOURCE_MAP_RECORDS = [
    {"unit_id": "page-map-lifecycle", "required_status": "partial"},
    {"unit_id": "os-allocation-policy", "required_status": "partial"},
]
FAULT_COMPONENT_SOURCE_UNITS = [
    "src/os.c", "src/page-map.c", "src/prim/unix/prim.c", "src/options.c", "src/arena.c",
]
FAULT_COMPONENT_UNQUALIFIED_IDS = (
    "remaining-ambient-and-hardware-fault-receivers",
)
SOURCE_ANCHORS = (
    {"member": "src/os.c", "start_line": 240, "end_line": 294, "sha256": "b90d71dbe1a3bdee02095502ca799cdea2cd4c1f42983b6117d932c47b931c02"},
    {"member": "src/os.c", "start_line": 303, "end_line": 430, "sha256": "e5ba5306a96cc2ccc54041ef1b7158b93cf6ae6db10e2d4bcecbc62741e6225b"},
    {"member": "src/os.c", "start_line": 438, "end_line": 527, "sha256": "fc4e177b6d6c35be7372e641d8d0209f03cdc84f2f87099dfcf1a00eb0ad1b89"},
    {"member": "src/os.c", "start_line": 534, "end_line": 712, "sha256": "dc9c44664aa3348206cdfe456b3a1eff19ffed26192d64ad314baf0b4d014feb"},
    {"member": "src/os.c", "start_line": 771, "end_line": 853, "sha256": "89affd5d917f2f40f32764001c58d52f72bf9e3faa23cdaa965f49bf322c05c2"},
    {"member": "src/page-map.c", "start_line": 214, "end_line": 515, "sha256": "b0218dd17e7a38ed3018fcb3f2941f5421fd72afb05c02023ce49bf21734edd3"},
    {"member": "src/arena.c", "start_line": 781, "end_line": 1297, "sha256": "93215720a105d4e9cbc359f17668dbd08aa0271e01064f3c03fa47b7243bd383"},
    {"member": "src/page.c", "start_line": 1048, "end_line": 1117, "sha256": "fd4a63385b988fa96324171916bc0db89af60818c6edf5ca79ba67b724253e6f"},
)
SOURCE_REQUIRED_DEFINITIONS = (
    ("void mi_os_prim_free", "void _mi_os_free_ex", "void _mi_os_free"),
    ("static void* mi_os_prim_alloc_at", "static void* mi_os_prim_alloc_aligned"),
    ("void* _mi_os_alloc", "void* _mi_os_alloc_aligned_at_offset"),
    ("bool _mi_os_commit_ex", "bool _mi_os_decommit", "bool _mi_os_purge_ex", "bool _mi_os_protect"),
    ("void* _mi_os_alloc_huge_os_pages", "static void mi_os_free_huge_os_pages"),
    ("static bool mi_page_map_init_once", "bool _mi_page_map_register"),
    ("static uint8_t* mi_arenas_page_alloc_fresh_area", "static mi_page_t* mi_arenas_page_alloc_fresh", "static void mi_arenas_page_free_prim"),
    ("static mi_decl_noinline void* mi_malloc_generic_fallback", "void* _mi_malloc_generic"),
)
BRANCH_OPEN_CONDITION = "The named source relation is bounded; it does not promote an unselected receiver."
FAULT_COMPONENT_UNQUALIFIED_MATRIX = [
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
    "The ordinary OS claim/publication receiver compares a repeated faulted request and a recovered request per case; the metadata-publication receiver remains single-request because a multi-request sequence exposes lazy PageMap submap mappings missing from subprocess reserved/committed statistics (pinned C `_mi_os_zalloc` counts them), which the vm-primitives statistics owner must supply. Both receivers are required independently of hardware.",
    "The selected node-62 fault diagnostic relation is source-bound and private; general diagnostic receivers, FILE parity, and recursive output remain unqualified.",
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


# Keep these source groups in their stable declaration order.  The branch rows below are
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
        "src/os.c:771-853",
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
    SourceRow(
        "os-aligned-page-publication", "src/arena.c:781-1297",
        ("os_page.rs OsAlignedPageClaim/PublishedOsAlignedPage and single_thread.rs rollback_fresh_os_aligned",),
        tuple("os-publication-" + case for case in OS_PUBLICATION_BOUNDARY["cases"]),
    ),
    SourceRow(
        "metadata-page-publication", "src/subproc.c:29-37; src/page.c:1048-1117",
        ("meta.rs MetadataEngine::zalloc through single_thread.rs allocate_generic_with_retry",),
        tuple("metadata-publication-" + case for case in METADATA_PUBLICATION_BOUNDARY["cases"]),
    ),
)

# The one fault-inventory check that proves each source row's branches.
SOURCE_ROW_CHECK_IDS = {
    "os-aligned-page-publication": OS_PUBLICATION_CHECK_ID,
    "metadata-page-publication": METADATA_PUBLICATION_CHECK_ID,
}


def _source_row_check_id(source_row: str) -> str:
    return SOURCE_ROW_CHECK_IDS.get(source_row, FAULT_COMPONENT_CHECK_ID)


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
    *(BranchRow(
        "os-publication-" + case, "os-aligned-page-publication",
        "arena.c ordinary OS claim/publication case " + str(index) + ": " + case,
        OS_PUBLICATION_TARGET, point, ordinal, "ENOMEM",
        "private source mapping; C void free and Rust typed owner remain distinct; retry accounts once",
        "exact source branch, unreachable failed page, and retained-range lower release relation",
    ) for index, (case, point, ordinal) in enumerate(zip(OS_PUBLICATION_BOUNDARY["cases"],
        ("Map", "Commit", "Commit", "Map", "Commit+Unmap", "Map+Unmap", "Unmap"),
        (1, 1, 2, 1, 1, 1, 1)), 1)),
    *(BranchRow(
        "metadata-publication-" + case, "metadata-page-publication",
        "detached-Theap _mi_meta_zalloc case " + str(index) + ": " + case,
        METADATA_PUBLICATION_TARGET, point, 0, "ENOMEM",
        "sustained primitive failure through `_mi_malloc_generic` search, fallback, and forced retry; committed delta equal to pinned C",
        "no capability, live metadata owner and PageMap entry intact, reserved restored, zeroed Malloc-provenance retry after recovery",
    ) for index, (case, point) in enumerate(zip(METADATA_PUBLICATION_BOUNDARY["cases"],
        ("Map", "Commit", "Commit")), 1)),
)

UNQUALIFIED_BRANCHES: tuple[dict[str, str], ...] = ()

STOPPED_RECEIVERS: tuple[StoppedReceiver, ...] = ()


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
    }, {
        "id": OS_PUBLICATION_CHECK_ID,
        "kind": "c-rust-fault-seam-inventory",
        "target": OS_PUBLICATION_TARGET,
        "expected_passed_test_count": 1,
    }, {
        "id": METADATA_PUBLICATION_CHECK_ID,
        "kind": "c-rust-fault-seam-inventory",
        "target": METADATA_PUBLICATION_TARGET,
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
            or definition.get("evidence_check_ids") != [_source_row_check_id(row.identifier)]
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
            or branch.get("evidence_check_ids") != [_source_row_check_id(row.source_row)]
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


def _rust_trace_source_files() -> list[dict[str, Any]]:
    """Bind the finite Rust route and its Cargo configuration inputs.

    `source_state_before/after` additionally authenticates the current whole
    checkout revision. This explicit roster names the selected direct receiver
    modules and all Cargo files that resolve this test binary, so a changed
    owner, lock, source-option reader, x86 syscall boundary, or root config
    cannot be hidden behind the aggregate revision record.
    """

    return [_local_file_record(ROOT / path) for path in RUST_TRACE_SOURCE_FILES]


def fault_component_fragment_receipt() -> dict[str, Any]:
    """Bind this report to the exact current fragment and its projection.

    `load_fragment` is the fail-closed schema/roster reader used by the M2
    assembly. Repeating its projection and both byte/canonical identities in
    the producer report prevents a legacy C-only receipt from being replayed
    under the selected private diagnostic-receiver boundary.
    """

    fragment = load_fragment()
    runner = _load_runner()
    return {
        "canonical_sha256": runner._m1_inventory_digest(fragment),
        "component": dict(fragment["component"]),
        "format": fragment["format"],
        "schema": fragment["schema"],
        "source": _local_file_record(FRAGMENT_PATH),
        "target": dict(fragment["target"]),
        "upstream": dict(fragment["upstream"]),
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
    direct_include = _validate_mbind_profile_record(
        receipt.get("c_mbind_direct_include_profile"), runner
    )
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
    expected_command = _bound_huge_branch_c_command(
        runner, command, source, binary, direct_include
    )
    if command != expected_command:
        raise ValueError("fault inventory C command or source closure changed")
    if c_run["cwd"] != c_build["cwd"] or c_run["command"] != [str(binary)]:
        raise ValueError("fault inventory C run command changed")
    if receipt.get("c_source_files") != list(PINNED_C_SOURCE_FILES):
        raise ValueError("fault inventory C source-file provenance changed")
    if receipt.get("c_compiled_source_closure") != {
        "direct_fixture_source_units": list(DIRECT_FIXTURE_SOURCE_UNITS),
        "mbind_direct_include_profile": receipt["c_mbind_direct_include_profile"],
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
    c_relation = _parse_fault_diagnostic_relation_trace(
        _combined_output(c_run), begin=FAULT_DIAGNOSTIC_C_TRACE_BEGIN,
        end=FAULT_DIAGNOSTIC_C_TRACE_END, source="retained pinned C stream",
    )
    c_default = _parse_fault_diagnostic_default_stderr(
        c_run["stderr"], begin=FAULT_DIAGNOSTIC_DEFAULT_C_BEGIN,
        end=FAULT_DIAGNOSTIC_DEFAULT_C_END, source="retained pinned C stderr",
    )
    if c_relation["thread_identity"] != c_default["thread_identity"]:
        raise EvidenceError("retained pinned C default/custom thread identities differ")

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
    if receipt.get("rust_source_files") != _rust_trace_source_files():
        raise ValueError("fault inventory Rust trace source changed")
    _parse_fixed_trace(
        output, begin=RUST_TRACE_BEGIN, end=RUST_TRACE_END,
        keys=RUST_TRACE_KEYS, source="retained Rust stream",
    )
    rust_relation = _parse_fault_diagnostic_relation_trace(
        output, begin=FAULT_DIAGNOSTIC_RUST_TRACE_BEGIN,
        end=FAULT_DIAGNOSTIC_RUST_TRACE_END, source="retained Rust stream",
    )
    rust_default = _parse_fault_diagnostic_default_stderr(
        rust_run["stderr"], begin=FAULT_DIAGNOSTIC_DEFAULT_RUST_BEGIN,
        end=FAULT_DIAGNOSTIC_DEFAULT_RUST_END, source="retained Rust stderr",
    )
    if rust_relation["thread_identity"] != rust_default["thread_identity"]:
        raise EvidenceError("retained Rust default/custom thread identities differ")
    if c_relation["body"] != rust_relation["body"] or c_default["body"] != rust_default["body"]:
        raise EvidenceError("retained C/Rust source mbind warning body differs")
    return dict(receipt)


def validate_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the immutable, current-source fault admission receipt shape."""

    if report.get("profile") == "os-aligned-page-publication":
        return validate_os_publication_report(report)
    if report.get("profile") == "metadata-page-publication":
        return validate_metadata_publication_report(report)
    if "os_publication_receipt" not in report:
        raise ValueError("fault inventory OS publication receipt is missing")
    if "metadata_publication_receipt" not in report:
        raise ValueError("fault inventory metadata publication receipt is missing")
    expected_keys = {
        "architecture", "branch_records", "diagnostic_owner_boundary", "format", "os_publication_receipt",
        "metadata_publication_receipt",
        "fault_component_fragment", "huge_branch_receipt", "inventory", "nonclaims", "schema", "status",
        "stopped_receivers", "source_state_after", "source_state_before", "upstream",
        "unqualified_branches", "vm_receipt",
    }
    if "fault_component_fragment" not in report:
        raise ValueError("fault inventory fragment receipt is missing")
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
    fragment_receipt = fault_component_fragment_receipt()
    if report.get("fault_component_fragment") != fragment_receipt:
        raise ValueError("fault inventory fragment receipt changed")
    huge_receipt = _validate_huge_branch_receipt(report.get("huge_branch_receipt"), runner)
    os_receipt = validate_os_publication_report(report["os_publication_receipt"])
    metadata_receipt = validate_metadata_publication_report(report["metadata_publication_receipt"])
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
    if report.get("nonclaims") != list(NONCLAIMS):
        raise ValueError("fault inventory nonclaims changed")
    nonclaims = list(NONCLAIMS)
    try:
        before = runner.validate_runtime_ticket_zero_soak_source_state(
            report.get("source_state_before"), "fault inventory source before"
        )
        after = runner.validate_runtime_ticket_zero_soak_source_state(
            report.get("source_state_after"), "fault inventory source after"
        )
    except runner.HarnessError as error:
        raise ValueError("fault inventory source attestation changed") from error
    if (not before["worktree_clean"] or before != after or os_receipt["source_state_before"] != before
            or metadata_receipt["source_state_before"] != before):
        raise ValueError("fault inventory source state is not one clean revision")
    return {
        "branch_records": records,
        "diagnostic_owner_boundary": dict(DIAGNOSTIC_OWNER_BOUNDARY),
        "fault_component_fragment": fragment_receipt,
        "huge_branch_receipt": huge_receipt,
        "os_publication_receipt": os_receipt,
        "metadata_publication_receipt": metadata_receipt,
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


_FAULT_DIAGNOSTIC_DEFAULT_MESSAGE = (
    b"failed to bind huge (1GiB) pages to numa node 62 (error: 1 (0x01))\n"
)
_FAULT_DIAGNOSTIC_DEFAULT_LINE = re.compile(
    rb"mimalloc: warning: thread 0x([0-9A-F]+): "
    + re.escape(_FAULT_DIAGNOSTIC_DEFAULT_MESSAGE[:-1])
)


def _extract_one_complete_lf_frame(stream: str, *, begin: str, end: str, source: str) -> bytes:
    """Return one exact line-delimited marker frame without line normalization.

    The selected C `fputs(stderr)` observation and its Rust caller-supplied
    musl bridge both produce ASCII source text.  Retain the authenticated
    process stream as-is and use literal LF separators only: Python's
    `splitlines` would incorrectly treat CR, VT, FF, and Unicode separators as
    marker boundaries.
    """

    try:
        raw = stream.encode("ascii")
    except UnicodeEncodeError as error:
        raise EvidenceError(f"{source} default stderr is not source ASCII") from error
    begin_line = begin.encode("ascii")
    end_line = end.encode("ascii")
    lines = raw.split(b"\n")
    begin_indexes = [index for index, line in enumerate(lines) if line == begin_line]
    end_indexes = [index for index, line in enumerate(lines) if line == end_line]
    if len(begin_indexes) != 1 or len(end_indexes) != 1:
        raise EvidenceError(f"{source} default stderr marker count changed")
    start = begin_indexes[0]
    finish = end_indexes[0]
    if finish <= start:
        raise EvidenceError(f"{source} default stderr markers are reversed")
    # A marker at the final split position has no literal LF after it.  CRLF
    # markers are not equal to their source-LF spelling above and are rejected.
    if finish == len(lines) - 1:
        raise EvidenceError(f"{source} default stderr end marker lacks LF")
    return b"\n".join(lines[start:finish + 1]) + b"\n"


def _parse_fault_diagnostic_default_stderr(
    stream: str, *, begin: str, end: str, source: str,
) -> dict[str, int | str]:
    """Reconstruct the one valid-node source default-sink warning frame.

    This finite reader binds the actual `options.c` post-init flush byte image:
    one source warning prefix and the fixed node-62/EPERM `prim.c` body.  It
    does not trim or synthesize the delayed image that `mi_out_buf_flush`
    retains for a later registration: that flushed warning plus its appended
    continuation LF.
    """

    frame = _extract_one_complete_lf_frame(stream, begin=begin, end=end, source=source)
    lines = frame.split(b"\n")
    # begin, one warning line, end, then the required terminal empty entry.
    if len(lines) != 4:
        raise EvidenceError(f"{source} default stderr payload shape changed")
    match = _FAULT_DIAGNOSTIC_DEFAULT_LINE.fullmatch(lines[1])
    if match is None:
        raise EvidenceError(f"{source} default stderr payload changed")
    raw_identity = match.group(1)
    if len(raw_identity) > 1 and raw_identity.startswith(b"0"):
        raise EvidenceError(f"{source} default stderr thread identity is noncanonical")
    identity = int(raw_identity, 16)
    return {
        "body": _FAULT_DIAGNOSTIC_DEFAULT_MESSAGE.decode("ascii"),
        "frame": frame.decode("ascii"),
        "thread_identity": identity,
    }


def _parse_fault_diagnostic_relation_trace(
    stream: str, *, begin: str, end: str, source: str,
) -> dict[str, Any]:
    """Read the finite source-receiver trace without address masking.

    C and Rust naturally have different TLS addresses. Each side therefore
    retains its own decimal identity, and this reader independently rebuilds
    the source's uppercase prefix before comparing the invariant body and
    selected control-flow fields. A malformed, noncanonical, or mismatched
    prefix cannot be admitted by dropping arbitrary address bytes.
    """

    frame = _extract_one_complete_lf_frame(stream, begin=begin, end=end, source=source)
    lines = frame.split(b"\n")
    expected_line_count = len(FAULT_DIAGNOSTIC_TRACE_KEYS) + len(FAULT_DIAGNOSTIC_TRACE_TAIL_KEYS) + 3
    if len(lines) != expected_line_count:
        raise EvidenceError(f"{source} fault-diagnostic relation trace shape changed")
    values: dict[str, str] = {}
    for line in lines[1:-2]:
        if line.count(b"=") != 1:
            raise EvidenceError(f"{source} fault-diagnostic relation observation is malformed")
        raw_key, raw_value = line.split(b"=", 1)
        try:
            key = raw_key.decode("ascii")
            value = raw_value.decode("ascii")
        except UnicodeDecodeError as error:
            raise EvidenceError(f"{source} fault-diagnostic relation is not ASCII") from error
        if not key or not value or key in values:
            raise EvidenceError(f"{source} fault-diagnostic relation observation changed")
        values[key] = value
    expected_keys = (*FAULT_DIAGNOSTIC_TRACE_KEYS, *FAULT_DIAGNOSTIC_TRACE_TAIL_KEYS)
    if tuple(values) != expected_keys:
        raise EvidenceError(f"{source} fault-diagnostic relation key order changed")
    if any(values[key] != "1" for key in FAULT_DIAGNOSTIC_TRACE_KEYS):
        raise EvidenceError(f"{source} fault-diagnostic relation control flow changed")
    identity_text = values["custom_thread_identity"]
    if not identity_text.isdecimal() or (len(identity_text) > 1 and identity_text.startswith("0")):
        raise EvidenceError(f"{source} fault-diagnostic relation identity changed")
    identity = int(identity_text, 10)
    encoded: dict[str, bytes] = {}
    for key in ("default_continuation_hex", "custom_prefix_hex", "custom_body_hex"):
        raw = values[key]
        if not raw or len(raw) % 2 != 0 or any(character not in "0123456789abcdef" for character in raw):
            raise EvidenceError(f"{source} fault-diagnostic relation fragment changed")
        encoded[key] = bytes.fromhex(raw)
    expected_prefix = f"mimalloc: warning: thread 0x{identity:X}: ".encode("ascii")
    if encoded["custom_prefix_hex"] != expected_prefix:
        raise EvidenceError(f"{source} fault-diagnostic relation prefix identity mismatched")
    if encoded["custom_body_hex"] != _FAULT_DIAGNOSTIC_DEFAULT_MESSAGE:
        raise EvidenceError(f"{source} fault-diagnostic relation body changed")
    if encoded["default_continuation_hex"] != (
        expected_prefix + _FAULT_DIAGNOSTIC_DEFAULT_MESSAGE + b"\n"
    ):
        raise EvidenceError(f"{source} fault-diagnostic delayed continuation changed")
    return {
        "body": encoded["custom_body_hex"],
        "continuation": encoded["default_continuation_hex"],
        "prefix": encoded["custom_prefix_hex"],
        "thread_identity": identity,
    }


def _parse_huge_branch_diagnosis(output: str) -> list[dict[str, int | str]]:
    """Read the finite C-only failed-conjunction control without inferring success."""

    lines = output.splitlines()
    if not lines or lines[0] != HUGE_BRANCH_DIAGNOSTIC_BEGIN or lines[-1] != HUGE_BRANCH_DIAGNOSTIC_END:
        raise ValueError("huge branch diagnosis markers changed")
    if len(lines) != len(HUGE_BRANCH_DIAGNOSTIC_CASES) + 2:
        raise ValueError("huge branch diagnosis case roster changed")
    rows: list[dict[str, int | str]] = []
    expected_fields = set(HUGE_BRANCH_DIAGNOSTIC_FIELDS)
    for expected_case, line in zip(HUGE_BRANCH_DIAGNOSTIC_CASES, lines[1:-1]):
        values: dict[str, str] = {}
        for token in line.split(" "):
            if token.count("=") != 1:
                raise ValueError("huge branch diagnosis observation is malformed")
            key, value = token.split("=", 1)
            if not key or not value or key in values:
                raise ValueError("huge branch diagnosis observation is malformed")
            values[key] = value
        if set(values) != expected_fields or values.get("case") != expected_case:
            raise ValueError("huge branch diagnosis case roster changed")
        row: dict[str, int | str] = {"case": expected_case}
        for key in expected_fields - {"case", *HUGE_BRANCH_DIAGNOSTIC_FRAGMENT_FIELDS}:
            try:
                parsed = int(values[key], 10)
            except ValueError as error:
                raise ValueError("huge branch diagnosis integer changed") from error
            row[key] = parsed
        for key in HUGE_BRANCH_DIAGNOSTIC_FRAGMENT_FIELDS:
            fragment = values[key]
            if fragment != "-" and (
                len(fragment) % 2 != 0 or any(character not in "0123456789abcdef" for character in fragment)
            ):
                raise ValueError("huge branch diagnosis fragment changed")
            row[key] = fragment
        if row["selected"] != HUGE_BRANCH_DIAGNOSTIC_SELECTED[expected_case]:
            raise ValueError("huge branch diagnosis selected arm changed")
        if any(row[key] not in (0, 1) for key in HUGE_BRANCH_DIAGNOSTIC_BOOLEAN_FIELDS):
            raise ValueError("huge branch diagnosis Boolean changed")
        if row["captured"] != 1 or row["exit_status"] not in (0, 3):
            raise ValueError("huge branch diagnosis child capture changed")
        if any(row[key] < 0 for key in HUGE_BRANCH_DIAGNOSTIC_COUNT_FIELDS):
            raise ValueError("huge branch diagnosis count changed")
        for length_key, fragment_key in (
            ("diagnostic_first_length", "diagnostic_first_hex"),
            ("diagnostic_second_length", "diagnostic_second_hex"),
        ):
            fragment = str(row[fragment_key])
            if (row[length_key] == 0 and fragment != "-") or (
                row[length_key] != 0 and len(fragment) != row[length_key] * 2
            ):
                raise ValueError("huge branch diagnosis fragment length changed")
        rows.append(row)
    if len(rows) != len(HUGE_BRANCH_DIAGNOSTIC_CASES):
        raise ValueError("huge branch diagnosis case roster changed")
    return rows


def _write_huge_branch_diagnosis_raw(
    runner: Any, artifacts: Path, attempt: Mapping[str, Any], run: Mapping[str, Any],
) -> dict[str, Any]:
    """Persist the direct C execution before any diagnostic-output interpretation."""

    raw = {**attempt, "run": dict(run), "status": "unadmitted"}
    runner.write_json(artifacts / "huge-branch-diagnosis.raw.json", raw)
    return raw


def _admit_huge_branch_diagnosis_run(
    runner: Any, artifacts: Path, attempt: Mapping[str, Any], run: Mapping[str, Any], *,
    raw_already_retained: bool = False,
) -> dict[str, Any]:
    """Parse a retained C-only control; this never marks the fault inventory passed."""

    if not raw_already_retained:
        _write_huge_branch_diagnosis_raw(runner, artifacts, attempt, run)
    observations = _parse_huge_branch_diagnosis(str(run["stdout"]))
    report = {
        **attempt,
        "observations": observations,
        "run": dict(run),
        "status": "diagnostic-observations",
    }
    runner.write_json(artifacts / "huge-branch-diagnosis.json", report)
    return report


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


def _workspace_relative(runner: Any, path: Path) -> str:
    """Return a physical runner-work-root child without accepting a symlink escape."""

    work_root = Path(runner.WORK_ROOT)
    if work_root.is_symlink():
        raise EvidenceError("fault inventory runner work root is a symlink")
    try:
        relative = path.resolve().relative_to(work_root.resolve())
    except ValueError as error:
        raise EvidenceError("fault inventory retained profile escapes the runner work root") from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise EvidenceError("fault inventory retained profile path is not a child")
    return relative.as_posix()


def _retained_profile_directory_record(runner: Any, profile: Path) -> dict[str, Any]:
    """Capture the concrete, non-symlink directory holding compiler input."""

    try:
        metadata = profile.lstat()
    except OSError as error:
        raise EvidenceError("fault inventory retained profile directory is missing") from error
    if profile.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError("fault inventory retained profile directory changed type")
    return {
        "kind": "directory",
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": _workspace_relative(runner, profile),
    }


def _retained_profile_file_record(runner: Any, path: Path) -> dict[str, Any]:
    """Capture one regular, non-symlink compiler-input file and its bytes."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError("fault inventory retained profile file is missing") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError("fault inventory retained profile file changed type")
    payload = path.read_bytes()
    return {
        "bytes": len(payload),
        "kind": "regular",
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": _workspace_relative(runner, path),
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
    direct.chmod(MBIND_PROFILE_FILE_MODE)
    derived_unix.chmod(MBIND_PROFILE_FILE_MODE)
    records = []
    for path, expected in zip((direct, derived_unix), MBIND_PROFILE_DERIVED_FILES):
        payload = path.read_bytes()
        records.append({
            "bytes": len(payload),
            "path": expected["path"],
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    if records != list(MBIND_PROFILE_DERIVED_FILES):
        raise EvidenceError("fault inventory mbind direct-include derived bytes changed")
    return direct


def _new_retained_mbind_profile(
    runner: Any, source: Path, artifacts: Path, *, artifact_name: str
) -> tuple[Path, Path]:
    """Materialize one immutable overlay below the evidence root, never tmp.

    A failed compile or run deliberately retains its direct include for later
    inspection.  The next same-mode collection must therefore allocate a new
    owned directory rather than overwriting or requiring deletion of that
    partial evidence.
    """

    artifacts.mkdir(parents=True, exist_ok=True)
    if artifacts.is_symlink() or not artifacts.is_dir():
        raise EvidenceError("fault inventory artifact root changed type")
    if not re.fullmatch(r"[a-z][a-z0-9-]*", artifact_name):
        raise EvidenceError("fault inventory retained profile name is invalid")
    profile = Path(tempfile.mkdtemp(prefix=f"{artifact_name}-", dir=artifacts))
    try:
        profile.relative_to(artifacts)
        profile.resolve().parent.relative_to(artifacts.resolve())
        artifacts.resolve().relative_to((ROOT / ".work").resolve())
    except ValueError as error:
        raise EvidenceError("fault inventory retained profile root escapes checkout work") from error
    profile.chmod(MBIND_PROFILE_DIRECTORY_MODE)
    _retained_profile_directory_record(runner, profile)
    return profile, _write_mbind_profile(source, profile)


def _retained_profile_file_records(runner: Any, profile: Path) -> list[dict[str, Any]]:
    return [
        _retained_profile_file_record(runner, profile / "prim.c"),
        _retained_profile_file_record(runner, profile / "unix/prim.c"),
    ]


def _expected_retained_profile_file_records(profile_path: str) -> list[dict[str, Any]]:
    return [
        {
            "bytes": expected["bytes"],
            "kind": "regular",
            "mode": MBIND_PROFILE_FILE_MODE,
            "path": f"{profile_path}/{expected['path']}",
            "sha256": expected["sha256"],
        }
        for expected in MBIND_PROFILE_DERIVED_FILES
    ]


def _mbind_profile_record(
    runner: Any,
    profile: Path,
    direct_include: Path,
    *,
    pre_compile_files: Sequence[Mapping[str, Any]],
    post_compile_files: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Retain the actual compiler input and its pre/post compilation identity."""

    directory = _retained_profile_directory_record(runner, profile)
    profile_path = directory["path"]
    expected = _expected_retained_profile_file_records(profile_path)
    expected_compiler_input = CONTAINER_WORK_ROOT / profile_path / "prim.c"
    if (
        list(pre_compile_files) != expected
        or list(post_compile_files) != expected
        or _retained_profile_file_records(runner, profile) != expected
        or direct_include != profile / "prim.c"
        or str(direct_include) != str(expected_compiler_input)
    ):
        raise EvidenceError("fault inventory retained profile compiler input changed")
    return {
        "compiler_direct_include": str(expected_compiler_input),
        "derived_files": expected,
        "directory": directory,
        "direct_include": expected[0],
        "input_source_files": [dict(record) for record in MBIND_PROFILE_PINNED_SOURCE_FILES],
        "post_compile_files": expected,
        "pre_compile_files": expected,
        "single_replacement": dict(MBIND_PROFILE_SINGLE_REPLACEMENT),
    }


def _validate_mbind_profile_record(value: object, runner: Any) -> Path:
    """Re-open the retained C compiler input and bind it to the macro argv."""

    expected_keys = {
        "compiler_direct_include", "derived_files", "directory", "direct_include",
        "input_source_files", "post_compile_files", "pre_compile_files", "single_replacement",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise ValueError("fault inventory mbind direct-include profile changed")
    directory = value.get("directory")
    if (
        not isinstance(directory, Mapping)
        or set(directory) != {"kind", "mode", "path"}
        or directory.get("kind") != "directory"
        or directory.get("mode") != MBIND_PROFILE_DIRECTORY_MODE
        or not isinstance(directory.get("path"), str)
        or not directory["path"]
        or Path(directory["path"]).is_absolute()
        or any(part in {"", ".", ".."} for part in Path(directory["path"]).parts)
    ):
        raise ValueError("fault inventory retained profile directory changed")
    profile = Path(runner.WORK_ROOT) / directory["path"]
    artifact_root = Path(runner.ARTIFACT_ROOT)
    if artifact_root.is_symlink() or not artifact_root.is_dir():
        raise ValueError("fault inventory artifact root changed type")
    try:
        profile.resolve().relative_to(artifact_root.resolve())
    except ValueError as error:
        raise ValueError("fault inventory retained profile is outside owned artifacts") from error
    try:
        actual_directory = _retained_profile_directory_record(runner, profile)
    except EvidenceError as error:
        raise ValueError("fault inventory retained profile directory cannot be replayed") from error
    if actual_directory != dict(directory):
        raise ValueError("fault inventory retained profile directory changed")
    expected_files = _expected_retained_profile_file_records(directory["path"])
    if (
        value.get("direct_include") != expected_files[0]
        or value.get("derived_files") != expected_files
        or value.get("pre_compile_files") != expected_files
        or value.get("post_compile_files") != expected_files
        or value.get("input_source_files") != list(MBIND_PROFILE_PINNED_SOURCE_FILES)
        or value.get("single_replacement") != MBIND_PROFILE_SINGLE_REPLACEMENT
    ):
        raise ValueError("fault inventory retained profile bytes changed")
    try:
        actual_files = _retained_profile_file_records(runner, profile)
    except EvidenceError as error:
        raise ValueError("fault inventory retained profile files cannot be replayed") from error
    if actual_files != expected_files:
        raise ValueError("fault inventory retained profile files changed after compilation")
    compiler_direct_include = value.get("compiler_direct_include")
    expected_compiler_input = str(CONTAINER_WORK_ROOT / directory["path"] / "prim.c")
    if compiler_direct_include != expected_compiler_input:
        raise ValueError("fault inventory compiler direct include does not join retained profile")
    return Path(compiler_direct_include)


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
    runner: Any, compiler: str, source: Path, binary: Path, *, direct_include: Path,
    fixture: Path = FIXTURE,
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
        str(fixture),
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


def _canonical_m2_vm_c_compile_command(
    runner: Any, compiler: str, source: Path, binary: Path,
) -> list[str]:
    """Rebuild the uninstrumented M2 C oracle without running its VM trace.

    This is the exact ordinary C command owned by `m2_vm_x86_64.py`.  The
    fault-inventory helpers must remain absent from this compilation unless
    their explicit profile is selected, so this narrow control catches a
    missing test-only preprocessor boundary before the full VM producer.
    """

    return [
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
        *runner.CONFIGURATION_PROFILES["release"],
        str(CANONICAL_M2_VM_FIXTURE),
        *(str(source / item) for item in runner.M2_X86_64_VM_C_ORACLE_SOURCES),
        "-Wl,--wrap=munmap",
        "-Wl,--wrap=mmap",
        "-Wl,--wrap=madvise",
        "-Wl,--wrap=mprotect",
        "-Wl,--wrap=prctl",
        "-pthread",
        "-o",
        str(binary),
    ]


def _fixture_command_argument_is_bound(argument: str) -> bool:
    """Accept the local or fixed Docker spelling of this one tracked fixture."""

    return argument in {
        str(FIXTURE),
        str(CONTAINER_CHECKOUT_ROOT / FIXTURE.relative_to(ROOT)),
    }


def _bound_huge_branch_c_command(
    runner: Any, command: Sequence[str], source: Path, binary: Path, direct_include: Path,
    *, mbind_boundary: bool = False,
) -> list[str] | None:
    """Reconstruct one C argv while preserving its fixed host/container fixture path."""

    builder = _mbind_boundary_c_command if mbind_boundary else _huge_branch_c_command
    expected_local = builder(runner, command[0], source, binary, direct_include=direct_include)
    try:
        fixture_index = expected_local.index(str(FIXTURE))
    except ValueError as error:
        raise EvidenceError("fault inventory C command lost its fixture position") from error
    if len(command) != len(expected_local) or not _fixture_command_argument_is_bound(command[fixture_index]):
        return None
    return builder(
        runner, command[0], source, binary, direct_include=direct_include,
        fixture=Path(command[fixture_index]),
    )


def _huge_retry_helper_c_command(
    runner: Any, compiler: str, source: Path, binary: Path, *, direct_include: Path
) -> list[str]:
    """Build the fixture's finite partial-retry predicate as an isolated binary."""

    command = _huge_branch_c_command(
        runner, compiler, source, binary, direct_include=direct_include
    )
    command.insert(command.index(FAULT_PROFILE_DEFINE) + 1, HUGE_RETRY_HELPER_TEST_DEFINE)
    return command


def _huge_branch_diagnostic_c_command(
    runner: Any, compiler: str, source: Path, binary: Path, *, direct_include: Path
) -> list[str]:
    """Build the isolated C control that retains each fixed huge-arm conjunction."""

    command = _huge_branch_c_command(
        runner, compiler, source, binary, direct_include=direct_include
    )
    command.insert(command.index(FAULT_PROFILE_DEFINE) + 1, HUGE_BRANCH_DIAGNOSTIC_TEST_DEFINE)
    return command


def _huge_timeout_clock_helper_c_command(
    runner: Any, compiler: str, source: Path, binary: Path, *, direct_include: Path
) -> list[str]:
    """Build the isolated source-calibrated huge-timeout clock regression."""

    command = _huge_branch_c_command(
        runner, compiler, source, binary, direct_include=direct_include
    )
    command.insert(command.index(FAULT_PROFILE_DEFINE) + 1, HUGE_TIMEOUT_CLOCK_HELPER_TEST_DEFINE)
    return command


def _huge_placement_warning_helper_c_command(
    runner: Any, compiler: str, source: Path, binary: Path, *, direct_include: Path
) -> list[str]:
    """Build the isolated pinned primitive placement-warning regression."""

    command = _huge_branch_c_command(
        runner, compiler, source, binary, direct_include=direct_include
    )
    command.insert(command.index(FAULT_PROFILE_DEFINE) + 1, HUGE_PLACEMENT_WARNING_HELPER_TEST_DEFINE)
    return command


def _mbind_boundary_c_command(
    runner: Any, compiler: str, source: Path, binary: Path, *, direct_include: Path,
    fixture: Path = FIXTURE,
) -> list[str]:
    """Compile the isolated `mi_prim_mbind` boundary regression."""

    command = _huge_branch_c_command(
        runner, compiler, source, binary, direct_include=direct_include, fixture=fixture
    )
    command.insert(command.index(FAULT_PROFILE_DEFINE) + 1, MBIND_BOUNDARY_TEST_DEFINE)
    return command


def run_canonical_m2_vm_c_compile_regression(*, offline: bool) -> dict[str, Any]:
    """Compile only the ordinary M2 C fixture before the fault-profile lane.

    The retained record is a compiler-bound regression control. It neither
    runs the VM fixture nor admits a fault-inventory or M2 evidence report.
    """

    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        compiler = runner.require_tool("musl-gcc")
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        artifacts.mkdir(parents=True, exist_ok=True)
        with runner.temporary_directory(prefix="crabc-mimalloc-fault-seam-canonical-m2-vm-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            binary = artifacts / "m2-vm-primitives-canonical-compile-regression"
            build = runner.command_record(
                _canonical_m2_vm_c_compile_command(runner, compiler, source, binary),
                cwd=source,
                timeout_seconds=300,
            )
            report = {
                "build": {**build, "cwd": str(source)},
                "c_source_files": list(runner.M2_X86_64_VM_C_ORACLE_SOURCES),
                "fixture": runner.artifact_record(CANONICAL_M2_VM_FIXTURE),
                "format": 1,
                "schema": CANONICAL_M2_VM_C_COMPILE_REGRESSION_SCHEMA,
                "upstream": {
                    "archive_sha256": pin["sha256"],
                    "revision": pin["revision"],
                },
            }
            runner.write_json(artifacts / "canonical-m2-vm-c-compile-regression.json", report)
            runner.require_success(build, "pinned C native x86 M2 VM oracle build")
            return report
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error


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
            profile, direct_include = _new_retained_mbind_profile(
                runner, source, artifacts, artifact_name="compile-mbind-direct-include"
            )
            pre_compile_files = _retained_profile_file_records(runner, profile)
            binary = artifacts / "m2-fault-seam-inventory-huge-oracle"
            command = _huge_branch_c_command(
                runner, compiler, source, binary, direct_include=direct_include
            )
            build = runner.command_record(command, cwd=source, timeout_seconds=300)
            runner.require_success(build, "pinned C native x86 fault-seam huge profile build")
            post_compile_files = _retained_profile_file_records(runner, profile)
            return {
                "command": command,
                "fixture": runner.artifact_record(FIXTURE),
                "mbind_direct_include_profile": _mbind_profile_record(
                    runner, profile, direct_include,
                    pre_compile_files=pre_compile_files, post_compile_files=post_compile_files,
                ),
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
            profile, direct_include = _new_retained_mbind_profile(
                runner, source, artifacts, artifact_name="retry-helper-mbind-direct-include"
            )
            pre_compile_files = _retained_profile_file_records(runner, profile)
            binary = artifacts / "m2-fault-seam-retry-helper"
            build = runner.command_record(
                _huge_retry_helper_c_command(
                    runner, compiler, source, binary, direct_include=direct_include
                ),
                cwd=source,
                timeout_seconds=300,
            )
            runner.require_success(build, "pinned C partial huge retry helper build")
            post_compile_files = _retained_profile_file_records(runner, profile)
            run = runner.command_record([str(binary)], cwd=source, timeout_seconds=60)
            runner.require_success(run, "pinned C partial huge retry helper")
            if str(run["stdout"]) != "allocator fault seam partial huge retry helper: PASS\n" or run["stderr"]:
                raise EvidenceError("pinned C partial huge retry helper output changed")
            report = {
                "build": {**build, "cwd": str(source)},
                "fixture": runner.artifact_record(FIXTURE),
                "format": 1,
                "mbind_direct_include_profile": _mbind_profile_record(
                    runner, profile, direct_include,
                    pre_compile_files=pre_compile_files, post_compile_files=post_compile_files,
                ),
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


def run_huge_timeout_clock_helper_regression(*, offline: bool) -> dict[str, Any]:
    """Execute only the four-read source-calibrated C timeout helper."""

    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        compiler = runner.require_tool("musl-gcc")
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        artifacts.mkdir(parents=True, exist_ok=True)
        with runner.temporary_directory(prefix="crabc-mimalloc-fault-seam-timeout-clock-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            _source_files(runner, source)
            profile, direct_include = _new_retained_mbind_profile(
                runner, source, artifacts, artifact_name="timeout-clock-helper-mbind-direct-include"
            )
            pre_compile_files = _retained_profile_file_records(runner, profile)
            binary = artifacts / "m2-fault-seam-timeout-clock-helper"
            build = runner.command_record(
                _huge_timeout_clock_helper_c_command(
                    runner, compiler, source, binary, direct_include=direct_include
                ),
                cwd=source,
                timeout_seconds=300,
            )
            post_compile_files = _retained_profile_file_records(runner, profile)
            attempt = {
                "build": {**build, "cwd": str(source)},
                "fixture": runner.artifact_record(FIXTURE),
                "format": 1,
                "mbind_direct_include_profile": _mbind_profile_record(
                    runner, profile, direct_include,
                    pre_compile_files=pre_compile_files, post_compile_files=post_compile_files,
                ),
                "schema": HUGE_TIMEOUT_CLOCK_HELPER_SCHEMA,
                "upstream": {
                    "archive_sha256": pin["sha256"],
                    "revision": pin["revision"],
                },
            }
            runner.write_json(artifacts / "huge-timeout-clock-helper.build.json", attempt)
            runner.require_success(build, "pinned C huge timeout clock helper build")
            run = {**runner.command_record([str(binary)], cwd=source, timeout_seconds=60), "cwd": str(source)}
            raw = {**attempt, "run": run, "status": "unadmitted"}
            runner.write_json(artifacts / "huge-timeout-clock-helper.raw.json", raw)
            runner.require_success(run, "pinned C huge timeout clock helper")
            if str(run["stdout"]) != "allocator fault seam timeout clock helper: PASS\n" or run["stderr"]:
                raise EvidenceError("pinned C huge timeout clock helper output changed")
            report = {**attempt, "run": run, "status": "passed"}
            runner.write_json(artifacts / "huge-timeout-clock-helper.json", report)
            return report
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error


def run_huge_placement_warning_helper_regression(*, offline: bool) -> dict[str, Any]:
    """Execute only the typed-mbind pinned C placement warning helper."""

    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        compiler = runner.require_tool("musl-gcc")
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        artifacts.mkdir(parents=True, exist_ok=True)
        with runner.temporary_directory(prefix="crabc-mimalloc-fault-seam-placement-warning-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            _source_files(runner, source)
            profile, direct_include = _new_retained_mbind_profile(
                runner, source, artifacts, artifact_name="placement-warning-helper-mbind-direct-include"
            )
            pre_compile_files = _retained_profile_file_records(runner, profile)
            binary = artifacts / "m2-fault-seam-placement-warning-helper"
            build = runner.command_record(
                _huge_placement_warning_helper_c_command(
                    runner, compiler, source, binary, direct_include=direct_include
                ),
                cwd=source,
                timeout_seconds=300,
            )
            post_compile_files = _retained_profile_file_records(runner, profile)
            attempt = {
                "build": {**build, "cwd": str(source)},
                "fixture": runner.artifact_record(FIXTURE),
                "format": 1,
                "mbind_direct_include_profile": _mbind_profile_record(
                    runner, profile, direct_include,
                    pre_compile_files=pre_compile_files, post_compile_files=post_compile_files,
                ),
                "schema": HUGE_PLACEMENT_WARNING_HELPER_SCHEMA,
                "upstream": {
                    "archive_sha256": pin["sha256"],
                    "revision": pin["revision"],
                },
            }
            runner.write_json(artifacts / "huge-placement-warning-helper.build.json", attempt)
            runner.require_success(build, "pinned C huge placement warning helper build")
            run = {**runner.command_record([str(binary)], cwd=source, timeout_seconds=60), "cwd": str(source)}
            raw = {**attempt, "run": run, "status": "unadmitted"}
            runner.write_json(artifacts / "huge-placement-warning-helper.raw.json", raw)
            runner.require_success(run, "pinned C huge placement warning helper")
            if str(run["stdout"]) != "allocator fault seam placement warning helper: PASS\n" or run["stderr"]:
                raise EvidenceError("pinned C huge placement warning helper output changed")
            report = {**attempt, "run": run, "status": "passed"}
            runner.write_json(artifacts / "huge-placement-warning-helper.json", report)
            return report
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error


def run_huge_branch_diagnosis(*, offline: bool) -> dict[str, Any]:
    """Run the C-only diagnostic control after a failed fixed huge-arm matrix."""

    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        compiler = runner.require_tool("musl-gcc")
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        artifacts.mkdir(parents=True, exist_ok=True)
        with runner.temporary_directory(prefix="crabc-mimalloc-fault-seam-huge-diagnosis-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            _source_files(runner, source)
            profile, direct_include = _new_retained_mbind_profile(
                runner, source, artifacts, artifact_name="huge-branch-diagnosis-mbind-direct-include"
            )
            pre_compile_files = _retained_profile_file_records(runner, profile)
            binary = artifacts / "m2-fault-seam-huge-branch-diagnosis"
            build = runner.command_record(
                _huge_branch_diagnostic_c_command(
                    runner, compiler, source, binary, direct_include=direct_include
                ),
                cwd=source,
                timeout_seconds=300,
            )
            post_compile_files = _retained_profile_file_records(runner, profile)
            attempt = {
                "build": {**build, "cwd": str(source)},
                "fixture": runner.artifact_record(FIXTURE),
                "format": 1,
                "mbind_direct_include_profile": _mbind_profile_record(
                    runner, profile, direct_include,
                    pre_compile_files=pre_compile_files, post_compile_files=post_compile_files,
                ),
                "schema": HUGE_BRANCH_DIAGNOSTIC_SCHEMA,
                "upstream": {
                    "archive_sha256": pin["sha256"],
                    "revision": pin["revision"],
                },
            }
            runner.write_json(artifacts / "huge-branch-diagnosis.build.json", attempt)
            runner.require_success(build, "pinned C huge branch diagnosis build")
            run = {**runner.command_record([str(binary)], cwd=source, timeout_seconds=60), "cwd": str(source)}
            _write_huge_branch_diagnosis_raw(runner, artifacts, attempt, run)
            runner.require_success(run, "pinned C huge branch diagnosis")
            return _admit_huge_branch_diagnosis_run(
                runner, artifacts, attempt, run, raw_already_retained=True
            )
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
            profile, direct_include = _new_retained_mbind_profile(
                runner, source, artifacts, artifact_name="mbind-boundary-direct-include"
            )
            pre_compile_files = _retained_profile_file_records(runner, profile)
            binary = artifacts / "m2-fault-seam-mbind-boundary"
            build = runner.command_record(
                _mbind_boundary_c_command(
                    runner, compiler, source, binary, direct_include=direct_include
                ),
                cwd=source,
                timeout_seconds=300,
            )
            runner.require_success(build, "pinned C typed mbind boundary build")
            post_compile_files = _retained_profile_file_records(runner, profile)
            run = runner.command_record([str(binary)], cwd=source, timeout_seconds=60)
            runner.require_success(run, "pinned C typed mbind boundary")
            if str(run["stdout"]) != "allocator fault seam mbind boundary: PASS\n" or run["stderr"]:
                raise EvidenceError("pinned C typed mbind boundary output changed")
            report = {
                "build": {**build, "cwd": str(source)},
                "fixture": runner.artifact_record(FIXTURE),
                "format": 1,
                "mbind_direct_include_profile": _mbind_profile_record(
                    runner, profile, direct_include,
                    pre_compile_files=pre_compile_files, post_compile_files=post_compile_files,
                ),
                "run": {**run, "cwd": str(source)},
                "schema": MBIND_BOUNDARY_SCHEMA,
                "upstream": {
                    "archive_sha256": pin["sha256"],
                    "revision": pin["revision"],
                },
            }
            validate_mbind_boundary_report(report)
            runner.write_json(artifacts / "mbind-boundary.json", report)
            return report
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_mbind_boundary_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Replay the isolated typed-mbind boundary without spawning another process."""

    expected_keys = {
        "build", "fixture", "format", "mbind_direct_include_profile", "run", "schema", "upstream",
    }
    if not isinstance(report, Mapping) or set(report) != expected_keys:
        raise ValueError("mbind boundary report fields changed")
    if report.get("schema") != MBIND_BOUNDARY_SCHEMA or report.get("format") != 1:
        raise ValueError("mbind boundary report schema changed")
    runner = _load_runner()
    profile = _validate_mbind_profile_record(report.get("mbind_direct_include_profile"), runner)
    build = _validate_process_record(report.get("build"), label="mbind boundary C build")
    source = Path(build["cwd"])
    command = build["command"]
    if (
        source.name != "mimalloc-3.5.0"
        or Path(command[0]).name != "musl-gcc"
        or len(command) < 3
        or command[-2] != "-o"
    ):
        raise ValueError("mbind boundary C build tool or working directory changed")
    binary = Path(command[-1])
    expected_command = _bound_huge_branch_c_command(
        runner, command, source, binary, profile, mbind_boundary=True
    )
    if command != expected_command:
        raise ValueError("mbind boundary C build command changed")
    run = _validate_process_record(report.get("run"), label="mbind boundary C run")
    if (
        run["cwd"] != build["cwd"]
        or run["command"] != [str(binary)]
        or run["stdout"] != "allocator fault seam mbind boundary: PASS\n"
        or run["stderr"] != ""
    ):
        raise ValueError("mbind boundary C run result changed")
    if report.get("fixture") != _local_file_record(FIXTURE):
        raise ValueError("mbind boundary generated fixture provenance changed")
    pin = runner.load_pin()
    if report.get("upstream") != {
        "archive_sha256": pin["sha256"], "revision": pin["revision"],
    }:
        raise ValueError("mbind boundary upstream identity changed")
    return dict(report)


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


def _os_publication_c_command(runner: Any, compiler: str, source: Path, binary: Path) -> list[str]:
    command = _canonical_m2_vm_c_compile_command(runner, compiler, source, binary)
    command.insert(8, OS_PUBLICATION_PROFILE_DEFINE)
    return command


def validate_os_publication_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Replay the independent ordinary OS receiver from retained C/Rust streams."""
    expected = {"schema", "format", "profile", "status", "boundary", "upstream",
        "source_state_before", "source_state_after", "c_build", "c_run", "c_source_files",
        "fixture", "rust_build", "rust_run", "rust_source_files"}
    if set(report) != expected or report.get("schema") != SCHEMA or report.get("format") != FORMAT:
        raise ValueError("OS publication receiver schema changed")
    if (report.get("profile") != "os-aligned-page-publication" or report.get("status") != "passed"
        or report.get("boundary") != OS_PUBLICATION_BOUNDARY):
        raise ValueError("OS publication receiver boundary changed")
    runner = _load_runner()
    pin = runner.load_pin()
    if report.get("upstream") != {"archive_sha256": pin["sha256"], "revision": pin["revision"]}:
        raise ValueError("OS publication upstream changed")
    c_build = _validate_process_record(report.get("c_build"), label="OS publication C build")
    c_run = _validate_process_record(report.get("c_run"), label="OS publication C run")
    source = Path(c_build["cwd"])
    command = c_build["command"]
    if (source.name != "mimalloc-3.5.0" or Path(command[0]).name != "musl-gcc"
        or len(command) < 3 or command[-2] != "-o"
        or command != _os_publication_c_command(runner, command[0], source, Path(command[-1]))):
        raise ValueError("OS publication C source command changed")
    if c_run["cwd"] != str(source) or c_run["command"] != [command[-1]]:
        raise ValueError("OS publication C execution changed")
    if report.get("c_source_files") != list(PINNED_C_SOURCE_FILES) or report.get("fixture") != _local_file_record(FIXTURE):
        raise ValueError("OS publication C source identity changed")
    rust_build = _validate_process_record(report.get("rust_build"), label="OS publication Rust build")
    rust_run = _validate_process_record(report.get("rust_run"), label="OS publication Rust run")
    if (Path(rust_build["command"][0]).name != "cargo"
        or rust_build["command"][1:] != runner._m2_x86_64_vm_rust_build_command()[1:]
        or rust_build["cwd"] != str(ROOT)):
        raise ValueError("OS publication Rust build changed")
    if (rust_run["cwd"] != str(ROOT) or len(rust_run["command"]) != 5
        or rust_run["command"][1:] != [OS_PUBLICATION_TARGET, "--exact", "--test-threads=1", "--nocapture"]
        or not runner._m2_x86_64_vm_rust_binary_path_is_bound(rust_run["command"][0])
        or runner.parse_rust_test_count(_combined_output(rust_run)) != 1
        or report.get("rust_source_files") != _rust_trace_source_files()):
        raise ValueError("OS publication Rust receiver changed")
    for language, record in (("C", c_run), ("Rust", rust_run)):
        _parse_fixed_trace(_combined_output(record), begin=OS_PUBLICATION_BEGIN,
            end=OS_PUBLICATION_END, keys=OS_PUBLICATION_KEYS, source=language)
    before = runner.validate_runtime_ticket_zero_soak_source_state(report.get("source_state_before"), "OS receiver before")
    after = runner.validate_runtime_ticket_zero_soak_source_state(report.get("source_state_after"), "OS receiver after")
    if not before["worktree_clean"] or before != after:
        raise ValueError("OS publication requires one clean unchanged source revision")
    return dict(report)


def run_os_publication_receiver(*, offline: bool, test_program: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Run the ordinary receiver independently; hardware receivers stay required elsewhere."""
    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        before = runner.m2_memory_substrate_source_state()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        artifacts.mkdir(parents=True, exist_ok=True)
        with runner.temporary_directory(prefix="crabc-os-publication-source-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            c_files = _source_files(runner, source)
            binary = artifacts / "m2-os-publication-oracle"
            build = runner.command_record(_os_publication_c_command(runner, runner.require_tool("musl-gcc"), source, binary), cwd=source, timeout_seconds=300)
            runner.write_json(artifacts / "os-publication-c-build.json", build)
            runner.require_success(build, "OS publication C build")
            c_run = runner.command_record([str(binary)], cwd=source, timeout_seconds=90)
            runner.write_json(artifacts / "os-publication-c-run.json", c_run)
            runner.require_success(c_run, "OS publication C receiver")
            c_build = {**build, "cwd": str(source)}
            c_run = {**c_run, "cwd": str(source)}
        if test_program is None:
            test_program = runner._x86_64_unit_test_program(runner._m2_x86_64_vm_rust_execution(),
                runner.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET, gate_name="OS publication receiver")
        rust_run = runner.command_record(runner._x86_64_program_check_command(test_program,
            OS_PUBLICATION_TARGET, nocapture=True, gate_name="OS publication receiver"), cwd=ROOT, timeout_seconds=300)
        runner.write_json(artifacts / "os-publication-rust-run.json", rust_run)
        runner.require_success(rust_run, "OS publication Rust receiver")
        report = {"schema": SCHEMA, "format": FORMAT, "profile": "os-aligned-page-publication",
            "status": "passed", "boundary": OS_PUBLICATION_BOUNDARY,
            "upstream": {"archive_sha256": pin["sha256"], "revision": pin["revision"]},
            "source_state_before": before, "source_state_after": runner.m2_memory_substrate_source_state(),
            "c_build": c_build, "c_run": c_run, "c_source_files": c_files,
            "fixture": runner.artifact_record(FIXTURE),
            "rust_build": {**test_program["build"], "cwd": str(ROOT)},
            "rust_run": {**rust_run, "cwd": str(ROOT)}, "rust_source_files": _rust_trace_source_files()}
        validate_os_publication_report(report)
        runner.write_json(artifacts / "os-publication.json", report)
        return report
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error


def _metadata_publication_c_command(runner: Any, compiler: str, source: Path, binary: Path) -> list[str]:
    command = _canonical_m2_vm_c_compile_command(runner, compiler, source, binary)
    command.insert(8, METADATA_PUBLICATION_PROFILE_DEFINE)
    return command


def _metadata_publication_rust_source_files() -> list[dict[str, Any]]:
    """The OS receiver roster plus the metadata engine and its process owner."""

    return [*_rust_trace_source_files(), *(
        _local_file_record(ROOT / path) for path in METADATA_PUBLICATION_RUST_SOURCE_FILES
    )]


def _parse_metadata_publication_deltas(output: str, *, source: str) -> dict[str, int]:
    """Read the signed committed-byte deltas that C and Rust must share."""

    begin, end = METADATA_PUBLICATION_DELTAS_BEGIN, METADATA_PUBLICATION_DELTAS_END
    if output.count(begin) != 1 or output.count(end) != 1 or output.index(end) < output.index(begin):
        raise EvidenceError(f"{source} metadata publication delta markers changed")
    values: dict[str, int] = {}
    for line in output[output.index(begin) + len(begin):output.index(end)].strip().splitlines():
        match = re.fullmatch(r"([a-z_.0-9]+)=(-?[0-9]+)", line)
        if match is None or match.group(1) in values:
            raise EvidenceError(f"{source} metadata publication delta is malformed: {line}")
        values[match.group(1)] = int(match.group(2))
    if tuple(values) != METADATA_PUBLICATION_DELTA_KEYS:
        raise EvidenceError(f"{source} metadata publication delta roster changed")
    return values


def validate_metadata_publication_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Replay the metadata-publication receiver from retained C/Rust streams."""
    expected = {"schema", "format", "profile", "status", "boundary", "upstream",
        "source_state_before", "source_state_after", "c_build", "c_run", "c_source_files",
        "fixture", "rust_build", "rust_run", "rust_source_files"}
    if set(report) != expected or report.get("schema") != SCHEMA or report.get("format") != FORMAT:
        raise ValueError("metadata publication receiver schema changed")
    if (report.get("profile") != "metadata-page-publication" or report.get("status") != "passed"
        or report.get("boundary") != METADATA_PUBLICATION_BOUNDARY):
        raise ValueError("metadata publication receiver boundary changed")
    runner = _load_runner()
    pin = runner.load_pin()
    if report.get("upstream") != {"archive_sha256": pin["sha256"], "revision": pin["revision"]}:
        raise ValueError("metadata publication upstream changed")
    c_build = _validate_process_record(report.get("c_build"), label="metadata publication C build")
    c_run = _validate_process_record(report.get("c_run"), label="metadata publication C run")
    source = Path(c_build["cwd"])
    command = c_build["command"]
    if (source.name != "mimalloc-3.5.0" or Path(command[0]).name != "musl-gcc"
        or len(command) < 3 or command[-2] != "-o"
        or command != _metadata_publication_c_command(runner, command[0], source, Path(command[-1]))):
        raise ValueError("metadata publication C source command changed")
    if c_run["cwd"] != str(source) or c_run["command"] != [command[-1]]:
        raise ValueError("metadata publication C execution changed")
    if report.get("c_source_files") != list(PINNED_C_SOURCE_FILES) or report.get("fixture") != _local_file_record(FIXTURE):
        raise ValueError("metadata publication C source identity changed")
    rust_build = _validate_process_record(report.get("rust_build"), label="metadata publication Rust build")
    rust_run = _validate_process_record(report.get("rust_run"), label="metadata publication Rust run")
    if (Path(rust_build["command"][0]).name != "cargo"
        or rust_build["command"][1:] != runner._m2_x86_64_vm_rust_build_command()[1:]
        or rust_build["cwd"] != str(ROOT)):
        raise ValueError("metadata publication Rust build changed")
    if (rust_run["cwd"] != str(ROOT) or len(rust_run["command"]) != 5
        or rust_run["command"][1:] != [METADATA_PUBLICATION_TARGET, "--exact", "--test-threads=1", "--nocapture"]
        or not runner._m2_x86_64_vm_rust_binary_path_is_bound(rust_run["command"][0])
        or runner.parse_rust_test_count(_combined_output(rust_run)) != 1
        or report.get("rust_source_files") != _metadata_publication_rust_source_files()):
        raise ValueError("metadata publication Rust receiver changed")
    deltas = []
    for language, record in (("C", c_run), ("Rust", rust_run)):
        _parse_fixed_trace(_combined_output(record), begin=METADATA_PUBLICATION_BEGIN,
            end=METADATA_PUBLICATION_END, keys=METADATA_PUBLICATION_KEYS, source=language)
        deltas.append(_parse_metadata_publication_deltas(_combined_output(record), source=language))
    if deltas[0] != deltas[1]:
        raise ValueError(f"metadata publication committed accounting differs: C {deltas[0]} Rust {deltas[1]}")
    before = runner.validate_runtime_ticket_zero_soak_source_state(report.get("source_state_before"), "metadata receiver before")
    after = runner.validate_runtime_ticket_zero_soak_source_state(report.get("source_state_after"), "metadata receiver after")
    if not before["worktree_clean"] or before != after:
        raise ValueError("metadata publication requires one clean unchanged source revision")
    return dict(report)


def run_metadata_publication_receiver(
    *, offline: bool, test_program: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the metadata-publication receiver as its own C/Rust relation."""
    runner = _load_runner()
    try:
        runner.require_native_x86_64()
        before = runner.m2_memory_substrate_source_state()
        pin = runner.load_pin()
        archive = runner.fetch_archive(pin, offline)
        artifacts = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
        artifacts.mkdir(parents=True, exist_ok=True)
        with runner.temporary_directory(prefix="crabc-metadata-publication-source-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            c_files = _source_files(runner, source)
            binary = artifacts / "m2-metadata-publication-oracle"
            build = runner.command_record(_metadata_publication_c_command(runner, runner.require_tool("musl-gcc"), source, binary), cwd=source, timeout_seconds=300)
            runner.write_json(artifacts / "metadata-publication-c-build.json", build)
            runner.require_success(build, "metadata publication C build")
            c_run = runner.command_record([str(binary)], cwd=source, timeout_seconds=90)
            runner.write_json(artifacts / "metadata-publication-c-run.json", c_run)
            runner.require_success(c_run, "metadata publication C receiver")
            c_build = {**build, "cwd": str(source)}
            c_run = {**c_run, "cwd": str(source)}
        try:
            _parse_fixed_trace(_combined_output(c_run), begin=METADATA_PUBLICATION_BEGIN,
                end=METADATA_PUBLICATION_END, keys=METADATA_PUBLICATION_KEYS, source="pinned C")
        except EvidenceError as error:
            raise EvidenceError(f"{error}:\n{_combined_output(c_run)}") from error
        if test_program is None:
            test_program = runner._x86_64_unit_test_program(runner._m2_x86_64_vm_rust_execution(),
                runner.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET, gate_name="metadata publication receiver")
        rust_run = runner.command_record(runner._x86_64_program_check_command(test_program,
            METADATA_PUBLICATION_TARGET, nocapture=True, gate_name="metadata publication receiver"), cwd=ROOT, timeout_seconds=300)
        runner.write_json(artifacts / "metadata-publication-rust-run.json", rust_run)
        runner.require_success(rust_run, "metadata publication Rust receiver")
        report = {"schema": SCHEMA, "format": FORMAT, "profile": "metadata-page-publication",
            "status": "passed", "boundary": METADATA_PUBLICATION_BOUNDARY,
            "upstream": {"archive_sha256": pin["sha256"], "revision": pin["revision"]},
            "source_state_before": before, "source_state_after": runner.m2_memory_substrate_source_state(),
            "c_build": c_build, "c_run": c_run, "c_source_files": c_files,
            "fixture": runner.artifact_record(FIXTURE),
            "rust_build": {**test_program["build"], "cwd": str(ROOT)},
            "rust_run": {**rust_run, "cwd": str(ROOT)},
            "rust_source_files": _metadata_publication_rust_source_files()}
        try:
            validate_metadata_publication_report(report)
        except ValueError as error:
            raise EvidenceError(str(error)) from error
        runner.write_json(artifacts / "metadata-publication.json", report)
        return report
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error


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
        fragment_receipt = fault_component_fragment_receipt()
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
            arena_owned_check = next(
                check for check in runner.M2_X86_64_ARENA_CHECKS
                if check["id"] == "process-wide-arena-purge-c-rust-differential"
            )
            vm = runner._run_m2_x86_64_vm_evidence(
                offline=offline, test_program=test_program, arena_owned_check=arena_owned_check,
            )
        else:
            vm = _validate_reused_vm_receipt(vm_evidence)
    except runner.HarnessError as error:
        raise EvidenceError(str(error)) from error

    os_receipt = run_os_publication_receiver(offline=offline, test_program=test_program)
    metadata_receipt = run_metadata_publication_receiver(offline=offline, test_program=test_program)
    artifacts.mkdir(parents=True, exist_ok=True)
    try:
        with runner.temporary_directory(prefix="crabc-mimalloc-fault-seam-source-") as temporary:
            source = runner.safe_extract(archive, Path(temporary), pin["archive_root"])
            c_files = _source_files(runner, source)
            profile, direct_include = _new_retained_mbind_profile(
                runner, source, artifacts, artifact_name="huge-profile-mbind-direct-include"
            )
            pre_compile_files = _retained_profile_file_records(runner, profile)
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
            post_compile_files = _retained_profile_file_records(runner, profile)
            c_mbind_direct_include_profile = _mbind_profile_record(
                runner, profile, direct_include,
                pre_compile_files=pre_compile_files, post_compile_files=post_compile_files,
            )
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
        "os_publication_receipt": os_receipt,
        "metadata_publication_receipt": metadata_receipt,
        "branch_records": _branch_records(),
        "format": FORMAT,
        "fault_component_fragment": fragment_receipt,
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
            "rust_source_files": _rust_trace_source_files(),
        },
        "diagnostic_owner_boundary": DIAGNOSTIC_OWNER_BOUNDARY,
        "inventory": inventory_definition(),
        "nonclaims": list(NONCLAIMS),
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
    parser.add_argument("--os-publication-receiver", action="store_true")
    parser.add_argument("--metadata-publication-receiver", action="store_true")
    parser.add_argument("--canonical-m2-vm-c-compile-regression", action="store_true")
    parser.add_argument("--retry-helper-regression", action="store_true")
    parser.add_argument("--timeout-clock-helper-regression", action="store_true")
    parser.add_argument("--placement-warning-helper-regression", action="store_true")
    parser.add_argument("--mbind-boundary-regression", action="store_true")
    parser.add_argument("--huge-branch-diagnosis", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        selected_modes = sum((
            arguments.compile_only,
            arguments.os_publication_receiver,
            arguments.metadata_publication_receiver,
            arguments.canonical_m2_vm_c_compile_regression,
            arguments.retry_helper_regression,
            arguments.timeout_clock_helper_regression,
            arguments.placement_warning_helper_regression,
            arguments.mbind_boundary_regression,
            arguments.huge_branch_diagnosis,
        ))
        if selected_modes > 1:
            raise EvidenceError("fault inventory accepts one focused mode")
        if arguments.os_publication_receiver:
            run_os_publication_receiver(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: OS publication C/Rust receiver PASS "
                  f"({len(OS_PUBLICATION_KEYS)} relations)")
            return 0
        if arguments.metadata_publication_receiver:
            run_metadata_publication_receiver(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: metadata publication C/Rust receiver PASS "
                  f"({len(METADATA_PUBLICATION_KEYS)} relations)")
            return 0
        if arguments.compile_only:
            compile_huge_branch_profile(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: C profile compile PASS")
            return 0
        if arguments.canonical_m2_vm_c_compile_regression:
            run_canonical_m2_vm_c_compile_regression(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: canonical M2 VM C compile PASS")
            return 0
        if arguments.retry_helper_regression:
            run_huge_retry_helper_regression(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: partial huge retry helper PASS")
            return 0
        if arguments.timeout_clock_helper_regression:
            run_huge_timeout_clock_helper_regression(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: huge timeout clock helper PASS")
            return 0
        if arguments.placement_warning_helper_regression:
            run_huge_placement_warning_helper_regression(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: huge placement warning helper PASS")
            return 0
        if arguments.mbind_boundary_regression:
            run_mbind_boundary_regression(offline=arguments.offline)
            print("allocator x86-64 fault seam inventory: typed mbind boundary PASS")
            return 0
        if arguments.huge_branch_diagnosis:
            report = run_huge_branch_diagnosis(offline=arguments.offline)
            print(
                "allocator x86-64 fault seam inventory: huge branch diagnosis PASS "
                f"({len(report['observations'])} fixed C arms)"
            )
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
