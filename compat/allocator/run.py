#!/usr/bin/env python3
"""Build and inventory the pinned mimalloc v3.5.0 C oracle.

This Milestone 0 runner deliberately has no third-party Python dependencies
and never regards the workspace's `libmimalloc-sys` copy as an oracle.  Its
only allocator source input is the SHA-256-verified upstream archive named in
`compat/upstreams.toml`.  It records the existing v3.3.2 integration solely
as migration provenance.

The runner is a source/provenance and C-oracle instrument. Its `--full` mode
also records the reviewed Milestone 5 lifecycle gate, distinguishing executed
bounded evidence from acceptance work that remains blocked. It does not claim
that a Rust allocator operation, adapter symbol, differential trace, or
performance comparison exists before its owning implementation milestone.
Its `--m2` mode records the deliberately partial native memory-substrate gate;
the selected PageMap records cover a success lifecycle, an explicit cold-root
safety divergence, and one initialized lazy-commit failure/retry differential.
They do not establish complete C/Rust PageMap fault or lifecycle parity.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]


def default_work_root() -> Path:
    """Return the checkout-local boundary for runner-owned mutable state."""

    configured = os.environ.get("CRABC_WORK_DIR")
    if not configured:
        return ROOT / ".work"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else ROOT / path


WORK_ROOT = default_work_root()
ARTIFACT_ROOT = WORK_ROOT / "target/compat/allocator"
REPORT_ROOT = WORK_ROOT / "reports/allocator"
TEMP_ROOT = WORK_ROOT / "tmp/allocator"


def temporary_directory(prefix: str) -> tempfile.TemporaryDirectory:
    """Create disposable runner state inside the configured work-root boundary."""

    TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=prefix, dir=TEMP_ROOT)


ALLOCATOR_ROOT = Path(__file__).resolve().parent
UPSTREAMS = ROOT / "compat/upstreams.toml"
CACHE = WORK_ROOT / "allocator-cache"
ORACLE_ARTIFACT_ROOT = ARTIFACT_ROOT / "oracle"
RUST_LAYOUT_CARGO_TARGET = ARTIFACT_ROOT / "rust-layout/cargo-target"
LOOM_CARGO_TARGET = ARTIFACT_ROOT / "loom/cargo-target"
NATIVE_OWNER_EXIT_CARGO_TARGET = ARTIFACT_ROOT / "native-owner-exit-lifecycle/cargo-target"
API_CONTRACT = ALLOCATOR_ROOT / "api-v3.5.0.json"
UPSTREAM_TEST_CONTRACT = ALLOCATOR_ROOT / "upstream-tests-v3.5.0.json"
ADAPTED_TEST_CONTRACT = ALLOCATOR_ROOT / "adapted-tests-v3.5.0.json"
X86_64_API_CONTRACT = ALLOCATOR_ROOT / "x86_64-api-v3.5.0.json"
X86_64_API_INVENTORY_RUNNER = ALLOCATOR_ROOT / "x86_64_api_inventory.py"
X86_64_API_COVERAGE_CONTRACT = ALLOCATOR_ROOT / "x86_64-api-coverage-v3.5.0.json"
X86_64_API_COVERAGE_RUNNER = ALLOCATOR_ROOT / "x86_64_api_coverage.py"
X86_64_SOURCE_MAP_CONTRACT = ALLOCATOR_ROOT / "x86_64-source-map-v3.5.0.json"
X86_64_SOURCE_MAP_RUNNER = ALLOCATOR_ROOT / "x86_64_source_map.py"
X86_64_TEST_ADAPTER_CONTRACT = ALLOCATOR_ROOT / "adapted-tests-x86_64-v3.5.0.json"
ADAPTED_STRESS_TEST_CONTRACT = ALLOCATOR_ROOT / "adapted-stress-test-v3.5.0.json"
NATIVE_SHADOW_STRESS_CONTRACT = ALLOCATOR_ROOT / "native-shadow-stress-v3.5.0.json"
NATIVE_SHADOW_STRESS_REPORT = REPORT_ROOT / "native-shadow-stress-latest.json"
TEST_ADAPTER_ROOT = ALLOCATOR_ROOT / "test-adapter"
TEST_ADAPTER_HEADER = TEST_ADAPTER_ROOT / "crabc-mimalloc-test-adapter.h"
TEST_ADAPTER_FIXTURE = TEST_ADAPTER_ROOT / "allocator-fixture-wrapper.c"
RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT = (
    ALLOCATOR_ROOT / "runtime-ticket-zero-test-v3.5.0.json"
)
RUNTIME_TICKET_ZERO_ADAPTER_ROOT = ALLOCATOR_ROOT / "runtime-ticket-zero-adapter"
RUNTIME_TICKET_ZERO_ADAPTER_HEADER = (
    RUNTIME_TICKET_ZERO_ADAPTER_ROOT / "crabc-mimalloc-runtime-ticket-zero-test.h"
)
RUNTIME_TICKET_ZERO_ADAPTER_FIXTURE = (
    RUNTIME_TICKET_ZERO_ADAPTER_ROOT / "runtime-ticket-zero-fixture.c"
)
RUNTIME_TICKET_ZERO_DEFAULT_WORKER_CYCLES = 3
RUNTIME_TICKET_ZERO_MAX_WORKER_CYCLES = 1024
RUNTIME_TICKET_ZERO_CHURN_WORKER_CYCLES = 128
RUNTIME_TICKET_ZERO_CHURN_WATCHDOG_SECONDS = 30
RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES = 1024
RUNTIME_TICKET_ZERO_SOAK_WATCHDOG_SECONDS = 180
RUNTIME_TICKET_ZERO_SOAK_REPORT_FILENAME = "runtime-ticket-zero-soak-1024.json"
RUNTIME_TICKET_ZERO_SOAK_REPORT_RELATIVE_PATH = Path("reports/allocator") / (
    RUNTIME_TICKET_ZERO_SOAK_REPORT_FILENAME
)
RUNTIME_TICKET_ZERO_SOAK_REPORT = REPORT_ROOT / RUNTIME_TICKET_ZERO_SOAK_REPORT_FILENAME
RUNTIME_TICKET_ZERO_SOAK_REPORT_FORMAT = 1
RUNTIME_TICKET_ZERO_SOAK_REPORT_SCHEMA = "crabc-mimalloc-runtime-ticket-zero-soak-report"
RUNTIME_TICKET_ZERO_SOAK_EVIDENCE_SCOPE = "bounded-private-ticket-zero-soak"
RUNTIME_TICKET_ZERO_SOAK_NONCLAIMS = [
    "does not consume or unblock an M5 gate",
    "does not establish general cross-thread, post-exit, upstream-pthread, or large-object acceptance",
    "does not establish a selected or default crabc-libc native-mimalloc allocator backend",
]
RUNTIME_TICKET_ZERO_SOAK_GIT_READ_ENVIRONMENT = {"GIT_OPTIONAL_LOCKS": "0"}
# The native lifecycle fixture visits every currently supported pointer-private
# worker route once per cycle, but derives that cycle's order from this seed.
# Keep the development and soak lanes deterministic and distinct so a report
# can reproduce the exact owner/B/C interleaving it exercised.
RUNTIME_TICKET_ZERO_DEFAULT_STRESS_SEED = 0x9E3779B97F4A7C15
RUNTIME_TICKET_ZERO_CHURN_STRESS_SEED = 0xD1B54A32D192ED03
RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED = 0x94D049BB133111EB
RUNTIME_TICKET_ZERO_MAX_STRESS_SEED = (1 << 64) - 1
RUNTIME_TICKET_ZERO_WORKER_ROUTES_PER_CYCLE = 2
RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_PREFIX = "runtime ticket-zero lifecycle audit "
RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_FIELDS = (
    "worker_cycles",
    "process_active",
    "page_owner_ready",
    "page_map_registered_entries",
    "page_map_published_submaps",
    "page_map_lazy_submap_allocations",
    "arena_registry_entries",
    "live_tlds",
    "metadata_live_capabilities",
    "metadata_high_water_capabilities",
    "shared_later_theaps",
    "abandoned_regular_pages",
    "os_abandoned_pages_empty",
)
RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_SUCCESS_LINE = "runtime ticket-zero allocator ok"
RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_CONTRACT = {
    "fixture_stdout_fields": list(RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_FIELDS),
    "fixture_stdout_prefix": RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_PREFIX,
    "fixture_success_line": RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_SUCCESS_LINE,
    "report": {
        "audit_snapshot_count": "worker_cycles + 1",
        "post_warm_cycle_count": "worker_cycles - 1",
        "status": "passed",
        "warm_baseline": "the exact first-complete-cycle scalar fixture record",
    },
}
RUNTIME_TICKET_ZERO_SOAK_REPORT_CONTRACT = {
    "evidence_scope": RUNTIME_TICKET_ZERO_SOAK_EVIDENCE_SCOPE,
    "format": RUNTIME_TICKET_ZERO_SOAK_REPORT_FORMAT,
    "git_read_environment": dict(RUNTIME_TICKET_ZERO_SOAK_GIT_READ_ENVIRONMENT),
    "mode": "soak",
    "nonclaims": list(RUNTIME_TICKET_ZERO_SOAK_NONCLAIMS),
    "relative_path": RUNTIME_TICKET_ZERO_SOAK_REPORT_RELATIVE_PATH.as_posix(),
    "requires_clean_git_source": True,
    "requires_source_before_equals_after": True,
    "schema": RUNTIME_TICKET_ZERO_SOAK_REPORT_SCHEMA,
    "status": "passed",
}
TLS_CODEGEN_RUNNER = ALLOCATOR_ROOT / "tls-codegen/run.py"
TLS_CODEGEN_REPORT = REPORT_ROOT / "tls-codegen.json"
X86_64_TLS_CODEGEN_RUNNER = ALLOCATOR_ROOT / "tls-codegen/run-x86_64.py"
X86_64_TLS_CODEGEN_REPORT = REPORT_ROOT / "tls-codegen-x86_64.json"
PORT_MAP = ALLOCATOR_ROOT / "port-map.toml"
RATCHET = ALLOCATOR_ROOT / "ratchet-v3.5.0.json"
M1_FOUNDATIONS_CONTRACT = ALLOCATOR_ROOT / "m1-foundations-v3.5.0.json"
M1_FOUNDATIONS_REPORT = REPORT_ROOT / "m1-foundations-latest.json"
M1_FOUNDATIONS_CARGO_TARGET = ARTIFACT_ROOT / "m1-foundations/cargo-target"
M1_RAW_PRIMITIVE_TRACE_ARTIFACT_ROOT = ARTIFACT_ROOT / "m1-foundations/raw-primitive-trace"
M1_COMPILER_TLS_TRACE_ARTIFACT_ROOT = ARTIFACT_ROOT / "m1-foundations/compiler-tls-trace"
# This is the source-only C producer for the selected same-TLD terminal
# trace. The standalone prototype command exposes its C half; the M1 gate
# consumes the same producer together with its dedicated Rust comparison.
M1_COMPILER_TLS_SAME_TLD_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "m1-foundations/compiler-tls-same-tld-trace"
)
# The native x86 M1 gate has a distinct contract and result path.  It may
# reuse only the source-shaped check and layout inventories that are common to
# both 64-bit Linux profiles; it never consumes the archived AArch64 status or
# report as target evidence.
M1_X86_64_FOUNDATIONS_CONTRACT = ALLOCATOR_ROOT / "m1-foundations-x86_64-v3.5.0.json"
M1_X86_64_FOUNDATIONS_REPORT = REPORT_ROOT / "x86_64/m1-foundations-latest.json"
M1_X86_64_FOUNDATIONS_CARGO_TARGET = (
    ARTIFACT_ROOT / "x86_64/m1-foundations/cargo-target"
)
M1_X86_64_RAW_PRIMITIVE_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "x86_64/m1-foundations/raw-primitive-trace"
)
M1_X86_64_COMPILER_TLS_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "x86_64/m1-foundations/compiler-tls-trace"
)
M1_X86_64_COMPILER_TLS_SAME_TLD_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "x86_64/m1-foundations/compiler-tls-same-tld-trace"
)
M1_X86_64_STATIC_IMAGE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "x86_64/m1-foundations/static-image"
)
M2_MEMORY_SUBSTRATE_CONTRACT = ALLOCATOR_ROOT / "m2-memory-substrate-v3.5.0.json"
M2_MEMORY_SUBSTRATE_REPORT = REPORT_ROOT / "m2-memory-substrate-latest.json"
M2_MEMORY_SUBSTRATE_CARGO_TARGET = ARTIFACT_ROOT / "m2-memory-substrate/cargo-target"
M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "m2-memory-substrate/detached-tld-static-preimage-trace"
)
M2_NORMAL_TLD_DIRECT_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "m2-memory-substrate/normal-tld-direct-trace"
)
M2_STATIC_FIRST_TLD_CREATE_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "m2-memory-substrate/static-first-tld-create-trace"
)
M2_PAGE_MAP_TRACE_ARTIFACT_ROOT = ARTIFACT_ROOT / "m2-memory-substrate/page-map-trace"
M2_BITMAP_ABANDONED_CLAIM_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "m2-memory-substrate/bitmap-abandoned-claim-trace"
)
M2_BITMAP_CLEAR_RANGE_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "m2-memory-substrate/bitmap-clear-range-trace"
)
M2_BITMAP_RANGESN_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "m2-memory-substrate/bitmap-rangesn-trace"
)
M2_BITMAP_SET_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "m2-memory-substrate/bitmap-set-trace"
)
M2_BINNED_BITMAP_BSR_INV_TRACE_ARTIFACT_ROOT = (
    ARTIFACT_ROOT / "m2-memory-substrate/binned-bitmap-bsr-inv-trace"
)
M5_GATE_CONTRACT = ALLOCATOR_ROOT / "m5-gate-v3.5.0.json"
CANONICAL_UPSTREAM_STRESS_CONTRACT = ALLOCATOR_ROOT / "upstream-stress-v3.5.0.json"
CANONICAL_UPSTREAM_STRESS_REPORT = REPORT_ROOT / "upstream-stress/latest.json"
CANONICAL_UPSTREAM_STRESS_GIT_ENVIRONMENT = {"GIT_OPTIONAL_LOCKS": "0"}
NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT = (
    ALLOCATOR_ROOT / "native-owner-exit-lifecycle-v3.5.0.json"
)
OWNER_EXIT_PUBLICATION_CONTRACT = (
    ALLOCATOR_ROOT / "owner-exit-publication-v3.5.0.json"
)

M5_GATE_IDS = (
    "m5.base",
    "m5.5a",
    "m5.5b",
    "m5.5c",
    "m5.5d",
    "m5.5e",
)
M5_STATIC_BLOCKED_GATE_IDS = frozenset({"m5.5d", "m5.5e"})
M5_5D_EVIDENCE = (
    "runtime-ticket-zero:128-cycle-churn",
    "native-post-exit-registry:high-water",
    "source-derived:test-stress-single-creating-thread",
    "canonical-upstream-stress:current-head-full-matrix",
)

# M1 is an intentionally finite foundations gate.  These are source-shaped
# components, not a claim that the four broad upstream units which contain
# them are complete.  Keeping the inventory in the runner makes a manifest
# reorder/removal an explicit reviewed contract change.
M1_FOUNDATIONS_COMPONENT_IDS = (
    "configuration-and-arithmetic",
    "atomics-locks-once-and-bootstrap",
    "provenance-and-represented-layouts",
    "random-image",
    "linux-raw-primitives",
    "compiler-tls-roots",
)
M1_FOUNDATIONS_GLOBAL_EVIDENCE = (
    "release-c-rust-layout",
    "raw-primitive-c-rust-trace",
    "compiler-tls-c-rust-trace",
    "compiler-tls-same-tld-terminal-c-rust-trace",
    "compiler-tls-codegen",
    "production-dependency-graph",
)

# M2 is an intentionally partial memory-substrate gate.  The eight categories
# are the closure boundary from native-mimalloc.md; a report may record focused
# evidence for one category without silently promoting the other seven.
M2_MEMORY_SUBSTRATE_COMPONENT_IDS = (
    "vm-primitives",
    "metadata",
    "bitmaps",
    "page-map",
    "arenas",
    "initialization",
    "fault-injection",
    "allocator-recursion",
)
M2_MEMORY_SUBSTRATE_COMPONENT_STATUSES = frozenset({"partial", "complete"})
M2_MEMORY_SUBSTRATE_EXCLUSION_DISPOSITIONS = frozenset(
    {"deferred-to-m3", "deferred-to-m8", "outside-m2"}
)
# This direct C/Rust record covers only src/init.c's detached static-preimage
# substep: the original MI_MEMID_STATIC image, its kind-only memid
# predecessor, then file-static mi_tld_init's detached writes. It uses only
# address-independent field relations: no mi_tld_t/mi_subproc_t byte layout,
# raw pointer, or pthread lock representation is a comparable value.
M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_KEYS = (
    "m2.initialization.detached_tld.pre.thread_id_detached",
    "m2.initialization.detached_tld.pre.thread_sequence_zero",
    "m2.initialization.detached_tld.pre.numa_node_zero",
    "m2.initialization.detached_tld.pre.subprocess_null",
    "m2.initialization.detached_tld.pre.theap_head_null",
    "m2.initialization.detached_tld.pre.lock_roundtrip",
    "m2.initialization.detached_tld.pre.recurse_false",
    "m2.initialization.detached_tld.pre.threadpool_false",
    "m2.initialization.detached_tld.pre.memid_static",
    "m2.initialization.detached_tld.pre.memid_base_null",
    "m2.initialization.detached_tld.pre.memid_size_zero",
    "m2.initialization.detached_tld.pre.memid_pinned",
    "m2.initialization.detached_tld.pre.memid_committed",
    "m2.initialization.detached_tld.pre.memid_zero_false",
    "m2.initialization.detached_tld.pre.total_thread_count_zero",
    "m2.initialization.detached_tld.pre.live_thread_count_zero",
    "m2.initialization.detached_tld.predecessor.memid_static",
    "m2.initialization.detached_tld.predecessor.memid_base_null",
    "m2.initialization.detached_tld.predecessor.memid_size_zero",
    "m2.initialization.detached_tld.predecessor.memid_unpinned",
    "m2.initialization.detached_tld.predecessor.memid_uncommitted",
    "m2.initialization.detached_tld.predecessor.memid_zero_false",
    "m2.initialization.detached_tld.post.thread_id_detached",
    "m2.initialization.detached_tld.post.thread_sequence_zero",
    "m2.initialization.detached_tld.post.numa_node_minus_one",
    "m2.initialization.detached_tld.post.subprocess_matches_input",
    "m2.initialization.detached_tld.post.theap_head_null",
    "m2.initialization.detached_tld.post.lock_roundtrip",
    "m2.initialization.detached_tld.post.recurse_false",
    "m2.initialization.detached_tld.post.threadpool_false",
    "m2.initialization.detached_tld.post.memid_static",
    "m2.initialization.detached_tld.post.memid_base_null",
    "m2.initialization.detached_tld.post.memid_size_zero",
    "m2.initialization.detached_tld.post.memid_unpinned",
    "m2.initialization.detached_tld.post.memid_uncommitted",
    "m2.initialization.detached_tld.post.memid_zero_false",
    "m2.initialization.detached_tld.post.total_thread_count_zero",
    "m2.initialization.detached_tld.post.total_thread_count_unchanged",
    "m2.initialization.detached_tld.post.live_thread_count_zero",
    "m2.initialization.detached_tld.post.live_thread_count_unchanged",
)
# This is the direct non-detached `mi_tld_init` body only. The C producer
# independently hooks its five observable calls (lock, NUMA, ID, pool, live
# count), while Rust's production-backed test instrumentation records all
# eight modeled field/counter effects after its outer `LiveThreadId` boundary.
# The common record compares only address-independent relations, not layout,
# raw IDs/pointers, or a claim that Rust invokes C primitives at the same time.
M2_NORMAL_TLD_DIRECT_TRACE_KEYS = (
    "m2.initialization.normal_tld.pre.thread_id_abandoned",
    "m2.initialization.normal_tld.pre.thread_sequence_zero",
    "m2.initialization.normal_tld.pre.numa_node_zero",
    "m2.initialization.normal_tld.pre.subprocess_null",
    "m2.initialization.normal_tld.pre.theap_head_null",
    "m2.initialization.normal_tld.pre.recurse_false",
    "m2.initialization.normal_tld.pre.threadpool_false",
    "m2.initialization.normal_tld.pre.memid_none",
    "m2.initialization.normal_tld.pre.total_thread_count_eight",
    "m2.initialization.normal_tld.pre.live_thread_count_zero",
    "m2.initialization.normal_tld.post.input_identity_preserved",
    "m2.initialization.normal_tld.post.subprocess_matches_input",
    "m2.initialization.normal_tld.post.theap_head_null",
    "m2.initialization.normal_tld.post.lock_roundtrip",
    "m2.initialization.normal_tld.post.numa_node_injected_three",
    "m2.initialization.normal_tld.post.thread_id_matches_input",
    "m2.initialization.normal_tld.post.thread_id_live",
    "m2.initialization.normal_tld.post.threadpool_matches_input",
    "m2.initialization.normal_tld.post.threadpool_false",
    "m2.initialization.normal_tld.post.thread_sequence_matches_input",
    "m2.initialization.normal_tld.post.recurse_false",
    "m2.initialization.normal_tld.post.memid_none",
    "m2.initialization.normal_tld.post.total_thread_count_eight",
    "m2.initialization.normal_tld.post.total_thread_count_unchanged",
    "m2.initialization.normal_tld.post.live_thread_count_one",
    "m2.initialization.normal_tld.post.live_thread_count_incremented",
    "m2.initialization.normal_tld.order.lock_before_numa",
    "m2.initialization.normal_tld.order.numa_before_thread_id",
    "m2.initialization.normal_tld.order.thread_id_before_threadpool",
    "m2.initialization.normal_tld.order.threadpool_before_live_increment",
    "m2.initialization.normal_tld.order.exactly_five_observable_effects",
)
# This selected source caller record begins at `mi_tld_create`'s own
# total-thread ticket and follows only its first-main/static-storage success
# arm. C records its real main-subprocess predicate and its no-metadata route;
# Rust instead enters its already selected main-static ticket/slot path after
# the separately modeled Heap foundation. The common values deliberately begin
# at the shared ticket-zero -> concrete-static-memid boundary and continue
# through normal-body, live, and result-visibility relations; C's predicate
# timing and Rust's prior selector/foundation are not literal-order parity.
# Every provenance value is a semantic/address-independent relation, never a
# raw static address, thread ID, or cross-language `mi_tld_t` layout size.
M2_STATIC_FIRST_TLD_CREATE_TRACE_KEYS = (
    "m2.initialization.static_first_tld.pre.main_subprocess_selected",
    "m2.initialization.static_first_tld.pre.static_slot_fresh",
    "m2.initialization.static_first_tld.pre.total_thread_count_zero",
    "m2.initialization.static_first_tld.pre.live_thread_count_zero",
    "m2.initialization.static_first_tld.post.static_branch_selected",
    "m2.initialization.static_first_tld.post.static_slot_identity_preserved",
    "m2.initialization.static_first_tld.post.subprocess_matches_input",
    "m2.initialization.static_first_tld.post.theap_head_null",
    "m2.initialization.static_first_tld.post.lock_roundtrip",
    "m2.initialization.static_first_tld.post.numa_node_injected_three",
    "m2.initialization.static_first_tld.post.thread_id_matches_input",
    "m2.initialization.static_first_tld.post.thread_id_live",
    "m2.initialization.static_first_tld.post.threadpool_false",
    "m2.initialization.static_first_tld.post.thread_sequence_zero",
    "m2.initialization.static_first_tld.post.recurse_false",
    "m2.initialization.static_first_tld.post.memid_static_kind",
    "m2.initialization.static_first_tld.post.memid_base_is_static_slot",
    "m2.initialization.static_first_tld.post.memid_size_is_own_tld_size",
    "m2.initialization.static_first_tld.post.memid_pinned",
    "m2.initialization.static_first_tld.post.memid_initially_committed",
    "m2.initialization.static_first_tld.post.memid_initially_zero_false",
    "m2.initialization.static_first_tld.post.metadata_allocation_bypassed",
    "m2.initialization.static_first_tld.post.total_thread_count_one",
    "m2.initialization.static_first_tld.post.total_thread_count_incremented",
    "m2.initialization.static_first_tld.post.live_thread_count_one",
    "m2.initialization.static_first_tld.post.live_thread_count_incremented",
    "m2.initialization.static_first_tld.post.result_visibility_after_live_registration",
    "m2.initialization.static_first_tld.order.ticket_zero_before_static_memid",
    "m2.initialization.static_first_tld.order.static_memid_before_normal_lock",
    "m2.initialization.static_first_tld.order.lock_before_numa",
    "m2.initialization.static_first_tld.order.numa_before_thread_id",
    "m2.initialization.static_first_tld.order.thread_id_before_threadpool",
    "m2.initialization.static_first_tld.order.threadpool_before_live_increment",
    "m2.initialization.static_first_tld.order.total_increment_before_live_increment",
    "m2.initialization.static_first_tld.order.live_increment_before_result_visibility",
    "m2.initialization.static_first_tld.order.selected_create_effects_ordered",
)
M2_PAGE_MAP_TRACE_KEYS = (
    "m2.page_map.control.page_size",
    "m2.page_map.control.has_overcommit_false",
    "m2.page_map.control.max_vabits",
    "m2.page_map.layout.header_bytes",
    "m2.page_map.layout.lock_bytes",
    "m2.page_map.init.root_empty_before",
    "m2.page_map.init.root_published",
    "m2.page_map.init.reserve_count",
    "m2.page_map.init.reserved_count",
    "m2.page_map.init.committed_count",
    "m2.page_map.init.committed_lt_reserved",
    "m2.page_map.init.submap_zero_present",
    "m2.page_map.extend.map_index",
    "m2.page_map.extend.start_sub_index",
    "m2.page_map.extend.slice_count",
    "m2.page_map.extend.committed_before",
    "m2.page_map.extend.committed_after",
    "m2.page_map.extend.committed_increased",
    "m2.page_map.extend.first_submap_present",
    "m2.page_map.extend.second_submap_present",
    "m2.page_map.extend.submaps_distinct",
    "m2.page_map.register.first_lookup_matches",
    "m2.page_map.register.second_lookup_matches",
    "m2.page_map.unregister.first_lookup_absent",
    "m2.page_map.unregister.second_lookup_absent",
    "m2.page_map.rollback.register_failed",
    "m2.page_map.rollback.submap_present",
    "m2.page_map.rollback.entry_cleared",
    "m2.page_map.rollback.out_of_bounds_absent",
    "m2.page_map.destroy.root_unpublished_before",
    "m2.page_map.destroy.root_absent_after",
)
# The source formula deliberately incorporates the concrete mapped header.
# Pinned C carries a musl `pthread_mutex_t`; the no_std port uses its mapped
# private futex lock.  Their header-size-dependent entry counts can therefore
# differ without changing the selected source-relative state transitions.
# Keep each value in the record and report both sides; never silently compare
# or normalize it as an exact-equality field.
M2_PAGE_MAP_HEADER_DEPENDENT_KEYS = (
    "m2.page_map.layout.header_bytes",
    "m2.page_map.layout.lock_bytes",
    "m2.page_map.init.reserved_count",
    "m2.page_map.init.committed_count",
    "m2.page_map.extend.map_index",
    "m2.page_map.extend.committed_before",
    "m2.page_map.extend.committed_after",
)
# C owns the global page-map root and resets it in `_mi_page_map_unsafe_destroy`.
# Rust keeps `PageMapRoot` as a separate owner and must unpublish it before the
# typed `PageMap::destroy` precondition can hold.  This explicit record keeps
# that lifecycle distinction visible while both traces prove an absent root
# after destruction.
M2_PAGE_MAP_ROOT_OWNERSHIP_DIFFERENCE_KEY = "m2.page_map.destroy.root_unpublished_before"
# The selected lazy-extension failure occurs after successful PageMap
# initialization. A lexical C `_mi_os_commit` wrapper and Rust's test-only
# pre-`mprotect` seam each fail exactly one attempt, before the source/Rust
# committed-prefix publication and before either side enters submap allocation.
# The record intentionally contains only address-free semantic relations; raw
# PageMap header counts and C's global-versus-Rust-local root representation do
# not describe this failure edge and are deliberately excluded.
M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_KEYS = (
    "m2.page_map.lazy_commit.control.page_size",
    "m2.page_map.lazy_commit.control.has_overcommit_false",
    "m2.page_map.lazy_commit.control.max_vabits",
    "m2.page_map.lazy_commit.failure.target_above_committed",
    "m2.page_map.lazy_commit.failure.commit_attempts",
    "m2.page_map.lazy_commit.failure.returned",
    "m2.page_map.lazy_commit.failure.committed_unchanged",
    "m2.page_map.lazy_commit.failure.no_submap_result",
    "m2.page_map.lazy_commit.failure.submap_allocation_attempts",
    "m2.page_map.lazy_commit.failure.top_owner_retained",
    "m2.page_map.lazy_commit.retry.succeeded",
    "m2.page_map.lazy_commit.retry.committed_advanced",
    "m2.page_map.lazy_commit.retry.submap_present",
    "m2.page_map.lazy_commit.retry.submap_allocation_attempts",
    "m2.page_map.lazy_commit.cleanup.top_owner_released",
)
# The first failed C `_mi_page_map_init` body keeps its static empty root and
# consumes the source once gate. Rust deliberately avoids exposing a fake live
# root: its typed process owner retains no map and becomes terminally poisoned.
# The cold-failure trace compares the shared failure facts while retaining this
# deliberate safety divergence as first-class evidence. The C-only
# `null_lookup_returns_null` observation is zero on Rust because no valid
# cold lookup operation exists there; `cold_lookup_route_unavailable` names
# that state rather than implying an attempted Rust lookup returned non-null.
M2_PAGE_MAP_COLD_INIT_TRACE_KEYS = (
    "m2.page_map.cold.first_init_failed",
    "m2.page_map.cold.dynamic_root_unpublished",
    "m2.page_map.cold.init_body_attempt_count",
    "m2.page_map.cold.static_empty_root",
    "m2.page_map.cold.absent_root",
    "m2.page_map.cold.second_call_returns_success",
    "m2.page_map.cold.second_call_returns_poisoned",
    "m2.page_map.cold.null_lookup_returns_null",
    "m2.page_map.cold.cold_lookup_route_unavailable",
)
M2_PAGE_MAP_COLD_INIT_MATCHED_KEYS = (
    "m2.page_map.cold.first_init_failed",
    "m2.page_map.cold.dynamic_root_unpublished",
    "m2.page_map.cold.init_body_attempt_count",
)
# This one-chunk record fixes the narrow abandoned-page visitor boundary: a
# rejected ownership callback restores the candidate and conservative map, a
# later successful callback drains the bit but retains that map, and one more
# search repairs the stale map without calling an ownership callback. It is not
# a general bitmap, arena, or clear-once-set concurrency contract.
M2_BITMAP_ABANDONED_CLAIM_TRACE_KEYS = (
    "m2.bitmap.control.bfield_bits",
    "m2.bitmap.control.bchunk_bits",
    "m2.bitmap.control.thread_sequence",
    "m2.bitmap.control.selected_index",
    "m2.bitmap.layout.byte_size",
    "m2.bitmap.setup.chunk_count",
    "m2.bitmap.setup.initial_set_transitioned",
    "m2.bitmap.reject.returned_claimed",
    "m2.bitmap.reject.callback_count",
    "m2.bitmap.reject.callback_index",
    "m2.bitmap.reject.bit_restored",
    "m2.bitmap.reject.chunkmap_retained",
    "m2.bitmap.accept.returned_claimed",
    "m2.bitmap.accept.callback_count",
    "m2.bitmap.accept.callback_index",
    "m2.bitmap.accept.claimed_index",
    "m2.bitmap.accept.bit_cleared",
    "m2.bitmap.accept.chunkmap_retained",
    "m2.bitmap.drain.returned_claimed",
    "m2.bitmap.drain.callback_count",
    "m2.bitmap.drain.chunkmap_cleared",
)
# This scalar one-chunk record fixes the source visitor's whole-field exchange
# boundary. It records both a full traversal (including the 64-bit split) and
# a callback stop, whose only restoration is the unvisited residual of the
# exchanged source field. It is not a multi-chunk, rangesn, binned, arena, or
# concurrent visitor contract.
M2_BITMAP_CLEAR_RANGE_TRACE_KEYS = (
    "m2.bitmap_range.control.bfield_bits",
    "m2.bitmap_range.control.bchunk_bits",
    "m2.bitmap_range.layout.byte_size",
    "m2.bitmap_range.complete.chunk_count",
    "m2.bitmap_range.complete.set_transitioned",
    "m2.bitmap_range.complete.returned_completed",
    "m2.bitmap_range.complete.callback_count",
    "m2.bitmap_range.complete.range_0_index",
    "m2.bitmap_range.complete.range_0_count",
    "m2.bitmap_range.complete.range_1_index",
    "m2.bitmap_range.complete.range_1_count",
    "m2.bitmap_range.complete.range_2_index",
    "m2.bitmap_range.complete.range_2_count",
    "m2.bitmap_range.complete.range_3_index",
    "m2.bitmap_range.complete.range_3_count",
    "m2.bitmap_range.complete.data_cleared",
    "m2.bitmap_range.complete.chunkmap_retained",
    "m2.bitmap_range.reject.set_transitioned",
    "m2.bitmap_range.reject.returned_completed",
    "m2.bitmap_range.reject.callback_count",
    "m2.bitmap_range.reject.range_index",
    "m2.bitmap_range.reject.range_count",
    "m2.bitmap_range.reject.visited_range_cleared",
    "m2.bitmap_range.reject.unvisited_same_field_restored",
    "m2.bitmap_range.reject.later_field_untouched",
    "m2.bitmap_range.reject.chunkmap_retained",
)
# This one-chunk record directly exercises the source rangesn wrapper. The
# aligned-three path retains incomplete windows and its top suffix, including
# when a callback stops after a lower skipped window. Fresh images also prove
# the <=1 generic delegation and the cap above one source field. It is not an
# arena policy, multi-chunk, binned, or concurrent bitmap contract.
M2_BITMAP_RANGESN_TRACE_KEYS = (
    "m2.bitmap_rangesn.control.bfield_bits",
    "m2.bitmap_rangesn.control.bchunk_bits",
    "m2.bitmap_rangesn.control.aligned_rngslices",
    "m2.bitmap_rangesn.control.capped_request",
    "m2.bitmap_rangesn.layout.byte_size",
    "m2.bitmap_rangesn.r3_complete.returned_completed",
    "m2.bitmap_rangesn.r3_complete.callback_count",
    "m2.bitmap_rangesn.r3_complete.range_0_index",
    "m2.bitmap_rangesn.r3_complete.range_0_count",
    "m2.bitmap_rangesn.r3_complete.range_1_index",
    "m2.bitmap_rangesn.r3_complete.range_1_count",
    "m2.bitmap_rangesn.r3_complete.range_2_index",
    "m2.bitmap_rangesn.r3_complete.range_2_count",
    "m2.bitmap_rangesn.r3_complete.field_0_after",
    "m2.bitmap_rangesn.r3_complete.chunkmap_field_0_after",
    "m2.bitmap_rangesn.r3_reject.returned_completed",
    "m2.bitmap_rangesn.r3_reject.callback_count",
    "m2.bitmap_rangesn.r3_reject.range_0_index",
    "m2.bitmap_rangesn.r3_reject.range_0_count",
    "m2.bitmap_rangesn.r3_reject.field_0_after",
    "m2.bitmap_rangesn.r3_reject.field_1_after",
    "m2.bitmap_rangesn.r3_reject.chunkmap_field_0_after",
    "m2.bitmap_rangesn.delegation_zero.returned_completed",
    "m2.bitmap_rangesn.delegation_zero.callback_count",
    "m2.bitmap_rangesn.delegation_zero.range_0_index",
    "m2.bitmap_rangesn.delegation_zero.range_0_count",
    "m2.bitmap_rangesn.delegation_zero.range_1_index",
    "m2.bitmap_rangesn.delegation_zero.range_1_count",
    "m2.bitmap_rangesn.delegation_zero.range_2_index",
    "m2.bitmap_rangesn.delegation_zero.range_2_count",
    "m2.bitmap_rangesn.delegation_zero.range_3_index",
    "m2.bitmap_rangesn.delegation_zero.range_3_count",
    "m2.bitmap_rangesn.delegation_zero.field_0_after",
    "m2.bitmap_rangesn.delegation_zero.chunkmap_field_0_after",
    "m2.bitmap_rangesn.delegation_one.returned_completed",
    "m2.bitmap_rangesn.delegation_one.callback_count",
    "m2.bitmap_rangesn.delegation_one.range_0_index",
    "m2.bitmap_rangesn.delegation_one.range_0_count",
    "m2.bitmap_rangesn.delegation_one.range_1_index",
    "m2.bitmap_rangesn.delegation_one.range_1_count",
    "m2.bitmap_rangesn.delegation_one.range_2_index",
    "m2.bitmap_rangesn.delegation_one.range_2_count",
    "m2.bitmap_rangesn.delegation_one.range_3_index",
    "m2.bitmap_rangesn.delegation_one.range_3_count",
    "m2.bitmap_rangesn.delegation_one.field_0_after",
    "m2.bitmap_rangesn.delegation_one.chunkmap_field_0_after",
    "m2.bitmap_rangesn.cap_over.returned_completed",
    "m2.bitmap_rangesn.cap_over.callback_count",
    "m2.bitmap_rangesn.cap_over.range_0_index",
    "m2.bitmap_rangesn.cap_over.range_0_count",
    "m2.bitmap_rangesn.cap_over.field_0_after",
    "m2.bitmap_rangesn.cap_over.chunkmap_field_0_after",
)
# This direct scalar record spans the first chunk-map field boundary in a
# 65-chunk valid bitmap. Completed and stopped walks prove low-to-high
# read-only callbacks, immediate refusal, and no data/map mutation. It is not
# a Heap/Page/Arena integration, callback-mutation, binned, or concurrent
# bitmap contract.
M2_BITMAP_SET_TRACE_KEYS = (
    "m2.bitmap_set.control.bfield_bits",
    "m2.bitmap_set.control.bchunk_bits",
    "m2.bitmap_set.control.chunk_count",
    "m2.bitmap_set.layout.byte_size",
    "m2.bitmap_set.complete.seeded",
    "m2.bitmap_set.complete.returned_completed",
    "m2.bitmap_set.complete.callback_count",
    "m2.bitmap_set.complete.visit_0_index",
    "m2.bitmap_set.complete.visit_0_count",
    "m2.bitmap_set.complete.visit_1_index",
    "m2.bitmap_set.complete.visit_1_count",
    "m2.bitmap_set.complete.visit_2_index",
    "m2.bitmap_set.complete.visit_2_count",
    "m2.bitmap_set.complete.chunk_0_field_0_after",
    "m2.bitmap_set.complete.chunk_0_field_1_after",
    "m2.bitmap_set.complete.chunk_64_field_0_after",
    "m2.bitmap_set.complete.chunkmap_field_0_after",
    "m2.bitmap_set.complete.chunkmap_field_1_after",
    "m2.bitmap_set.reject.seeded",
    "m2.bitmap_set.reject.returned_completed",
    "m2.bitmap_set.reject.callback_count",
    "m2.bitmap_set.reject.visit_0_index",
    "m2.bitmap_set.reject.visit_0_count",
    "m2.bitmap_set.reject.visit_1_index",
    "m2.bitmap_set.reject.visit_1_count",
    "m2.bitmap_set.reject.chunk_0_field_0_after",
    "m2.bitmap_set.reject.chunk_0_field_1_after",
    "m2.bitmap_set.reject.chunk_64_field_0_after",
    "m2.bitmap_set.reject.chunkmap_field_0_after",
    "m2.bitmap_set.reject.chunkmap_field_1_after",
)
# This direct binned observer record fixes only the source's rounded-capacity
# and high-to-low inverse-BSR scan. It intentionally observes valid images
# whose conservative set-bit map remains empty; it is not a binned search,
# chunk-map-maintenance, or allocator-integration contract.
M2_BINNED_BITMAP_BSR_INV_TRACE_KEYS = (
    "m2.bbitmap_bsr_inv.control.bfield_bits",
    "m2.bbitmap_bsr_inv.control.bchunk_bits",
    "m2.bbitmap_bsr_inv.padding.logical_bit_count",
    "m2.bbitmap_bsr_inv.padding.chunk_count",
    "m2.bbitmap_bsr_inv.padding.max_bits",
    "m2.bbitmap_bsr_inv.padding.byte_size",
    "m2.bbitmap_bsr_inv.padding.chunkmap_empty",
    "m2.bbitmap_bsr_inv.padding.returned_found",
    "m2.bbitmap_bsr_inv.padding.index",
    "m2.bbitmap_bsr_inv.scan.chunk_count",
    "m2.bbitmap_bsr_inv.scan.byte_size",
    "m2.bbitmap_bsr_inv.scan.chunkmap_empty_before",
    "m2.bbitmap_bsr_inv.scan.first_returned_found",
    "m2.bbitmap_bsr_inv.scan.first_index",
    "m2.bbitmap_bsr_inv.scan.second_returned_found",
    "m2.bbitmap_bsr_inv.scan.second_index",
    "m2.bbitmap_bsr_inv.scan.third_returned_found",
    "m2.bbitmap_bsr_inv.scan.third_index",
    "m2.bbitmap_bsr_inv.scan.drained_returned_found",
    "m2.bbitmap_bsr_inv.scan.chunkmap_empty_after",
)
M1_FOUNDATIONS_COMPONENT_STATUSES = frozenset({"partial", "complete"})
M1_X86_64_FOUNDATIONS_COMPONENT_STATUS = "ready-for-native-evidence"
M1_FOUNDATIONS_EXCLUSION_DISPOSITIONS = frozenset(
    {
        "deferred-to-m2",
        "deferred-to-m2-m3",
        "deferred-to-m5",
        "deferred-to-m7",
        "deferred-to-m8",
        "outside-m1",
    }
)
# This is the complete frozen normal-release configuration record emitted by
# both `LAYOUT_PROBE` and `types::tests::emit_layout`. Keeping it explicit
# means the M1 configuration component cannot quietly narrow itself back to a
# representative handful of values: every frozen source-derived configuration
# result must remain directly C/Rust checked.
M1_CONFIGURATION_LAYOUT_KEYS = (
    "config.WORD_SIZE",
    "config.MAX_ALIGN_SIZE",
    "config.SECURE_LEVEL",
    "config.DEBUG_LEVEL",
    "config.STAT_LEVEL",
    "config.FREE_IS_CHECKED",
    "config.FREE_USE_PAGEMAP",
    "config.OPT_FREE_SMALL",
    "config.ENABLE_LARGE_PAGES",
    "config.ENCODE_FREELIST",
    "config.GUARDED",
    "config.OPT_SIMD",
    "config.PADDING_SIZE",
    "config.PADDING_WSIZE",
    "config.PAGE_KEY_COUNT",
    "config.ARENA_SLICE_SHIFT",
    "config.BCHUNK_BITS_SHIFT",
    "config.BCHUNK_BITS",
    "config.ARENA_SLICE_SIZE",
    "config.ARENA_SLICE_ALIGN",
    "config.ARENA_CHUNK_SIZE",
    "config.ARENA_MIN_OBJ_SLICES",
    "config.ARENA_MAX_CHUNK_OBJ_SLICES",
    "config.ARENA_MIN_OBJ_SIZE",
    "config.ARENA_MAX_CHUNK_OBJ_SIZE",
    "config.SMALL_PAGE_SIZE",
    "config.MEDIUM_PAGE_SIZE",
    "config.LARGE_PAGE_SIZE",
    "config.BIN_HUGE",
    "config.BIN_FULL",
    "config.BIN_COUNT",
    "config.MAX_ALLOC_SIZE",
    "config.PAGE_MIN_COMMIT_SIZE",
    "config.PAGE_META_IS_SEPARATED",
    "config.PAGE_META_IS_ALIGNED",
    "config.PAGE_META_ALIGNED_CHUNKS",
    "config.PAGE_META_ALIGNED_COUNT",
    "config.PAGE_META_ALIGNMENT",
    "config.ARENA_ALIGNMENT",
    "config.PAGE_ALIGN",
    "config.PAGE_MIN_START_BLOCK_ALIGN",
    "config.PAGE_MAX_START_BLOCK_ALIGN2",
    "config.PAGE_OSPAGE_BLOCK_ALIGN2",
    "config.PAGE_MAX_OVERALLOC_ALIGN",
    "config.SMALL_WSIZE_MAX",
    "config.SMALL_SIZE_MAX",
    "config.SMALL_MAX_OBJ_SIZE",
    "config.MEDIUM_MAX_OBJ_SIZE",
    "config.LARGE_MAX_OBJ_SIZE",
    "config.LARGE_MAX_OBJ_WSIZE",
    "config.MAX_SINGLETON_BIN",
    "config.PAGES_DIRECT",
    "config.MAX_ARENAS",
    "config.ARENA_BIN_COUNT",
    "config.BITMAP_MAX_BIT_COUNT",
    "config.ARENA_MIN_SIZE",
    "config.ARENA_MAX_SIZE",
    "config.MAX_VABITS",
    "config.MIN_VABITS",
    "config.PAGE_MAP_FLAT",
    "config.PAGE_MAP_SUB_SHIFT",
    "config.PAGE_MAP_SUB_COUNT",
    "config.PAGE_MAP_SHIFT",
)
M1_CONFIGURATION_AND_ARITHMETIC_LAYOUT_KEYS = (
    *M1_CONFIGURATION_LAYOUT_KEYS,
    "m1.scalar.is_power_of_two.zero",
    "m1.scalar.is_aligned.zero",
    "m1.scalar.align_down.generic.101_by_24",
    "m1.scalar.align_up.generic.101_by_24",
    "m1.scalar.divide_up.17_by_6",
    "m1.scalar.wsize_from_size.17",
    "m1.scalar.slice_count.one_past_slice",
    "m1.scalar.size_of_slices.3",
)

# This is the complete address-independent record for the selected Rust
# representation of `src/init.c`'s pre-process-initialization static images.
# Pointer-valued arrays deliberately use relationships (every direct slot is
# the one empty-page sentinel; every queue link is null) instead of unstable
# process addresses. Every queue block-size value remains individual so the
# relation cannot hide one incorrect static queue initializer. The C detached
# TLD later becomes mutable during process initialization; its source image is
# deliberately read before that lifecycle step.
M1_BOOTSTRAP_PAGE_QUEUE_BLOCK_SIZE_LAYOUT_KEYS = tuple(
    f"m1.bootstrap.empty_theap.page_queues.block_size.{index}"
    for index in range(75)
)
M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEYS = (
    "m1.bootstrap.empty_page.self_is_null",
    "m1.bootstrap.empty_page.xthread_id",
    "m1.bootstrap.empty_page.free_is_null",
    "m1.bootstrap.empty_page.used",
    "m1.bootstrap.empty_page.local_free_is_null",
    "m1.bootstrap.empty_page.block_size",
    "m1.bootstrap.empty_page.page_offset",
    "m1.bootstrap.empty_page.capacity",
    "m1.bootstrap.empty_page.reserved",
    "m1.bootstrap.empty_page.slice_pcommitted",
    "m1.bootstrap.empty_page.retire_expire",
    "m1.bootstrap.empty_page.free_is_zero",
    "m1.bootstrap.empty_page.xthread_free",
    "m1.bootstrap.empty_page.theap_is_null",
    "m1.bootstrap.empty_page.heap_is_null",
    "m1.bootstrap.empty_page.next_is_null",
    "m1.bootstrap.empty_page.prev_is_null",
    "m1.bootstrap.empty_page.memid.base_is_null",
    "m1.bootstrap.empty_page.memid.size",
    "m1.bootstrap.empty_page.memid.kind",
    "m1.bootstrap.empty_page.memid.pinned",
    "m1.bootstrap.empty_page.memid.committed",
    "m1.bootstrap.empty_page.memid.zero",
    "m1.bootstrap.empty_theap.pages_free_direct.count",
    "m1.bootstrap.empty_theap.pages_free_direct.all_empty_page",
    "m1.bootstrap.detached_tld.thread_id",
    "m1.bootstrap.detached_tld.thread_seq",
    "m1.bootstrap.detached_tld.numa_node",
    "m1.bootstrap.detached_tld.subproc_is_null",
    "m1.bootstrap.detached_tld.theaps_is_null",
    "m1.bootstrap.detached_tld.lock_is_initially_acquirable",
    "m1.bootstrap.detached_tld.recurse",
    "m1.bootstrap.detached_tld.is_in_threadpool",
    "m1.bootstrap.detached_tld.memid.base_is_null",
    "m1.bootstrap.detached_tld.memid.size",
    "m1.bootstrap.detached_tld.memid.kind",
    "m1.bootstrap.detached_tld.memid.pinned",
    "m1.bootstrap.detached_tld.memid.committed",
    "m1.bootstrap.detached_tld.memid.zero",
    "m1.bootstrap.empty_theap.tld_is_detached_tld",
    "m1.bootstrap.empty_theap.heap_is_null",
    "m1.bootstrap.empty_theap.subproc_is_null",
    "m1.bootstrap.empty_theap.refcount",
    "m1.bootstrap.empty_theap.heartbeat",
    "m1.bootstrap.empty_theap.cookie",
    "m1.bootstrap.empty_theap.random.input_all_zero",
    "m1.bootstrap.empty_theap.random.output_all_zero",
    "m1.bootstrap.empty_theap.random.output_available",
    "m1.bootstrap.empty_theap.random.weak",
    "m1.bootstrap.empty_theap.page_count",
    "m1.bootstrap.empty_theap.page_retired_min",
    "m1.bootstrap.empty_theap.page_retired_max",
    "m1.bootstrap.empty_theap.pages_full_size",
    "m1.bootstrap.empty_theap.generic_count",
    "m1.bootstrap.empty_theap.generic_collect_count",
    "m1.bootstrap.empty_theap.tnext_is_null",
    "m1.bootstrap.empty_theap.tprev_is_null",
    "m1.bootstrap.empty_theap.hnext_is_null",
    "m1.bootstrap.empty_theap.hprev_is_null",
    "m1.bootstrap.empty_theap.page_full_retain",
    "m1.bootstrap.empty_theap.allow_page_reclaim",
    "m1.bootstrap.empty_theap.allow_page_abandon",
    "m1.bootstrap.empty_theap.is_detached",
    "m1.bootstrap.empty_theap.page_queues.count",
    "m1.bootstrap.empty_theap.page_queues.all_first_null",
    "m1.bootstrap.empty_theap.page_queues.all_last_null",
    "m1.bootstrap.empty_theap.page_queues.all_count_zero",
    *M1_BOOTSTRAP_PAGE_QUEUE_BLOCK_SIZE_LAYOUT_KEYS,
    "m1.bootstrap.empty_theap.memid.base_is_null",
    "m1.bootstrap.empty_theap.memid.size",
    "m1.bootstrap.empty_theap.memid.kind",
    "m1.bootstrap.empty_theap.memid.pinned",
    "m1.bootstrap.empty_theap.memid.committed",
    "m1.bootstrap.empty_theap.memid.zero",
)
M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEY_SET = frozenset(
    M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEYS
)
# These eight fields predate the enlarged vector and remain in the ordinary
# layout reader: their pointed source objects are const and process attach
# does not mutate them. The separate reader owns every newly audited mutable
# detached-TLD relationship and all other static-image-only observations.
M1_BOOTSTRAP_LEGACY_GENERIC_LAYOUT_KEYS = (
    "m1.bootstrap.empty_page.memid.kind",
    "m1.bootstrap.empty_page.memid.pinned",
    "m1.bootstrap.empty_page.memid.committed",
    "m1.bootstrap.empty_page.memid.zero",
    "m1.bootstrap.empty_theap.memid.kind",
    "m1.bootstrap.empty_theap.memid.pinned",
    "m1.bootstrap.empty_theap.memid.committed",
    "m1.bootstrap.empty_theap.memid.zero",
)
M1_BOOTSTRAP_STATIC_IMAGE_READER_ONLY_LAYOUT_KEY_SET = (
    M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEY_SET
    - frozenset(M1_BOOTSTRAP_LEGACY_GENERIC_LAYOUT_KEYS)
)

# `src/prim/prim.c` normally auto-attaches before C `main`, which runs
# `mi_heap_main_init_once` and changes the mutable detached-TLD object.  The
# static-image reader alone suppresses that constructor so it observes the
# `src/init.c` initializer; normal C-oracle artifacts retain their production
# automatic process-attach configuration.
M1_BOOTSTRAP_STATIC_IMAGE_PROBE_DEFINES = (
    "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
)

# `mi_atomic_do_once` is a macro, so its finite M1 accounting must name every
# pinned direct invocation rather than imply that a local once unit test has
# covered each lifecycle route. M1 covers immutable static images plus the
# generic once protocol and one bounded ProcessMain envelope; full
# process/page-map/TLS lifecycle routes remain explicitly deferred.
M1_BOOTSTRAP_ATOMIC_ONCE_CALL_SITE_DISPOSITIONS = (
    {
        "configuration": "all selected builds",
        "disposition": "deferred-to-m2",
        "function": "_mi_page_map_init",
        "reason": "page-map allocation and release publication are a later memory-substrate boundary",
        "source": "src/page-map.c:361",
    },
    {
        "configuration": "all selected builds",
        "disposition": "m1-static-image-only",
        "function": "mi_heap_main_init_once",
        "reason": "the immutable initial images are checked here; full main-heap initialization, publication, and lifecycle remain outside M1",
        "source": "src/init.c:211",
    },
    {
        "configuration": "all selected builds",
        "disposition": "deferred-to-m5",
        "function": "mi_process_setup_auto_thread_done",
        "reason": "automatic thread-exit registration and teardown are lifecycle work",
        "source": "src/init.c:443",
    },
    {
        "configuration": "all selected builds",
        "disposition": "m1-bounded-once-envelope",
        "function": "mi_process_init",
        "reason": "the bounded identity-capable ProcessMain route proves active-racer blocking, recursive refusal, terminal publication before release, retained failure wakeup, and pre-body cancellation; options, OS, statistics, TLS-key/local, arena, automatic, and general lifecycle work remain M5",
        "source": "src/init.c:589",
    },
    {
        "configuration": "all selected builds",
        "disposition": "deferred-to-m5",
        "function": "mi_process_done",
        "reason": "a separate source once instance, process destruction, and lifecycle remain M5; ProcessMainThread teardown is ticket-zero thread teardown, not this function",
        "source": "src/init.c:653",
    },
    {
        "configuration": "MI_TLS_MODEL_WINDOWS",
        "disposition": "outside-m1",
        "function": "_mi_tls_slots_init",
        "reason": "Windows TLS-slot branch is outside the Linux/AArch64 target",
        "source": "src/prim/prim-tls.c:124",
    },
    {
        "configuration": "MI_TLS_MODEL_PTHREADS",
        "disposition": "deferred-to-m5",
        "function": "_mi_tls_slots_init",
        "reason": "pthread-key allocation and destruction belong to the later TLS/process lifecycle",
        "source": "src/prim/prim-tls.c:165",
    },
    {
        "configuration": "MI_TLS_MODEL_FIXED",
        "disposition": "outside-m1",
        "function": "_mi_tls_slots_init",
        "reason": "fixed TLS-slot branch is not the selected Linux/AArch64 pthread model",
        "source": "src/prim/prim-tls.c:182",
    },
    {
        "configuration": "MI_OSX_INTERPOSE && MI_SHARED_LIB_EXPORT",
        "disposition": "outside-m1",
        "function": "mi_get_default_zone",
        "reason": "macOS malloc-zone interposition is outside the active platform",
        "source": "src/prim/osx/alloc-override-zone.c:291",
    },
    {
        "configuration": "Windows",
        "disposition": "outside-m1",
        "function": "win_enable_large_os_pages",
        "reason": "Windows large-page privilege setup is outside the active platform",
        "source": "src/prim/windows/prim.c:162",
    },
    {
        "configuration": "Windows",
        "disposition": "outside-m1",
        "function": "_mi_prim_process_info",
        "reason": "Windows psapi lazy loading is outside the active platform",
        "source": "src/prim/windows/prim.c:610",
    },
    {
        "configuration": "Windows && !MI_USE_RTLGENRANDOM",
        "disposition": "outside-m1",
        "function": "_mi_prim_random_buf",
        "reason": "Windows bcrypt lazy loading is outside the active platform",
        "source": "src/prim/windows/prim.c:721",
    },
)
M1_RAW_PRIMITIVE_DECLARATIONS = (
    "mi_os_mem_config_t",
    "_mi_prim_mem_init",
    "_mi_prim_free",
    "_mi_prim_alloc",
    "_mi_prim_commit",
    "_mi_prim_decommit",
    "_mi_prim_reset",
    "_mi_prim_reuse",
    "_mi_prim_protect",
    "_mi_prim_alloc_huge_os_pages",
    "_mi_prim_numa_node",
    "_mi_prim_numa_node_count",
    "_mi_prim_clock_now",
    "mi_process_info_t",
    "_mi_prim_process_info",
    "_mi_prim_out_stderr",
    "_mi_prim_getenv",
    "_mi_prim_random_buf",
    "_mi_prim_thread_init_auto_done",
    "_mi_prim_thread_done_auto_done",
    "_mi_prim_thread_associate_default_theap",
    "_mi_prim_thread_is_in_threadpool",
    "_mi_prim_thread_yield",
)
M1_RAW_PRIMITIVE_DECLARATION_CLASSIFICATIONS = frozenset(
    {"m1-raw-boundary", "later-milestone-exclusion"}
)

# This is a source-order contract, not a claim that the incomplete Rust port
# has completed generic owner exit.  Each name fixes the source fact to its
# pinned-v3.5.0 definition so a later contract edit cannot silently turn a
# different helper into the owner-exit evidence anchor.
OWNER_EXIT_PUBLICATION_SOURCE_FACT_SHAPES = {
    "thread-exit-selects-abandon-collection": ("src/init.c", "mi_thread_theaps_done"),
    "owner-exit-collect-before-abandon": ("src/theap.c", "mi_theap_page_collect"),
    "queue-detach-before-abandoned-identity": ("src/page.c", "_mi_page_abandon"),
    "abandoned-identity-release-publication": (
        "include/mimalloc/internal.h",
        "mi_page_set_theap",
    ),
    "mapped-bitmap-publication-before-unown": (
        "src/arena.c",
        "_mi_arenas_page_abandon",
    ),
    "os-list-publication-before-unown": ("src/arena.c", "_mi_arenas_page_abandon"),
    "empty-owner-exit-terminal-release": ("src/page.c", "_mi_page_abandon"),
    "empty-abandoned-terminal-release": ("src/free.c", "mi_abandoned_page_try_free"),
}

OWNER_EXIT_PUBLICATION_ROUTE_SHAPES = {
    "mapped-arena-bitmap": {
        "sequence": [
            "queue-detach",
            "abandoned-identity",
            "mapped-bitmap-publication",
            "unown",
        ],
        "source_fact_ids": [
            "queue-detach-before-abandoned-identity",
            "abandoned-identity-release-publication",
            "mapped-bitmap-publication-before-unown",
        ],
    },
    "non-arena-os-list": {
        "sequence": [
            "queue-detach",
            "abandoned-identity",
            "os-list-publication",
            "unown",
        ],
        "source_fact_ids": [
            "queue-detach-before-abandoned-identity",
            "abandoned-identity-release-publication",
            "os-list-publication-before-unown",
        ],
    },
}

OWNER_EXIT_EMPTY_TERMINAL_FORBIDDEN_EVENTS = [
    "queue-detach",
    "abandoned-identity",
    "mapped-bitmap-publication",
    "os-list-publication",
    "unown",
]

OWNER_EXIT_STALE_W07_FORBIDDEN_INPUTS = [
    "raw-page-pointer",
    "raw-block-pointer",
    "xthread-free-head",
    "departed-theap-hint",
]

# These are the concrete Gate 5C conditions, plus the two acceptance-boundary
# facts that make the evidence about the one production traversal rather than
# a collection of special routes. The checked-in behavior contract maps each
# condition to an executable direct test or source-level focused test filter.
NATIVE_OWNER_EXIT_REQUIRED_SCENARIOS = frozenset(
    {
        "a-exits-b-frees",
        "completed-route-local-session-continuation",
        "empty-during-exit-collection",
        "failed-os-terminal-release",
        "general-production-traversal",
        "live-page-abandonment",
        "mixed-departing-theap",
        "multiple-bins-and-page-kinds",
        "multiple-live-pages",
        "old-theap-teardown",
        "post-exit-claim-page-map-lifetime",
        "post-exit-page-map-and-live-remote",
        "remote-free-after-exit",
        "remote-free-before-exit",
        "source-permitted-adoption",
        "terminal-admission-order",
        "terminal-ownership-release",
    }
)

PRODUCTION_RUST_TARGET = "aarch64-unknown-linux-musl"
X86_64_RUST_TARGET = "x86_64-unknown-linux-musl"
X86_64_INTERPRETER = "ld-musl-x86_64.so.1"
X86_64_ORACLE_REPORT_ROOT = REPORT_ROOT / "x86_64"
X86_64_ORACLE_ARTIFACT_ROOT = ARTIFACT_ROOT / "x86_64"

# The reviewed source selection for the adapter remains in the AArch64 M4
# contract.  The native x86-64 profile owns a separate target-local adapter
# contract that binds only that reviewed source selection by digest; it does
# not inherit the AArch64 target, dependency, or public-API claims.
X86_64_TARGET_METADATA: Mapping[str, Any] = {
    "architecture": "x86_64",
    "target": X86_64_RUST_TARGET,
    "interpreter": X86_64_INTERPRETER,
}
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
EXPECTED_PRODUCTION_DEPENDENCY_VERSIONS: Mapping[str, str] = {
    "crabc-mimalloc": "0.3.0",
    "crabc-core": "0.3.0",
    "chacha20": "0.10.1",
    "cfg-if": "1.0.4",
    "cipher": "0.5.2",
    "block-buffer": "0.12.1",
    "hybrid-array": "0.4.14",
    "typenum": "1.20.1",
    "crypto-common": "0.2.2",
    "inout": "0.2.2",
    "zeroize": "1.9.0",
}
EXPECTED_PRODUCTION_DEPENDENCY_EDGES: Mapping[str, tuple[str, ...]] = {
    "crabc-mimalloc": ("chacha20", "crabc-core", "zeroize"),
    "crabc-core": (),
    "chacha20": ("cfg-if", "cipher", "zeroize"),
    "cfg-if": (),
    "cipher": ("block-buffer", "crypto-common", "inout"),
    "block-buffer": ("hybrid-array",),
    "hybrid-array": ("typenum",),
    "typenum": (),
    "crypto-common": ("hybrid-array",),
    "inout": ("hybrid-array",),
    "zeroize": (),
}
# This is intentionally not derived from the AArch64 production contract.
# `chacha20` selects RustCrypto's no_std x86 CPUID helper on this target, while
# the x86_64-unknown-linux-musl normal graph selects no `libc` package.  Keep
# both the extra package and the absence of libc reviewable at this target
# boundary instead of treating lockfile-wide package presence as evidence.
EXPECTED_X86_64_ENGINE_DEPENDENCY_VERSIONS: Mapping[str, str] = {
    "crabc-mimalloc": "0.3.0",
    "crabc-core": "0.3.0",
    "chacha20": "0.10.1",
    "cfg-if": "1.0.4",
    "cipher": "0.5.2",
    "block-buffer": "0.12.1",
    "hybrid-array": "0.4.14",
    "typenum": "1.20.1",
    "crypto-common": "0.2.2",
    "inout": "0.2.2",
    "zeroize": "1.9.0",
    "cpufeatures": "0.3.0",
}
EXPECTED_X86_64_ENGINE_DEPENDENCY_EDGES: Mapping[str, tuple[str, ...]] = {
    "crabc-mimalloc": ("chacha20", "crabc-core", "zeroize"),
    "crabc-core": (),
    "chacha20": ("cfg-if", "cipher", "cpufeatures", "zeroize"),
    "cfg-if": (),
    "cipher": ("block-buffer", "crypto-common", "inout"),
    "block-buffer": ("hybrid-array",),
    "hybrid-array": ("typenum",),
    "typenum": (),
    "crypto-common": ("hybrid-array",),
    "inout": ("hybrid-array",),
    "zeroize": (),
    "cpufeatures": (),
}
# The native x86-64 Docker path bind-mounts an initially empty Cargo cache.
# `--locked` therefore gives the required reproducible resolution boundary,
# while allowing Cargo to populate that cache with only lockfile-selected
# packages on a first run.  Do not add `--offline` to this evidence lane unless
# the canonical image has a separately verified cache-bootstrap contract.
X86_64_LOCKFILE_RESOLUTION: Mapping[str, Any] = {
    "cache": "may be populated from the network with lockfile-selected packages",
    "lockfile_verified": True,
    "offline": False,
}

STATUS_FIELDS = (
    "exported",
    "implemented",
    "unit_verified",
    "differential_verified",
    "stress_verified",
    "performance_qualified",
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

# The M1 raw fixture includes the pinned `src/os.c` into its own translation
# unit so it can observe the source-private immutable configuration record.
# The ordinary source list must omit that one file to keep every C definition
# singular; `src/prim/prim.c` continues to own the Unix primitive inclusion.
M1_RAW_PRIMITIVE_ORACLE_SOURCES = tuple(
    item for item in ORACLE_SOURCES if item != "src/os.c"
)

# Both compiler-TLS readers include the pinned `src/threadlocal.c` directly
# to observe its otherwise-private direct TLS roots. Their source lists omit
# the standalone translation unit so every C definition remains singular. The
# image reader and normal transition reader are deliberately separate: only
# the former suppresses `src/prim/prim.c` automatic process attach.
M1_COMPILER_TLS_ORACLE_SOURCES = tuple(
    item for item in ORACLE_SOURCES if item != "src/threadlocal.c"
)

# The same-TLD terminal trace includes the pinned `src/init.c` into its dedicated
# probe translation unit so the probe can call the source-private static
# `mi_thread_theaps_done` body. Keep the ordinary source list otherwise
# normal, including `threadlocal.c`; omitting only `init.c` keeps every C
# definition singular.
M1_COMPILER_TLS_SAME_TLD_TRACE_ORACLE_SOURCES = tuple(
    item for item in ORACLE_SOURCES if item != "src/init.c"
)

# This detached-TLD producer includes `src/init.c` directly solely to call
# file-static `mi_tld_init` on a fresh source-shaped local image. Keep the
# ordinary list otherwise complete and omit only init.c so the direct source
# body has exactly one definition. The build also defines
# MI_PRIM_HAS_PROCESS_ATTACH=1: unlike a normal mimalloc artifact, this
# isolated preimage must not let prim.c's constructor mutate state before
# main observes it.
M2_DETACHED_TLD_STATIC_PREIMAGE_ORACLE_SOURCES = tuple(
    item for item in ORACLE_SOURCES if item != "src/init.c"
)

# The normal direct-helper producer follows the same one-definition rule as
# the detached producer, but has its own fixture and source/provenance record.
M2_NORMAL_TLD_DIRECT_ORACLE_SOURCES = tuple(
    item for item in ORACLE_SOURCES if item != "src/init.c"
)

# The static-first caller producer also direct-includes only init.c. It keeps
# subproc.c in the ordinary source list because its real static main identity
# is an explicit precondition of the selected branch.
M2_STATIC_FIRST_TLD_CREATE_ORACLE_SOURCES = tuple(
    item for item in ORACLE_SOURCES if item != "src/init.c"
)

# The selected M2 PageMap producer directly includes the three source units
# whose private state and source-order initialization are under test. Keep
# those units out of the ordinary C source list so every definition remains
# singular in the dedicated executable.
M2_PAGE_MAP_ORACLE_SOURCES = tuple(
    item
    for item in ORACLE_SOURCES
    if item not in {"src/os.c", "src/page-map.c", "src/init.c"}
)

# The reviewed M4 and M5 adapters are intentionally partial adaptations, not a
# claim that every pinned upstream test now runs. Keep their exact source and
# support input names here, beside the generated inventory, so an inventory
# refresh cannot regress them back to the historical "adapter absent" state.
# `adapted-tests-v3.5.0.json` remains the durable selection/omission contract
# for the 33 selected `test-api.c` checks. The separate M5 stress contract
# preserves one constrained `test-stress.c` creating-thread route only.
M4_ADAPTED_UPSTREAM_TEST_PATHS = frozenset(
    {
        "test/test-api.c",
        "test/testhelper.h",
    }
)
M4_ADAPTED_UPSTREAM_TEST_NOTE = (
    "Milestone 4: selected through the reviewed prefixed Rust test C API adapter; "
    "the exact selected checks and omissions are in adapted-tests-v3.5.0.json."
)
M5_ADAPTED_UPSTREAM_TEST_PATHS = frozenset({"test/test-stress.c"})
M5_ADAPTED_UPSTREAM_TEST_NOTE = (
    "Milestone 5 preliminary evidence: a reviewed source-derived, single-creating-thread "
    "adaptation runs test/test-stress.c through the prefixed Rust adapter; its exact "
    "scope and exclusions are in adapted-stress-test-v3.5.0.json."
)
M5_PLUS_UNADAPTED_UPSTREAM_TEST_NOTE = (
    "Milestone 5+: outside the reviewed M4 adapter selection; this source needs its own "
    "API, lifecycle, and execution contract before it can run through the Rust adapter."
)

# These files are translation units included by the sources above, not absent
# source-map work.  They remain independent rows because their invariants need
# a direct Rust destination and verification record later.
REQUIRED_PORT_UNITS = (
    "include/mimalloc.h",
    "include/mimalloc-stats.h",
    "include/mimalloc/types.h",
    "include/mimalloc/atomic.h",
    "include/mimalloc/bits.h",
    "include/mimalloc/prim.h",
    "include/mimalloc/prim-tls.h",
    "include/mimalloc/internal.h",
    "src/alloc.c",
    "src/alloc-aligned.c",
    "src/alloc-posix.c",
    "src/alloc-override.c",
    "src/free.c",
    "src/arena.c",
    "src/bitmap.h",
    "src/bitmap.c",
    "src/heap.c",
    "src/init.c",
    "src/libc.c",
    "src/options.c",
    "src/os.c",
    "src/page-map.c",
    "src/page.c",
    "src/page-queue.c",
    "src/random.c",
    "src/stats.c",
    "src/static.c",
    "src/subproc.c",
    "src/theap.c",
    "src/threadlocal.c",
    "src/prim/prim.c",
    "src/prim/prim-tls.c",
    "src/prim/unix/prim.c",
    "src/prim/unix/prim-tls.c",
)

PUBLIC_HEADERS = (
    "include/mimalloc.h",
    "include/mimalloc-stats.h",
    "include/mimalloc-override.h",
    "include/mimalloc-new-delete.h",
)

# `CMakeLists.txt` puts these four declarations in the installed public header,
# but the normal shared library does not define them.  The two stale entries
# have no v3.5.0 definition at all; the two malloc-size helpers are supplied
# only when the opt-in `src/alloc-override.c` translation unit is selected.
# Keeping this table explicit makes a header/symbol discrepancy a reviewed
# compatibility fact instead of a parser accident.
NORMAL_RELEASE_SYMBOL_EXCEPTIONS: Mapping[str, str] = {
    "mi_collect_reduce": (
        "Deprecated public-header declaration has no definition in the pinned "
        "v3.5.0 normal-release source set."
    ),
    "mi_malloc_size": (
        "Defined only by opt-in src/alloc-override.c, which is outside the "
        "normal v3.5.0 shared-library source set."
    ),
    "mi_malloc_usable_size": (
        "Defined only by opt-in src/alloc-override.c, which is outside the "
        "normal v3.5.0 shared-library source set."
    ),
    "mi_stats_merge": (
        "Deprecated public-header declaration has no definition in the pinned "
        "v3.5.0 normal-release source set."
    ),
}

STALE_EXTERNAL_DECLARATIONS = frozenset({"mi_collect_reduce", "mi_stats_merge"})
OVERRIDE_ONLY_EXTERNAL_DECLARATIONS = frozenset({"mi_malloc_size", "mi_malloc_usable_size"})

# The wide-environment helper is an applicable Linux interface: the pinned C
# oracle exports it, and its non-Windows EINVAL result is observable behavior
# that a parity implementation must preserve.
LINUX_AARCH64_LIMITED_EXTERNAL_REASONS: Mapping[str, str] = {
    "mi_wdupenv_s": (
        "The pinned src/alloc-posix.c body explicitly reports this Windows "
        "wide-environment operation unsupported on non-Windows targets. The "
        "Linux C oracle still defines the EINVAL-returning symbol, and the "
        "release-symbol contract records it."
    ),
}

API_CLASSIFICATION_SOURCES: Mapping[str, tuple[str, ...]] = {
    "mi_collect_reduce": (
        "include/mimalloc.h:450",
        "normal-release-source-set:no-definition",
    ),
    "mi_option_os_tag": (
        "include/mimalloc.h:484",
        "src/options.c:143",
        "src/prim/unix/prim.c:367-377",
    ),
    "mi_option_retry_on_oom": (
        "include/mimalloc.h:493",
        "src/options.c:152",
        "src/prim/windows/prim.c:321-340",
    ),
    "mi_stats_merge": (
        "include/mimalloc.h:453",
        "normal-release-source-set:no-definition",
    ),
    "mi_wdupenv_s": (
        "include/mimalloc.h:564",
        "src/alloc-posix.c:157-175",
    ),
}

EXPERIMENTAL_EXTERNAL_FUNCTIONS = frozenset(
    {
        "mi_manage_memory",
        "mi_theap_guarded_set_sample_rate",
        "mi_theap_guarded_set_size_bound",
        "mi_unsafe_heap_page_is_under_utilized",
    }
)

DEPRECATED_EXTERNAL_FUNCTIONS = frozenset(
    {
        "mi_check_owned",
        "mi_collect_reduce",
        "mi_is_in_heap_region",
        "mi_reserve_huge_os_pages",
        "mi_stats_merge",
        "mi_stats_print",
        "mi_stats_reset",
        "mi_theap_visit_blocks",
        "mi_thread_stats_print_out",
    }
)

CXX_NEW_DELETE_EXTERNAL_FUNCTIONS = frozenset(
    {
        "mi_heap_alloc_new",
        "mi_heap_alloc_new_n",
        "mi_new",
        "mi_new_aligned",
        "mi_new_aligned_nothrow",
        "mi_new_n",
        "mi_new_nothrow",
        "mi_new_realloc",
        "mi_new_reallocn",
    }
)

HEADER_DEPRECATED_OPTIONS = frozenset(
    {
        "mi_option_deprecated_abandoned_page_purge",
        "mi_option_deprecated_eager_commit",
        "mi_option_deprecated_eager_commit_delay",
        "mi_option_deprecated_max_segment_reclaim",
        "mi_option_deprecated_page_reset",
        "mi_option_deprecated_purge_extend_delay",
        "mi_option_deprecated_segment_cache",
        "mi_option_deprecated_segment_reset",
        "mi_option_deprecated_visit_abandoned",
    }
)

LEGACY_OPTION_ALIASES = frozenset(
    {
        "mi_option_eager_region_commit",
        "mi_option_large_os_pages",
        "mi_option_limit_os_alloc",
        "mi_option_reset_decommits",
        "mi_option_reset_delay",
    }
)

CXX_DECLARATION_MACROS = frozenset({"mi_decl_new", "mi_decl_new_nothrow"})

GUARDED_MODE_OPTIONS = frozenset(
    {
        "mi_option_guarded_max",
        "mi_option_guarded_min",
        "mi_option_guarded_precise",
        "mi_option_guarded_sample_rate",
        "mi_option_guarded_sample_seed",
    }
)

PLATFORM_SPECIFIC_EFFECT_OPTIONS: Mapping[str, str] = {
    "mi_option_os_tag": (
        "Unconditional public enum value backed by the Linux option table and accepted by option get/set; "
        "only its OS logging effect is platform-specific."
    ),
    "mi_option_retry_on_oom": (
        "Unconditional public enum value backed by the Linux option table and accepted by option get/set; "
        "only its out-of-memory retry effect is Windows-specific."
    ),
}

PLATFORM_LIMITED_LINUX_AARCH64_COMPILE_MODES: Mapping[
    str, tuple[str, tuple[str, ...]]
] = {
    "MI_OSX_INTERPOSE": (
        "The unconditional root-CMake option is accepted on Linux/AArch64 and omitted from the APPLE-only interposition branch; that no-op result is required observable behavior.",
        ("CMakeLists.txt:36", "CMakeLists.txt:254-274"),
    ),
    "MI_OSX_ZONE": (
        "The unconditional root-CMake option is accepted on Linux/AArch64 and omitted from the APPLE-only malloc-zone branch; that no-op result is required observable behavior.",
        ("CMakeLists.txt:37", "CMakeLists.txt:254-274"),
    ),
    "MI_TRACK_ETW": (
        "The unconditional deprecated option is accepted on Linux/AArch64; its Windows-only ETW request is disabled by the pinned configuration, which is required observable behavior.",
        ("CMakeLists.txt:82", "CMakeLists.txt:322-329"),
    ),
    "MI_TLS_MODEL_FIXED": (
        "The unconditional deprecated option is accepted on Linux/AArch64 and selects a fixed-slot source path that emits a compile error without out-of-contract custom slots; that rejection is required observable behavior.",
        ("CMakeLists.txt:74", "include/mimalloc/prim-tls.h:342-365"),
    ),
    "MI_WIN_DIRECT_TLS": (
        "The unconditional deprecated Windows direct-TLS selector is accepted by root CMake on Linux/AArch64; its platform-limited compile behavior remains a parity obligation.",
        ("CMakeLists.txt:79", "CMakeLists.txt:560-563"),
    ),
    "MI_WIN_INIT": (
        "The unconditional Windows initialization cache selector is accepted by root CMake on Linux/AArch64; its platform-limited selection behavior remains a parity obligation.",
        ("CMakeLists.txt:59", "CMakeLists.txt:565-589"),
    ),
    "MI_WIN_INIT_USE_RAW_DLLMAIN": (
        "The unconditional deprecated raw-DllMain selector is accepted by root CMake on Linux/AArch64; its platform-limited selection behavior remains a parity obligation.",
        ("CMakeLists.txt:77", "CMakeLists.txt:565-577"),
    ),
    "MI_WIN_INIT_USE_TLS_DLLMAIN": (
        "The unconditional deprecated TLS-DllMain selector is accepted by root CMake on Linux/AArch64; its platform-limited selection behavior remains a parity obligation.",
        ("CMakeLists.txt:78", "CMakeLists.txt:565-582"),
    ),
    "MI_WIN_REDIRECT": (
        "The unconditional root-CMake option is accepted on Linux/AArch64 and omitted from the WIN32-only redirection branch; that no-op result is required observable behavior.",
        ("CMakeLists.txt:38", "CMakeLists.txt:276-281"),
    ),
    "MI_WIN_USE_FLS": (
        "The unconditional deprecated FLS selector is accepted by root CMake on Linux/AArch64; its platform-limited selection behavior remains a parity obligation.",
        ("CMakeLists.txt:76", "CMakeLists.txt:565-586"),
    ),
}

DEPRECATED_COMPILE_MODES = frozenset(
    {
        "MI_CHECK_FULL",
        "MI_DEBUG_FULL",
        "MI_DEBUG_INTERNAL",
        "MI_LOCAL_DYNAMIC_TLS",
        "MI_OPT_FREE_SMALL",
        "MI_SECURE_FULL",
        "MI_TLS_MODEL_FIXED",
        "MI_TLS_MODEL_LOCAL",
        "MI_TLS_MODEL_PTHREADS",
        "MI_TRACK_ASAN",
        "MI_TRACK_ETW",
        "MI_TRACK_VALGRIND",
        "MI_USE_LIBATOMIC",
        "MI_WIN_DIRECT_TLS",
        "MI_WIN_INIT_USE_RAW_DLLMAIN",
        "MI_WIN_INIT_USE_TLS_DLLMAIN",
        "MI_WIN_USE_FLS",
    }
)

SOURCE_BUILD_CONTROL_MODES = frozenset(
    {"MI_BUILD_TESTS", "MI_EXTRA_CPPDEFS", "MI_INSTALL_TOPLEVEL", "MI_SEE_ASM"}
)

ARTIFACT_COMPILE_MODES = frozenset({"MI_BUILD_OBJECT", "MI_BUILD_SHARED", "MI_BUILD_STATIC"})

PLATFORM_LIMITED_LINUX_AARCH64_MODE_VALUES: Mapping[
    tuple[str, str], tuple[str, tuple[str, ...]]
] = {
    ("MI_TLS_MODEL", "FIXED"): (
        "The value is accepted by root CMake and the pinned fixed-slot TLS source emits a compile error on Linux/AArch64 without an out-of-contract custom slot definition; that rejection is required observable behavior.",
        ("CMakeLists.txt:62", "include/mimalloc/prim-tls.h:342-365"),
    ),
    ("MI_TLS_MODEL", "WIN32"): (
        "The value is accepted by root CMake and selects the direct Win32 TlsAlloc source path; its Linux/AArch64 compile result is required observable behavior.",
        ("CMakeLists.txt:62", "include/mimalloc/prim-tls.h:22-25", "include/mimalloc/prim-tls.h:297-341"),
    ),
    ("MI_TRACK", "ETW"): (
        "The value is accepted on Linux/AArch64 and the pinned root CMake configuration warns and resets MI_TRACK to OFF; that fallback is required observable behavior.",
        ("CMakeLists.txt:24", "CMakeLists.txt:322-329"),
    ),
}

CONFIGURATION_PROFILES: Mapping[str, tuple[str, ...]] = {
    # The normal Linux/AArch64 profile deliberately does not use v3's optional
    # Armv8.3 path: crabc's production baseline is Armv8.0 / Linux 5.10.
    "release": (
        "-O3",
        "-DNDEBUG",
        "-DMI_BUILD_RELEASE=1",
        "-DMI_DEBUG=0",
        "-DMI_STAT=0",
        "-DMI_SECURE=0",
        "-DMI_GUARDED=0",
    ),
    "debug-full": (
        "-O0",
        "-g3",
        "-DMI_DEBUG=3",
        "-DMI_STAT=2",
        "-DMI_GUARDED=1",
        "-DMI_SECURE=0",
    ),
    "secure": (
        "-O2",
        "-DNDEBUG",
        "-DMI_BUILD_RELEASE=1",
        "-DMI_DEBUG=0",
        "-DMI_STAT=0",
        "-DMI_SECURE=4",
        "-DMI_FREE_IS_CHECKED=1",
    ),
    "secure-full": (
        "-O2",
        "-DNDEBUG",
        "-DMI_BUILD_RELEASE=1",
        "-DMI_DEBUG=0",
        "-DMI_STAT=0",
        "-DMI_SECURE=5",
        "-DMI_FREE_IS_CHECKED=1",
    ),
    "guarded-stats": (
        "-O2",
        "-DNDEBUG",
        "-DMI_BUILD_RELEASE=1",
        "-DMI_DEBUG=0",
        "-DMI_STAT=2",
        "-DMI_SECURE=0",
        "-DMI_GUARDED=1",
    ),
}

LAYOUT_PROBE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <mimalloc.h>
#include <mimalloc/internal.h>
#include "bitmap.h"

#ifdef MI_GUARDED
#define CRABC_MI_GUARDED MI_GUARDED
#else
#define CRABC_MI_GUARDED 0
#endif
#ifdef MI_PADDING
#define CRABC_MI_PADDING MI_PADDING
#else
#define CRABC_MI_PADDING 0
#endif
#ifdef MI_ENCODE_FREELIST
#define CRABC_MI_ENCODE_FREELIST MI_ENCODE_FREELIST
#else
#define CRABC_MI_ENCODE_FREELIST 0
#endif
#ifdef MI_FREE_IS_CHECKED
#define CRABC_MI_FREE_IS_CHECKED MI_FREE_IS_CHECKED
#else
#define CRABC_MI_FREE_IS_CHECKED 0
#endif
#ifdef MI_FREE_USE_PAGEMAP
#define CRABC_MI_FREE_USE_PAGEMAP MI_FREE_USE_PAGEMAP
#else
#define CRABC_MI_FREE_USE_PAGEMAP 0
#endif
#ifdef MI_OPT_FREE_SMALL
#define CRABC_MI_OPT_FREE_SMALL MI_OPT_FREE_SMALL
#else
#define CRABC_MI_OPT_FREE_SMALL 0
#endif
#ifdef MI_OPT_SIMD
#define CRABC_MI_OPT_SIMD MI_OPT_SIMD
#else
#define CRABC_MI_OPT_SIMD 0
#endif
#ifdef MI_PAGE_META_IS_ALIGNED
#define CRABC_MI_PAGE_META_IS_ALIGNED MI_PAGE_META_IS_ALIGNED
#else
#define CRABC_MI_PAGE_META_IS_ALIGNED 0
#endif
#ifdef MI_PAGE_META_ALIGNED_CHUNKS
#define CRABC_MI_PAGE_META_ALIGNED_CHUNKS MI_PAGE_META_ALIGNED_CHUNKS
#else
#define CRABC_MI_PAGE_META_ALIGNED_CHUNKS 0
#endif
#ifdef MI_PAGE_META_ALIGNED_COUNT
#define CRABC_MI_PAGE_META_ALIGNED_COUNT MI_PAGE_META_ALIGNED_COUNT
#else
#define CRABC_MI_PAGE_META_ALIGNED_COUNT 0
#endif
#ifdef MI_PAGE_META_ALIGNMENT
#define CRABC_MI_PAGE_META_ALIGNMENT MI_PAGE_META_ALIGNMENT
#else
#define CRABC_MI_PAGE_META_ALIGNMENT 0
#endif

// `_mi_theap_alloc` rounds the complete pinned C image to one arena minimum
// object. Rust deliberately does not use its partial Theap representation as
// a complete C object, so keep the complete C-size fact in this C oracle
// rather than comparing the two layouts.
_Static_assert(sizeof(mi_theap_t) <= MI_ARENA_MIN_OBJ_SIZE,
               "pinned mi_theap_t must fit one arena minimum object");

static uint64_t m1_random_state_fingerprint(const mi_random_ctx_t* ctx) {
  uint64_t fingerprint = UINT64_C(0xcbf29ce484222325);
  for (size_t index = 0; index < 16; index++) {
    fingerprint ^= (uint64_t)ctx->input[index];
    fingerprint *= UINT64_C(0x00000100000001b3);
  }
  for (size_t index = 0; index < 16; index++) {
    fingerprint ^= (uint64_t)ctx->output[index];
    fingerprint *= UINT64_C(0x00000100000001b3);
  }
  fingerprint ^= (uint64_t)(uint32_t)ctx->output_available;
  fingerprint *= UINT64_C(0x00000100000001b3);
  fingerprint ^= (uint64_t)ctx->weak;
  return fingerprint * UINT64_C(0x00000100000001b3);
}

static uint64_t m1_memkind_predicate_mask(bool is_os) {
  const mi_memkind_t kinds[] = {
    MI_MEM_NONE,
    MI_MEM_EXTERNAL,
    MI_MEM_STATIC,
    MI_MEM_OS,
    MI_MEM_OS_HUGE,
    MI_MEM_OS_REMAP,
    MI_MEM_ARENA,
    MI_MEM_MALLOC,
  };
  uint64_t mask = 0;
  for (size_t index = 0; index < sizeof(kinds) / sizeof(kinds[0]); index++) {
    const bool selected = (is_os
      ? mi_memkind_is_os(kinds[index])
      : mi_memkind_needs_no_free(kinds[index]));
    if (selected) {
      mask |= (UINT64_C(1) << index);
    }
  }
  return mask;
}

#define U(name, value) printf(name "=%llu\n", (unsigned long long)(value))
int main(void) {
  U("pointer.size", sizeof(void*));
  U("public.handle.mi_heap_t", sizeof(mi_heap_t*));
  U("public.handle.mi_theap_t", sizeof(mi_theap_t*));
  U("public.handle.mi_subproc_t", sizeof(mi_subproc_t*));
  U("sizeof.mi_memkind_t", sizeof(mi_memkind_t));
  U("alignof.mi_memkind_t", _Alignof(mi_memkind_t));
  U("value.MI_MEM_NONE", MI_MEM_NONE);
  U("value.MI_MEM_EXTERNAL", MI_MEM_EXTERNAL);
  U("value.MI_MEM_STATIC", MI_MEM_STATIC);
  U("value.MI_MEM_OS", MI_MEM_OS);
  U("value.MI_MEM_OS_HUGE", MI_MEM_OS_HUGE);
  U("value.MI_MEM_OS_REMAP", MI_MEM_OS_REMAP);
  U("value.MI_MEM_ARENA", MI_MEM_ARENA);
  U("value.MI_MEM_MALLOC", MI_MEM_MALLOC);
  U("sizeof.mi_memid_t.mem", sizeof(((mi_memid_t*)0)->mem));
  U("alignof.mi_memid_t.mem", __alignof__(((mi_memid_t*)0)->mem));
  U("sizeof.mi_memid_os_info_t", sizeof(mi_memid_os_info_t));
  U("alignof.mi_memid_os_info_t", _Alignof(mi_memid_os_info_t));
  U("offsetof.mi_memid_os_info_t.base", offsetof(mi_memid_os_info_t, base));
  U("offsetof.mi_memid_os_info_t.size", offsetof(mi_memid_os_info_t, size));
  U("sizeof.mi_memid_arena_info_t", sizeof(mi_memid_arena_info_t));
  U("alignof.mi_memid_arena_info_t", _Alignof(mi_memid_arena_info_t));
  U("offsetof.mi_memid_arena_info_t.arena", offsetof(mi_memid_arena_info_t, arena));
  U("offsetof.mi_memid_arena_info_t.slice_index", offsetof(mi_memid_arena_info_t, slice_index));
  U("offsetof.mi_memid_arena_info_t.slice_count", offsetof(mi_memid_arena_info_t, slice_count));
  U("sizeof.mi_memid_malloc_info_t", sizeof(mi_memid_malloc_info_t));
  U("alignof.mi_memid_malloc_info_t", _Alignof(mi_memid_malloc_info_t));
  U("offsetof.mi_memid_malloc_info_t.base", offsetof(mi_memid_malloc_info_t, base));
  U("offsetof.mi_memid_malloc_info_t.size", offsetof(mi_memid_malloc_info_t, size));
  U("sizeof.mi_memid_t", sizeof(mi_memid_t));
  U("alignof.mi_memid_t", _Alignof(mi_memid_t));
  U("offsetof.mi_memid_t.mem", offsetof(mi_memid_t, mem));
  U("offsetof.mi_memid_t.mem.os.base", offsetof(mi_memid_t, mem.os.base));
  U("offsetof.mi_memid_t.mem.os.size", offsetof(mi_memid_t, mem.os.size));
  U("offsetof.mi_memid_t.mem.arena.arena", offsetof(mi_memid_t, mem.arena.arena));
  U("offsetof.mi_memid_t.mem.arena.slice_index", offsetof(mi_memid_t, mem.arena.slice_index));
  U("offsetof.mi_memid_t.mem.arena.slice_count", offsetof(mi_memid_t, mem.arena.slice_count));
  U("offsetof.mi_memid_t.mem.malloc.base", offsetof(mi_memid_t, mem.malloc.base));
  U("offsetof.mi_memid_t.mem.malloc.size", offsetof(mi_memid_t, mem.malloc.size));
  U("offsetof.mi_memid_t.memkind", offsetof(mi_memid_t, memkind));
  U("offsetof.mi_memid_t.is_pinned", offsetof(mi_memid_t, is_pinned));
  U("offsetof.mi_memid_t.initially_committed", offsetof(mi_memid_t, initially_committed));
  U("offsetof.mi_memid_t.initially_zero", offsetof(mi_memid_t, initially_zero));
  U("m1.provenance.memkind.is_os.mask", m1_memkind_predicate_mask(true));
  U("m1.provenance.memkind.needs_no_free.mask", m1_memkind_predicate_mask(false));
  uint8_t m1_memid_anchor = 0;
  const mi_memid_t m1_memid_none = _mi_memid_none();
  const mi_memid_t m1_memid_static = _mi_memid_create(MI_MEM_STATIC);
  const mi_memid_t m1_memid_static_allocation =
      _mi_memid_create_static(&m1_memid_anchor, 37);
  const mi_memid_t m1_memid_malloc =
      _mi_memid_create_malloc(&m1_memid_anchor, 41, true);
  const mi_memid_t m1_memid_os =
      _mi_memid_create_os(&m1_memid_anchor, 43, false, true, true);
  U("m1.provenance.create.none.kind", m1_memid_none.memkind);
  U("m1.provenance.create.none.pinned", m1_memid_none.is_pinned);
  U("m1.provenance.create.none.committed", m1_memid_none.initially_committed);
  U("m1.provenance.create.none.zero", m1_memid_none.initially_zero);
  U("m1.provenance.create.none.memid_size", _mi_memid_size(m1_memid_none));
  U("m1.provenance.create.static.kind", m1_memid_static.memkind);
  U("m1.provenance.create.static.pinned", m1_memid_static.is_pinned);
  U("m1.provenance.create.static.committed", m1_memid_static.initially_committed);
  U("m1.provenance.create.static.zero", m1_memid_static.initially_zero);
  U("m1.provenance.create.static.base_is_null", m1_memid_static.mem.malloc.base == NULL);
  U("m1.provenance.create.static.stored_size", m1_memid_static.mem.malloc.size);
  U("m1.provenance.create.static.memid_size", _mi_memid_size(m1_memid_static));
  U("m1.provenance.create.static_allocation.kind", m1_memid_static_allocation.memkind);
  U("m1.provenance.create.static_allocation.pinned", m1_memid_static_allocation.is_pinned);
  U("m1.provenance.create.static_allocation.committed", m1_memid_static_allocation.initially_committed);
  U("m1.provenance.create.static_allocation.zero", m1_memid_static_allocation.initially_zero);
  U("m1.provenance.create.static_allocation.base_is_input", m1_memid_static_allocation.mem.malloc.base == &m1_memid_anchor);
  U("m1.provenance.create.static_allocation.stored_size", m1_memid_static_allocation.mem.malloc.size);
  U("m1.provenance.create.static_allocation.memid_size", _mi_memid_size(m1_memid_static_allocation));
  U("m1.provenance.create.malloc.kind", m1_memid_malloc.memkind);
  U("m1.provenance.create.malloc.pinned", m1_memid_malloc.is_pinned);
  U("m1.provenance.create.malloc.committed", m1_memid_malloc.initially_committed);
  U("m1.provenance.create.malloc.zero", m1_memid_malloc.initially_zero);
  U("m1.provenance.create.malloc.base_is_input", m1_memid_malloc.mem.malloc.base == &m1_memid_anchor);
  U("m1.provenance.create.malloc.stored_size", m1_memid_malloc.mem.malloc.size);
  U("m1.provenance.create.malloc.memid_size", _mi_memid_size(m1_memid_malloc));
  U("m1.provenance.create.os.kind", m1_memid_os.memkind);
  U("m1.provenance.create.os.pinned", m1_memid_os.is_pinned);
  U("m1.provenance.create.os.committed", m1_memid_os.initially_committed);
  U("m1.provenance.create.os.zero", m1_memid_os.initially_zero);
  U("m1.provenance.create.os.base_is_input", m1_memid_os.mem.os.base == &m1_memid_anchor);
  U("m1.provenance.create.os.stored_size", m1_memid_os.mem.os.size);
  U("m1.provenance.create.os.memid_size", _mi_memid_size(m1_memid_os));
  const mi_memid_t empty_page_memid = _mi_page_empty_get()->memid;
  const mi_memid_t empty_theap_memid = _mi_theap_empty.memid;
  U("m1.bootstrap.empty_page.memid.kind", empty_page_memid.memkind);
  U("m1.bootstrap.empty_page.memid.pinned", empty_page_memid.is_pinned);
  U("m1.bootstrap.empty_page.memid.committed", empty_page_memid.initially_committed);
  U("m1.bootstrap.empty_page.memid.zero", empty_page_memid.initially_zero);
  U("m1.bootstrap.empty_theap.memid.kind", empty_theap_memid.memkind);
  U("m1.bootstrap.empty_theap.memid.pinned", empty_theap_memid.is_pinned);
  U("m1.bootstrap.empty_theap.memid.committed", empty_theap_memid.initially_committed);
  U("m1.bootstrap.empty_theap.memid.zero", empty_theap_memid.initially_zero);
  U("sizeof.mi_random_ctx_t", sizeof(mi_random_ctx_t));
  U("alignof.mi_random_ctx_t", _Alignof(mi_random_ctx_t));
  U("offsetof.mi_random_ctx_t.input", offsetof(mi_random_ctx_t, input));
  U("offsetof.mi_random_ctx_t.output", offsetof(mi_random_ctx_t, output));
  U("offsetof.mi_random_ctx_t.output_available", offsetof(mi_random_ctx_t, output_available));
  U("offsetof.mi_random_ctx_t.weak", offsetof(mi_random_ctx_t, weak));
  // This selected M1 state vector deliberately records only values that are
  // stable across independent C and Rust processes. Weak-key bytes and child
  // block output depend on the documented degraded-entropy substitution or an
  // address-derived nonce, so they are not a false equality claim.
  mi_random_ctx_t random_parent = {
    { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
      0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
      0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
      0x00000001, 0x09000000, 0x4a000000, 0x00000000 },
    { 0 }, 0, true
  };
  mi_random_ctx_t random_child = { 0 };
  const uint64_t random_child_address = (uint64_t)(uintptr_t)&random_child;
  _mi_random_split(&random_parent, &random_child);
  const uint64_t random_child_nonce =
      (uint64_t)random_child.input[14] | ((uint64_t)random_child.input[15] << 32);
  U("m1.random.split.parent.output_available", random_parent.output_available);
  U("m1.random.split.parent.consumed_words_cleared",
    random_parent.output[0] == 0 && random_parent.output[1] == 0);
  U("m1.random.split.parent.counter_low", random_parent.input[12]);
  U("m1.random.split.parent.counter_high", random_parent.input[13]);
  U("m1.random.split.child.output_available", random_child.output_available);
  U("m1.random.split.child.counter_low", random_child.input[12]);
  U("m1.random.split.child.counter_high", random_child.input[13]);
  U("m1.random.split.child.weak", random_child.weak);
  U("m1.random.split.child.nonce_xor_destination", random_child_nonce ^ random_child_address);

  mi_random_ctx_t random_zero_retry = {
    { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 },
    { 0, 0, 0x11223344, 0x55667788 }, 16, false
  };
  const uintptr_t random_zero_retry_result = _mi_random_next(&random_zero_retry);
  U("m1.random.next.zero_retry.result", random_zero_retry_result);
  U("m1.random.next.zero_retry.output_available", random_zero_retry.output_available);
  U("m1.random.next.zero_retry.consumed_words_cleared",
    random_zero_retry.output[0] == 0 && random_zero_retry.output[1] == 0
      && random_zero_retry.output[2] == 0 && random_zero_retry.output[3] == 0);

  mi_random_ctx_t random_forced_weak = { 0 };
  const uint64_t random_forced_weak_address = (uint64_t)(uintptr_t)&random_forced_weak;
  _mi_random_init_weak(&random_forced_weak);
  const uint64_t random_forced_weak_nonce =
      (uint64_t)random_forced_weak.input[14]
      | ((uint64_t)random_forced_weak.input[15] << 32);
  U("m1.random.forced_weak.initialized", random_forced_weak.input[0] != 0);
  U("m1.random.forced_weak.weak", random_forced_weak.weak);
  U("m1.random.forced_weak.output_available", random_forced_weak.output_available);
  U("m1.random.forced_weak.counter_low", random_forced_weak.input[12]);
  U("m1.random.forced_weak.counter_high", random_forced_weak.input[13]);
  U("m1.random.forced_weak.nonce_xor_destination",
    random_forced_weak_nonce ^ random_forced_weak_address);

  mi_random_ctx_t random_strong = {
    { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
      0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
      0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
      0x00000001, 0x09000000, 0x4a000000, 0x00000000 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, 3, false
  };
  const uint64_t random_strong_before = m1_random_state_fingerprint(&random_strong);
  _mi_random_reinit_if_weak(&random_strong);
  const uint64_t random_strong_after = m1_random_state_fingerprint(&random_strong);
  U("m1.random.reinit.strong.attempted", 0);
  U("m1.random.reinit.strong.state_preserved", random_strong_before == random_strong_after);
  U("m1.random.reinit.strong.fingerprint", random_strong_after);
  U("sizeof.mi_page_map_t", sizeof(mi_page_map_t));
  U("alignof.mi_page_map_t", _Alignof(mi_page_map_t));
  U("offsetof.mi_page_map_t.committed_count", offsetof(mi_page_map_t, committed_count));
  U("offsetof.mi_page_map_t.reserved_size", offsetof(mi_page_map_t, reserved_size));
  U("offsetof.mi_page_map_t.memid", offsetof(mi_page_map_t, memid));
  U("offsetof.mi_page_map_t.lock", offsetof(mi_page_map_t, lock));
  U("offsetof.mi_page_map_t.submaps", offsetof(mi_page_map_t, submaps));
  U("sizeof.mi_encoded_t", sizeof(mi_encoded_t));
  U("alignof.mi_encoded_t", _Alignof(mi_encoded_t));
  U("sizeof.mi_threadid_t", sizeof(mi_threadid_t));
  U("alignof.mi_threadid_t", _Alignof(mi_threadid_t));
  U("sizeof.mi_thread_free_t", sizeof(mi_thread_free_t));
  U("alignof.mi_thread_free_t", _Alignof(mi_thread_free_t));
  U("sizeof.mi_used_t", sizeof(mi_used_t));
  U("alignof.mi_used_t", _Alignof(mi_used_t));
  U("sizeof.mi_page_flags_t", sizeof(mi_page_flags_t));
  U("alignof.mi_page_flags_t", _Alignof(mi_page_flags_t));
  U("value.MI_PAGE_IN_FULL_QUEUE", MI_PAGE_IN_FULL_QUEUE);
  U("value.MI_PAGE_HAS_INTERIOR_POINTERS", MI_PAGE_HAS_INTERIOR_POINTERS);
  U("value.MI_PAGE_FLAG_MASK", MI_PAGE_FLAG_MASK);
  U("value.MI_PAGE_FLAG_BITS", MI_PAGE_FLAG_BITS);
  U("value.MI_THREADID_ABANDONED", MI_THREADID_ABANDONED);
  U("value.MI_THREADID_ABANDONED_MAPPED", MI_THREADID_ABANDONED_MAPPED);
  U("value.MI_THREADID_DETACHED", MI_THREADID_DETACHED);
  U("sizeof.mi_block_t", sizeof(mi_block_t));
  U("alignof.mi_block_t", _Alignof(mi_block_t));
  U("offsetof.mi_block_t.next", offsetof(mi_block_t, next));
  U("sizeof.mi_page_t", sizeof(mi_page_t));
  U("alignof.mi_page_t", _Alignof(mi_page_t));
#if MI_PAGE_META_IS_ALIGNED
  U("offsetof.mi_page_t.self", offsetof(mi_page_t, self));
#endif
  U("offsetof.mi_page_t.xthread_id", offsetof(mi_page_t, xthread_id));
  U("offsetof.mi_page_t.free", offsetof(mi_page_t, free));
  U("offsetof.mi_page_t.used", offsetof(mi_page_t, used));
  U("offsetof.mi_page_t.local_free", offsetof(mi_page_t, local_free));
  U("offsetof.mi_page_t.block_size", offsetof(mi_page_t, block_size));
  U("offsetof.mi_page_t.page_offset", offsetof(mi_page_t, page_offset));
  U("offsetof.mi_page_t.capacity", offsetof(mi_page_t, capacity));
  U("offsetof.mi_page_t.reserved", offsetof(mi_page_t, reserved));
  U("offsetof.mi_page_t.slice_pcommitted", offsetof(mi_page_t, slice_pcommitted));
  U("offsetof.mi_page_t.retire_expire", offsetof(mi_page_t, retire_expire));
  U("offsetof.mi_page_t.free_is_zero", offsetof(mi_page_t, free_is_zero));
  U("offsetof.mi_page_t.xthread_free", offsetof(mi_page_t, xthread_free));
  U("offsetof.mi_page_t.theap", offsetof(mi_page_t, theap));
  U("offsetof.mi_page_t.heap", offsetof(mi_page_t, heap));
  U("offsetof.mi_page_t.next", offsetof(mi_page_t, next));
  U("offsetof.mi_page_t.prev", offsetof(mi_page_t, prev));
  U("offsetof.mi_page_t.memid", offsetof(mi_page_t, memid));
  U("sizeof.mi_page_kind_t", sizeof(mi_page_kind_t));
  U("alignof.mi_page_kind_t", _Alignof(mi_page_kind_t));
  U("value.MI_PAGE_SMALL", MI_PAGE_SMALL);
  U("value.MI_PAGE_MEDIUM", MI_PAGE_MEDIUM);
  U("value.MI_PAGE_LARGE", MI_PAGE_LARGE);
  U("value.MI_PAGE_SINGLETON", MI_PAGE_SINGLETON);
  U("sizeof.mi_page_queue_t", sizeof(mi_page_queue_t));
  U("alignof.mi_page_queue_t", _Alignof(mi_page_queue_t));
  U("offsetof.mi_page_queue_t.first", offsetof(mi_page_queue_t, first));
  U("offsetof.mi_page_queue_t.last", offsetof(mi_page_queue_t, last));
  U("offsetof.mi_page_queue_t.count", offsetof(mi_page_queue_t, count));
  U("offsetof.mi_page_queue_t.block_size", offsetof(mi_page_queue_t, block_size));
  U("sizeof.mi_theap_t", sizeof(mi_theap_t));
  U("alignof.mi_theap_t", _Alignof(mi_theap_t));
  U("offsetof.mi_theap_t.pages_free_direct", offsetof(mi_theap_t, pages_free_direct));
  U("offsetof.mi_theap_t.page_count", offsetof(mi_theap_t, page_count));
  U("offsetof.mi_theap_t.pages", offsetof(mi_theap_t, pages));
  U("offsetof.mi_theap_t.memid", offsetof(mi_theap_t, memid));
  U("offsetof.mi_theap_t.stats", offsetof(mi_theap_t, stats));
  U("sizeof.mi_heap_t", sizeof(mi_heap_t));
  U("alignof.mi_heap_t", _Alignof(mi_heap_t));
  U("offsetof.mi_heap_t.theap", offsetof(mi_heap_t, theap));
  U("offsetof.mi_heap_t.abandoned_count", offsetof(mi_heap_t, abandoned_count));
  U("offsetof.mi_heap_t.arena_pages", offsetof(mi_heap_t, arena_pages));
  U("offsetof.mi_heap_t.stats", offsetof(mi_heap_t, stats));
  U("sizeof.mi_arena_t", sizeof(mi_arena_t));
  U("alignof.mi_arena_t", _Alignof(mi_arena_t));
  U("offsetof.mi_arena_t.memid", offsetof(mi_arena_t, memid));
  U("offsetof.mi_arena_t.subproc", offsetof(mi_arena_t, subproc));
  U("offsetof.mi_arena_t.arena_idx", offsetof(mi_arena_t, arena_idx));
  U("offsetof.mi_arena_t.start", offsetof(mi_arena_t, start));
  U("offsetof.mi_arena_t.slice_count", offsetof(mi_arena_t, slice_count));
  U("offsetof.mi_arena_t.info_slices", offsetof(mi_arena_t, info_slices));
  U("offsetof.mi_arena_t.numa_node", offsetof(mi_arena_t, numa_node));
  U("offsetof.mi_arena_t.is_exclusive", offsetof(mi_arena_t, is_exclusive));
  U("offsetof.mi_arena_t.purge_expire", offsetof(mi_arena_t, purge_expire));
  U("offsetof.mi_arena_t.commit_fun", offsetof(mi_arena_t, commit_fun));
  U("offsetof.mi_arena_t.commit_fun_arg", offsetof(mi_arena_t, commit_fun_arg));
  U("offsetof.mi_arena_t.total_size", offsetof(mi_arena_t, total_size));
  U("offsetof.mi_arena_t.parent", offsetof(mi_arena_t, parent));
  U("offsetof.mi_arena_t.slices_free", offsetof(mi_arena_t, slices_free));
  U("offsetof.mi_arena_t.slices_committed", offsetof(mi_arena_t, slices_committed));
  U("offsetof.mi_arena_t.slices_dirty", offsetof(mi_arena_t, slices_dirty));
  U("offsetof.mi_arena_t.slices_purge", offsetof(mi_arena_t, slices_purge));
  U("offsetof.mi_arena_t.pages_meta", offsetof(mi_arena_t, pages_meta));
  U("offsetof.mi_arena_t.pages_main", offsetof(mi_arena_t, pages_main));
  U("sizeof.mi_arena_pages_t", sizeof(mi_arena_pages_t));
  U("alignof.mi_arena_pages_t", _Alignof(mi_arena_pages_t));
  U("offsetof.mi_arena_pages_t.pages", offsetof(mi_arena_pages_t, pages));
  U("offsetof.mi_arena_pages_t.pages_abandoned", offsetof(mi_arena_pages_t, pages_abandoned));
  U("sizeof.mi_stats_t", sizeof(mi_stats_t));
  U("alignof.mi_stats_t", _Alignof(mi_stats_t));
  U("MI_MALLOC_VERSION", MI_MALLOC_VERSION);
  U("MI_DEBUG", MI_DEBUG);
  U("MI_SECURE", MI_SECURE);
  U("MI_STAT", MI_STAT);
  U("MI_GUARDED", CRABC_MI_GUARDED);
  U("MI_PADDING", CRABC_MI_PADDING);
  U("MI_ENCODE_FREELIST", CRABC_MI_ENCODE_FREELIST);
  U("MI_FREE_IS_CHECKED", CRABC_MI_FREE_IS_CHECKED);
  U("MI_BIN_COUNT", MI_BIN_COUNT);
  U("MI_BIN_HUGE", MI_BIN_HUGE);
  U("MI_ARENA_SLICE_SIZE", MI_ARENA_SLICE_SIZE);
  U("MI_ARENA_CHUNK_SIZE", MI_ARENA_CHUNK_SIZE);
  U("MI_SMALL_PAGE_SIZE", MI_SMALL_PAGE_SIZE);
  U("MI_MEDIUM_PAGE_SIZE", MI_MEDIUM_PAGE_SIZE);
  U("MI_LARGE_PAGE_SIZE", MI_LARGE_PAGE_SIZE);
  U("MI_SMALL_MAX_OBJ_SIZE", MI_SMALL_MAX_OBJ_SIZE);
  U("MI_MEDIUM_MAX_OBJ_SIZE", MI_MEDIUM_MAX_OBJ_SIZE);
  U("MI_LARGE_MAX_OBJ_SIZE", MI_LARGE_MAX_OBJ_SIZE);
  U("MI_MAX_ARENAS", MI_MAX_ARENAS);

  // M1 scalar vector: every operand is representable before rounding, so this
  // proves the source calculation rather than C's unsigned-overflow behavior.
  // In particular, zero has its source-specific no-constraint meaning for
  // `_mi_is_aligned`, while the two 24-byte records take internal.h's generic
  // non-power-of-two division paths.
  U("m1.scalar.is_power_of_two.zero", _mi_is_power_of_two(0));
  U("m1.scalar.is_aligned.zero", _mi_is_aligned((const void*)(uintptr_t)0x12345678, 0));
  U("m1.scalar.align_down.generic.101_by_24", _mi_align_down(101, 24));
  U("m1.scalar.align_up.generic.101_by_24", _mi_align_up(101, 24));
  U("m1.scalar.divide_up.17_by_6", _mi_divide_up(17, 6));
  U("m1.scalar.wsize_from_size.17", _mi_wsize_from_size(17));
  U("m1.scalar.slice_count.one_past_slice", mi_slice_count_of_size(MI_ARENA_SLICE_SIZE + 1));
  U("m1.scalar.size_of_slices.3", mi_size_of_slices(3));

  // `config.*` is the complete source-derived production-constant record
  // for the frozen Rust profile.  Expressions intentionally use the pinned
  // v3.5.0 macro names (or the exact unset-option-to-zero expression below),
  // so this record remains a differential probe rather than a Python oracle.
  U("config.WORD_SIZE", MI_SIZE_SIZE);
  U("config.MAX_ALIGN_SIZE", MI_MAX_ALIGN_SIZE);
  U("config.SECURE_LEVEL", MI_SECURE);
  U("config.DEBUG_LEVEL", MI_DEBUG);
  U("config.STAT_LEVEL", MI_STAT);
  U("config.FREE_IS_CHECKED", (CRABC_MI_FREE_IS_CHECKED != 0));
  U("config.FREE_USE_PAGEMAP", (CRABC_MI_FREE_USE_PAGEMAP != 0));
  U("config.OPT_FREE_SMALL", (CRABC_MI_OPT_FREE_SMALL != 0));
  U("config.ENABLE_LARGE_PAGES", (MI_ENABLE_LARGE_PAGES != 0));
  U("config.ENCODE_FREELIST", (CRABC_MI_ENCODE_FREELIST != 0));
  U("config.GUARDED", (CRABC_MI_GUARDED != 0));
  U("config.OPT_SIMD", (CRABC_MI_OPT_SIMD != 0));
  U("config.PADDING_SIZE", MI_PADDING_SIZE);
  U("config.PADDING_WSIZE", MI_PADDING_WSIZE);
  U("config.PAGE_KEY_COUNT", MI_PAGE_KEY_COUNT);
  U("config.ARENA_SLICE_SHIFT", MI_ARENA_SLICE_SHIFT);
  U("config.BCHUNK_BITS_SHIFT", MI_BCHUNK_BITS_SHIFT);
  U("config.BCHUNK_BITS", MI_BCHUNK_BITS);
  U("config.ARENA_SLICE_SIZE", MI_ARENA_SLICE_SIZE);
  U("config.ARENA_SLICE_ALIGN", MI_ARENA_SLICE_ALIGN);
  U("config.ARENA_CHUNK_SIZE", MI_ARENA_CHUNK_SIZE);
  U("config.ARENA_MIN_OBJ_SLICES", MI_ARENA_MIN_OBJ_SLICES);
  U("config.ARENA_MAX_CHUNK_OBJ_SLICES", MI_ARENA_MAX_CHUNK_OBJ_SLICES);
  U("config.ARENA_MIN_OBJ_SIZE", MI_ARENA_MIN_OBJ_SIZE);
  U("config.ARENA_MAX_CHUNK_OBJ_SIZE", MI_ARENA_MAX_CHUNK_OBJ_SIZE);
  U("config.SMALL_PAGE_SIZE", MI_SMALL_PAGE_SIZE);
  U("config.MEDIUM_PAGE_SIZE", MI_MEDIUM_PAGE_SIZE);
  U("config.LARGE_PAGE_SIZE", MI_LARGE_PAGE_SIZE);
  U("config.BIN_HUGE", MI_BIN_HUGE);
  U("config.BIN_FULL", MI_BIN_FULL);
  U("config.BIN_COUNT", MI_BIN_COUNT);
  U("config.MAX_ALLOC_SIZE", MI_MAX_ALLOC_SIZE);
  U("config.PAGE_MIN_COMMIT_SIZE", MI_PAGE_MIN_COMMIT_SIZE);
  U("config.PAGE_META_IS_SEPARATED", (MI_PAGE_META_IS_SEPARATED != 0));
  U("config.PAGE_META_IS_ALIGNED", (CRABC_MI_PAGE_META_IS_ALIGNED != 0));
  U("config.PAGE_META_ALIGNED_CHUNKS", CRABC_MI_PAGE_META_ALIGNED_CHUNKS);
  U("config.PAGE_META_ALIGNED_COUNT", CRABC_MI_PAGE_META_ALIGNED_COUNT);
  U("config.PAGE_META_ALIGNMENT", CRABC_MI_PAGE_META_ALIGNMENT);
  U("config.ARENA_ALIGNMENT", MI_ARENA_ALIGNMENT);
  U("config.PAGE_ALIGN", MI_PAGE_ALIGN);
  U("config.PAGE_MIN_START_BLOCK_ALIGN", MI_PAGE_MIN_START_BLOCK_ALIGN);
  U("config.PAGE_MAX_START_BLOCK_ALIGN2", MI_PAGE_MAX_START_BLOCK_ALIGN2);
  U("config.PAGE_OSPAGE_BLOCK_ALIGN2", MI_PAGE_OSPAGE_BLOCK_ALIGN2);
  U("config.PAGE_MAX_OVERALLOC_ALIGN", MI_PAGE_MAX_OVERALLOC_ALIGN);
  U("config.SMALL_WSIZE_MAX", MI_SMALL_WSIZE_MAX);
  U("config.SMALL_SIZE_MAX", MI_SMALL_SIZE_MAX);
  U("config.SMALL_MAX_OBJ_SIZE", MI_SMALL_MAX_OBJ_SIZE);
  U("config.MEDIUM_MAX_OBJ_SIZE", MI_MEDIUM_MAX_OBJ_SIZE);
  U("config.LARGE_MAX_OBJ_SIZE", MI_LARGE_MAX_OBJ_SIZE);
  U("config.LARGE_MAX_OBJ_WSIZE", MI_LARGE_MAX_OBJ_WSIZE);
  U("config.MAX_SINGLETON_BIN", MI_MAX_SINGLETON_BIN);
  U("config.PAGES_DIRECT", MI_PAGES_DIRECT);
  U("config.MAX_ARENAS", MI_MAX_ARENAS);
  U("config.ARENA_BIN_COUNT", MI_ARENA_BIN_COUNT);
  U("config.BITMAP_MAX_BIT_COUNT", MI_BITMAP_MAX_BIT_COUNT);
  U("config.ARENA_MIN_SIZE", MI_ARENA_MIN_SIZE);
  U("config.ARENA_MAX_SIZE", MI_ARENA_MAX_SIZE);
  U("config.MAX_VABITS", MI_MAX_VABITS);
  U("config.MIN_VABITS", MI_MIN_VABITS);
  U("config.PAGE_MAP_FLAT", (MI_PAGE_MAP_FLAT != 0));
  U("config.PAGE_MAP_SUB_SHIFT", MI_PAGE_MAP_SUB_SHIFT);
  U("config.PAGE_MAP_SUB_COUNT", MI_PAGE_MAP_SUB_COUNT);
  U("config.PAGE_MAP_SHIFT", MI_PAGE_MAP_SHIFT);
  for (size_t bin = 0; bin < MI_BIN_COUNT; bin++) {
    const size_t boundary = _mi_theap_empty.pages[bin].block_size;
    printf("bin.block_size.%zu=%zu\n", bin, boundary);
    printf("bin.index.%zu.minus=%zu\n", bin, _mi_bin(boundary - 1));
    printf("bin.index.%zu.at=%zu\n", bin, _mi_bin(boundary));
    printf("bin.index.%zu.plus=%zu\n", bin, _mi_bin(boundary + 1));
  }
  return 0;
}
"""


# This reader is deliberately separate from `LAYOUT_PROBE`.  It compiles only
# the finite M1 static image through a pre-process-initialization configuration
# and cannot change the generic profile-layout artifact, runtime, or macro
# evidence.  Its `MI_PRIM_HAS_PROCESS_ATTACH` define is passed only by
# `build_m1_static_image_probe` below.
STATIC_IMAGE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <mimalloc.h>
#include <mimalloc/internal.h>

static bool m1_u32_words_are_zero(const uint32_t* words, size_t count) {
  for (size_t index = 0; index < count; index++) {
    if (words[index] != 0) return false;
  }
  return true;
}

#define U(name, value) printf(name "=%llu\n", (unsigned long long)(value))
int main(void) {
  const mi_page_t* const empty_page = _mi_page_empty_get();
  const mi_theap_t* const empty_theap = &_mi_theap_empty;
  mi_tld_t* const detached_tld = empty_theap->tld;
  const mi_memid_t empty_page_memid = empty_page->memid;
  const mi_memid_t detached_tld_memid = detached_tld->memid;
  const mi_memid_t empty_theap_memid = empty_theap->memid;

  #if MI_PAGE_META_IS_ALIGNED
  U("m1.bootstrap.empty_page.self_is_null",
    mi_atomic_load_ptr_relaxed(mi_page_t, &empty_page->self) == NULL);
  #else
  U("m1.bootstrap.empty_page.self_is_null", 0);
  #endif
  U("m1.bootstrap.empty_page.xthread_id",
    mi_atomic_load_relaxed(&empty_page->xthread_id));
  U("m1.bootstrap.empty_page.free_is_null", empty_page->free == NULL);
  U("m1.bootstrap.empty_page.used", empty_page->used);
  U("m1.bootstrap.empty_page.local_free_is_null", empty_page->local_free == NULL);
  U("m1.bootstrap.empty_page.block_size", empty_page->block_size);
  U("m1.bootstrap.empty_page.page_offset", empty_page->page_offset);
  U("m1.bootstrap.empty_page.capacity", empty_page->capacity);
  U("m1.bootstrap.empty_page.reserved", empty_page->reserved);
  U("m1.bootstrap.empty_page.slice_pcommitted", empty_page->slice_pcommitted);
  U("m1.bootstrap.empty_page.retire_expire", empty_page->retire_expire);
  U("m1.bootstrap.empty_page.free_is_zero", empty_page->free_is_zero);
  U("m1.bootstrap.empty_page.xthread_free",
    mi_atomic_load_relaxed(&empty_page->xthread_free));
  U("m1.bootstrap.empty_page.theap_is_null", empty_page->theap == NULL);
  U("m1.bootstrap.empty_page.heap_is_null", empty_page->heap == NULL);
  U("m1.bootstrap.empty_page.next_is_null", empty_page->next == NULL);
  U("m1.bootstrap.empty_page.prev_is_null", empty_page->prev == NULL);
  U("m1.bootstrap.empty_page.memid.base_is_null", empty_page_memid.mem.os.base == NULL);
  U("m1.bootstrap.empty_page.memid.size", empty_page_memid.mem.os.size);
  U("m1.bootstrap.empty_page.memid.kind", empty_page_memid.memkind);
  U("m1.bootstrap.empty_page.memid.pinned", empty_page_memid.is_pinned);
  U("m1.bootstrap.empty_page.memid.committed", empty_page_memid.initially_committed);
  U("m1.bootstrap.empty_page.memid.zero", empty_page_memid.initially_zero);

  bool direct_all_empty_page = true;
  for (size_t index = 0; index < MI_PAGES_DIRECT; index++) {
    if (empty_theap->pages_free_direct[index] != empty_page) {
      direct_all_empty_page = false;
    }
  }
  U("m1.bootstrap.empty_theap.pages_free_direct.count", MI_PAGES_DIRECT);
  U("m1.bootstrap.empty_theap.pages_free_direct.all_empty_page", direct_all_empty_page);

  // The operational sequence is unlocked -> locked -> unlocked -> locked ->
  // unlocked. It proves an initial/recovered private-lock state, not the
  // platform-specific pthread mutex bytes used by pinned C.
  const bool detached_tld_lock_is_initially_acquirable =
    mi_lock_try_acquire(&detached_tld->theaps_lock);
  bool detached_tld_lock_restored_to_unlocked = false;
  if (detached_tld_lock_is_initially_acquirable) {
    mi_lock_release(&detached_tld->theaps_lock);
    detached_tld_lock_restored_to_unlocked =
      mi_lock_try_acquire(&detached_tld->theaps_lock);
    if (detached_tld_lock_restored_to_unlocked) {
      mi_lock_release(&detached_tld->theaps_lock);
    }
  }
  U("m1.bootstrap.detached_tld.thread_id", detached_tld->thread_id);
  U("m1.bootstrap.detached_tld.thread_seq", detached_tld->thread_seq);
  U("m1.bootstrap.detached_tld.numa_node", detached_tld->numa_node);
  U("m1.bootstrap.detached_tld.subproc_is_null", detached_tld->subproc == NULL);
  U("m1.bootstrap.detached_tld.theaps_is_null", detached_tld->theaps == NULL);
  U("m1.bootstrap.detached_tld.lock_is_initially_acquirable",
    detached_tld_lock_is_initially_acquirable && detached_tld_lock_restored_to_unlocked);
  U("m1.bootstrap.detached_tld.recurse", detached_tld->recurse);
  U("m1.bootstrap.detached_tld.is_in_threadpool", detached_tld->is_in_threadpool);
  U("m1.bootstrap.detached_tld.memid.base_is_null", detached_tld_memid.mem.os.base == NULL);
  U("m1.bootstrap.detached_tld.memid.size", detached_tld_memid.mem.os.size);
  U("m1.bootstrap.detached_tld.memid.kind", detached_tld_memid.memkind);
  U("m1.bootstrap.detached_tld.memid.pinned", detached_tld_memid.is_pinned);
  U("m1.bootstrap.detached_tld.memid.committed", detached_tld_memid.initially_committed);
  U("m1.bootstrap.detached_tld.memid.zero", detached_tld_memid.initially_zero);

  bool queues_all_first_null = true;
  bool queues_all_last_null = true;
  bool queues_all_count_zero = true;
  for (size_t index = 0; index < MI_BIN_COUNT; index++) {
    const mi_page_queue_t* const queue = &empty_theap->pages[index];
    if (queue->first != NULL) queues_all_first_null = false;
    if (queue->last != NULL) queues_all_last_null = false;
    if (queue->count != 0) queues_all_count_zero = false;
    printf("m1.bootstrap.empty_theap.page_queues.block_size.%zu=%zu\n",
      index, queue->block_size);
  }
  U("m1.bootstrap.empty_theap.tld_is_detached_tld", empty_theap->tld == detached_tld);
  U("m1.bootstrap.empty_theap.heap_is_null",
    mi_atomic_load_ptr_relaxed(mi_heap_t, &empty_theap->heap) == NULL);
  U("m1.bootstrap.empty_theap.subproc_is_null",
    mi_atomic_load_ptr_relaxed(mi_subproc_t, &empty_theap->subproc) == NULL);
  U("m1.bootstrap.empty_theap.refcount", mi_atomic_load_relaxed(&empty_theap->refcount));
  U("m1.bootstrap.empty_theap.heartbeat", empty_theap->heartbeat);
  U("m1.bootstrap.empty_theap.cookie", empty_theap->cookie);
  U("m1.bootstrap.empty_theap.random.input_all_zero",
    m1_u32_words_are_zero(empty_theap->random.input, 16));
  U("m1.bootstrap.empty_theap.random.output_all_zero",
    m1_u32_words_are_zero(empty_theap->random.output, 16));
  U("m1.bootstrap.empty_theap.random.output_available",
    empty_theap->random.output_available);
  U("m1.bootstrap.empty_theap.random.weak", empty_theap->random.weak);
  U("m1.bootstrap.empty_theap.page_count", empty_theap->page_count);
  U("m1.bootstrap.empty_theap.page_retired_min", empty_theap->page_retired_min);
  U("m1.bootstrap.empty_theap.page_retired_max", empty_theap->page_retired_max);
  U("m1.bootstrap.empty_theap.pages_full_size", empty_theap->pages_full_size);
  U("m1.bootstrap.empty_theap.generic_count", empty_theap->generic_count);
  U("m1.bootstrap.empty_theap.generic_collect_count", empty_theap->generic_collect_count);
  U("m1.bootstrap.empty_theap.tnext_is_null", empty_theap->tnext == NULL);
  U("m1.bootstrap.empty_theap.tprev_is_null", empty_theap->tprev == NULL);
  U("m1.bootstrap.empty_theap.hnext_is_null", empty_theap->hnext == NULL);
  U("m1.bootstrap.empty_theap.hprev_is_null", empty_theap->hprev == NULL);
  U("m1.bootstrap.empty_theap.page_full_retain", empty_theap->page_full_retain);
  U("m1.bootstrap.empty_theap.allow_page_reclaim", empty_theap->allow_page_reclaim);
  U("m1.bootstrap.empty_theap.allow_page_abandon", empty_theap->allow_page_abandon);
  U("m1.bootstrap.empty_theap.is_detached", empty_theap->is_detached);
  U("m1.bootstrap.empty_theap.page_queues.count", MI_BIN_COUNT);
  U("m1.bootstrap.empty_theap.page_queues.all_first_null", queues_all_first_null);
  U("m1.bootstrap.empty_theap.page_queues.all_last_null", queues_all_last_null);
  U("m1.bootstrap.empty_theap.page_queues.all_count_zero", queues_all_count_zero);
  U("m1.bootstrap.empty_theap.memid.base_is_null", empty_theap_memid.mem.os.base == NULL);
  U("m1.bootstrap.empty_theap.memid.size", empty_theap_memid.mem.os.size);
  U("m1.bootstrap.empty_theap.memid.kind", empty_theap_memid.memkind);
  U("m1.bootstrap.empty_theap.memid.pinned", empty_theap_memid.is_pinned);
  U("m1.bootstrap.empty_theap.memid.committed", empty_theap_memid.initially_committed);
  U("m1.bootstrap.empty_theap.memid.zero", empty_theap_memid.initially_zero);
  return 0;
}
"""


SMALL_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mimalloc.h>
#include <mimalloc/internal.h>

#define CRABC_TRACE_MAX_BOUNDARIES 384
#define CRABC_TRACE_REPEAT_COUNT 96

static bool append_unique(size_t* requests, size_t* count, size_t request) {
  for (size_t index = 0; index < *count; index++) {
    if (requests[index] == request) return true;
  }
  if (*count >= CRABC_TRACE_MAX_BOUNDARIES) return false;
  requests[*count] = request;
  *count += 1;
  return true;
}

static size_t collect_small_boundaries(size_t* requests) {
  size_t count = 0;
  size_t previous = SIZE_MAX;
  for (size_t request = 0; request <= MI_SMALL_SIZE_MAX; request++) {
    const size_t usable = mi_good_size(request);
    if (request == 0 || usable != previous) {
      if (request > 0 && !append_unique(requests, &count, request - 1)) return 0;
      if (!append_unique(requests, &count, request)) return 0;
      if (request < MI_SMALL_SIZE_MAX && !append_unique(requests, &count, request + 1)) return 0;
    }
    previous = usable;
  }
  return count;
}

static bool bytes_equal(const uint8_t* bytes, size_t size, uint8_t value) {
  for (size_t index = 0; index < size; index++) {
    if (bytes[index] != value) return false;
  }
  return true;
}

int main(void) {
  size_t requests[CRABC_TRACE_MAX_BOUNDARIES];
  const size_t boundary_count = collect_small_boundaries(requests);
  if (boundary_count == 0) return 2;

  puts("CRABC_MI_SMALL_TRACE_BEGIN");
  printf("trace.boundary.count=%zu\n", boundary_count);
  for (size_t index = 0; index < boundary_count; index++) {
    const size_t request = requests[index];
    uint8_t* const first = (uint8_t*)mi_malloc(request);
    uint8_t* const second = (uint8_t*)mi_malloc(request);
    if (first == NULL || second == NULL) return 3;
    const size_t first_usable = mi_usable_size(first);
    const size_t second_usable = mi_usable_size(second);
    if (first_usable < request || first_usable != second_usable) return 4;
    const uint8_t pattern = (uint8_t)(0x41u + (index % 47u));
    memset(first, pattern, request);
    printf("trace.boundary.%zu.request=%zu\n", index, request);
    printf("trace.boundary.%zu.usable=%zu\n", index, first_usable);
    printf("trace.boundary.%zu.distinct=%u\n", index, first != second);
    printf("trace.boundary.%zu.word_aligned=%u\n", index,
           (((uintptr_t)first % sizeof(uintptr_t)) == 0));
    printf("trace.boundary.%zu.max_aligned=%u\n", index,
           (((uintptr_t)first % MI_MAX_ALIGN_SIZE) == 0));
    printf("trace.boundary.%zu.preserved=%u\n", index,
           bytes_equal(first, request, pattern));
    mi_free(second);
    mi_free(first);
  }

  uint8_t* const zeroed = (uint8_t*)mi_zalloc(37);
  if (zeroed == NULL) return 5;
  printf("trace.zero.request=37\n");
  printf("trace.zero.usable=%zu\n", mi_usable_size(zeroed));
  printf("trace.zero.cleared=%u\n", bytes_equal(zeroed, 37, 0));
  mi_free(zeroed);

  uint8_t* live[CRABC_TRACE_REPEAT_COUNT];
  bool repeat_ok = true;
  for (size_t index = 0; index < CRABC_TRACE_REPEAT_COUNT; index++) {
    live[index] = (uint8_t*)mi_malloc(MI_SMALL_SIZE_MAX);
    if (live[index] == NULL) return 6;
    const uint8_t pattern = (uint8_t)(index + 1);
    memset(live[index], pattern, MI_SMALL_SIZE_MAX);
  }
  for (size_t index = 0; index < CRABC_TRACE_REPEAT_COUNT; index++) {
    const uint8_t pattern = (uint8_t)(index + 1);
    repeat_ok = repeat_ok && bytes_equal(live[index], MI_SMALL_SIZE_MAX, pattern);
  }
  for (size_t ordinal = 0; ordinal < CRABC_TRACE_REPEAT_COUNT; ordinal++) {
    const size_t index = (ordinal * 37u) % CRABC_TRACE_REPEAT_COUNT;
    mi_free(live[index]);
  }
  printf("trace.repeat.count=%u\n", CRABC_TRACE_REPEAT_COUNT);
  printf("trace.repeat.fill_preserved=%u\n", repeat_ok);
  puts("CRABC_MI_SMALL_TRACE_END");
  return 0;
}
"""


# This trace deliberately exercises only public allocator operations, while
# selecting each ordinary page class with the exact v3.5.0 boundary constants
# from `mimalloc/internal.h`.  The emitted record contains only logical case
# names, booleans, sizes, and deterministic content fingerprints: emitting an
# allocation address would make a differential record non-reproducible and
# would not prove an allocator contract.
FUNDAMENTAL_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mimalloc.h>
#include <mimalloc/internal.h>

static bool bytes_equal(const uint8_t* bytes, size_t size, uint8_t value) {
  for (size_t index = 0; index < size; index++) {
    if (bytes[index] != value) return false;
  }
  return true;
}

/* A deterministic non-cryptographic content fingerprint for trace evidence. */
static uint64_t content_hash(const uint8_t* bytes, size_t size) {
  uint64_t value = UINT64_C(14695981039346656037);
  for (size_t index = 0; index < size; index++) {
    value ^= bytes[index];
    value *= UINT64_C(1099511628211);
  }
  return value;
}

static bool record_page_class(const char* name, size_t request) {
  uint8_t* const block = (uint8_t*)mi_malloc(request);
  if (block == NULL) return false;
  const size_t usable = mi_usable_size(block);
  const bool valid = usable >= request;
  printf("trace.fundamental.class.%s.request=%zu\n", name, request);
  printf("trace.fundamental.class.%s.usable=%zu\n", name, usable);
  printf("trace.fundamental.class.%s.success=%u\n", name, valid);
  mi_free(block);
  return valid;
}

int main(void) {
  puts("CRABC_MI_FUNDAMENTAL_TRACE_BEGIN");

  if (!record_page_class("small", MI_SMALL_MAX_OBJ_SIZE)) return 2;
  if (!record_page_class("medium", MI_SMALL_MAX_OBJ_SIZE + 1)) return 3;
  if (!record_page_class("large", MI_MEDIUM_MAX_OBJ_SIZE + 1)) return 4;
  if (!record_page_class("singleton", MI_LARGE_MAX_OBJ_SIZE + 1)) return 5;

  const size_t calloc_count = 7;
  const size_t calloc_size = 13;
  const size_t calloc_total = calloc_count * calloc_size;
  uint8_t* const zeroed = (uint8_t*)mi_calloc(calloc_count, calloc_size);
  if (zeroed == NULL) return 6;
  printf("trace.fundamental.calloc.count=%zu\n", calloc_count);
  printf("trace.fundamental.calloc.size=%zu\n", calloc_size);
  printf("trace.fundamental.calloc.usable=%zu\n", mi_usable_size(zeroed));
  printf("trace.fundamental.calloc.cleared=%u\n", bytes_equal(zeroed, calloc_total, 0));
  printf("trace.fundamental.calloc.content_hash=%llu\n",
         (unsigned long long)content_hash(zeroed, calloc_total));
  mi_free(zeroed);

  const size_t overflow_count = SIZE_MAX;
  const size_t overflow_size = 2;
  void* const overflow = mi_calloc(overflow_count, overflow_size);
  printf("trace.fundamental.calloc_overflow.count=%zu\n", overflow_count);
  printf("trace.fundamental.calloc_overflow.size=%zu\n", overflow_size);
  printf("trace.fundamental.calloc_overflow.returns_null=%u\n", overflow == NULL);
  if (overflow != NULL) {
    mi_free(overflow);
    return 7;
  }

  uint8_t* const realloc_null = (uint8_t*)mi_realloc(NULL, 41);
  if (realloc_null == NULL) return 8;
  memset(realloc_null, 0x31, 41);
  printf("trace.fundamental.realloc_null.request=41\n");
  printf("trace.fundamental.realloc_null.usable=%zu\n", mi_usable_size(realloc_null));
  printf("trace.fundamental.realloc_null.content_hash=%llu\n",
         (unsigned long long)content_hash(realloc_null, 41));
  mi_free(realloc_null);

  const size_t grow_original_size = 257;
  const size_t grow_size = 8193;
  uint8_t* grow = (uint8_t*)mi_malloc(grow_original_size);
  if (grow == NULL) return 9;
  memset(grow, 0x42, grow_original_size);
  const uint64_t grow_before = content_hash(grow, grow_original_size);
  grow = (uint8_t*)mi_realloc(grow, grow_size);
  if (grow == NULL) return 10;
  const uint64_t grow_after = content_hash(grow, grow_original_size);
  printf("trace.fundamental.realloc_grow.original_size=%zu\n", grow_original_size);
  printf("trace.fundamental.realloc_grow.new_size=%zu\n", grow_size);
  printf("trace.fundamental.realloc_grow.usable=%zu\n", mi_usable_size(grow));
  printf("trace.fundamental.realloc_grow.preserved=%u\n", grow_before == grow_after);
  printf("trace.fundamental.realloc_grow.content_hash=%llu\n", (unsigned long long)grow_after);

  const size_t shrink_size = 71;
  const uint64_t shrink_expected = content_hash(grow, shrink_size);
  grow = (uint8_t*)mi_realloc(grow, shrink_size);
  if (grow == NULL) return 11;
  const uint64_t shrink_after = content_hash(grow, shrink_size);
  printf("trace.fundamental.realloc_shrink.new_size=%zu\n", shrink_size);
  printf("trace.fundamental.realloc_shrink.usable=%zu\n", mi_usable_size(grow));
  printf("trace.fundamental.realloc_shrink.preserved=%u\n", shrink_expected == shrink_after);
  printf("trace.fundamental.realloc_shrink.content_hash=%llu\n", (unsigned long long)shrink_after);
  mi_free(grow);

  uint8_t* failure_preserved = (uint8_t*)mi_malloc(59);
  if (failure_preserved == NULL) return 12;
  memset(failure_preserved, 0x73, 59);
  const uint64_t failure_before = content_hash(failure_preserved, 59);
  void* const failed_realloc = mi_realloc(failure_preserved, MI_MAX_ALLOC_SIZE + 1);
  if (failed_realloc != NULL) {
    mi_free(failed_realloc);
    return 13;
  }
  const uint64_t failure_after = content_hash(failure_preserved, 59);
  printf("trace.fundamental.realloc_failure.request=%zu\n", (size_t)(MI_MAX_ALLOC_SIZE + 1));
  printf("trace.fundamental.realloc_failure.returns_null=%u\n", failed_realloc == NULL);
  printf("trace.fundamental.realloc_failure.preserved=%u\n", failure_before == failure_after);
  printf("trace.fundamental.realloc_failure.content_hash=%llu\n", (unsigned long long)failure_after);
  mi_free(failure_preserved);

  uint8_t* size_zero = (uint8_t*)mi_malloc(59);
  if (size_zero == NULL) return 14;
  size_zero = (uint8_t*)mi_realloc(size_zero, 0);
  printf("trace.fundamental.realloc_size_zero.request=0\n");
  printf("trace.fundamental.realloc_size_zero.returns_nonnull=%u\n", size_zero != NULL);
  if (size_zero == NULL) return 15;
  printf("trace.fundamental.realloc_size_zero.usable=%zu\n", mi_usable_size(size_zero));
  mi_free(size_zero);

#if defined(__x86_64__)
  const size_t recalloc_original_size = 257;
  const size_t recalloc_count = 3;
  const size_t recalloc_size = 2731;
  const size_t recalloc_total = recalloc_count * recalloc_size;
  uint8_t* recalloc = (uint8_t*)mi_malloc(recalloc_original_size);
  if (recalloc == NULL) return 16;
  const size_t recalloc_old_usable = mi_usable_size(recalloc);
  memset(recalloc, 0x54, recalloc_old_usable);
  const uint64_t recalloc_before = content_hash(recalloc, recalloc_old_usable);
  recalloc = (uint8_t*)mi_recalloc(recalloc, recalloc_count, recalloc_size);
  if (recalloc == NULL) return 17;
  const size_t recalloc_new_usable = mi_usable_size(recalloc);
  const bool recalloc_preserved =
      content_hash(recalloc, recalloc_old_usable) == recalloc_before;
  const bool recalloc_tail_zeroed =
      recalloc_new_usable >= recalloc_old_usable
      && bytes_equal(recalloc + recalloc_old_usable,
                     recalloc_new_usable - recalloc_old_usable, 0);
  const bool recalloc_valid =
      recalloc_new_usable >= recalloc_total
      && recalloc_preserved
      && recalloc_tail_zeroed;
  printf("trace.fundamental.recalloc.count=%zu\n", recalloc_count);
  printf("trace.fundamental.recalloc.size=%zu\n", recalloc_size);
  printf("trace.fundamental.recalloc.total=%zu\n", recalloc_total);
  printf("trace.fundamental.recalloc.old_usable=%zu\n", recalloc_old_usable);
  printf("trace.fundamental.recalloc.new_usable=%zu\n", recalloc_new_usable);
  printf("trace.fundamental.recalloc.preserved=%u\n", recalloc_preserved);
  printf("trace.fundamental.recalloc.tail_zeroed=%u\n", recalloc_tail_zeroed);
  printf("trace.fundamental.recalloc.valid=%u\n", recalloc_valid);
  mi_free(recalloc);
  if (!recalloc_valid) return 18;

  const size_t recalloc_zero_count = 0;
  const size_t recalloc_zero_size = SIZE_MAX;
  uint8_t* const recalloc_zero =
      (uint8_t*)mi_recalloc(NULL, recalloc_zero_count, recalloc_zero_size);
  if (recalloc_zero == NULL) return 19;
  printf("trace.fundamental.recalloc_zero.count=%zu\n", recalloc_zero_count);
  printf("trace.fundamental.recalloc_zero.size=%zu\n", recalloc_zero_size);
  printf("trace.fundamental.recalloc_zero.total=0\n");
  printf("trace.fundamental.recalloc_zero.returns_nonnull=1\n");
  printf("trace.fundamental.recalloc_zero.first_byte_zero=%u\n", recalloc_zero[0] == 0);
  mi_free(recalloc_zero);

  const size_t recalloc_overflow_count = SIZE_MAX;
  const size_t recalloc_overflow_size = 2;
  uint8_t* const recalloc_overflow = (uint8_t*)mi_malloc(59);
  if (recalloc_overflow == NULL) return 20;
  const size_t recalloc_overflow_usable = mi_usable_size(recalloc_overflow);
  memset(recalloc_overflow, 0x7c, recalloc_overflow_usable);
  const uint64_t recalloc_overflow_before =
      content_hash(recalloc_overflow, recalloc_overflow_usable);
  void* const recalloc_overflow_result = mi_recalloc(
      recalloc_overflow, recalloc_overflow_count, recalloc_overflow_size);
  if (recalloc_overflow_result != NULL) {
    mi_free(recalloc_overflow_result);
    return 21;
  }
  const bool recalloc_overflow_preserved =
      content_hash(recalloc_overflow, recalloc_overflow_usable)
          == recalloc_overflow_before;
  printf("trace.fundamental.recalloc_overflow.count=%zu\n", recalloc_overflow_count);
  printf("trace.fundamental.recalloc_overflow.size=%zu\n", recalloc_overflow_size);
  printf("trace.fundamental.recalloc_overflow.returns_null=1\n");
  printf("trace.fundamental.recalloc_overflow.preserved=%u\n", recalloc_overflow_preserved);
  mi_free(recalloc_overflow);

  const size_t expand_request = 59;
  uint8_t* const expand = (uint8_t*)mi_malloc(expand_request);
  if (expand == NULL) return 19;
  const size_t expand_usable = mi_usable_size(expand);
  if (expand_usable < 2 || expand_usable == SIZE_MAX) {
    mi_free(expand);
    return 20;
  }
  memset(expand, 0x6d, expand_request);
  const uint64_t expand_before = content_hash(expand, expand_request);
  // `mi_expand` must reject NULL regardless of the requested size.
  void* const expand_null = mi_expand(NULL, expand_request);
  void* const expand_zero = mi_expand(expand, 0);
  void* const expand_below_half = mi_expand(expand, expand_usable / 2 - 1);
  void* const expand_exact = mi_expand(expand, expand_usable);
  void* const expand_oversize = mi_expand(expand, expand_usable + 1);
  const uint64_t expand_after = content_hash(expand, expand_request);
  printf("trace.fundamental.expand.usable=%zu\n", expand_usable);
  printf("trace.fundamental.expand.null_nonzero_returns_null=%u\n", (unsigned)(expand_null == NULL));
  printf("trace.fundamental.expand.zero_returns_input=%u\n", (unsigned)(expand_zero == expand));
  printf("trace.fundamental.expand.below_half_returns_input=%u\n", (unsigned)(expand_below_half == expand));
  printf("trace.fundamental.expand.exact_returns_input=%u\n", (unsigned)(expand_exact == expand));
  printf("trace.fundamental.expand.oversize_returns_null=%u\n", (unsigned)(expand_oversize == NULL));
  printf("trace.fundamental.expand.failure_preserves=%u\n", (unsigned)(expand_before == expand_after));
  const bool expand_valid =
      expand_null == NULL
      && expand_zero == expand
      && expand_below_half == expand
      && expand_exact == expand
      && expand_oversize == NULL
      && expand_before == expand_after;
  mi_free(expand);
  if (!expand_valid) return 21;
#endif

  const size_t aligned_size = 97;
  const size_t aligned_alignment = 256;
  uint8_t* const aligned = (uint8_t*)mi_malloc_aligned(aligned_size, aligned_alignment);
  if (aligned == NULL) return 22;
  printf("trace.fundamental.aligned.size=%zu\n", aligned_size);
  printf("trace.fundamental.aligned.alignment=%zu\n", aligned_alignment);
  printf("trace.fundamental.aligned.usable=%zu\n", mi_usable_size(aligned));
  printf("trace.fundamental.aligned.valid=%u\n",
         mi_usable_size(aligned) >= aligned_size && ((uintptr_t)aligned % aligned_alignment) == 0);
  mi_free(aligned);

  const size_t offset_size = 191;
  const size_t offset_alignment = 512;
  const size_t offset = 13;
  uint8_t* const offset_aligned =
      (uint8_t*)mi_malloc_aligned_at(offset_size, offset_alignment, offset);
  if (offset_aligned == NULL) return 23;
  printf("trace.fundamental.offset_aligned.size=%zu\n", offset_size);
  printf("trace.fundamental.offset_aligned.alignment=%zu\n", offset_alignment);
  printf("trace.fundamental.offset_aligned.offset=%zu\n", offset);
  printf("trace.fundamental.offset_aligned.usable=%zu\n", mi_usable_size(offset_aligned));
  printf("trace.fundamental.offset_aligned.valid=%u\n",
         mi_usable_size(offset_aligned) >= offset_size
             && (((uintptr_t)offset_aligned + offset) % offset_alignment) == 0);
  mi_free(offset_aligned);

  const size_t forced_oom_request = MI_MAX_ALLOC_SIZE + 1;
  void* const forced_oom = mi_malloc(forced_oom_request);
  printf("trace.fundamental.oom.request=%zu\n", forced_oom_request);
  printf("trace.fundamental.oom.classification_invalid_request=1\n");
  printf("trace.fundamental.oom.returns_null=%u\n", forced_oom == NULL);
  if (forced_oom != NULL) {
    mi_free(forced_oom);
    return 24;
  }

  puts("CRABC_MI_FUNDAMENTAL_TRACE_END");
  return 0;
}
"""


# This fixture is deliberately not a host-model test.  It compiles the pinned
# C `src/os.c` directly into the probe translation unit, so the fixed record
# below observes its otherwise-private `mi_os_mem_config` state as well as the
# selected Unix primitive calls.  `build_m1_raw_primitive_trace` omits the
# standalone `src/os.c` object from `ORACLE_SOURCES` for this one executable.
#
# The record names only normal Linux/AArch64 success paths selected by M1:
# immutable configuration, allocation-size/large-page predicates, one regular
# no-hint/non-large mapping transition sequence, direct observations, and the
# source's constant false threadpool result.  It intentionally has no raw
# addresses, random bytes, exact clocks, errno/error paths, allocation hints,
# huge/THP options, or C fallback branches.
M1_RAW_PRIMITIVE_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

// Resolved through `-I <pinned-source>/src`.  This makes the source-private
// configuration image observable without editing the pinned archive.
#include "os.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

int main(void) {
  // `_mi_os_init` is the source owner of the immutable record below. Calling
  // it directly prevents constructor/link ordering from becoming evidence.
  _mi_os_init();

  const size_t page = mi_os_mem_config.page_size;
  bool is_large = true;
  bool is_zero = false;
  void* address = NULL;
  if (_mi_prim_alloc(NULL, page, page, false, false, &is_large, &is_zero, &address) != 0
      || address == NULL) {
    return 10;
  }
  bool commit_zero = true;
  if (_mi_prim_commit(address, page, &commit_zero) != 0) return 11;
  bool needs_recommit = true;
  if (_mi_prim_decommit(address, page, &needs_recommit) != 0) return 12;
  if (_mi_prim_reset(address, page) != 0) return 13;
  if (_mi_prim_protect(address, page, true) != 0) return 14;
  if (_mi_prim_protect(address, page, false) != 0) return 15;
  if (_mi_prim_free(address, page) != 0) return 16;

  const mi_msecs_t clock_before = _mi_prim_clock_now();
  _mi_prim_thread_yield();
  const mi_msecs_t clock_after = _mi_prim_clock_now();
  uint8_t entropy[16] = { 0 };
  const bool entropy_zero = _mi_prim_random_buf(entropy, 0);
  const bool entropy_sixteen = _mi_prim_random_buf(entropy, sizeof(entropy));
  const size_t numa_count = _mi_prim_numa_node_count();
  const size_t numa_current = _mi_prim_numa_node();

  puts("CRABC_MI_M1_RAW_TRACE_BEGIN");
  U("m1.raw.config.page_size", mi_os_mem_config.page_size);
  U("m1.raw.config.large_page_size", mi_os_mem_config.large_page_size);
  U("m1.raw.config.alloc_granularity", mi_os_mem_config.alloc_granularity);
  U("m1.raw.config.physical_memory_in_kib", mi_os_mem_config.physical_memory_in_kib);
  U("m1.raw.config.virtual_address_bits", mi_os_mem_config.virtual_address_bits);
  U("m1.raw.config.has_overcommit", mi_os_mem_config.has_overcommit);
  U("m1.raw.config.has_partial_free", mi_os_mem_config.has_partial_free);
  U("m1.raw.config.has_virtual_reserve", mi_os_mem_config.has_virtual_reserve);
  U("m1.raw.config.has_transparent_huge_pages", mi_os_mem_config.has_transparent_huge_pages);

  U("m1.raw.good_alloc_size.zero", _mi_os_good_alloc_size(0));
  U("m1.raw.good_alloc_size.one", _mi_os_good_alloc_size(1));
  U("m1.raw.good_alloc_size.512k_minus_one", _mi_os_good_alloc_size(512*MI_KiB - 1));
  U("m1.raw.good_alloc_size.512k", _mi_os_good_alloc_size(512*MI_KiB));
  U("m1.raw.good_alloc_size.512k_plus_one", _mi_os_good_alloc_size(512*MI_KiB + 1));
  U("m1.raw.good_alloc_size.2m_minus_one", _mi_os_good_alloc_size(2*MI_MiB - 1));
  U("m1.raw.good_alloc_size.2m", _mi_os_good_alloc_size(2*MI_MiB));
  U("m1.raw.good_alloc_size.2m_plus_one", _mi_os_good_alloc_size(2*MI_MiB + 1));
  U("m1.raw.good_alloc_size.8m_minus_one", _mi_os_good_alloc_size(8*MI_MiB - 1));
  U("m1.raw.good_alloc_size.8m", _mi_os_good_alloc_size(8*MI_MiB));
  U("m1.raw.good_alloc_size.8m_plus_one", _mi_os_good_alloc_size(8*MI_MiB + 1));
  U("m1.raw.good_alloc_size.32m_minus_one", _mi_os_good_alloc_size(32*MI_MiB - 1));
  U("m1.raw.good_alloc_size.32m", _mi_os_good_alloc_size(32*MI_MiB));
  U("m1.raw.good_alloc_size.32m_plus_one", _mi_os_good_alloc_size(32*MI_MiB + 1));
  U("m1.raw.good_alloc_size.size_max", _mi_os_good_alloc_size(SIZE_MAX));
  U("m1.raw.can_use_large_page.aligned", _mi_os_canuse_large_page(2*MI_MiB, 2*MI_MiB));
  U("m1.raw.can_use_large_page.page_aligned_only", _mi_os_canuse_large_page(2*MI_MiB, page));

  U("m1.raw.map.request.no_hint", 1);
  U("m1.raw.map.request.allow_large", 0);
  U("m1.raw.map.reserved.success", 1);
  U("m1.raw.map.reserved.is_large", is_large);
  U("m1.raw.map.reserved.is_zero", is_zero);
  U("m1.raw.map.reserved.initially_committed", 0);
  U("m1.raw.map.commit.success", 1);
  U("m1.raw.map.commit.is_zero", commit_zero);
  U("m1.raw.map.decommit.success", 1);
  U("m1.raw.map.decommit.needs_recommit", needs_recommit);
  U("m1.raw.map.reset.success", 1);
  U("m1.raw.map.protect.success", 1);
  U("m1.raw.map.unprotect.success", 1);
  U("m1.raw.map.free.success", 1);

  U("m1.raw.numa.count", numa_count);
  U("m1.raw.numa.current_lt_count", numa_current < numa_count);
  U("m1.raw.clock.monotonic_after_yield", clock_after >= clock_before);
  U("m1.raw.yield.success", 1);
  U("m1.raw.entropy.zero_success", entropy_zero);
  U("m1.raw.entropy.sixteen_success", entropy_sixteen);
  U("m1.raw.threadpool.false", !_mi_prim_thread_is_in_threadpool());
  puts("CRABC_MI_M1_RAW_TRACE_END");
  return 0;
}
"""


# This fixture directly includes the pinned C `src/os.c`, `src/page-map.c`,
# and `src/init.c` so it can force the selected non-overcommit branch and
# observe the source-private two-level map lifecycle. The dedicated source
# list omits those three units. Setup follows the source process-init order
# through `_mi_page_map_init`; the trace then uses the source range writer with
# a synthetic page marker, avoiding unstable virtual addresses while covering
# lazy extension, lookup, unregister, natural boundary rollback, and an absent
# root after destruction. The global-C versus owner-Rust root order and the
# static empty-root/once failure behavior are intentionally explicit
# differences, not part of exact success equality.
M2_PAGE_MAP_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>

// Keep source-private definitions in this translation unit. The normal C
// source list omits these exact three files to preserve one-definition C
// linkage and this source order mirrors init.c's prerequisites.
#include "os.c"
#include "page-map.c"
#include "init.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

int main(void) {
  _mi_detect_cpu_features();
  _mi_options_init();
  mi_option_set_enabled(mi_option_pagemap_commit, false);
  if (mi_option_is_enabled(mi_option_pagemap_commit)) return 10;
  mi_option_set(mi_option_max_vabits, MI_MAX_VABITS);
  if (mi_option_get(mi_option_max_vabits) != MI_MAX_VABITS) return 11;
  _mi_stats_init();
  _mi_os_init();
  // Force the selected reserve-then-commit path independently of host
  // overcommit policy; this is a fixture precondition, not a production mode.
  mi_os_mem_config.has_overcommit = false;
  mi_heap_main_init();

  const bool root_empty_before = (_mi_page_map() == &mi_page_map_empty);
  if (!_mi_page_map_init()) return 12;
  mi_page_map_t* const page_map = _mi_page_map();
  if (page_map == NULL) return 13;

  const size_t initial_committed =
      mi_atomic_load_relaxed(&page_map->committed_count);
  const size_t reserved_count =
      (page_map->reserved_size < sizeof(mi_page_map_t)
          ? 0
          : 1 + (page_map->reserved_size - sizeof(mi_page_map_t)) / sizeof(mi_submap_t));
  size_t vbits = (size_t)mi_option_get_clamp(mi_option_max_vabits, 0, MI_MAX_VABITS);
  if (vbits == 0) vbits = _mi_os_virtual_address_bits();
  if (vbits < MI_PAGE_MAP_SUB_SHIFT + MI_ARENA_SLICE_SHIFT) {
    vbits = MI_PAGE_MAP_SUB_SHIFT + MI_ARENA_SLICE_SHIFT;
  }
  if (vbits < MI_MIN_VABITS) vbits = MI_MIN_VABITS;
  if (vbits > MI_MAX_VABITS) vbits = MI_MAX_VABITS;
  const size_t reserve_count =
      (MI_ZU(1) << (vbits - MI_PAGE_MAP_SUB_SHIFT - MI_ARENA_SLICE_SHIFT));
  const bool root_published = (page_map != &mi_page_map_empty);
  const bool committed_lt_reserved = initial_committed < reserved_count;
  const bool submap_zero_present =
      (mi_atomic_load_ptr_relaxed(mi_page_t*, &page_map->submaps[0]) != NULL);

  // Start one root entry beyond the initial committed prefix and at the last
  // sub-entry. Two slices therefore cross into two lazily allocated submaps.
  mi_page_t page = mi_init_struct_zero;
  const size_t map_index = initial_committed + 1;
  const size_t sub_index = MI_PAGE_MAP_SUB_COUNT - 1;
  const size_t slice_count = 2;
  if (map_index + 1 >= reserved_count) return 14;
  const size_t committed_before =
      mi_atomic_load_relaxed(&page_map->committed_count);
  const bool register_ok = mi_page_map_set_range(
      page_map, &page, map_index, sub_index, slice_count);
  const size_t committed_after =
      mi_atomic_load_relaxed(&page_map->committed_count);
  const size_t submap_count =
      (page_map->submaps[map_index] != NULL) +
      (page_map->submaps[map_index + 1] != NULL);
  const bool first_submap_present = page_map->submaps[map_index] != NULL;
  const bool second_submap_present = page_map->submaps[map_index + 1] != NULL;
  const bool submaps_distinct =
      first_submap_present && second_submap_present &&
      (page_map->submaps[map_index] != page_map->submaps[map_index + 1]);
  const bool lookup_first =
      (page_map->submaps[map_index][sub_index] == &page);
  const bool lookup_second =
      (page_map->submaps[map_index + 1][0] == &page);

  const bool unregister_ok = mi_page_map_set_range(
      page_map, NULL, map_index, sub_index, slice_count);
  const bool unregister_first_absent =
      (page_map->submaps[map_index][sub_index] == NULL);
  const bool unregister_second_absent =
      (page_map->submaps[map_index + 1][0] == NULL);

  // Commit the final root entry so the source's range writer reaches its
  // second iteration and can prove rollback after the out-of-bounds index.
  if (!mi_page_map_commit_entries(page_map, reserved_count - 1)) return 15;
  const size_t final_index = reserved_count - 1;
  const bool rollback_failed = !mi_page_map_set_range(
      page_map, &page, final_index, MI_PAGE_MAP_SUB_COUNT - 1, 2);
  const bool rollback_submap_present = page_map->submaps[final_index] != NULL;
  const bool rollback_first_cleared =
      page_map->submaps[final_index][MI_PAGE_MAP_SUB_COUNT - 1] == NULL;
  const bool rollback_out_of_bounds_absent = (final_index + 1 >= reserved_count);
  const bool all_relations =
      initial_committed != 0 && reserved_count >= reserve_count &&
      root_empty_before && root_published && committed_lt_reserved &&
      submap_zero_present && register_ok &&
      committed_after >= committed_before && committed_after > committed_before &&
      submap_count == 2 && submaps_distinct && lookup_first && lookup_second &&
      unregister_ok && unregister_first_absent && unregister_second_absent &&
      rollback_failed && rollback_submap_present &&
      rollback_first_cleared && rollback_out_of_bounds_absent;
  if (!all_relations) return 16;

  const bool root_unpublished_before = (_mi_page_map() == &mi_page_map_empty);
  _mi_page_map_unsafe_destroy();
  const bool root_absent_after = (_mi_page_map() == &mi_page_map_empty);
  if (!root_absent_after) return 17;

  puts("CRABC_MI_M2_PAGE_MAP_TRACE_BEGIN");
  U("m2.page_map.control.page_size", _mi_os_page_size());
  U("m2.page_map.control.has_overcommit_false", !mi_os_mem_config.has_overcommit);
  U("m2.page_map.control.max_vabits", mi_option_get(mi_option_max_vabits));
  U("m2.page_map.layout.header_bytes", sizeof(mi_page_map_t));
  U("m2.page_map.layout.lock_bytes", sizeof(mi_lock_t));
  U("m2.page_map.init.root_empty_before", root_empty_before);
  U("m2.page_map.init.root_published", root_published);
  U("m2.page_map.init.reserve_count", reserve_count);
  U("m2.page_map.init.reserved_count", reserved_count);
  U("m2.page_map.init.committed_count", initial_committed);
  U("m2.page_map.init.committed_lt_reserved", committed_lt_reserved);
  U("m2.page_map.init.submap_zero_present", submap_zero_present);
  U("m2.page_map.extend.map_index", map_index);
  U("m2.page_map.extend.start_sub_index", sub_index);
  U("m2.page_map.extend.slice_count", slice_count);
  U("m2.page_map.extend.committed_before", committed_before);
  U("m2.page_map.extend.committed_after", committed_after);
  U("m2.page_map.extend.committed_increased", committed_after > committed_before);
  U("m2.page_map.extend.first_submap_present", first_submap_present);
  U("m2.page_map.extend.second_submap_present", second_submap_present);
  U("m2.page_map.extend.submaps_distinct", submaps_distinct);
  U("m2.page_map.register.first_lookup_matches", lookup_first);
  U("m2.page_map.register.second_lookup_matches", lookup_second);
  U("m2.page_map.unregister.first_lookup_absent", unregister_first_absent);
  U("m2.page_map.unregister.second_lookup_absent", unregister_second_absent);
  U("m2.page_map.rollback.register_failed", rollback_failed);
  U("m2.page_map.rollback.submap_present", rollback_submap_present);
  U("m2.page_map.rollback.entry_cleared", rollback_first_cleared);
  U("m2.page_map.rollback.out_of_bounds_absent", rollback_out_of_bounds_absent);
  U("m2.page_map.destroy.root_unpublished_before", root_unpublished_before);
  U("m2.page_map.destroy.root_absent_after", root_absent_after);
  puts("CRABC_MI_M2_PAGE_MAP_TRACE_END");
  return 0;
}
"""


# This dedicated initialized-PageMap fixture injects one lexical
# `_mi_os_commit` failure only into the pinned `src/page-map.c` body. It avoids
# the cold-init once gate and the range writer's rollback replay: the direct
# private `mi_page_map_ensure_submap_at` call reaches exactly
# `mi_page_map_commit_entries` and must return before submap allocation or the
# Release committed-count store. The C wrapper is test-only and preserves the
# ordinary `src/os.c` definition for setup, retry, and all other source units.
M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>

#include "os.c"

static bool m2_fail_next_page_map_commit;
static size_t m2_page_map_commit_attempts;
static size_t m2_page_map_submap_allocation_attempts;

static bool m2_page_map_commit(
    mi_subproc_t* subproc,
    void* address,
    size_t size,
    bool* is_zero)
{
  m2_page_map_commit_attempts++;
  if (m2_fail_next_page_map_commit) {
    m2_fail_next_page_map_commit = false;
    if (is_zero != NULL) *is_zero = false;
    return false;
  }
  return _mi_os_commit(subproc, address, size, is_zero);
}

static void* m2_page_map_zalloc(
    mi_subproc_t* subproc,
    size_t size,
    mi_memid_t* memid)
{
  m2_page_map_submap_allocation_attempts++;
  return _mi_os_zalloc(subproc, size, memid);
}

// Preserve the ordinary `os.c` definitions and redirect only calls emitted
// lexically from this selected `page-map.c` body.
#define _mi_os_commit m2_page_map_commit
#define _mi_os_zalloc m2_page_map_zalloc
#include "page-map.c"
#undef _mi_os_zalloc
#undef _mi_os_commit

#include "init.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

int main(void) {
  _mi_detect_cpu_features();
  _mi_options_init();
  mi_option_set_enabled(mi_option_pagemap_commit, false);
  if (mi_option_is_enabled(mi_option_pagemap_commit)) return 10;
  mi_option_set(mi_option_max_vabits, MI_MAX_VABITS);
  if (mi_option_get(mi_option_max_vabits) != MI_MAX_VABITS) return 11;
  _mi_stats_init();
  _mi_os_init();
  // Force the selected reserve-then-commit path independently of host
  // overcommit policy; this is a fixture precondition, not a production mode.
  mi_os_mem_config.has_overcommit = false;
  mi_heap_main_init();
  if (!_mi_page_map_init()) return 12;

  mi_page_map_t* const page_map = _mi_page_map();
  if (page_map == NULL || page_map == &mi_page_map_empty) return 13;
  const size_t committed_before =
      mi_atomic_load_acquire(&page_map->committed_count);
  const size_t reserved_count =
      (page_map->reserved_size < sizeof(mi_page_map_t)
          ? 0
          : 1 + (page_map->reserved_size - sizeof(mi_page_map_t)) / sizeof(mi_submap_t));
  const size_t target = committed_before + 1;
  if (target >= reserved_count) return 14;

  m2_page_map_commit_attempts = 0;
  m2_page_map_submap_allocation_attempts = 0;
  m2_fail_next_page_map_commit = true;
  mi_submap_t failed_submap = NULL;
  const bool failure_returned = !mi_page_map_ensure_submap_at(
      page_map, target, &failed_submap);
  const size_t committed_after_failure =
      mi_atomic_load_acquire(&page_map->committed_count);
  const size_t failure_commit_attempts = m2_page_map_commit_attempts;
  const size_t failure_submap_allocation_attempts =
      m2_page_map_submap_allocation_attempts;
  const bool failure_committed_unchanged =
      (committed_after_failure == committed_before);
  const bool failure_no_submap_result = (failed_submap == NULL);
  const bool failure_top_owner_retained = (_mi_page_map() == page_map);

  mi_submap_t retry_submap = NULL;
  const bool retry_succeeded = mi_page_map_ensure_submap_at(
      page_map, target, &retry_submap);
  const size_t committed_after_retry =
      mi_atomic_load_acquire(&page_map->committed_count);
  const size_t retry_commit_attempts = m2_page_map_commit_attempts;
  const size_t retry_submap_allocation_attempts =
      m2_page_map_submap_allocation_attempts;
  const bool retry_committed_advanced =
      (committed_after_retry > committed_before);
  const bool retry_submap_present =
      retry_succeeded && retry_submap != NULL &&
      mi_atomic_load_ptr_acquire(mi_page_t*, &page_map->submaps[target]) == retry_submap;
  const bool all_relations =
      _mi_os_page_size() == 4*MI_KiB && !mi_os_mem_config.has_overcommit &&
      mi_option_get(mi_option_max_vabits) == MI_MAX_VABITS &&
      target > committed_before && failure_returned &&
      failure_commit_attempts == 1 &&
      failure_committed_unchanged && failure_no_submap_result &&
      failure_top_owner_retained &&
      // The failed commit cannot enter source lazy allocation. The retry
      // enters it exactly once after publishing commitment.
      failure_submap_allocation_attempts == 0 &&
      retry_commit_attempts == 2 && retry_submap_allocation_attempts == 1 &&
      retry_succeeded && retry_committed_advanced && retry_submap_present;
  if (!all_relations) return 15;

  _mi_page_map_unsafe_destroy();
  const bool cleanup_top_owner_released = (_mi_page_map() == &mi_page_map_empty);
  if (!cleanup_top_owner_released) return 16;

  puts("CRABC_MI_M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_BEGIN");
  U("m2.page_map.lazy_commit.control.page_size", _mi_os_page_size());
  U("m2.page_map.lazy_commit.control.has_overcommit_false", !mi_os_mem_config.has_overcommit);
  U("m2.page_map.lazy_commit.control.max_vabits", mi_option_get(mi_option_max_vabits));
  U("m2.page_map.lazy_commit.failure.target_above_committed", target > committed_before);
  U("m2.page_map.lazy_commit.failure.commit_attempts", failure_commit_attempts);
  U("m2.page_map.lazy_commit.failure.returned", failure_returned);
  U("m2.page_map.lazy_commit.failure.committed_unchanged", failure_committed_unchanged);
  U("m2.page_map.lazy_commit.failure.no_submap_result", failure_no_submap_result);
  U("m2.page_map.lazy_commit.failure.submap_allocation_attempts", failure_submap_allocation_attempts);
  U("m2.page_map.lazy_commit.failure.top_owner_retained", failure_top_owner_retained);
  U("m2.page_map.lazy_commit.retry.succeeded", retry_succeeded);
  U("m2.page_map.lazy_commit.retry.committed_advanced", retry_committed_advanced);
  U("m2.page_map.lazy_commit.retry.submap_present", retry_submap_present);
  U("m2.page_map.lazy_commit.retry.submap_allocation_attempts", retry_submap_allocation_attempts);
  U("m2.page_map.lazy_commit.cleanup.top_owner_released", cleanup_top_owner_released);
  puts("CRABC_MI_M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_END");
  return 0;
}
"""


# This independent process deliberately fails the one allocation performed by
# `mi_page_map_init_once`. It cannot share the normal-success producer because
# the source once body is intentionally consumed after its first failure.
# `os.c` retains the real allocator primitive; only lexical calls compiled
# from the directly included `page-map.c` route through the one-shot wrapper.
M2_PAGE_MAP_COLD_INIT_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>

#include "os.c"

static bool m2_fail_next_page_map_alloc;
static size_t m2_page_map_alloc_attempt_count;

static void* m2_page_map_alloc_aligned(
    mi_subproc_t* subproc,
    size_t size,
    size_t alignment,
    bool commit,
    bool allow_large,
    mi_memid_t* memid)
{
  m2_page_map_alloc_attempt_count++;
  if (m2_fail_next_page_map_alloc) {
    m2_fail_next_page_map_alloc = false;
    *memid = _mi_memid_none();
    return NULL;
  }
  return _mi_os_alloc_aligned(subproc, size, alignment, commit, allow_large, memid);
}

// Preserve the ordinary `os.c` definition and redirect only source calls
// lexically emitted from the selected `page-map.c` body.
#define _mi_os_alloc_aligned m2_page_map_alloc_aligned
#include "page-map.c"
#undef _mi_os_alloc_aligned

#include "init.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

int main(void) {
  _mi_detect_cpu_features();
  _mi_options_init();
  mi_option_set_enabled(mi_option_pagemap_commit, false);
  mi_option_set(mi_option_max_vabits, MI_MAX_VABITS);
  _mi_stats_init();
  _mi_os_init();
  mi_os_mem_config.has_overcommit = false;
  mi_heap_main_init();

  m2_page_map_alloc_attempt_count = 0;
  m2_fail_next_page_map_alloc = true;
  const bool first_init_failed = !_mi_page_map_init();
  const bool root_after_first_static_empty = (_mi_page_map() == &mi_page_map_empty);
  const bool second_call_returns_success = _mi_page_map_init();
  const bool static_empty_root = (_mi_page_map() == &mi_page_map_empty);
  const bool null_lookup_returns_null = (_mi_checked_ptr_page(NULL) == NULL);
  const bool dynamic_root_unpublished = root_after_first_static_empty && static_empty_root;
  const bool all_relations =
      first_init_failed && dynamic_root_unpublished &&
      m2_page_map_alloc_attempt_count == 1 && second_call_returns_success &&
      static_empty_root && null_lookup_returns_null;
  if (!all_relations) return 10;

  puts("CRABC_MI_M2_PAGE_MAP_COLD_INIT_TRACE_BEGIN");
  U("m2.page_map.cold.first_init_failed", first_init_failed);
  U("m2.page_map.cold.dynamic_root_unpublished", dynamic_root_unpublished);
  U("m2.page_map.cold.init_body_attempt_count", m2_page_map_alloc_attempt_count);
  U("m2.page_map.cold.static_empty_root", static_empty_root);
  U("m2.page_map.cold.absent_root", false);
  U("m2.page_map.cold.second_call_returns_success", second_call_returns_success);
  U("m2.page_map.cold.second_call_returns_poisoned", false);
  U("m2.page_map.cold.null_lookup_returns_null", null_lookup_returns_null);
  U("m2.page_map.cold.cold_lookup_route_unavailable", false);
  puts("CRABC_MI_M2_PAGE_MAP_COLD_INIT_TRACE_END");
  return 0;
}
"""


# This fixture includes pinned `src/init.c` only so it can directly invoke its
# file-static `mi_tld_init` body. It deliberately constructs the source-shaped
# detached static image locally rather than calling mi_heap_main_init_once,
# mi_process_init, mi_tld_create, or any Theap/Heap/TLS lifecycle. The exact
# line-192 memid predecessor is visible as its own trace checkpoint. Both
# source thread counters belong to a fresh zero-initialized address-only
# `mi_subproc_t` fixture valid only for this detached helper and must remain
# zero: the branch does not register a live thread or initialize a process
# main subprocess.
# `MI_PRIM_HAS_PROCESS_ATTACH=1` belongs to the build command so prim.c cannot
# run its normal automatic process constructor before main.
M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>

// The normal source list omits init.c, preserving one-definition linkage while
// exposing only this translation unit's file-static mi_tld_init body.
#include "init.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

static bool m2_lock_roundtrip(mi_lock_t* lock) {
  if (!mi_lock_try_acquire(lock)) return false;
  mi_lock_release(lock);
  if (!mi_lock_try_acquire(lock)) return false;
  mi_lock_release(lock);
  return true;
}

static bool m2_memid_static(mi_memid_t memid) {
  return memid.memkind == MI_MEM_STATIC;
}

static bool m2_memid_base_null(mi_memid_t memid) {
  return memid.mem.os.base == NULL;
}

static bool m2_memid_size_zero(mi_memid_t memid) {
  return memid.mem.os.size == 0;
}

int main(void) {
  mi_tld_t tld = {
    MI_THREADID_DETACHED,
    0,
    0,
    NULL,
    NULL,
    MI_LOCK_INITIALIZER,
    false,
    false,
    MI_MEMID_STATIC,
  };
  mi_subproc_t subproc = mi_init_struct_zero;

  const size_t pre_total_thread_count =
      mi_atomic_load_relaxed(&subproc.thread_total_count);
  const size_t pre_live_thread_count =
      mi_atomic_load_relaxed(&subproc.thread_count);
  const bool pre_thread_id_detached = (tld.thread_id == MI_THREADID_DETACHED);
  const bool pre_thread_sequence_zero = (tld.thread_seq == 0);
  const bool pre_numa_node_zero = (tld.numa_node == 0);
  const bool pre_subprocess_null = (tld.subproc == NULL);
  const bool pre_theap_head_null = (tld.theaps == NULL);
  const bool pre_lock_roundtrip = m2_lock_roundtrip(&tld.theaps_lock);
  const bool pre_recurse_false = !tld.recurse;
  const bool pre_threadpool_false = !tld.is_in_threadpool;
  const mi_memid_t pre_memid = tld.memid;

  // This is exactly src/init.c:192's predecessor, separated from the private
  // helper call below so the helper cannot silently receive the old static
  // initializer flags.
  tld.memid = _mi_memid_create(MI_MEM_STATIC);
  const mi_memid_t predecessor_memid = tld.memid;

  // This invokes the file-static helper that src/init.c calls at :193, but
  // deliberately supplies a fresh zero-initialized address-only fixture valid
  // only for this detached helper rather than `_mi_subproc_main_init()`'s
  // process identity. The detached branch accepts tseq zero but must not use
  // it to register a live thread.
  mi_tld_init(&tld, 0, &subproc);

  const size_t post_total_thread_count =
      mi_atomic_load_relaxed(&subproc.thread_total_count);
  const size_t post_live_thread_count =
      mi_atomic_load_relaxed(&subproc.thread_count);
  const bool post_thread_id_detached = (tld.thread_id == MI_THREADID_DETACHED);
  const bool post_thread_sequence_zero = (tld.thread_seq == 0);
  const bool post_numa_node_minus_one = (tld.numa_node == -1);
  const bool post_subprocess_matches_input = (tld.subproc == &subproc);
  const bool post_theap_head_null = (tld.theaps == NULL);
  const bool post_lock_roundtrip = m2_lock_roundtrip(&tld.theaps_lock);
  const bool post_recurse_false = !tld.recurse;
  const bool post_threadpool_false = !tld.is_in_threadpool;

  const bool all_relations =
      pre_total_thread_count == 0 && pre_live_thread_count == 0 &&
      pre_thread_id_detached && pre_thread_sequence_zero && pre_numa_node_zero &&
      pre_subprocess_null && pre_theap_head_null && pre_lock_roundtrip &&
      pre_recurse_false && pre_threadpool_false &&
      m2_memid_static(pre_memid) && m2_memid_base_null(pre_memid) &&
      m2_memid_size_zero(pre_memid) && pre_memid.is_pinned &&
      pre_memid.initially_committed && !pre_memid.initially_zero &&
      m2_memid_static(predecessor_memid) &&
      m2_memid_base_null(predecessor_memid) &&
      m2_memid_size_zero(predecessor_memid) &&
      !predecessor_memid.is_pinned && !predecessor_memid.initially_committed &&
      !predecessor_memid.initially_zero &&
      post_thread_id_detached && post_thread_sequence_zero &&
      post_numa_node_minus_one && post_subprocess_matches_input &&
      post_theap_head_null && post_lock_roundtrip && post_recurse_false &&
      post_threadpool_false && m2_memid_static(tld.memid) &&
      m2_memid_base_null(tld.memid) && m2_memid_size_zero(tld.memid) &&
      !tld.memid.is_pinned && !tld.memid.initially_committed &&
      !tld.memid.initially_zero && post_total_thread_count == 0 &&
      post_live_thread_count == 0 &&
      post_total_thread_count == pre_total_thread_count &&
      post_live_thread_count == pre_live_thread_count;
  if (!all_relations) return 10;

  puts("CRABC_MI_M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_BEGIN");
  U("m2.initialization.detached_tld.pre.thread_id_detached", pre_thread_id_detached);
  U("m2.initialization.detached_tld.pre.thread_sequence_zero", pre_thread_sequence_zero);
  U("m2.initialization.detached_tld.pre.numa_node_zero", pre_numa_node_zero);
  U("m2.initialization.detached_tld.pre.subprocess_null", pre_subprocess_null);
  U("m2.initialization.detached_tld.pre.theap_head_null", pre_theap_head_null);
  U("m2.initialization.detached_tld.pre.lock_roundtrip", pre_lock_roundtrip);
  U("m2.initialization.detached_tld.pre.recurse_false", pre_recurse_false);
  U("m2.initialization.detached_tld.pre.threadpool_false", pre_threadpool_false);
  U("m2.initialization.detached_tld.pre.memid_static", m2_memid_static(pre_memid));
  U("m2.initialization.detached_tld.pre.memid_base_null", m2_memid_base_null(pre_memid));
  U("m2.initialization.detached_tld.pre.memid_size_zero", m2_memid_size_zero(pre_memid));
  U("m2.initialization.detached_tld.pre.memid_pinned", pre_memid.is_pinned);
  U("m2.initialization.detached_tld.pre.memid_committed", pre_memid.initially_committed);
  U("m2.initialization.detached_tld.pre.memid_zero_false", !pre_memid.initially_zero);
  U("m2.initialization.detached_tld.pre.total_thread_count_zero", pre_total_thread_count == 0);
  U("m2.initialization.detached_tld.pre.live_thread_count_zero", pre_live_thread_count == 0);
  U("m2.initialization.detached_tld.predecessor.memid_static", m2_memid_static(predecessor_memid));
  U("m2.initialization.detached_tld.predecessor.memid_base_null", m2_memid_base_null(predecessor_memid));
  U("m2.initialization.detached_tld.predecessor.memid_size_zero", m2_memid_size_zero(predecessor_memid));
  U("m2.initialization.detached_tld.predecessor.memid_unpinned", !predecessor_memid.is_pinned);
  U("m2.initialization.detached_tld.predecessor.memid_uncommitted", !predecessor_memid.initially_committed);
  U("m2.initialization.detached_tld.predecessor.memid_zero_false", !predecessor_memid.initially_zero);
  U("m2.initialization.detached_tld.post.thread_id_detached", post_thread_id_detached);
  U("m2.initialization.detached_tld.post.thread_sequence_zero", post_thread_sequence_zero);
  U("m2.initialization.detached_tld.post.numa_node_minus_one", post_numa_node_minus_one);
  U("m2.initialization.detached_tld.post.subprocess_matches_input", post_subprocess_matches_input);
  U("m2.initialization.detached_tld.post.theap_head_null", post_theap_head_null);
  U("m2.initialization.detached_tld.post.lock_roundtrip", post_lock_roundtrip);
  U("m2.initialization.detached_tld.post.recurse_false", post_recurse_false);
  U("m2.initialization.detached_tld.post.threadpool_false", post_threadpool_false);
  U("m2.initialization.detached_tld.post.memid_static", m2_memid_static(tld.memid));
  U("m2.initialization.detached_tld.post.memid_base_null", m2_memid_base_null(tld.memid));
  U("m2.initialization.detached_tld.post.memid_size_zero", m2_memid_size_zero(tld.memid));
  U("m2.initialization.detached_tld.post.memid_unpinned", !tld.memid.is_pinned);
  U("m2.initialization.detached_tld.post.memid_uncommitted", !tld.memid.initially_committed);
  U("m2.initialization.detached_tld.post.memid_zero_false", !tld.memid.initially_zero);
  U("m2.initialization.detached_tld.post.total_thread_count_zero", post_total_thread_count == 0);
  U("m2.initialization.detached_tld.post.total_thread_count_unchanged", post_total_thread_count == pre_total_thread_count);
  U("m2.initialization.detached_tld.post.live_thread_count_zero", post_live_thread_count == 0);
  U("m2.initialization.detached_tld.post.live_thread_count_unchanged", post_live_thread_count == pre_live_thread_count);
  puts("CRABC_MI_M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_END");
  return 0;
}
"""


# This fixture direct-includes pinned `src/init.c` to call only its file-static
# non-detached `mi_tld_init` body. A local zero TLD and local zero subprocess
# are the exact minimal helper read/write preimage, plus an outer post-ticket
# count context (total=8, tseq=7); they are not `mi_tld_create`, static-main
# storage, metadata allocation, or `_mi_subproc_main_init`. The normal source
# list omits init.c so every C definition remains singular. `MI_PRIM_HAS_PROCESS_ATTACH=1`
# is passed by the builder to prevent prim.c's normal constructor before main.
#
# C can dynamically observe lock/NUMA/ID/pool/live calls, but not all plain
# assignments. Poststate plus the pinned direct include anchors those writes.
# NUMA is fixture-injected as the already-normalized source-valid value three;
# this records no OS discovery or NUMA policy. The Rust side independently
# observes modeled field order after its prevalidated identity boundary.
M2_NORMAL_TLD_DIRECT_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <mimalloc.h>
#include <mimalloc/atomic.h>
#include <mimalloc/prim.h>
#include <mimalloc/prim-tls.h>
#include <mimalloc/internal.h>

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

static bool m2_normal_recording = false;
static size_t m2_normal_event_count = 0;
static size_t m2_normal_lock_event = 0;
static size_t m2_normal_numa_event = 0;
static size_t m2_normal_thread_id_event = 0;
static size_t m2_normal_threadpool_event = 0;
static size_t m2_normal_live_increment_event = 0;
static mi_threadid_t m2_normal_thread_id_result = MI_THREADID_ABANDONED;
static bool m2_normal_threadpool_result = true;
static _Atomic(size_t)* m2_normal_live_increment_target = NULL;

static void m2_normal_record(size_t* event) {
  if (m2_normal_recording) {
    *event = ++m2_normal_event_count;
  }
}

// Define wrappers while the original header functions/macros remain visible.
// Only aliases around the direct init.c include redirect the selected body.
static void m2_normal_lock_init(mi_lock_t* lock) {
  m2_normal_record(&m2_normal_lock_event);
  mi_lock_init(lock);
}

static int m2_normal_numa_node(void) {
  m2_normal_record(&m2_normal_numa_event);
  return 3;
}

static mi_threadid_t m2_normal_thread_id(void) {
  m2_normal_record(&m2_normal_thread_id_event);
  const mi_threadid_t result = _mi_prim_thread_id();
  m2_normal_thread_id_result = result;
  return result;
}

static bool m2_normal_thread_is_in_threadpool(void) {
  m2_normal_record(&m2_normal_threadpool_event);
  const bool result = _mi_prim_thread_is_in_threadpool();
  m2_normal_threadpool_result = result;
  return result;
}

static size_t m2_normal_increment_relaxed(_Atomic(size_t)* target) {
  m2_normal_record(&m2_normal_live_increment_event);
  m2_normal_live_increment_target = target;
  return mi_atomic_increment_relaxed(target);
}

#define mi_lock_init(lock) m2_normal_lock_init(lock)
#define _mi_os_numa_node() m2_normal_numa_node()
#define _mi_prim_thread_id() m2_normal_thread_id()
#define _mi_prim_thread_is_in_threadpool() m2_normal_thread_is_in_threadpool()
// The original is function-like, so undefine it only after the wrapper above
// captured its real expansion; otherwise strict builds reject redefinition.
#undef mi_atomic_increment_relaxed
#define mi_atomic_increment_relaxed(target) m2_normal_increment_relaxed(target)
#include "init.c"
#undef mi_atomic_increment_relaxed
#undef _mi_prim_thread_is_in_threadpool
#undef _mi_prim_thread_id
#undef _mi_os_numa_node
#undef mi_lock_init

static bool m2_normal_lock_roundtrip(mi_lock_t* lock) {
  if (!mi_lock_try_acquire(lock)) return false;
  mi_lock_release(lock);
  if (!mi_lock_try_acquire(lock)) return false;
  mi_lock_release(lock);
  return true;
}

static bool m2_normal_memid_none(mi_memid_t memid) {
  return memid.memkind == MI_MEM_NONE && memid.mem.os.base == NULL &&
      memid.mem.os.size == 0 && !memid.is_pinned &&
      !memid.initially_committed && !memid.initially_zero;
}

int main(void) {
  mi_tld_t tld = mi_init_struct_zero;
  mi_subproc_t subproc = mi_init_struct_zero;
  mi_atomic_store_relaxed(&subproc.thread_total_count, 8);

  const size_t pre_total_thread_count =
      mi_atomic_load_relaxed(&subproc.thread_total_count);
  const size_t pre_live_thread_count =
      mi_atomic_load_relaxed(&subproc.thread_count);
  const bool pre_thread_id_abandoned = (tld.thread_id == MI_THREADID_ABANDONED);
  const bool pre_thread_sequence_zero = (tld.thread_seq == 0);
  const bool pre_numa_node_zero = (tld.numa_node == 0);
  const bool pre_subprocess_null = (tld.subproc == NULL);
  const bool pre_theap_head_null = (tld.theaps == NULL);
  const bool pre_recurse_false = !tld.recurse;
  const bool pre_threadpool_false = !tld.is_in_threadpool;
  const bool pre_memid_none = m2_normal_memid_none(tld.memid);

  // Do not probe this lock before the normal arm: source initializes it.
  m2_normal_recording = true;
  mi_tld_t* returned = mi_tld_init(&tld, 7, &subproc);
  m2_normal_recording = false;

  const size_t post_total_thread_count =
      mi_atomic_load_relaxed(&subproc.thread_total_count);
  const size_t post_live_thread_count =
      mi_atomic_load_relaxed(&subproc.thread_count);
  const bool post_input_identity_preserved = (returned == &tld);
  const bool post_subprocess_matches_input = (tld.subproc == &subproc);
  const bool post_theap_head_null = (tld.theaps == NULL);
  const bool post_lock_roundtrip = m2_normal_lock_roundtrip(&tld.theaps_lock);
  const bool post_numa_node_injected_three = (tld.numa_node == 3);
  const bool post_thread_id_matches_input =
      (tld.thread_id == m2_normal_thread_id_result);
  const bool post_thread_id_live =
      (tld.thread_id > MI_THREADID_DETACHED &&
       (tld.thread_id & MI_PAGE_FLAG_MASK) == 0);
  const bool post_threadpool_matches_input =
      (tld.is_in_threadpool == m2_normal_threadpool_result);
  const bool post_threadpool_false = !tld.is_in_threadpool;
  const bool post_thread_sequence_matches_input = (tld.thread_seq == 7);
  const bool post_recurse_false = !tld.recurse;
  const bool post_memid_none = m2_normal_memid_none(tld.memid);
  const bool lock_before_numa =
      (m2_normal_lock_event == 1 && m2_normal_numa_event == 2);
  const bool numa_before_thread_id =
      (m2_normal_numa_event == 2 && m2_normal_thread_id_event == 3);
  const bool thread_id_before_threadpool =
      (m2_normal_thread_id_event == 3 && m2_normal_threadpool_event == 4);
  const bool threadpool_before_live_increment =
      (m2_normal_threadpool_event == 4 && m2_normal_live_increment_event == 5);
  const bool exactly_five_observable_effects = (m2_normal_event_count == 5);

  const bool all_relations =
      pre_total_thread_count == 8 && pre_live_thread_count == 0 &&
      pre_thread_id_abandoned && pre_thread_sequence_zero && pre_numa_node_zero &&
      pre_subprocess_null && pre_theap_head_null && pre_recurse_false &&
      pre_threadpool_false && pre_memid_none &&
      post_input_identity_preserved && post_subprocess_matches_input && post_theap_head_null && post_lock_roundtrip &&
      post_numa_node_injected_three && post_thread_id_matches_input &&
      post_thread_id_live && post_threadpool_matches_input &&
      post_threadpool_false && post_thread_sequence_matches_input &&
      post_recurse_false && post_memid_none && post_total_thread_count == 8 &&
      post_total_thread_count == pre_total_thread_count && post_live_thread_count == 1 &&
      post_live_thread_count == pre_live_thread_count + 1 &&
      m2_normal_live_increment_target == &subproc.thread_count &&
      lock_before_numa && numa_before_thread_id && thread_id_before_threadpool &&
      threadpool_before_live_increment && exactly_five_observable_effects;
  if (!all_relations) {
    mi_lock_done(&tld.theaps_lock);
    return 10;
  }

  puts("CRABC_MI_M2_NORMAL_TLD_DIRECT_TRACE_BEGIN");
  U("m2.initialization.normal_tld.pre.thread_id_abandoned", pre_thread_id_abandoned);
  U("m2.initialization.normal_tld.pre.thread_sequence_zero", pre_thread_sequence_zero);
  U("m2.initialization.normal_tld.pre.numa_node_zero", pre_numa_node_zero);
  U("m2.initialization.normal_tld.pre.subprocess_null", pre_subprocess_null);
  U("m2.initialization.normal_tld.pre.theap_head_null", pre_theap_head_null);
  U("m2.initialization.normal_tld.pre.recurse_false", pre_recurse_false);
  U("m2.initialization.normal_tld.pre.threadpool_false", pre_threadpool_false);
  U("m2.initialization.normal_tld.pre.memid_none", pre_memid_none);
  U("m2.initialization.normal_tld.pre.total_thread_count_eight", pre_total_thread_count == 8);
  U("m2.initialization.normal_tld.pre.live_thread_count_zero", pre_live_thread_count == 0);
  U("m2.initialization.normal_tld.post.input_identity_preserved", post_input_identity_preserved);
  U("m2.initialization.normal_tld.post.subprocess_matches_input", post_subprocess_matches_input);
  U("m2.initialization.normal_tld.post.theap_head_null", post_theap_head_null);
  U("m2.initialization.normal_tld.post.lock_roundtrip", post_lock_roundtrip);
  U("m2.initialization.normal_tld.post.numa_node_injected_three", post_numa_node_injected_three);
  U("m2.initialization.normal_tld.post.thread_id_matches_input", post_thread_id_matches_input);
  U("m2.initialization.normal_tld.post.thread_id_live", post_thread_id_live);
  U("m2.initialization.normal_tld.post.threadpool_matches_input", post_threadpool_matches_input);
  U("m2.initialization.normal_tld.post.threadpool_false", post_threadpool_false);
  U("m2.initialization.normal_tld.post.thread_sequence_matches_input", post_thread_sequence_matches_input);
  U("m2.initialization.normal_tld.post.recurse_false", post_recurse_false);
  U("m2.initialization.normal_tld.post.memid_none", post_memid_none);
  U("m2.initialization.normal_tld.post.total_thread_count_eight", post_total_thread_count == 8);
  U("m2.initialization.normal_tld.post.total_thread_count_unchanged", post_total_thread_count == pre_total_thread_count);
  U("m2.initialization.normal_tld.post.live_thread_count_one", post_live_thread_count == 1);
  U("m2.initialization.normal_tld.post.live_thread_count_incremented", post_live_thread_count == pre_live_thread_count + 1);
  U("m2.initialization.normal_tld.order.lock_before_numa", lock_before_numa);
  U("m2.initialization.normal_tld.order.numa_before_thread_id", numa_before_thread_id);
  U("m2.initialization.normal_tld.order.thread_id_before_threadpool", thread_id_before_threadpool);
  U("m2.initialization.normal_tld.order.threadpool_before_live_increment", threadpool_before_live_increment);
  U("m2.initialization.normal_tld.order.exactly_five_observable_effects", exactly_five_observable_effects);
  puts("CRABC_MI_M2_NORMAL_TLD_DIRECT_TRACE_END");

  // Fixture hygiene only: this is not mi_tld_free or a lifecycle claim.
  mi_lock_done(&tld.theaps_lock);
  return 0;
}
"""


# This fixture direct-includes pinned `src/init.c` to call the source-private
# `mi_tld_create` exactly once through its real main-subprocess/static-TLD
# success arm.  Unlike the direct normal-helper fixture above, its preimage is
# the source's own `_mi_subproc_main()` and `mi_process_tld_main` identities.
# `MI_PRIM_HAS_PROCESS_ATTACH=1` leaves both uninitialized; the fixture sets
# only the source-required non-null `theap_meta` field to an inert static
# placeholder and initializes the two counters to zero.  It intentionally
# does not call `_mi_subproc_main_init`, initialize a Heap/Theap, or allocate
# metadata.  The metadata wrapper is a no-call witness for the selected arm.
#
# The wrappers record the exact C-only selected-body order: total ticket,
# main-subprocess predicate, static memid, normal lock/NUMA/ID/pool, then live
# registration.  The common record omits the C predicate's timing because the
# Rust lifecycle path selects/founds its static storage before its ticket.
M2_STATIC_FIRST_TLD_CREATE_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <mimalloc.h>
#include <mimalloc/atomic.h>
#include <mimalloc/prim.h>
#include <mimalloc/prim-tls.h>
#include <mimalloc/internal.h>

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

static bool m2_static_first_recording = false;
static size_t m2_static_first_event_count = 0;
static size_t m2_static_first_total_increment_event = 0;
static size_t m2_static_first_main_predicate_event = 0;
static size_t m2_static_first_static_memid_event = 0;
static size_t m2_static_first_lock_event = 0;
static size_t m2_static_first_numa_event = 0;
static size_t m2_static_first_thread_id_event = 0;
static size_t m2_static_first_threadpool_event = 0;
static size_t m2_static_first_live_increment_event = 0;
static size_t m2_static_first_result_visibility_event = 0;
static size_t m2_static_first_meta_zalloc_calls = 0;
static mi_subproc_t* m2_static_first_subproc = NULL;
static mi_tld_t* m2_static_first_static_memid_target = NULL;
static size_t m2_static_first_static_memid_size = 0;
static mi_threadid_t m2_static_first_thread_id_result = MI_THREADID_ABANDONED;
static bool m2_static_first_threadpool_result = true;
static bool m2_static_first_main_predicate_result = false;
static mi_subproc_t* m2_static_first_main_predicate_target = NULL;
static size_t m2_static_first_total_ticket_value = SIZE_MAX;
static _Atomic(size_t)* m2_static_first_total_increment_target = NULL;
static _Atomic(size_t)* m2_static_first_live_increment_target = NULL;

// This placeholder exists only to satisfy mi_tld_create's asserted non-null
// precondition. It is never initialized, dereferenced, or used as metadata.
static mi_theap_t m2_static_first_inert_theap_meta = mi_init_struct_zero;

static void m2_static_first_record(size_t* event) {
  if (m2_static_first_recording) {
    *event = ++m2_static_first_event_count;
  }
}

// Define wrappers while the original header functions/macros remain visible.
// Only aliases around the direct init.c include redirect the selected body.
static void m2_static_first_lock_init(mi_lock_t* lock) {
  m2_static_first_record(&m2_static_first_lock_event);
  mi_lock_init(lock);
}

static int m2_static_first_numa_node(void) {
  m2_static_first_record(&m2_static_first_numa_event);
  return 3;
}

static mi_threadid_t m2_static_first_thread_id(void) {
  m2_static_first_record(&m2_static_first_thread_id_event);
  const mi_threadid_t result = _mi_prim_thread_id();
  m2_static_first_thread_id_result = result;
  return result;
}

static bool m2_static_first_thread_is_in_threadpool(void) {
  m2_static_first_record(&m2_static_first_threadpool_event);
  const bool result = _mi_prim_thread_is_in_threadpool();
  m2_static_first_threadpool_result = result;
  return result;
}

static bool m2_static_first_is_main(mi_subproc_t* subproc) {
  m2_static_first_record(&m2_static_first_main_predicate_event);
  m2_static_first_main_predicate_target = subproc;
  const bool result = _mi_subproc_is_main(subproc);
  m2_static_first_main_predicate_result = result;
  return result;
}

static mi_memid_t m2_static_first_memid_create_static(void* p, size_t size) {
  m2_static_first_record(&m2_static_first_static_memid_event);
  m2_static_first_static_memid_target = (mi_tld_t*)p;
  m2_static_first_static_memid_size = size;
  return _mi_memid_create_static(p, size);
}

static void* m2_static_first_meta_zalloc(
    mi_subproc_t* subproc, size_t size, mi_memid_t* memid) {
  (void)subproc;
  (void)size;
  (void)memid;
  m2_static_first_meta_zalloc_calls++;
  return NULL;
}

static size_t m2_static_first_increment_relaxed(_Atomic(size_t)* target) {
  const size_t result = mi_atomic_increment_relaxed(target);
  if (target == &m2_static_first_subproc->thread_total_count) {
    m2_static_first_record(&m2_static_first_total_increment_event);
    m2_static_first_total_increment_target = target;
    m2_static_first_total_ticket_value = result;
  }
  else if (target == &m2_static_first_subproc->thread_count) {
    m2_static_first_record(&m2_static_first_live_increment_event);
    m2_static_first_live_increment_target = target;
  }
  return result;
}

#define mi_lock_init(lock) m2_static_first_lock_init(lock)
#define _mi_os_numa_node() m2_static_first_numa_node()
#define _mi_prim_thread_id() m2_static_first_thread_id()
#define _mi_prim_thread_is_in_threadpool() m2_static_first_thread_is_in_threadpool()
#define _mi_subproc_is_main(subproc) m2_static_first_is_main(subproc)
#define _mi_memid_create_static(p, size) m2_static_first_memid_create_static(p, size)
#define _mi_meta_zalloc(subproc, size, memid) m2_static_first_meta_zalloc(subproc, size, memid)
// The original is function-like, so undefine it only after the wrapper above
// captured its real expansion; otherwise strict builds reject redefinition.
#undef mi_atomic_increment_relaxed
#define mi_atomic_increment_relaxed(target) m2_static_first_increment_relaxed(target)
#include "init.c"
#undef mi_atomic_increment_relaxed
#undef _mi_meta_zalloc
#undef _mi_memid_create_static
#undef _mi_subproc_is_main
#undef _mi_prim_thread_is_in_threadpool
#undef _mi_prim_thread_id
#undef _mi_os_numa_node
#undef mi_lock_init

static bool m2_static_first_lock_roundtrip(mi_lock_t* lock) {
  if (!mi_lock_try_acquire(lock)) return false;
  mi_lock_release(lock);
  if (!mi_lock_try_acquire(lock)) return false;
  mi_lock_release(lock);
  return true;
}

static bool m2_static_first_memid_none(mi_memid_t memid) {
  return memid.memkind == MI_MEM_NONE && memid.mem.os.base == NULL &&
      memid.mem.os.size == 0 && !memid.is_pinned &&
      !memid.initially_committed && !memid.initially_zero;
}

int main(void) {
  mi_subproc_t* const subproc = _mi_subproc_main();
  m2_static_first_subproc = subproc;
  subproc->theap_meta = &m2_static_first_inert_theap_meta;
  mi_atomic_store_relaxed(&subproc->thread_total_count, 0);
  mi_atomic_store_relaxed(&subproc->thread_count, 0);

  const size_t pre_total_thread_count =
      mi_atomic_load_relaxed(&subproc->thread_total_count);
  const size_t pre_live_thread_count =
      mi_atomic_load_relaxed(&subproc->thread_count);
  const bool pre_main_subprocess_selected = (subproc == _mi_subproc_main());
  const bool pre_theap_meta_nonnull = (subproc->theap_meta != NULL);
  // Do not probe the source static lock before mi_tld_create initializes it.
  const bool pre_static_slot_fresh =
      mi_process_tld_main.thread_id == MI_THREADID_ABANDONED &&
      mi_process_tld_main.thread_seq == 0 &&
      mi_process_tld_main.numa_node == 0 &&
      mi_process_tld_main.subproc == NULL && mi_process_tld_main.theaps == NULL &&
      !mi_process_tld_main.recurse && !mi_process_tld_main.is_in_threadpool &&
      m2_static_first_memid_none(mi_process_tld_main.memid);

  m2_static_first_recording = true;
  // Directly invoke the file-static selected caller exactly once.
  mi_tld_t* returned = mi_tld_create(_mi_subproc_main());
  // This fixture observer represents return/result visibility only after the
  // selected source body completed; it is not an additional source effect.
  m2_static_first_result_visibility_event = ++m2_static_first_event_count;
  m2_static_first_recording = false;

  const size_t post_total_thread_count =
      mi_atomic_load_relaxed(&subproc->thread_total_count);
  const size_t post_live_thread_count =
      mi_atomic_load_relaxed(&subproc->thread_count);
  const bool post_static_branch_selected =
      m2_static_first_main_predicate_result && m2_static_first_total_ticket_value == 0 &&
      returned == &mi_process_tld_main;
  const bool post_static_slot_identity_preserved =
      (returned == &mi_process_tld_main);
  const bool post_subprocess_matches_input =
      (returned != NULL && returned->subproc == subproc);
  const bool post_theap_head_null = (returned != NULL && returned->theaps == NULL);
  const bool post_lock_roundtrip =
      (returned != NULL && m2_static_first_lock_roundtrip(&returned->theaps_lock));
  const bool post_numa_node_injected_three =
      (returned != NULL && returned->numa_node == 3);
  const bool post_thread_id_matches_input =
      (returned != NULL && returned->thread_id == m2_static_first_thread_id_result);
  const bool post_thread_id_live =
      (returned != NULL && returned->thread_id > MI_THREADID_DETACHED &&
       (returned->thread_id & MI_PAGE_FLAG_MASK) == 0);
  const bool post_threadpool_false =
      (returned != NULL && !returned->is_in_threadpool &&
       !m2_static_first_threadpool_result);
  const bool post_thread_sequence_zero = (returned != NULL && returned->thread_seq == 0);
  const bool post_recurse_false = (returned != NULL && !returned->recurse);
  const bool post_memid_static_kind =
      (returned != NULL && returned->memid.memkind == MI_MEM_STATIC);
  const bool post_memid_base_is_static_slot =
      (returned != NULL && returned->memid.mem.malloc.base == returned);
  const bool post_memid_size_is_own_tld_size =
      (returned != NULL && returned->memid.mem.malloc.size == sizeof(*returned));
  const bool post_memid_pinned = (returned != NULL && returned->memid.is_pinned);
  const bool post_memid_initially_committed =
      (returned != NULL && returned->memid.initially_committed);
  const bool post_memid_initially_zero_false =
      (returned != NULL && !returned->memid.initially_zero);
  const bool post_metadata_allocation_bypassed = (m2_static_first_meta_zalloc_calls == 0);
  const bool post_total_thread_count_one = (post_total_thread_count == 1);
  const bool post_total_thread_count_incremented =
      (post_total_thread_count == pre_total_thread_count + 1);
  const bool post_live_thread_count_one = (post_live_thread_count == 1);
  const bool post_live_thread_count_incremented =
      (post_live_thread_count == pre_live_thread_count + 1);
  const bool post_result_visibility_after_live_registration =
      (returned != NULL && m2_static_first_live_increment_event <
       m2_static_first_result_visibility_event);
  const bool ticket_zero_before_static_memid =
      (m2_static_first_total_increment_event == 1 &&
       m2_static_first_static_memid_event == 3);
  const bool static_memid_before_normal_lock =
      (m2_static_first_static_memid_event == 3 && m2_static_first_lock_event == 4);
  const bool lock_before_numa =
      (m2_static_first_lock_event == 4 && m2_static_first_numa_event == 5);
  const bool numa_before_thread_id =
      (m2_static_first_numa_event == 5 && m2_static_first_thread_id_event == 6);
  const bool thread_id_before_threadpool =
      (m2_static_first_thread_id_event == 6 && m2_static_first_threadpool_event == 7);
  const bool threadpool_before_live_increment =
      (m2_static_first_threadpool_event == 7 &&
       m2_static_first_live_increment_event == 8);
  const bool total_increment_before_live_increment =
      (m2_static_first_total_increment_event == 1 &&
       m2_static_first_live_increment_event == 8);
  const bool live_increment_before_result_visibility =
      (m2_static_first_live_increment_event == 8 &&
       m2_static_first_result_visibility_event == 9);
  // This is deliberately C-only: it includes the real source predicate.
  const bool c_selected_create_effects_ordered =
      (m2_static_first_event_count == 9 &&
       m2_static_first_total_increment_event == 1 &&
       m2_static_first_main_predicate_event == 2 &&
       m2_static_first_static_memid_event == 3 && m2_static_first_lock_event == 4 &&
       m2_static_first_numa_event == 5 && m2_static_first_thread_id_event == 6 &&
       m2_static_first_threadpool_event == 7 &&
       m2_static_first_live_increment_event == 8 &&
       m2_static_first_result_visibility_event == 9);
  // The shared aggregate deliberately omits the C-only predicate event.
  const bool selected_create_effects_ordered =
      ticket_zero_before_static_memid && static_memid_before_normal_lock &&
      lock_before_numa && numa_before_thread_id && thread_id_before_threadpool &&
      threadpool_before_live_increment && total_increment_before_live_increment &&
      live_increment_before_result_visibility;

  const bool all_relations =
      pre_main_subprocess_selected && pre_theap_meta_nonnull && pre_static_slot_fresh &&
      pre_total_thread_count == 0 && pre_live_thread_count == 0 &&
      post_static_branch_selected && post_static_slot_identity_preserved &&
      post_subprocess_matches_input && post_theap_head_null && post_lock_roundtrip &&
      post_numa_node_injected_three && post_thread_id_matches_input && post_thread_id_live &&
      post_threadpool_false && post_thread_sequence_zero && post_recurse_false &&
      post_memid_static_kind && post_memid_base_is_static_slot &&
      post_memid_size_is_own_tld_size && post_memid_pinned &&
      post_memid_initially_committed && post_memid_initially_zero_false &&
      post_metadata_allocation_bypassed && post_total_thread_count_one &&
      post_total_thread_count_incremented && post_live_thread_count_one &&
      post_live_thread_count_incremented && post_result_visibility_after_live_registration &&
      m2_static_first_total_increment_target == &subproc->thread_total_count &&
      m2_static_first_live_increment_target == &subproc->thread_count &&
      m2_static_first_main_predicate_target == subproc &&
      m2_static_first_static_memid_target == &mi_process_tld_main &&
      m2_static_first_static_memid_size == sizeof(mi_process_tld_main) &&
      ticket_zero_before_static_memid && static_memid_before_normal_lock &&
      lock_before_numa && numa_before_thread_id && thread_id_before_threadpool &&
      threadpool_before_live_increment && total_increment_before_live_increment &&
      live_increment_before_result_visibility && c_selected_create_effects_ordered &&
      selected_create_effects_ordered;
  if (!all_relations) {
    if (returned != NULL) mi_lock_done(&returned->theaps_lock);
    return 10;
  }

  puts("CRABC_MI_M2_STATIC_FIRST_TLD_CREATE_TRACE_BEGIN");
  U("m2.initialization.static_first_tld.pre.main_subprocess_selected", pre_main_subprocess_selected);
  U("m2.initialization.static_first_tld.pre.static_slot_fresh", pre_static_slot_fresh);
  U("m2.initialization.static_first_tld.pre.total_thread_count_zero", pre_total_thread_count == 0);
  U("m2.initialization.static_first_tld.pre.live_thread_count_zero", pre_live_thread_count == 0);
  U("m2.initialization.static_first_tld.post.static_branch_selected", post_static_branch_selected);
  U("m2.initialization.static_first_tld.post.static_slot_identity_preserved", post_static_slot_identity_preserved);
  U("m2.initialization.static_first_tld.post.subprocess_matches_input", post_subprocess_matches_input);
  U("m2.initialization.static_first_tld.post.theap_head_null", post_theap_head_null);
  U("m2.initialization.static_first_tld.post.lock_roundtrip", post_lock_roundtrip);
  U("m2.initialization.static_first_tld.post.numa_node_injected_three", post_numa_node_injected_three);
  U("m2.initialization.static_first_tld.post.thread_id_matches_input", post_thread_id_matches_input);
  U("m2.initialization.static_first_tld.post.thread_id_live", post_thread_id_live);
  U("m2.initialization.static_first_tld.post.threadpool_false", post_threadpool_false);
  U("m2.initialization.static_first_tld.post.thread_sequence_zero", post_thread_sequence_zero);
  U("m2.initialization.static_first_tld.post.recurse_false", post_recurse_false);
  U("m2.initialization.static_first_tld.post.memid_static_kind", post_memid_static_kind);
  U("m2.initialization.static_first_tld.post.memid_base_is_static_slot", post_memid_base_is_static_slot);
  U("m2.initialization.static_first_tld.post.memid_size_is_own_tld_size", post_memid_size_is_own_tld_size);
  U("m2.initialization.static_first_tld.post.memid_pinned", post_memid_pinned);
  U("m2.initialization.static_first_tld.post.memid_initially_committed", post_memid_initially_committed);
  U("m2.initialization.static_first_tld.post.memid_initially_zero_false", post_memid_initially_zero_false);
  U("m2.initialization.static_first_tld.post.metadata_allocation_bypassed", post_metadata_allocation_bypassed);
  U("m2.initialization.static_first_tld.post.total_thread_count_one", post_total_thread_count_one);
  U("m2.initialization.static_first_tld.post.total_thread_count_incremented", post_total_thread_count_incremented);
  U("m2.initialization.static_first_tld.post.live_thread_count_one", post_live_thread_count_one);
  U("m2.initialization.static_first_tld.post.live_thread_count_incremented", post_live_thread_count_incremented);
  U("m2.initialization.static_first_tld.post.result_visibility_after_live_registration", post_result_visibility_after_live_registration);
  U("m2.initialization.static_first_tld.order.ticket_zero_before_static_memid", ticket_zero_before_static_memid);
  U("m2.initialization.static_first_tld.order.static_memid_before_normal_lock", static_memid_before_normal_lock);
  U("m2.initialization.static_first_tld.order.lock_before_numa", lock_before_numa);
  U("m2.initialization.static_first_tld.order.numa_before_thread_id", numa_before_thread_id);
  U("m2.initialization.static_first_tld.order.thread_id_before_threadpool", thread_id_before_threadpool);
  U("m2.initialization.static_first_tld.order.threadpool_before_live_increment", threadpool_before_live_increment);
  U("m2.initialization.static_first_tld.order.total_increment_before_live_increment", total_increment_before_live_increment);
  U("m2.initialization.static_first_tld.order.live_increment_before_result_visibility", live_increment_before_result_visibility);
  U("m2.initialization.static_first_tld.order.selected_create_effects_ordered", selected_create_effects_ordered);
  puts("CRABC_MI_M2_STATIC_FIRST_TLD_CREATE_TRACE_END");

  // Fixture hygiene only: this is neither mi_tld_free nor lifecycle evidence.
  mi_lock_done(&returned->theaps_lock);
  return 0;
}
"""


# This fixture includes only the selected pinned `src/bitmap.c` body. Its
# one-chunk static image never invokes allocator initialization or any arena
# callback state; linker section collection deliberately discards the other
# bitmap implementation paths. The trace therefore compares the exact
# source-private reject/restore, claim, and stale-conservative-map repair
# transitions without pretending to exercise full arena abandonment.
M2_BITMAP_ABANDONED_CLAIM_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bitmap.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

enum {
  m2_bitmap_thread_sequence = 5,
  m2_bitmap_selected_index = 17,
};

static mi_bitmap_t m2_bitmap_image;
static size_t m2_bitmap_callback_count;
static size_t m2_bitmap_reject_index;
static size_t m2_bitmap_accept_index;
static size_t m2_bitmap_drain_callback_count;

static bool m2_bitmap_reject(
    size_t slice_index, mi_arena_t* arena, bool* keep_set)
{
  if (arena != NULL || keep_set == NULL) return false;
  m2_bitmap_callback_count++;
  m2_bitmap_reject_index = slice_index;
  *keep_set = true;
  return false;
}

static bool m2_bitmap_accept(
    size_t slice_index, mi_arena_t* arena, bool* keep_set)
{
  if (arena != NULL || keep_set == NULL) return false;
  m2_bitmap_callback_count++;
  m2_bitmap_accept_index = slice_index;
  *keep_set = false;
  return true;
}

static bool m2_bitmap_drain_callback(
    size_t slice_index, mi_arena_t* arena, bool* keep_set)
{
  MI_UNUSED(slice_index);
  if (arena != NULL || keep_set == NULL) return false;
  m2_bitmap_drain_callback_count++;
  *keep_set = true;
  return false;
}

int main(void) {
  const size_t byte_size = mi_bitmap_init(
      &m2_bitmap_image, MI_BCHUNK_BITS, true);
  const size_t chunk_count = mi_bitmap_chunk_count(&m2_bitmap_image);
  const bool initial_set_transitioned =
      mi_bitmap_set(&m2_bitmap_image, m2_bitmap_selected_index);

  size_t rejected_index = SIZE_MAX;
  const bool rejected_returned_claimed = mi_bitmap_try_find_and_claim(
      &m2_bitmap_image, m2_bitmap_thread_sequence, &rejected_index, &m2_bitmap_reject, NULL);
  const bool rejected_bit_restored = mi_bitmap_is_set(
      &m2_bitmap_image, m2_bitmap_selected_index);
  const bool rejected_chunkmap_retained = mi_bchunk_is_xsetN(
      MI_BIT_SET, &m2_bitmap_image.chunkmap, 0, 1);
  const size_t reject_callback_count = m2_bitmap_callback_count;

  size_t accepted_index = SIZE_MAX;
  const bool accepted_returned_claimed = mi_bitmap_try_find_and_claim(
      &m2_bitmap_image, m2_bitmap_thread_sequence, &accepted_index, &m2_bitmap_accept, NULL);
  const bool accepted_bit_cleared = mi_bitmap_is_clear(
      &m2_bitmap_image, m2_bitmap_selected_index);
  const bool accepted_chunkmap_retained = mi_bchunk_is_xsetN(
      MI_BIT_SET, &m2_bitmap_image.chunkmap, 0, 1);
  const size_t accept_callback_count =
      m2_bitmap_callback_count - reject_callback_count;

  size_t drained_index = SIZE_MAX;
  const bool drained_returned_claimed = mi_bitmap_try_find_and_claim(
      &m2_bitmap_image, m2_bitmap_thread_sequence, &drained_index, &m2_bitmap_drain_callback, NULL);
  const bool drained_chunkmap_cleared = mi_bchunk_is_xsetN(
      MI_BIT_CLEAR, &m2_bitmap_image.chunkmap, 0, 1);

  const bool all_relations =
      byte_size == sizeof(m2_bitmap_image) && chunk_count == 1 &&
      initial_set_transitioned &&
      !rejected_returned_claimed && rejected_index == SIZE_MAX &&
      reject_callback_count == 1 &&
      m2_bitmap_reject_index == m2_bitmap_selected_index &&
      rejected_bit_restored && rejected_chunkmap_retained &&
      accepted_returned_claimed &&
      accept_callback_count == 1 &&
      m2_bitmap_accept_index == m2_bitmap_selected_index &&
      accepted_index == m2_bitmap_selected_index &&
      accepted_bit_cleared && accepted_chunkmap_retained &&
      !drained_returned_claimed && drained_index == SIZE_MAX &&
      m2_bitmap_drain_callback_count == 0 && drained_chunkmap_cleared;
  if (!all_relations) return 10;

  puts("CRABC_MI_M2_BITMAP_ABANDONED_CLAIM_TRACE_BEGIN");
  U("m2.bitmap.control.bfield_bits", MI_BFIELD_BITS);
  U("m2.bitmap.control.bchunk_bits", MI_BCHUNK_BITS);
  U("m2.bitmap.control.thread_sequence", m2_bitmap_thread_sequence);
  U("m2.bitmap.control.selected_index", m2_bitmap_selected_index);
  U("m2.bitmap.layout.byte_size", byte_size);
  U("m2.bitmap.setup.chunk_count", chunk_count);
  U("m2.bitmap.setup.initial_set_transitioned", initial_set_transitioned);
  U("m2.bitmap.reject.returned_claimed", rejected_returned_claimed);
  U("m2.bitmap.reject.callback_count", reject_callback_count);
  U("m2.bitmap.reject.callback_index", m2_bitmap_reject_index);
  U("m2.bitmap.reject.bit_restored", rejected_bit_restored);
  U("m2.bitmap.reject.chunkmap_retained", rejected_chunkmap_retained);
  U("m2.bitmap.accept.returned_claimed", accepted_returned_claimed);
  U("m2.bitmap.accept.callback_count", accept_callback_count);
  U("m2.bitmap.accept.callback_index", m2_bitmap_accept_index);
  U("m2.bitmap.accept.claimed_index", accepted_index);
  U("m2.bitmap.accept.bit_cleared", accepted_bit_cleared);
  U("m2.bitmap.accept.chunkmap_retained", accepted_chunkmap_retained);
  U("m2.bitmap.drain.returned_claimed", drained_returned_claimed);
  U("m2.bitmap.drain.callback_count", m2_bitmap_drain_callback_count);
  U("m2.bitmap.drain.chunkmap_cleared", drained_chunkmap_cleared);
  puts("CRABC_MI_M2_BITMAP_ABANDONED_CLAIM_TRACE_END");
  return 0;
}
"""


# This fixture directly includes the selected pinned scalar bitmap source.
# It uses one static chunk in two independent images: the completed walk proves
# source field-bounded maximal runs, while the stopped walk proves that only
# the residual bits from its exchanged field are restored. It supplies no
# arena state and does not exercise the `rangesn` policy wrapper.
M2_BITMAP_CLEAR_RANGE_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bitmap.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

typedef struct m2_bitmap_range_trace_s {
  size_t count;
  size_t indices[4];
  size_t counts[4];
} m2_bitmap_range_trace_t;

static mi_bitmap_t m2_bitmap_complete;
static mi_bitmap_t m2_bitmap_reject;
static m2_bitmap_range_trace_t m2_complete_trace;
static m2_bitmap_range_trace_t m2_reject_trace;

static bool m2_complete_visit(
    size_t slice_index, size_t slice_count, mi_arena_t* arena, void* arg)
{
  m2_bitmap_range_trace_t* const trace = (m2_bitmap_range_trace_t*)arg;
  if (arena != NULL || trace != &m2_complete_trace || trace->count >= 4) return false;
  trace->indices[trace->count] = slice_index;
  trace->counts[trace->count] = slice_count;
  trace->count++;
  return true;
}

static bool m2_reject_visit(
    size_t slice_index, size_t slice_count, mi_arena_t* arena, void* arg)
{
  m2_bitmap_range_trace_t* const trace = (m2_bitmap_range_trace_t*)arg;
  if (arena != NULL || trace != &m2_reject_trace || trace->count != 0) return false;
  trace->indices[trace->count] = slice_index;
  trace->counts[trace->count] = slice_count;
  trace->count++;
  return false;
}

int main(void) {
  const size_t complete_size = mi_bitmap_init(
      &m2_bitmap_complete, MI_BCHUNK_BITS, true);
  const size_t reject_size = mi_bitmap_init(
      &m2_bitmap_reject, MI_BCHUNK_BITS, true);
  const size_t complete_chunk_count = mi_bitmap_chunk_count(&m2_bitmap_complete);
  const bool complete_set_transitioned =
      mi_bitmap_setN(&m2_bitmap_complete, 1, 2, NULL) &&
      mi_bitmap_setN(&m2_bitmap_complete, 5, 2, NULL) &&
      mi_bitmap_setN(&m2_bitmap_complete, MI_BFIELD_BITS - 2, 4, NULL);
  const bool complete_returned_completed = _mi_bitmap_forall_setc_ranges(
      &m2_bitmap_complete, &m2_complete_visit, NULL, &m2_complete_trace);
  const bool complete_data_cleared = mi_bitmap_is_clearN(
      &m2_bitmap_complete, 0, MI_BCHUNK_BITS);
  const bool complete_chunkmap_retained = mi_bchunk_is_xsetN(
      MI_BIT_SET, &m2_bitmap_complete.chunkmap, 0, 1);

  const bool reject_set_transitioned =
      mi_bitmap_setN(&m2_bitmap_reject, 1, 2, NULL) &&
      mi_bitmap_setN(&m2_bitmap_reject, 5, 2, NULL) &&
      mi_bitmap_setN(&m2_bitmap_reject, MI_BFIELD_BITS, 2, NULL);
  const bool reject_returned_completed = _mi_bitmap_forall_setc_ranges(
      &m2_bitmap_reject, &m2_reject_visit, NULL, &m2_reject_trace);
  const bool reject_visited_range_cleared = mi_bitmap_is_clearN(
      &m2_bitmap_reject, 1, 2);
  const bool reject_unvisited_same_field_restored = mi_bitmap_is_xsetN(
      MI_BIT_SET, &m2_bitmap_reject, 5, 2);
  const bool reject_later_field_untouched = mi_bitmap_is_xsetN(
      MI_BIT_SET, &m2_bitmap_reject, MI_BFIELD_BITS, 2);
  const bool reject_chunkmap_retained = mi_bchunk_is_xsetN(
      MI_BIT_SET, &m2_bitmap_reject.chunkmap, 0, 1);

  const bool all_relations =
      complete_size == sizeof(m2_bitmap_complete) &&
      reject_size == sizeof(m2_bitmap_reject) &&
      complete_chunk_count == 1 && complete_set_transitioned &&
      complete_returned_completed && m2_complete_trace.count == 4 &&
      m2_complete_trace.indices[0] == 1 && m2_complete_trace.counts[0] == 2 &&
      m2_complete_trace.indices[1] == 5 && m2_complete_trace.counts[1] == 2 &&
      m2_complete_trace.indices[2] == MI_BFIELD_BITS - 2 &&
      m2_complete_trace.counts[2] == 2 &&
      m2_complete_trace.indices[3] == MI_BFIELD_BITS &&
      m2_complete_trace.counts[3] == 2 &&
      complete_data_cleared && complete_chunkmap_retained &&
      reject_set_transitioned && !reject_returned_completed &&
      m2_reject_trace.count == 1 &&
      m2_reject_trace.indices[0] == 1 && m2_reject_trace.counts[0] == 2 &&
      reject_visited_range_cleared && reject_unvisited_same_field_restored &&
      reject_later_field_untouched && reject_chunkmap_retained;
  if (!all_relations) return 10;

  puts("CRABC_MI_M2_BITMAP_CLEAR_RANGE_TRACE_BEGIN");
  U("m2.bitmap_range.control.bfield_bits", MI_BFIELD_BITS);
  U("m2.bitmap_range.control.bchunk_bits", MI_BCHUNK_BITS);
  U("m2.bitmap_range.layout.byte_size", complete_size);
  U("m2.bitmap_range.complete.chunk_count", complete_chunk_count);
  U("m2.bitmap_range.complete.set_transitioned", complete_set_transitioned);
  U("m2.bitmap_range.complete.returned_completed", complete_returned_completed);
  U("m2.bitmap_range.complete.callback_count", m2_complete_trace.count);
  U("m2.bitmap_range.complete.range_0_index", m2_complete_trace.indices[0]);
  U("m2.bitmap_range.complete.range_0_count", m2_complete_trace.counts[0]);
  U("m2.bitmap_range.complete.range_1_index", m2_complete_trace.indices[1]);
  U("m2.bitmap_range.complete.range_1_count", m2_complete_trace.counts[1]);
  U("m2.bitmap_range.complete.range_2_index", m2_complete_trace.indices[2]);
  U("m2.bitmap_range.complete.range_2_count", m2_complete_trace.counts[2]);
  U("m2.bitmap_range.complete.range_3_index", m2_complete_trace.indices[3]);
  U("m2.bitmap_range.complete.range_3_count", m2_complete_trace.counts[3]);
  U("m2.bitmap_range.complete.data_cleared", complete_data_cleared);
  U("m2.bitmap_range.complete.chunkmap_retained", complete_chunkmap_retained);
  U("m2.bitmap_range.reject.set_transitioned", reject_set_transitioned);
  U("m2.bitmap_range.reject.returned_completed", reject_returned_completed);
  U("m2.bitmap_range.reject.callback_count", m2_reject_trace.count);
  U("m2.bitmap_range.reject.range_index", m2_reject_trace.indices[0]);
  U("m2.bitmap_range.reject.range_count", m2_reject_trace.counts[0]);
  U("m2.bitmap_range.reject.visited_range_cleared", reject_visited_range_cleared);
  U("m2.bitmap_range.reject.unvisited_same_field_restored", reject_unvisited_same_field_restored);
  U("m2.bitmap_range.reject.later_field_untouched", reject_later_field_untouched);
  U("m2.bitmap_range.reject.chunkmap_retained", reject_chunkmap_retained);
  puts("CRABC_MI_M2_BITMAP_CLEAR_RANGE_TRACE_END");
  return 0;
}
"""


# This fixture includes the source-private rangesn wrapper itself. Each static
# image is fresh because the source visitor exchanges data fields with zero;
# the record is address-free and fixes only selected one-chunk scalar behavior.
M2_BITMAP_RANGESN_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bitmap.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

typedef struct m2_bitmap_rangesn_trace_s {
  size_t count;
  size_t indices[4];
  size_t counts[4];
} m2_bitmap_rangesn_trace_t;

static mi_bitmap_t m2_bitmap_rangesn_complete;
static mi_bitmap_t m2_bitmap_rangesn_reject;
static mi_bitmap_t m2_bitmap_rangesn_delegation_zero;
static mi_bitmap_t m2_bitmap_rangesn_delegation_one;
static mi_bitmap_t m2_bitmap_rangesn_cap_over;
static m2_bitmap_rangesn_trace_t m2_rangesn_complete_trace;
static m2_bitmap_rangesn_trace_t m2_rangesn_reject_trace;
static m2_bitmap_rangesn_trace_t m2_rangesn_delegation_zero_trace;
static m2_bitmap_rangesn_trace_t m2_rangesn_delegation_one_trace;
static m2_bitmap_rangesn_trace_t m2_rangesn_cap_over_trace;

static bool m2_rangesn_seed_complete(mi_bitmap_t* bitmap) {
  return mi_bitmap_setN(bitmap, 0, 8, NULL) &&
      mi_bitmap_setN(bitmap, 9, 3, NULL) &&
      mi_bitmap_setN(bitmap, 60, 2, NULL) &&
      mi_bitmap_setN(bitmap, 63, 1, NULL);
}

static bool m2_rangesn_seed_reject(mi_bitmap_t* bitmap) {
  return mi_bitmap_setN(bitmap, 0, 1, NULL) &&
      mi_bitmap_setN(bitmap, 2, 4, NULL) &&
      mi_bitmap_setN(bitmap, 6, 2, NULL) &&
      mi_bitmap_setN(bitmap, 9, 3, NULL) &&
      mi_bitmap_setN(bitmap, 60, 2, NULL) &&
      mi_bitmap_setN(bitmap, 63, 1, NULL) &&
      mi_bitmap_setN(bitmap, MI_BFIELD_BITS, 3, NULL);
}

static bool m2_rangesn_accept_visit(
    size_t slice_index, size_t slice_count, mi_arena_t* arena, void* arg)
{
  m2_bitmap_rangesn_trace_t* const trace = (m2_bitmap_rangesn_trace_t*)arg;
  if (arena != NULL || trace == NULL || trace->count >= 4) return false;
  trace->indices[trace->count] = slice_index;
  trace->counts[trace->count] = slice_count;
  trace->count++;
  return true;
}

static bool m2_rangesn_reject_visit(
    size_t slice_index, size_t slice_count, mi_arena_t* arena, void* arg)
{
  m2_bitmap_rangesn_trace_t* const trace = (m2_bitmap_rangesn_trace_t*)arg;
  if (arena != NULL || trace != &m2_rangesn_reject_trace || trace->count != 0) return false;
  trace->indices[0] = slice_index;
  trace->counts[0] = slice_count;
  trace->count = 1;
  return false;
}

int main(void) {
  const size_t complete_size = mi_bitmap_init(
      &m2_bitmap_rangesn_complete, MI_BCHUNK_BITS, true);
  const size_t reject_size = mi_bitmap_init(
      &m2_bitmap_rangesn_reject, MI_BCHUNK_BITS, true);
  const size_t delegation_zero_size = mi_bitmap_init(
      &m2_bitmap_rangesn_delegation_zero, MI_BCHUNK_BITS, true);
  const size_t delegation_one_size = mi_bitmap_init(
      &m2_bitmap_rangesn_delegation_one, MI_BCHUNK_BITS, true);
  const size_t cap_over_size = mi_bitmap_init(
      &m2_bitmap_rangesn_cap_over, MI_BCHUNK_BITS, true);

  const bool complete_seeded = m2_rangesn_seed_complete(&m2_bitmap_rangesn_complete);
  const bool complete_returned_completed = _mi_bitmap_forall_setc_rangesn(
      &m2_bitmap_rangesn_complete, 3, &m2_rangesn_accept_visit, NULL,
      &m2_rangesn_complete_trace);
  const mi_bfield_t complete_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_complete.chunks[0].bfields[0]);
  const mi_bfield_t complete_chunkmap_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_complete.chunkmap.bfields[0]);

  const bool reject_seeded = m2_rangesn_seed_reject(&m2_bitmap_rangesn_reject);
  const bool reject_returned_completed = _mi_bitmap_forall_setc_rangesn(
      &m2_bitmap_rangesn_reject, 3, &m2_rangesn_reject_visit, NULL,
      &m2_rangesn_reject_trace);
  const mi_bfield_t reject_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_reject.chunks[0].bfields[0]);
  const mi_bfield_t reject_field_1_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_reject.chunks[0].bfields[1]);
  const mi_bfield_t reject_chunkmap_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_reject.chunkmap.bfields[0]);

  const bool delegation_zero_seeded = m2_rangesn_seed_complete(
      &m2_bitmap_rangesn_delegation_zero);
  const bool delegation_zero_returned_completed = _mi_bitmap_forall_setc_rangesn(
      &m2_bitmap_rangesn_delegation_zero, 0, &m2_rangesn_accept_visit, NULL,
      &m2_rangesn_delegation_zero_trace);
  const mi_bfield_t delegation_zero_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_delegation_zero.chunks[0].bfields[0]);
  const mi_bfield_t delegation_zero_chunkmap_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_delegation_zero.chunkmap.bfields[0]);

  const bool delegation_one_seeded = m2_rangesn_seed_complete(
      &m2_bitmap_rangesn_delegation_one);
  const bool delegation_one_returned_completed = _mi_bitmap_forall_setc_rangesn(
      &m2_bitmap_rangesn_delegation_one, 1, &m2_rangesn_accept_visit, NULL,
      &m2_rangesn_delegation_one_trace);
  const mi_bfield_t delegation_one_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_delegation_one.chunks[0].bfields[0]);
  const mi_bfield_t delegation_one_chunkmap_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_delegation_one.chunkmap.bfields[0]);

  const bool cap_over_seeded = mi_bitmap_setN(
      &m2_bitmap_rangesn_cap_over, 0, MI_BFIELD_BITS, NULL);
  const bool cap_over_returned_completed = _mi_bitmap_forall_setc_rangesn(
      &m2_bitmap_rangesn_cap_over, MI_BFIELD_BITS + 1, &m2_rangesn_accept_visit, NULL,
      &m2_rangesn_cap_over_trace);
  const mi_bfield_t cap_over_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_cap_over.chunks[0].bfields[0]);
  const mi_bfield_t cap_over_chunkmap_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_rangesn_cap_over.chunkmap.bfields[0]);

  const bool all_relations =
      complete_size == sizeof(m2_bitmap_rangesn_complete) &&
      reject_size == sizeof(m2_bitmap_rangesn_reject) &&
      delegation_zero_size == sizeof(m2_bitmap_rangesn_delegation_zero) &&
      delegation_one_size == sizeof(m2_bitmap_rangesn_delegation_one) &&
      cap_over_size == sizeof(m2_bitmap_rangesn_cap_over) &&
      complete_seeded && complete_returned_completed &&
      m2_rangesn_complete_trace.count == 3 &&
      m2_rangesn_complete_trace.indices[0] == 0 &&
      m2_rangesn_complete_trace.counts[0] == 3 &&
      m2_rangesn_complete_trace.indices[1] == 3 &&
      m2_rangesn_complete_trace.counts[1] == 3 &&
      m2_rangesn_complete_trace.indices[2] == 9 &&
      m2_rangesn_complete_trace.counts[2] == 3 &&
      complete_field_0_after == (mi_bfield_t)UINT64_C(0xb0000000000000c0) &&
      complete_chunkmap_field_0_after == 1 &&
      reject_seeded && !reject_returned_completed &&
      m2_rangesn_reject_trace.count == 1 &&
      m2_rangesn_reject_trace.indices[0] == 3 &&
      m2_rangesn_reject_trace.counts[0] == 3 &&
      reject_field_0_after == (mi_bfield_t)UINT64_C(0xb000000000000ec5) &&
      reject_field_1_after == 7 && reject_chunkmap_field_0_after == 1 &&
      delegation_zero_seeded && delegation_zero_returned_completed &&
      m2_rangesn_delegation_zero_trace.count == 4 &&
      m2_rangesn_delegation_zero_trace.indices[0] == 0 &&
      m2_rangesn_delegation_zero_trace.counts[0] == 8 &&
      m2_rangesn_delegation_zero_trace.indices[1] == 9 &&
      m2_rangesn_delegation_zero_trace.counts[1] == 3 &&
      m2_rangesn_delegation_zero_trace.indices[2] == 60 &&
      m2_rangesn_delegation_zero_trace.counts[2] == 2 &&
      m2_rangesn_delegation_zero_trace.indices[3] == 63 &&
      m2_rangesn_delegation_zero_trace.counts[3] == 1 &&
      delegation_zero_field_0_after == 0 &&
      delegation_zero_chunkmap_field_0_after == 1 &&
      delegation_one_seeded && delegation_one_returned_completed &&
      m2_rangesn_delegation_one_trace.count == 4 &&
      m2_rangesn_delegation_one_trace.indices[0] == 0 &&
      m2_rangesn_delegation_one_trace.counts[0] == 8 &&
      m2_rangesn_delegation_one_trace.indices[1] == 9 &&
      m2_rangesn_delegation_one_trace.counts[1] == 3 &&
      m2_rangesn_delegation_one_trace.indices[2] == 60 &&
      m2_rangesn_delegation_one_trace.counts[2] == 2 &&
      m2_rangesn_delegation_one_trace.indices[3] == 63 &&
      m2_rangesn_delegation_one_trace.counts[3] == 1 &&
      delegation_one_field_0_after == 0 &&
      delegation_one_chunkmap_field_0_after == 1 &&
      cap_over_seeded && cap_over_returned_completed &&
      m2_rangesn_cap_over_trace.count == 1 &&
      m2_rangesn_cap_over_trace.indices[0] == 0 &&
      m2_rangesn_cap_over_trace.counts[0] == MI_BFIELD_BITS &&
      cap_over_field_0_after == 0 && cap_over_chunkmap_field_0_after == 1;
  if (!all_relations) return 10;

  puts("CRABC_MI_M2_BITMAP_RANGESN_TRACE_BEGIN");
  U("m2.bitmap_rangesn.control.bfield_bits", MI_BFIELD_BITS);
  U("m2.bitmap_rangesn.control.bchunk_bits", MI_BCHUNK_BITS);
  U("m2.bitmap_rangesn.control.aligned_rngslices", 3);
  U("m2.bitmap_rangesn.control.capped_request", MI_BFIELD_BITS + 1);
  U("m2.bitmap_rangesn.layout.byte_size", complete_size);
  U("m2.bitmap_rangesn.r3_complete.returned_completed", complete_returned_completed);
  U("m2.bitmap_rangesn.r3_complete.callback_count", m2_rangesn_complete_trace.count);
  U("m2.bitmap_rangesn.r3_complete.range_0_index", m2_rangesn_complete_trace.indices[0]);
  U("m2.bitmap_rangesn.r3_complete.range_0_count", m2_rangesn_complete_trace.counts[0]);
  U("m2.bitmap_rangesn.r3_complete.range_1_index", m2_rangesn_complete_trace.indices[1]);
  U("m2.bitmap_rangesn.r3_complete.range_1_count", m2_rangesn_complete_trace.counts[1]);
  U("m2.bitmap_rangesn.r3_complete.range_2_index", m2_rangesn_complete_trace.indices[2]);
  U("m2.bitmap_rangesn.r3_complete.range_2_count", m2_rangesn_complete_trace.counts[2]);
  U("m2.bitmap_rangesn.r3_complete.field_0_after", complete_field_0_after);
  U("m2.bitmap_rangesn.r3_complete.chunkmap_field_0_after", complete_chunkmap_field_0_after);
  U("m2.bitmap_rangesn.r3_reject.returned_completed", reject_returned_completed);
  U("m2.bitmap_rangesn.r3_reject.callback_count", m2_rangesn_reject_trace.count);
  U("m2.bitmap_rangesn.r3_reject.range_0_index", m2_rangesn_reject_trace.indices[0]);
  U("m2.bitmap_rangesn.r3_reject.range_0_count", m2_rangesn_reject_trace.counts[0]);
  U("m2.bitmap_rangesn.r3_reject.field_0_after", reject_field_0_after);
  U("m2.bitmap_rangesn.r3_reject.field_1_after", reject_field_1_after);
  U("m2.bitmap_rangesn.r3_reject.chunkmap_field_0_after", reject_chunkmap_field_0_after);
  U("m2.bitmap_rangesn.delegation_zero.returned_completed", delegation_zero_returned_completed);
  U("m2.bitmap_rangesn.delegation_zero.callback_count", m2_rangesn_delegation_zero_trace.count);
  U("m2.bitmap_rangesn.delegation_zero.range_0_index", m2_rangesn_delegation_zero_trace.indices[0]);
  U("m2.bitmap_rangesn.delegation_zero.range_0_count", m2_rangesn_delegation_zero_trace.counts[0]);
  U("m2.bitmap_rangesn.delegation_zero.range_1_index", m2_rangesn_delegation_zero_trace.indices[1]);
  U("m2.bitmap_rangesn.delegation_zero.range_1_count", m2_rangesn_delegation_zero_trace.counts[1]);
  U("m2.bitmap_rangesn.delegation_zero.range_2_index", m2_rangesn_delegation_zero_trace.indices[2]);
  U("m2.bitmap_rangesn.delegation_zero.range_2_count", m2_rangesn_delegation_zero_trace.counts[2]);
  U("m2.bitmap_rangesn.delegation_zero.range_3_index", m2_rangesn_delegation_zero_trace.indices[3]);
  U("m2.bitmap_rangesn.delegation_zero.range_3_count", m2_rangesn_delegation_zero_trace.counts[3]);
  U("m2.bitmap_rangesn.delegation_zero.field_0_after", delegation_zero_field_0_after);
  U("m2.bitmap_rangesn.delegation_zero.chunkmap_field_0_after", delegation_zero_chunkmap_field_0_after);
  U("m2.bitmap_rangesn.delegation_one.returned_completed", delegation_one_returned_completed);
  U("m2.bitmap_rangesn.delegation_one.callback_count", m2_rangesn_delegation_one_trace.count);
  U("m2.bitmap_rangesn.delegation_one.range_0_index", m2_rangesn_delegation_one_trace.indices[0]);
  U("m2.bitmap_rangesn.delegation_one.range_0_count", m2_rangesn_delegation_one_trace.counts[0]);
  U("m2.bitmap_rangesn.delegation_one.range_1_index", m2_rangesn_delegation_one_trace.indices[1]);
  U("m2.bitmap_rangesn.delegation_one.range_1_count", m2_rangesn_delegation_one_trace.counts[1]);
  U("m2.bitmap_rangesn.delegation_one.range_2_index", m2_rangesn_delegation_one_trace.indices[2]);
  U("m2.bitmap_rangesn.delegation_one.range_2_count", m2_rangesn_delegation_one_trace.counts[2]);
  U("m2.bitmap_rangesn.delegation_one.range_3_index", m2_rangesn_delegation_one_trace.indices[3]);
  U("m2.bitmap_rangesn.delegation_one.range_3_count", m2_rangesn_delegation_one_trace.counts[3]);
  U("m2.bitmap_rangesn.delegation_one.field_0_after", delegation_one_field_0_after);
  U("m2.bitmap_rangesn.delegation_one.chunkmap_field_0_after", delegation_one_chunkmap_field_0_after);
  U("m2.bitmap_rangesn.cap_over.returned_completed", cap_over_returned_completed);
  U("m2.bitmap_rangesn.cap_over.callback_count", m2_rangesn_cap_over_trace.count);
  U("m2.bitmap_rangesn.cap_over.range_0_index", m2_rangesn_cap_over_trace.indices[0]);
  U("m2.bitmap_rangesn.cap_over.range_0_count", m2_rangesn_cap_over_trace.counts[0]);
  U("m2.bitmap_rangesn.cap_over.field_0_after", cap_over_field_0_after);
  U("m2.bitmap_rangesn.cap_over.chunkmap_field_0_after", cap_over_chunkmap_field_0_after);
  puts("CRABC_MI_M2_BITMAP_RANGESN_TRACE_END");
  return 0;
}
"""


# This fixture includes the source-private read-only set-bit visitor itself.
# Its valid 65-chunk tail image crosses the first chunk-map field boundary;
# fresh complete and stopped images make the record address-free and prove no
# source data/map exchange or repair occurs in either selected walk.
M2_BITMAP_SET_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bitmap.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

typedef struct m2_bitmap_set_image_s {
  mi_bitmap_t bitmap;
  mi_bchunk_t extra[MI_BFIELD_BITS];
} m2_bitmap_set_image_t;

typedef struct m2_bitmap_set_trace_s {
  size_t count;
  size_t indices[3];
  size_t counts[3];
} m2_bitmap_set_trace_t;

static m2_bitmap_set_image_t m2_bitmap_set_complete;
static m2_bitmap_set_image_t m2_bitmap_set_reject;
static m2_bitmap_set_trace_t m2_bitmap_set_complete_trace;
static m2_bitmap_set_trace_t m2_bitmap_set_reject_trace;

static bool m2_bitmap_set_seed(mi_bitmap_t* bitmap) {
  return mi_bitmap_setN(bitmap, 1, 1, NULL) &&
      mi_bitmap_setN(bitmap, MI_BFIELD_BITS + 1, 1, NULL) &&
      mi_bitmap_setN(bitmap, MI_BFIELD_BITS * MI_BCHUNK_BITS + 2, 1, NULL);
}

static bool m2_bitmap_set_complete_visit(
    size_t slice_index, size_t slice_count, mi_arena_t* arena, void* arg)
{
  m2_bitmap_set_trace_t* const trace = (m2_bitmap_set_trace_t*)arg;
  if (arena != NULL || trace != &m2_bitmap_set_complete_trace ||
      slice_count != 1 || trace->count >= 3) return false;
  trace->indices[trace->count] = slice_index;
  trace->counts[trace->count] = slice_count;
  trace->count++;
  return true;
}

static bool m2_bitmap_set_reject_visit(
    size_t slice_index, size_t slice_count, mi_arena_t* arena, void* arg)
{
  m2_bitmap_set_trace_t* const trace = (m2_bitmap_set_trace_t*)arg;
  if (arena != NULL || trace != &m2_bitmap_set_reject_trace ||
      slice_count != 1 || trace->count >= 3) return false;
  trace->indices[trace->count] = slice_index;
  trace->counts[trace->count] = slice_count;
  trace->count++;
  return trace->count != 2;
}

int main(void) {
  const size_t bit_count = MI_BCHUNK_BITS * (MI_BFIELD_BITS + 1);
  const size_t complete_size = mi_bitmap_init(
      &m2_bitmap_set_complete.bitmap, bit_count, true);
  const size_t reject_size = mi_bitmap_init(
      &m2_bitmap_set_reject.bitmap, bit_count, true);

  const bool complete_seeded = m2_bitmap_set_seed(&m2_bitmap_set_complete.bitmap);
  const bool complete_returned_completed = _mi_bitmap_forall_set(
      &m2_bitmap_set_complete.bitmap, &m2_bitmap_set_complete_visit, NULL,
      &m2_bitmap_set_complete_trace);
  const mi_bfield_t complete_chunk_0_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_complete.bitmap.chunks[0].bfields[0]);
  const mi_bfield_t complete_chunk_0_field_1_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_complete.bitmap.chunks[0].bfields[1]);
  const mi_bfield_t complete_chunk_64_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_complete.bitmap.chunks[MI_BFIELD_BITS].bfields[0]);
  const mi_bfield_t complete_chunkmap_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_complete.bitmap.chunkmap.bfields[0]);
  const mi_bfield_t complete_chunkmap_field_1_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_complete.bitmap.chunkmap.bfields[1]);

  const bool reject_seeded = m2_bitmap_set_seed(&m2_bitmap_set_reject.bitmap);
  const bool reject_returned_completed = _mi_bitmap_forall_set(
      &m2_bitmap_set_reject.bitmap, &m2_bitmap_set_reject_visit, NULL,
      &m2_bitmap_set_reject_trace);
  const mi_bfield_t reject_chunk_0_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_reject.bitmap.chunks[0].bfields[0]);
  const mi_bfield_t reject_chunk_0_field_1_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_reject.bitmap.chunks[0].bfields[1]);
  const mi_bfield_t reject_chunk_64_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_reject.bitmap.chunks[MI_BFIELD_BITS].bfields[0]);
  const mi_bfield_t reject_chunkmap_field_0_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_reject.bitmap.chunkmap.bfields[0]);
  const mi_bfield_t reject_chunkmap_field_1_after = mi_atomic_load_relaxed(
      &m2_bitmap_set_reject.bitmap.chunkmap.bfields[1]);

  const bool all_relations =
      complete_size == sizeof(m2_bitmap_set_complete) &&
      reject_size == sizeof(m2_bitmap_set_reject) &&
      complete_seeded && complete_returned_completed &&
      m2_bitmap_set_complete_trace.count == 3 &&
      m2_bitmap_set_complete_trace.indices[0] == 1 &&
      m2_bitmap_set_complete_trace.counts[0] == 1 &&
      m2_bitmap_set_complete_trace.indices[1] == MI_BFIELD_BITS + 1 &&
      m2_bitmap_set_complete_trace.counts[1] == 1 &&
      m2_bitmap_set_complete_trace.indices[2] == MI_BFIELD_BITS * MI_BCHUNK_BITS + 2 &&
      m2_bitmap_set_complete_trace.counts[2] == 1 &&
      complete_chunk_0_field_0_after == 2 &&
      complete_chunk_0_field_1_after == 2 &&
      complete_chunk_64_field_0_after == 4 &&
      complete_chunkmap_field_0_after == 1 &&
      complete_chunkmap_field_1_after == 1 &&
      reject_seeded && !reject_returned_completed &&
      m2_bitmap_set_reject_trace.count == 2 &&
      m2_bitmap_set_reject_trace.indices[0] == 1 &&
      m2_bitmap_set_reject_trace.counts[0] == 1 &&
      m2_bitmap_set_reject_trace.indices[1] == MI_BFIELD_BITS + 1 &&
      m2_bitmap_set_reject_trace.counts[1] == 1 &&
      reject_chunk_0_field_0_after == 2 &&
      reject_chunk_0_field_1_after == 2 &&
      reject_chunk_64_field_0_after == 4 &&
      reject_chunkmap_field_0_after == 1 &&
      reject_chunkmap_field_1_after == 1;
  if (!all_relations) return 10;

  puts("CRABC_MI_M2_BITMAP_SET_TRACE_BEGIN");
  U("m2.bitmap_set.control.bfield_bits", MI_BFIELD_BITS);
  U("m2.bitmap_set.control.bchunk_bits", MI_BCHUNK_BITS);
  U("m2.bitmap_set.control.chunk_count", MI_BFIELD_BITS + 1);
  U("m2.bitmap_set.layout.byte_size", complete_size);
  U("m2.bitmap_set.complete.seeded", complete_seeded);
  U("m2.bitmap_set.complete.returned_completed", complete_returned_completed);
  U("m2.bitmap_set.complete.callback_count", m2_bitmap_set_complete_trace.count);
  U("m2.bitmap_set.complete.visit_0_index", m2_bitmap_set_complete_trace.indices[0]);
  U("m2.bitmap_set.complete.visit_0_count", m2_bitmap_set_complete_trace.counts[0]);
  U("m2.bitmap_set.complete.visit_1_index", m2_bitmap_set_complete_trace.indices[1]);
  U("m2.bitmap_set.complete.visit_1_count", m2_bitmap_set_complete_trace.counts[1]);
  U("m2.bitmap_set.complete.visit_2_index", m2_bitmap_set_complete_trace.indices[2]);
  U("m2.bitmap_set.complete.visit_2_count", m2_bitmap_set_complete_trace.counts[2]);
  U("m2.bitmap_set.complete.chunk_0_field_0_after", complete_chunk_0_field_0_after);
  U("m2.bitmap_set.complete.chunk_0_field_1_after", complete_chunk_0_field_1_after);
  U("m2.bitmap_set.complete.chunk_64_field_0_after", complete_chunk_64_field_0_after);
  U("m2.bitmap_set.complete.chunkmap_field_0_after", complete_chunkmap_field_0_after);
  U("m2.bitmap_set.complete.chunkmap_field_1_after", complete_chunkmap_field_1_after);
  U("m2.bitmap_set.reject.seeded", reject_seeded);
  U("m2.bitmap_set.reject.returned_completed", reject_returned_completed);
  U("m2.bitmap_set.reject.callback_count", m2_bitmap_set_reject_trace.count);
  U("m2.bitmap_set.reject.visit_0_index", m2_bitmap_set_reject_trace.indices[0]);
  U("m2.bitmap_set.reject.visit_0_count", m2_bitmap_set_reject_trace.counts[0]);
  U("m2.bitmap_set.reject.visit_1_index", m2_bitmap_set_reject_trace.indices[1]);
  U("m2.bitmap_set.reject.visit_1_count", m2_bitmap_set_reject_trace.counts[1]);
  U("m2.bitmap_set.reject.chunk_0_field_0_after", reject_chunk_0_field_0_after);
  U("m2.bitmap_set.reject.chunk_0_field_1_after", reject_chunk_0_field_1_after);
  U("m2.bitmap_set.reject.chunk_64_field_0_after", reject_chunk_64_field_0_after);
  U("m2.bitmap_set.reject.chunkmap_field_0_after", reject_chunkmap_field_0_after);
  U("m2.bitmap_set.reject.chunkmap_field_1_after", reject_chunkmap_field_1_after);
  puts("CRABC_MI_M2_BITMAP_SET_TRACE_END");
  return 0;
}
"""


# This producer directly includes the pinned binned inverse-BSR observer. It
# uses only two valid, caller-owned two-chunk images: one exposes rounded top
# padding and the other exposes descending chunk/field selection. Its empty
# conservative chunk map is deliberate: `mi_bbitmap_bsr_inv` does not consult
# or repair that map.
M2_BINNED_BITMAP_BSR_INV_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bitmap.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

typedef struct m2_binned_bitmap_bsr_inv_image_s {
  mi_bbitmap_t bitmap;
  mi_bchunk_t tail[1];
} m2_binned_bitmap_bsr_inv_image_t;

static m2_binned_bitmap_bsr_inv_image_t m2_binned_bitmap_bsr_inv_padding;
static m2_binned_bitmap_bsr_inv_image_t m2_binned_bitmap_bsr_inv_scan;

int main(void) {
  const size_t padding_logical_bit_count = MI_BCHUNK_BITS + 1;
  const size_t scan_bit_count = MI_BCHUNK_BITS * 2;
  const size_t lower_index = MI_BCHUNK_BITS - 1;
  const size_t upper_lower_field_index = MI_BCHUNK_BITS + MI_BFIELD_BITS + 9;
  const size_t upper_higher_field_index = MI_BCHUNK_BITS + MI_BCHUNK_BITS - MI_BFIELD_BITS + 3;

  const size_t padding_size = mi_bbitmap_init(
      NULL, &m2_binned_bitmap_bsr_inv_padding.bitmap, padding_logical_bit_count, false);
  const bool padding_chunkmap_empty = mi_bchunk_all_are_clear_relaxed(
      &m2_binned_bitmap_bsr_inv_padding.bitmap.chunkmap);
  size_t padding_index = 0;
  const bool padding_returned_found = mi_bbitmap_bsr_inv(
      &m2_binned_bitmap_bsr_inv_padding.bitmap, &padding_index);

  const size_t scan_size = mi_bbitmap_init(
      NULL, &m2_binned_bitmap_bsr_inv_scan.bitmap, scan_bit_count, false);
  const bool scan_seeded =
      mi_bchunk_setN(&m2_binned_bitmap_bsr_inv_scan.bitmap.chunks[0], 0, MI_BCHUNK_BITS, NULL) &&
      mi_bchunk_setN(&m2_binned_bitmap_bsr_inv_scan.bitmap.chunks[1], 0, MI_BCHUNK_BITS, NULL);
  const bool scan_chunkmap_empty_before = mi_bchunk_all_are_clear_relaxed(
      &m2_binned_bitmap_bsr_inv_scan.bitmap.chunkmap);
  const bool scan_cleared =
      mi_bchunk_clear(&m2_binned_bitmap_bsr_inv_scan.bitmap.chunks[0], lower_index, NULL) &&
      mi_bchunk_clear(&m2_binned_bitmap_bsr_inv_scan.bitmap.chunks[1],
          upper_lower_field_index - MI_BCHUNK_BITS, NULL) &&
      mi_bchunk_clear(&m2_binned_bitmap_bsr_inv_scan.bitmap.chunks[1],
          upper_higher_field_index - MI_BCHUNK_BITS, NULL);

  size_t first_index = 0;
  const bool first_returned_found = mi_bbitmap_bsr_inv(
      &m2_binned_bitmap_bsr_inv_scan.bitmap, &first_index);
  const bool first_restored = first_returned_found && mi_bchunk_set(
      &m2_binned_bitmap_bsr_inv_scan.bitmap.chunks[first_index / MI_BCHUNK_BITS],
      first_index % MI_BCHUNK_BITS, NULL);

  size_t second_index = 0;
  const bool second_returned_found = mi_bbitmap_bsr_inv(
      &m2_binned_bitmap_bsr_inv_scan.bitmap, &second_index);
  const bool second_restored = second_returned_found && mi_bchunk_set(
      &m2_binned_bitmap_bsr_inv_scan.bitmap.chunks[second_index / MI_BCHUNK_BITS],
      second_index % MI_BCHUNK_BITS, NULL);

  size_t third_index = 0;
  const bool third_returned_found = mi_bbitmap_bsr_inv(
      &m2_binned_bitmap_bsr_inv_scan.bitmap, &third_index);
  const bool third_restored = third_returned_found && mi_bchunk_set(
      &m2_binned_bitmap_bsr_inv_scan.bitmap.chunks[third_index / MI_BCHUNK_BITS],
      third_index % MI_BCHUNK_BITS, NULL);

  size_t drained_index = 0;
  const bool drained_returned_found = mi_bbitmap_bsr_inv(
      &m2_binned_bitmap_bsr_inv_scan.bitmap, &drained_index);
  const bool scan_chunkmap_empty_after = mi_bchunk_all_are_clear_relaxed(
      &m2_binned_bitmap_bsr_inv_scan.bitmap.chunkmap);

  const bool all_relations =
      padding_size == sizeof(m2_binned_bitmap_bsr_inv_padding) &&
      scan_size == sizeof(m2_binned_bitmap_bsr_inv_scan) &&
      padding_chunkmap_empty && padding_returned_found &&
      padding_index == MI_BCHUNK_BITS * 2 - 1 &&
      scan_seeded && scan_chunkmap_empty_before && scan_cleared &&
      first_returned_found && first_index == upper_higher_field_index && first_restored &&
      second_returned_found && second_index == upper_lower_field_index && second_restored &&
      third_returned_found && third_index == lower_index && third_restored &&
      !drained_returned_found && scan_chunkmap_empty_after;
  if (!all_relations) return 10;

  puts("CRABC_MI_M2_BINNED_BITMAP_BSR_INV_TRACE_BEGIN");
  U("m2.bbitmap_bsr_inv.control.bfield_bits", MI_BFIELD_BITS);
  U("m2.bbitmap_bsr_inv.control.bchunk_bits", MI_BCHUNK_BITS);
  U("m2.bbitmap_bsr_inv.padding.logical_bit_count", padding_logical_bit_count);
  U("m2.bbitmap_bsr_inv.padding.chunk_count",
      mi_bbitmap_chunk_count(&m2_binned_bitmap_bsr_inv_padding.bitmap));
  U("m2.bbitmap_bsr_inv.padding.max_bits",
      mi_bbitmap_max_bits(&m2_binned_bitmap_bsr_inv_padding.bitmap));
  U("m2.bbitmap_bsr_inv.padding.byte_size", padding_size);
  U("m2.bbitmap_bsr_inv.padding.chunkmap_empty", padding_chunkmap_empty);
  U("m2.bbitmap_bsr_inv.padding.returned_found", padding_returned_found);
  U("m2.bbitmap_bsr_inv.padding.index", padding_index);
  U("m2.bbitmap_bsr_inv.scan.chunk_count",
      mi_bbitmap_chunk_count(&m2_binned_bitmap_bsr_inv_scan.bitmap));
  U("m2.bbitmap_bsr_inv.scan.byte_size", scan_size);
  U("m2.bbitmap_bsr_inv.scan.chunkmap_empty_before", scan_chunkmap_empty_before);
  U("m2.bbitmap_bsr_inv.scan.first_returned_found", first_returned_found);
  U("m2.bbitmap_bsr_inv.scan.first_index", first_index);
  U("m2.bbitmap_bsr_inv.scan.second_returned_found", second_returned_found);
  U("m2.bbitmap_bsr_inv.scan.second_index", second_index);
  U("m2.bbitmap_bsr_inv.scan.third_returned_found", third_returned_found);
  U("m2.bbitmap_bsr_inv.scan.third_index", third_index);
  U("m2.bbitmap_bsr_inv.scan.drained_returned_found", drained_returned_found);
  U("m2.bbitmap_bsr_inv.scan.chunkmap_empty_after", scan_chunkmap_empty_after);
  puts("CRABC_MI_M2_BINNED_BITMAP_BSR_INV_TRACE_END");
  return 0;
}
"""


# The image reader directly includes `src/threadlocal.c` solely to observe
# its private static root and direct-TLS declarations. It is compiled with
# the same isolated constructor-suppression define as the M1 bootstrap reader;
# it never calls a process/thread initializer or exercises a normal artifact.
M1_COMPILER_TLS_IMAGE_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>
#include <mimalloc/prim-tls.h>

// The selected direct-thread-pointer branch does not need this declaration in
// `prim-tls.h`, but `prim-tls.c:32` still defines the source helper root.
extern mi_decl_hidden mi_decl_thread void* __mi_thread_id_helper;

// Resolved through `-I <pinned-source>/src`; this exposes only the source
// private static root image for this dedicated reader translation unit.
#include "threadlocal.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

int main(void) {
  const mi_thread_locals_t* const dynamic = mi_thread_locals_peek();
  if (dynamic == NULL) return 10;
  const mi_memid_t memid = dynamic->memid;
  const mi_threadid_t identity = _mi_prim_thread_id();

  puts("CRABC_MI_M1_TLS_IMAGE_TRACE_BEGIN");
  U("m1.tls.image.dynamic.is_empty", dynamic == &mi_thread_locals_empty);
  U("m1.tls.image.dynamic.count", dynamic->count);
  U("m1.tls.image.dynamic.memid.base_is_null", memid.mem.os.base == NULL);
  U("m1.tls.image.dynamic.memid.size", memid.mem.os.size);
  U("m1.tls.image.dynamic.memid.kind", memid.memkind);
  U("m1.tls.image.dynamic.memid.pinned", memid.is_pinned);
  U("m1.tls.image.dynamic.memid.initially_committed", memid.initially_committed);
  U("m1.tls.image.dynamic.memid.initially_zero", memid.initially_zero);
  U("m1.tls.image.dynamic.slot0.version", dynamic->slots[0].version);
  U("m1.tls.image.dynamic.slot0.value_is_null", dynamic->slots[0].value == NULL);
  U("m1.tls.image.fast_is_null", mi_slot_fast_peek() == NULL);
  U("m1.tls.image.default_is_empty", _mi_theap_default() == (mi_theap_t*)&_mi_theap_empty);
  U("m1.tls.image.cached_is_empty", _mi_theap_cached() == (mi_theap_t*)&_mi_theap_empty);
  U("m1.tls.image.helper_is_null", __mi_thread_id_helper == NULL);
  U("m1.tls.image.identity.nonzero", identity != 0);
  U("m1.tls.image.identity.not_helper", identity != (mi_threadid_t)(uintptr_t)&__mi_thread_id_helper);
  U("m1.tls.image.empty_theap.refcount", mi_atomic_load_relaxed(&_mi_theap_empty.refcount));
  puts("CRABC_MI_M1_TLS_IMAGE_TRACE_END");
  return 0;
}
"""


# This normal-artifact reader drives only two finite source primitives. The
# first is the positive-count regular backing teardown in `threadlocal.c`; the
# second is the source-local cached-root store/refcount pair. It deliberately
# does not call `_mi_thread_done`, `mi_thread_theaps_done`, or any pthread/
# process hook, so it cannot be mistaken for the composite M5 lifecycle.
M1_COMPILER_TLS_TRANSITION_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>
#include <mimalloc/prim-tls.h>

// Resolved through `-I <pinned-source>/src`; this lets the probe inspect the
// raw dynamic-root and fast-slot state immediately around the exact source
// teardown routine without altering the pinned archive.
#include "threadlocal.c"

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

int main(void) {
  uintptr_t payload = 0x5a;
  const mi_thread_local_t regular_key = ((mi_thread_local_t)1 << 16);
  if (!_mi_thread_local_set(regular_key, &payload)) return 10;
  const mi_thread_locals_t* const regular_before = mi_thread_locals_peek();
  if (regular_before == NULL || regular_before->count != 16) return 11;
  const size_t regular_count = regular_before->count;
  const size_t regular_slot0_version = regular_before->slots[0].version;
  const bool regular_slot0_value_nonnull = regular_before->slots[0].value != NULL;
  if (!mi_slot_fast_set(&payload)) return 12;
  const bool regular_fast_nonnull = mi_slot_fast_peek() != NULL;
  mi_theap_t* const default_before = _mi_theap_default();
  mi_theap_t* const cached_before = _mi_theap_cached();
  _mi_thread_locals_thread_done();
  const bool default_unchanged = _mi_theap_default() == default_before;
  const bool cached_unchanged = _mi_theap_cached() == cached_before;

  // Normalize only the probe's cache predecessor. The previous normal root
  // is source-owned and is not part of the primitive refcount witness.
  _mi_theap_cached_set((mi_theap_t*)&_mi_theap_empty);
  mi_theap_t dynamic = mi_init_struct_zero;
  dynamic.memid = _mi_memid_create(MI_MEM_MALLOC);
  mi_atomic_store_relaxed(&dynamic.refcount, 1);
  const size_t empty_before = mi_atomic_load_relaxed(&_mi_theap_empty.refcount);
  if (mi_atomic_load_relaxed(&dynamic.refcount) != 1) return 13;
  _mi_theap_cached_set(&dynamic);
  const bool cached_is_dynamic = _mi_theap_cached() == &dynamic;
  const size_t dynamic_enter = mi_atomic_load_relaxed(&dynamic.refcount);
  const size_t empty_enter = mi_atomic_load_relaxed(&_mi_theap_empty.refcount);
  _mi_theap_cached_set((mi_theap_t*)&_mi_theap_empty);

  puts("CRABC_MI_M1_TLS_TRANSITION_TRACE_BEGIN");
  U("m1.tls.regular.before.count", regular_count);
  U("m1.tls.regular.before.slot0.version", regular_slot0_version);
  U("m1.tls.regular.before.slot0.value_nonnull", regular_slot0_value_nonnull);
  U("m1.tls.regular.before.fast_nonnull", regular_fast_nonnull);
  U("m1.tls.regular.after.dynamic_is_null", mi_thread_locals_peek() == NULL);
  U("m1.tls.regular.after.fast_is_null", mi_slot_fast_peek() == NULL);
  U("m1.tls.regular.after.default_unchanged", default_unchanged);
  U("m1.tls.regular.after.cached_unchanged", cached_unchanged);
  U("m1.tls.cache.initial.empty_refcount", empty_before);
  U("m1.tls.cache.enter.cached_is_dynamic", cached_is_dynamic);
  U("m1.tls.cache.enter.dynamic_refcount", dynamic_enter);
  U("m1.tls.cache.enter.empty_refcount", empty_enter);
  U("m1.tls.cache.reset.cached_is_empty", _mi_theap_cached() == (mi_theap_t*)&_mi_theap_empty);
  U("m1.tls.cache.reset.dynamic_refcount", mi_atomic_load_relaxed(&dynamic.refcount));
  U("m1.tls.cache.reset.empty_refcount", mi_atomic_load_relaxed(&_mi_theap_empty.refcount));
  puts("CRABC_MI_M1_TLS_TRANSITION_TRACE_END");
  return 0;
}
"""


# This source-internal C fixture reaches the file-static terminal
# body in the pinned `src/init.c` itself. The preprocessor wrappers are not
# substitute implementations: each records one address-free observation and
# immediately calls the original C function. Recording is disabled throughout
# setup, so only calls made by the selected static body contribute events.
#
# The setup deliberately makes the ordinary default and cached Theaps distinct
# members of one TLD list. It uses the pinned source-private Heap/Theap setup
# primitives so A is allocated through the detached metadata Theap rather than
# D; the probe asserts both selected theaps are page-free before the source
# terminal routine and records their post-collection state. The fixture then
# calls the exact file-static body directly from the included pinned source.
# The standalone C producer is only one half of the evidence; `--m1` consumes
# it with the dedicated Rust record. Neither route makes a general claim about
# outer `mi_thread_done`, pthread, or process teardown.
M1_COMPILER_TLS_SAME_TLD_TRACE_PROBE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>
#include <mimalloc/prim-tls.h>

static bool fixture_recording = false;
static size_t fixture_order = 0;
static size_t fixture_collect_count = 0;
static size_t fixture_collect_default_post_page_count = 0;
static size_t fixture_collect_cached_post_page_count = 0;
static size_t fixture_collect_default_ordinal = 0;
static size_t fixture_collect_cached_ordinal = 0;
static size_t fixture_default_order = 0;
static size_t fixture_default_is_empty = 0;
static size_t fixture_default_cached_is_aux = 0;
static size_t fixture_default_member_count = 0;
static size_t fixture_default_aux_refcount = 0;
static size_t fixture_cached_order = 0;
static size_t fixture_cached_default_is_empty = 0;
static size_t fixture_cached_is_empty = 0;
static size_t fixture_cached_member_count = 0;
static size_t fixture_cached_aux_refcount = 0;
static size_t fixture_detach_order = 0;
static size_t fixture_detach_default_and_cached_empty = 0;
static size_t fixture_detach_default_heap_is_null = 0;
static size_t fixture_detach_cached_heap_is_null = 0;
static size_t fixture_detach_main_default_detached = 0;
static size_t fixture_detach_aux_heap_list_empty = 0;
static size_t fixture_detach_member_count = 0;
static size_t fixture_final_dynamic_ordinal = 0;
static size_t fixture_final_static_ordinal = 0;
static size_t fixture_decref_dynamic_pre_refcount = 0;
static size_t fixture_final_dynamic_tld_is_null = 0;
static size_t fixture_final_dynamic_links_null = 0;
static size_t fixture_final_dynamic_subproc_nonnull = 0;
static size_t fixture_final_static_tld_is_null = 0;
static size_t fixture_final_static_links_null = 0;

static mi_theap_t* fixture_default_before = NULL;
static mi_theap_t* fixture_cached_before = NULL;
static mi_tld_t* fixture_tld_before = NULL;
static mi_heap_t* fixture_main_heap_before = NULL;
static mi_heap_t fixture_aux_heap = mi_init_struct_zero;

static size_t fixture_tld_theap_count(const mi_tld_t* tld) {
  size_t count = 0;
  for (const mi_theap_t* theap = tld->theaps; theap != NULL; theap = theap->tnext) {
    count++;
  }
  return count;
}

static bool fixture_heap_has_exact_theap(const mi_heap_t* heap, const mi_theap_t* target) {
  return heap->theaps == target && target->hprev == NULL && target->hnext == NULL &&
         mi_atomic_load_ptr_relaxed(mi_heap_t, &target->heap) == heap;
}

// This trace admits only the two source-observed main-Heap shapes: the
// metadata Theap plus D before `_mi_tld_detach_theaps`, then metadata alone
// after D detaches.  Bound the traversal so a malformed link cannot turn the
// fixture into a general Heap-list walk.
static bool fixture_heap_has_bounded_theap_member(
    const mi_heap_t* heap, const mi_theap_t* target, size_t member_count, bool contains) {
  if (heap == NULL || target == NULL || member_count > 2) return false;
  const mi_theap_t* previous = NULL;
  const mi_theap_t* current = heap->theaps;
  bool found = false;
  for (size_t index = 0; index < member_count; index++) {
    if (current == NULL || current->hprev != previous ||
        mi_atomic_load_ptr_relaxed(mi_heap_t, &current->heap) != heap) {
      return false;
    }
    found = found || (current == target);
    previous = current;
    current = current->hnext;
  }
  return current == NULL && found == contains;
}

static bool fixture_theap_links_are_null(const mi_theap_t* theap) {
  return theap->tnext == NULL && theap->tprev == NULL &&
         theap->hnext == NULL && theap->hprev == NULL;
}

static void fixture_collect_abandon(mi_theap_t* theap) {
  if (fixture_recording) {
    fixture_order++;
    fixture_collect_count++;
    if (theap == fixture_default_before) {
      fixture_collect_default_ordinal = fixture_order;
    }
    if (theap == fixture_cached_before) {
      fixture_collect_cached_ordinal = fixture_order;
    }
  }
  _mi_theap_collect_abandon(theap);
  if (fixture_recording && theap == fixture_default_before) {
    fixture_collect_default_post_page_count = theap->page_count;
  }
  if (fixture_recording && theap == fixture_cached_before) {
    fixture_collect_cached_post_page_count = theap->page_count;
  }
}

static void fixture_default_set(mi_theap_t* theap) {
  if (fixture_recording) {
    fixture_default_order = ++fixture_order;
  }
  _mi_theap_default_set(theap);
  if (fixture_recording) {
    fixture_default_is_empty = (_mi_theap_default() == (mi_theap_t*)&_mi_theap_empty);
    fixture_default_cached_is_aux = (_mi_theap_cached() == fixture_cached_before);
    fixture_default_member_count = fixture_tld_theap_count(fixture_tld_before);
    fixture_default_aux_refcount = mi_atomic_load_relaxed(&fixture_cached_before->refcount);
  }
}

static void fixture_cached_set(mi_theap_t* theap) {
  if (fixture_recording) {
    fixture_cached_order = ++fixture_order;
  }
  _mi_theap_cached_set(theap);
  if (fixture_recording) {
    fixture_cached_default_is_empty = (_mi_theap_default() == (mi_theap_t*)&_mi_theap_empty);
    fixture_cached_is_empty = (_mi_theap_cached() == (mi_theap_t*)&_mi_theap_empty);
    fixture_cached_member_count = fixture_tld_theap_count(fixture_tld_before);
    fixture_cached_aux_refcount = mi_atomic_load_relaxed(&fixture_cached_before->refcount);
  }
}

static void fixture_tld_detach_theaps(mi_tld_t* tld) {
  if (fixture_recording) {
    fixture_detach_order = ++fixture_order;
  }
  _mi_tld_detach_theaps(tld);
  if (fixture_recording) {
    fixture_detach_default_and_cached_empty =
        (_mi_theap_default() == (mi_theap_t*)&_mi_theap_empty &&
         _mi_theap_cached() == (mi_theap_t*)&_mi_theap_empty);
    fixture_detach_default_heap_is_null =
        (mi_atomic_load_ptr_relaxed(mi_heap_t, &fixture_default_before->heap) == NULL);
    fixture_detach_cached_heap_is_null =
        (mi_atomic_load_ptr_relaxed(mi_heap_t, &fixture_cached_before->heap) == NULL);
    // The source main Heap retains its metadata Theap after D leaves. This
    // proves D's list absence instead of conflating it with D.heap == NULL.
    fixture_detach_main_default_detached = fixture_heap_has_bounded_theap_member(
        fixture_main_heap_before, fixture_default_before, 1, false);
    fixture_detach_aux_heap_list_empty = (fixture_aux_heap.theaps == NULL);
    fixture_detach_member_count = fixture_tld_theap_count(tld);
  }
}

static void fixture_theap_decref(mi_theap_t* theap) {
  if (fixture_recording) {
    fixture_order++;
    if (theap == fixture_cached_before) {
      fixture_final_dynamic_ordinal = fixture_order;
      fixture_decref_dynamic_pre_refcount = mi_atomic_load_relaxed(&theap->refcount);
      fixture_final_dynamic_tld_is_null = (theap->tld == NULL);
      fixture_final_dynamic_links_null = fixture_theap_links_are_null(theap);
      fixture_final_dynamic_subproc_nonnull =
          (mi_atomic_load_ptr_relaxed(mi_subproc_t, &theap->subproc) != NULL);
    }
    if (theap == fixture_default_before) {
      fixture_final_static_ordinal = fixture_order;
      fixture_final_static_tld_is_null = (theap->tld == NULL);
      fixture_final_static_links_null = fixture_theap_links_are_null(theap);
    }
  }
  _mi_theap_decref(theap);
}

// Resolve through `-I <pinned-source>/src`. These aliases apply only while
// the actual pinned `init.c` is preprocessed. The wrapper definitions above
// were parsed before the aliases and therefore call the unmodified external
// source functions.
#define _mi_theap_collect_abandon fixture_collect_abandon
#define _mi_theap_default_set fixture_default_set
#define _mi_theap_cached_set fixture_cached_set
#define _mi_tld_detach_theaps fixture_tld_detach_theaps
#define _mi_theap_decref fixture_theap_decref
#include "init.c"
#undef _mi_theap_collect_abandon
#undef _mi_theap_default_set
#undef _mi_theap_cached_set
#undef _mi_tld_detach_theaps
#undef _mi_theap_decref

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

static void fixture_exit(int status) {
  (void)fflush(stdout);
  (void)fflush(stderr);
  _Exit(status);
}

int main(void) {
  mi_process_init();
  fixture_default_before = _mi_theap_default();
  if (fixture_default_before == NULL) fixture_exit(10);
  fixture_tld_before = fixture_default_before->tld;
  if (fixture_tld_before == NULL) fixture_exit(11);
  fixture_main_heap_before = _mi_subproc_heap_main(fixture_tld_before->subproc);
  if (fixture_main_heap_before == NULL) fixture_exit(12);
  const mi_thread_local_t aux_key = _mi_thread_local_create();
  if (aux_key == 0) fixture_exit(13);
  _mi_heap_init(&fixture_aux_heap, aux_key, fixture_tld_before->subproc, 0);
  fixture_cached_before = _mi_heap_theap_get_or_init(&fixture_aux_heap);
  if (fixture_cached_before == NULL) fixture_exit(14);
  if (fixture_default_before == fixture_cached_before) fixture_exit(15);
  if (fixture_cached_before->tld != fixture_tld_before) fixture_exit(16);
  const size_t pre_list_count = fixture_tld_theap_count(fixture_tld_before);
  const bool pre_same_tld = (fixture_cached_before->tld == fixture_tld_before);
  const size_t pre_cached_refcount = mi_atomic_load_relaxed(&fixture_cached_before->refcount);
  const bool pre_default_is_main = (_mi_theap_default() == fixture_default_before);
  const bool pre_cached_is_aux = (_mi_theap_cached() == fixture_cached_before);
  // The source main Heap contains its metadata Theap plus D. Require that
  // finite list shape and D membership rather than merely reading D.heap.
  const bool pre_main_heap_contains_default =
      fixture_heap_has_bounded_theap_member(
          fixture_main_heap_before, fixture_default_before, 2, true);
  const bool pre_aux_heap_contains_aux = fixture_heap_has_exact_theap(
      &fixture_aux_heap, fixture_cached_before);
  const bool pre_list_is_cached_then_default =
      (fixture_tld_before->theaps == fixture_cached_before &&
       fixture_cached_before->tprev == NULL &&
       fixture_cached_before->tnext == fixture_default_before &&
       fixture_default_before->tprev == fixture_cached_before &&
       fixture_default_before->tnext == NULL);
  const bool pre_default_is_static =
      (fixture_default_before->memid.memkind == MI_MEM_STATIC);
  const bool pre_cached_is_malloc =
      (fixture_cached_before->memid.memkind == MI_MEM_MALLOC);
  const bool pre_aux_heap_uses_aux_key = (fixture_aux_heap.theap == aux_key);
  const bool pre_aux_key_points_to_cached =
      ((mi_theap_t*)_mi_thread_local_get(aux_key) == fixture_cached_before);
  if (!pre_default_is_main || !pre_cached_is_aux || !pre_same_tld ||
      !pre_main_heap_contains_default || !pre_aux_heap_contains_aux ||
      !pre_list_is_cached_then_default || !pre_default_is_static ||
      !pre_cached_is_malloc || !pre_aux_heap_uses_aux_key ||
      !pre_aux_key_points_to_cached || pre_list_count != 2 || pre_cached_refcount != 2) {
    fixture_exit(17);
  }
  if (fixture_default_before->page_count != 0 || fixture_cached_before->page_count != 0) {
    fixture_exit(18);
  }

  fixture_recording = true;
  // This exact file-static body is compiled from the included pinned
  // `src/init.c` below. Deliberately exclude outer mi_thread_done work such
  // as regular TLS, fast-root, statistics, and TLD destruction.
  mi_thread_theaps_done(fixture_tld_before);
  fixture_recording = false;

  const bool default_empty = (_mi_theap_default() == (mi_theap_t*)&_mi_theap_empty);
  const bool cached_empty = (_mi_theap_cached() == (mi_theap_t*)&_mi_theap_empty);
  const bool list_empty = (fixture_tld_before->theaps == NULL);
  const bool default_detached =
      (mi_atomic_load_ptr_relaxed(mi_heap_t, &fixture_default_before->heap) == NULL &&
       fixture_default_before->tld == NULL);
  const bool order_is_source_shaped =
      (fixture_collect_count == 2 &&
       fixture_collect_cached_ordinal == 1 &&
       fixture_collect_default_ordinal == 2 &&
       fixture_collect_default_post_page_count == 0 &&
       fixture_collect_cached_post_page_count == 0 &&
       fixture_default_order == 3 && fixture_default_is_empty &&
       fixture_default_cached_is_aux && fixture_default_member_count == 2 &&
       fixture_default_aux_refcount == 2 &&
       fixture_cached_order == 4 && fixture_cached_default_is_empty &&
       fixture_cached_is_empty && fixture_cached_member_count == 2 &&
       fixture_cached_aux_refcount == 1 &&
       fixture_detach_order == 5 && fixture_detach_default_and_cached_empty &&
       fixture_detach_default_heap_is_null && fixture_detach_cached_heap_is_null &&
       fixture_detach_main_default_detached && fixture_detach_aux_heap_list_empty &&
       fixture_detach_member_count == 2 &&
       fixture_final_dynamic_ordinal == 6 && fixture_final_static_ordinal == 7 &&
       fixture_decref_dynamic_pre_refcount == 1 && fixture_final_dynamic_tld_is_null &&
       fixture_final_dynamic_links_null && fixture_final_dynamic_subproc_nonnull &&
       fixture_final_static_tld_is_null && fixture_final_static_links_null);

  puts("CRABC_MI_M1_TLS_SAME_TLD_TRACE_BEGIN");
  U("m1.tls.same_tld.entry.default_is_main", pre_default_is_main);
  U("m1.tls.same_tld.entry.cached_is_aux", pre_cached_is_aux);
  U("m1.tls.same_tld.entry.same_tld", pre_same_tld);
  U("m1.tls.same_tld.entry.member_count", pre_list_count);
  U("m1.tls.same_tld.entry.main_heap_contains_default", pre_main_heap_contains_default);
  U("m1.tls.same_tld.entry.aux_heap_contains_aux", pre_aux_heap_contains_aux);
  U("m1.tls.same_tld.entry.aux_refcount", pre_cached_refcount);
  U("m1.tls.same_tld.collect.call_count", fixture_collect_count);
  U("m1.tls.same_tld.collect.aux_first", fixture_collect_cached_ordinal == 1);
  U("m1.tls.same_tld.collect.main_second", fixture_collect_default_ordinal == 2);
  U("m1.tls.same_tld.collect.after.default_page_count", fixture_collect_default_post_page_count);
  U("m1.tls.same_tld.collect.after.aux_page_count", fixture_collect_cached_post_page_count);
  U("m1.tls.same_tld.default.ordinal", fixture_default_order);
  U("m1.tls.same_tld.default.default_is_empty", fixture_default_is_empty);
  U("m1.tls.same_tld.default.cached_is_aux", fixture_default_cached_is_aux);
  U("m1.tls.same_tld.default.member_count", fixture_default_member_count);
  U("m1.tls.same_tld.default.aux_refcount", fixture_default_aux_refcount);
  U("m1.tls.same_tld.cached.ordinal", fixture_cached_order);
  U("m1.tls.same_tld.cached.default_is_empty", fixture_cached_default_is_empty);
  U("m1.tls.same_tld.cached.cached_is_empty", fixture_cached_is_empty);
  U("m1.tls.same_tld.cached.member_count", fixture_cached_member_count);
  U("m1.tls.same_tld.cached.aux_refcount", fixture_cached_aux_refcount);
  U("m1.tls.same_tld.detach.ordinal", fixture_detach_order);
  U("m1.tls.same_tld.detach.default_and_cached_empty", fixture_detach_default_and_cached_empty);
  U("m1.tls.same_tld.detach.default_heap_is_null", fixture_detach_default_heap_is_null);
  U("m1.tls.same_tld.detach.aux_heap_is_null", fixture_detach_cached_heap_is_null);
  U("m1.tls.same_tld.detach.main_default_detached", fixture_detach_main_default_detached);
  U("m1.tls.same_tld.detach.aux_heap_list_empty", fixture_detach_aux_heap_list_empty);
  U("m1.tls.same_tld.detach.member_count", fixture_detach_member_count);
  U("m1.tls.same_tld.final.dynamic_ordinal", fixture_final_dynamic_ordinal);
  U("m1.tls.same_tld.final.static_ordinal", fixture_final_static_ordinal);
  U("m1.tls.same_tld.final.dynamic_refcount", fixture_decref_dynamic_pre_refcount);
  U("m1.tls.same_tld.final.dynamic_tld_is_null", fixture_final_dynamic_tld_is_null);
  U("m1.tls.same_tld.final.dynamic_links_null", fixture_final_dynamic_links_null);
  U("m1.tls.same_tld.final.dynamic_subproc_nonnull", fixture_final_dynamic_subproc_nonnull);
  U("m1.tls.same_tld.final.tld_list_empty", list_empty);
  U("m1.tls.same_tld.final.static_tld_is_null", fixture_final_static_tld_is_null);
  U("m1.tls.same_tld.final.static_links_null", fixture_final_static_links_null);
  U("m1.tls.same_tld.return.default_is_empty", default_empty);
  U("m1.tls.same_tld.return.cached_is_empty", cached_empty);
  puts("CRABC_MI_M1_TLS_SAME_TLD_TRACE_END");
  fixture_exit(
      default_empty && cached_empty && list_empty && default_detached && order_is_source_shaped ? 0 : 19);
}
"""


# This schema freezes the selected direct C/Rust fundamental trace. Comparing
# only the two observed maps would allow a synchronized deletion to silently
# shrink the recorded contract. The 51-field base is shared, while the 24-field
# `mi_expand`/`mi_recalloc` extension is explicitly native x86-64-only; evidence
# qualification remains in the architecture-specific ledgers.
FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS = frozenset(
    {
        *(
            f"trace.fundamental.class.{kind}.{field}"
            for kind in ("small", "medium", "large", "singleton")
            for field in ("request", "usable", "success")
        ),
        "trace.fundamental.calloc.count",
        "trace.fundamental.calloc.size",
        "trace.fundamental.calloc.usable",
        "trace.fundamental.calloc.cleared",
        "trace.fundamental.calloc.content_hash",
        "trace.fundamental.calloc_overflow.count",
        "trace.fundamental.calloc_overflow.size",
        "trace.fundamental.calloc_overflow.returns_null",
        "trace.fundamental.realloc_null.request",
        "trace.fundamental.realloc_null.usable",
        "trace.fundamental.realloc_null.content_hash",
        "trace.fundamental.realloc_grow.original_size",
        "trace.fundamental.realloc_grow.new_size",
        "trace.fundamental.realloc_grow.usable",
        "trace.fundamental.realloc_grow.preserved",
        "trace.fundamental.realloc_grow.content_hash",
        "trace.fundamental.realloc_shrink.new_size",
        "trace.fundamental.realloc_shrink.usable",
        "trace.fundamental.realloc_shrink.preserved",
        "trace.fundamental.realloc_shrink.content_hash",
        "trace.fundamental.realloc_failure.request",
        "trace.fundamental.realloc_failure.returns_null",
        "trace.fundamental.realloc_failure.preserved",
        "trace.fundamental.realloc_failure.content_hash",
        "trace.fundamental.realloc_size_zero.request",
        "trace.fundamental.realloc_size_zero.returns_nonnull",
        "trace.fundamental.realloc_size_zero.usable",
        "trace.fundamental.recalloc.count",
        "trace.fundamental.recalloc.size",
        "trace.fundamental.recalloc.total",
        "trace.fundamental.recalloc.old_usable",
        "trace.fundamental.recalloc.new_usable",
        "trace.fundamental.recalloc.preserved",
        "trace.fundamental.recalloc.tail_zeroed",
        "trace.fundamental.recalloc.valid",
        "trace.fundamental.recalloc_zero.count",
        "trace.fundamental.recalloc_zero.size",
        "trace.fundamental.recalloc_zero.total",
        "trace.fundamental.recalloc_zero.returns_nonnull",
        "trace.fundamental.recalloc_zero.first_byte_zero",
        "trace.fundamental.recalloc_overflow.count",
        "trace.fundamental.recalloc_overflow.size",
        "trace.fundamental.recalloc_overflow.returns_null",
        "trace.fundamental.recalloc_overflow.preserved",
        "trace.fundamental.expand.usable",
        "trace.fundamental.expand.null_nonzero_returns_null",
        "trace.fundamental.expand.zero_returns_input",
        "trace.fundamental.expand.below_half_returns_input",
        "trace.fundamental.expand.exact_returns_input",
        "trace.fundamental.expand.oversize_returns_null",
        "trace.fundamental.expand.failure_preserves",
        "trace.fundamental.aligned.size",
        "trace.fundamental.aligned.alignment",
        "trace.fundamental.aligned.usable",
        "trace.fundamental.aligned.valid",
        "trace.fundamental.offset_aligned.size",
        "trace.fundamental.offset_aligned.alignment",
        "trace.fundamental.offset_aligned.offset",
        "trace.fundamental.offset_aligned.usable",
        "trace.fundamental.offset_aligned.valid",
        "trace.fundamental.oom.request",
        "trace.fundamental.oom.classification_invalid_request",
        "trace.fundamental.oom.returns_null",
    }
)
FUNDAMENTAL_TRACE_X86_64_EXPECTED_COUNT = 75
FUNDAMENTAL_TRACE_X86_64_EXTENSION_KEYS = frozenset(
    key
    for key in FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS
    if key.startswith(("trace.fundamental.recalloc", "trace.fundamental.expand."))
)
FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS = frozenset(
    FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS - FUNDAMENTAL_TRACE_X86_64_EXTENSION_KEYS
)
FUNDAMENTAL_TRACE_AARCH64_EXPECTED_COUNT = 51

# Keep the historical names bound to the production/AArch64 contract. Native
# x86-64 evidence must opt into its explicitly extended 75-field record.
FUNDAMENTAL_TRACE_EXPECTED_KEYS = FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS
FUNDAMENTAL_TRACE_EXPECTED_COUNT = FUNDAMENTAL_TRACE_AARCH64_EXPECTED_COUNT


def fundamental_trace_schema(architecture: str) -> tuple[frozenset[str], int]:
    """Return the fixed trace schema for one explicitly selected architecture."""

    if architecture == "aarch64":
        return FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS, FUNDAMENTAL_TRACE_AARCH64_EXPECTED_COUNT
    if architecture == "x86_64":
        return FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS, FUNDAMENTAL_TRACE_X86_64_EXPECTED_COUNT
    raise HarnessError(f"unsupported fundamental trace architecture: {architecture}")


# This source-order-independent schema fixes the finite raw M1 witness.  A C
# and Rust probe cannot jointly remove a case without this separate inventory
# failing first.  The selected values are all source-relative facts; addresses,
# random bytes, and timestamps are intentionally not evidence fields.
M1_RAW_PRIMITIVE_TRACE_EXPECTED_KEYS = frozenset(
    {
        "m1.raw.config.page_size",
        "m1.raw.config.large_page_size",
        "m1.raw.config.alloc_granularity",
        "m1.raw.config.physical_memory_in_kib",
        "m1.raw.config.virtual_address_bits",
        "m1.raw.config.has_overcommit",
        "m1.raw.config.has_partial_free",
        "m1.raw.config.has_virtual_reserve",
        "m1.raw.config.has_transparent_huge_pages",
        "m1.raw.good_alloc_size.zero",
        "m1.raw.good_alloc_size.one",
        "m1.raw.good_alloc_size.512k_minus_one",
        "m1.raw.good_alloc_size.512k",
        "m1.raw.good_alloc_size.512k_plus_one",
        "m1.raw.good_alloc_size.2m_minus_one",
        "m1.raw.good_alloc_size.2m",
        "m1.raw.good_alloc_size.2m_plus_one",
        "m1.raw.good_alloc_size.8m_minus_one",
        "m1.raw.good_alloc_size.8m",
        "m1.raw.good_alloc_size.8m_plus_one",
        "m1.raw.good_alloc_size.32m_minus_one",
        "m1.raw.good_alloc_size.32m",
        "m1.raw.good_alloc_size.32m_plus_one",
        "m1.raw.good_alloc_size.size_max",
        "m1.raw.can_use_large_page.aligned",
        "m1.raw.can_use_large_page.page_aligned_only",
        "m1.raw.map.request.no_hint",
        "m1.raw.map.request.allow_large",
        "m1.raw.map.reserved.success",
        "m1.raw.map.reserved.is_large",
        "m1.raw.map.reserved.is_zero",
        "m1.raw.map.reserved.initially_committed",
        "m1.raw.map.commit.success",
        "m1.raw.map.commit.is_zero",
        "m1.raw.map.decommit.success",
        "m1.raw.map.decommit.needs_recommit",
        "m1.raw.map.reset.success",
        "m1.raw.map.protect.success",
        "m1.raw.map.unprotect.success",
        "m1.raw.map.free.success",
        "m1.raw.numa.count",
        "m1.raw.numa.current_lt_count",
        "m1.raw.clock.monotonic_after_yield",
        "m1.raw.yield.success",
        "m1.raw.entropy.zero_success",
        "m1.raw.entropy.sixteen_success",
        "m1.raw.threadpool.false",
    }
)
M1_RAW_PRIMITIVE_TRACE_EXPECTED_COUNT = 47
# This is a scalar width, not an address-bearing observation. Keep the one
# exception explicit at the raw M1 boundary so the shared parser still rejects
# address fields in every other trace.
M1_RAW_PRIMITIVE_ADDRESS_LIKE_SCALAR_KEYS = frozenset(
    {"m1.raw.config.virtual_address_bits"}
)


# These two C records deliberately remain distinct execution modes. The first
# reads only compiler/linker initialized source state, while the second lets
# the normal C artifact exercise the finite regular-backing and cached-root
# primitives. The union is fixed so matching C/Rust probes cannot erase a
# root, reset, or reference-count transition together.
M1_COMPILER_TLS_IMAGE_TRACE_EXPECTED_KEYS = frozenset(
    {
        "m1.tls.image.dynamic.is_empty",
        "m1.tls.image.dynamic.count",
        "m1.tls.image.dynamic.memid.base_is_null",
        "m1.tls.image.dynamic.memid.size",
        "m1.tls.image.dynamic.memid.kind",
        "m1.tls.image.dynamic.memid.pinned",
        "m1.tls.image.dynamic.memid.initially_committed",
        "m1.tls.image.dynamic.memid.initially_zero",
        "m1.tls.image.dynamic.slot0.version",
        "m1.tls.image.dynamic.slot0.value_is_null",
        "m1.tls.image.fast_is_null",
        "m1.tls.image.default_is_empty",
        "m1.tls.image.cached_is_empty",
        "m1.tls.image.helper_is_null",
        "m1.tls.image.identity.nonzero",
        "m1.tls.image.identity.not_helper",
        "m1.tls.image.empty_theap.refcount",
    }
)
M1_COMPILER_TLS_TRANSITION_TRACE_EXPECTED_KEYS = frozenset(
    {
        "m1.tls.regular.before.count",
        "m1.tls.regular.before.slot0.version",
        "m1.tls.regular.before.slot0.value_nonnull",
        "m1.tls.regular.before.fast_nonnull",
        "m1.tls.regular.after.dynamic_is_null",
        "m1.tls.regular.after.fast_is_null",
        "m1.tls.regular.after.default_unchanged",
        "m1.tls.regular.after.cached_unchanged",
        "m1.tls.cache.initial.empty_refcount",
        "m1.tls.cache.enter.cached_is_dynamic",
        "m1.tls.cache.enter.dynamic_refcount",
        "m1.tls.cache.enter.empty_refcount",
        "m1.tls.cache.reset.cached_is_empty",
        "m1.tls.cache.reset.dynamic_refcount",
        "m1.tls.cache.reset.empty_refcount",
    }
)
M1_COMPILER_TLS_TRACE_EXPECTED_KEYS = frozenset(
    M1_COMPILER_TLS_IMAGE_TRACE_EXPECTED_KEYS
    | M1_COMPILER_TLS_TRANSITION_TRACE_EXPECTED_KEYS
)
M1_COMPILER_TLS_TRACE_EXPECTED_COUNT = 32


# This fixed C/Rust trace describes only one source-internal, page-free
# `D -> A` setup: static main default D and Malloc-backed cached A share one
# TLD, then the direct included pinned `mi_thread_theaps_done(D.tld)` body
# executes. It does not claim outer `mi_thread_done`, public `mi_heap_new`,
# general allocator, pthread, or process-destruction lifecycle parity.
M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_VALUES = {
    "m1.tls.same_tld.entry.default_is_main": 1,
    "m1.tls.same_tld.entry.cached_is_aux": 1,
    "m1.tls.same_tld.entry.same_tld": 1,
    "m1.tls.same_tld.entry.member_count": 2,
    "m1.tls.same_tld.entry.main_heap_contains_default": 1,
    "m1.tls.same_tld.entry.aux_heap_contains_aux": 1,
    "m1.tls.same_tld.entry.aux_refcount": 2,
    "m1.tls.same_tld.collect.call_count": 2,
    "m1.tls.same_tld.collect.aux_first": 1,
    "m1.tls.same_tld.collect.main_second": 1,
    "m1.tls.same_tld.collect.after.default_page_count": 0,
    "m1.tls.same_tld.collect.after.aux_page_count": 0,
    "m1.tls.same_tld.default.ordinal": 3,
    "m1.tls.same_tld.default.default_is_empty": 1,
    "m1.tls.same_tld.default.cached_is_aux": 1,
    "m1.tls.same_tld.default.member_count": 2,
    "m1.tls.same_tld.default.aux_refcount": 2,
    "m1.tls.same_tld.cached.ordinal": 4,
    "m1.tls.same_tld.cached.default_is_empty": 1,
    "m1.tls.same_tld.cached.cached_is_empty": 1,
    "m1.tls.same_tld.cached.member_count": 2,
    "m1.tls.same_tld.cached.aux_refcount": 1,
    "m1.tls.same_tld.detach.ordinal": 5,
    "m1.tls.same_tld.detach.default_and_cached_empty": 1,
    "m1.tls.same_tld.detach.default_heap_is_null": 1,
    "m1.tls.same_tld.detach.aux_heap_is_null": 1,
    "m1.tls.same_tld.detach.main_default_detached": 1,
    "m1.tls.same_tld.detach.aux_heap_list_empty": 1,
    "m1.tls.same_tld.detach.member_count": 2,
    "m1.tls.same_tld.final.dynamic_ordinal": 6,
    "m1.tls.same_tld.final.static_ordinal": 7,
    "m1.tls.same_tld.final.dynamic_refcount": 1,
    "m1.tls.same_tld.final.dynamic_tld_is_null": 1,
    "m1.tls.same_tld.final.dynamic_links_null": 1,
    "m1.tls.same_tld.final.dynamic_subproc_nonnull": 1,
    "m1.tls.same_tld.final.tld_list_empty": 1,
    "m1.tls.same_tld.final.static_tld_is_null": 1,
    "m1.tls.same_tld.final.static_links_null": 1,
    "m1.tls.same_tld.return.default_is_empty": 1,
    "m1.tls.same_tld.return.cached_is_empty": 1,
}
M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_KEYS = frozenset(
    M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_VALUES
)
M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_COUNT = 40


class HarnessError(RuntimeError):
    """A reproducibility, source, or oracle-build contract failure."""


class MilestoneUnavailable(HarnessError):
    """A requested later milestone has no implementation yet."""


class CanonicalUpstreamStressRejected(HarnessError):
    """A canonical upstream-stress report cannot be consumed as M5 evidence."""


class RuntimeTicketZeroSoakRejected(HarnessError):
    """A durable private ticket-zero soak report cannot be consumed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Atomically replace one report without sharing a fixed staging filename."""

    path.parent.mkdir(parents=True, exist_ok=True)
    staged: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            staged = Path(stream.name)
        os.replace(staged, path)
    except BaseException:
        if staged is not None:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
        raise


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessError(f"invalid JSON contract: {path}") from error
    if not isinstance(value, dict):
        raise HarnessError(f"JSON contract is not an object: {path}")
    return value


def normalize_mimalloc_pin(raw: object) -> dict[str, str]:
    """Validate the fixed v3.5.0 pin after one trusted byte read."""

    if not isinstance(raw, Mapping):
        raise HarnessError("compat/upstreams.toml must be a TOML object")
    pin = raw.get("mimalloc")
    if not isinstance(pin, dict):
        raise HarnessError("compat/upstreams.toml requires a [mimalloc] table")
    required = ("version", "repository", "tag", "source", "sha256", "tag_object", "revision", "archive_root")
    normalized: dict[str, str] = {}
    for key in required:
        value = pin.get(key)
        if not isinstance(value, str) or not value:
            raise HarnessError(f"mimalloc.{key} must be a non-empty string")
        normalized[key] = value
    if normalized["version"] != "3.5.0":
        raise HarnessError("Milestone 0 is fixed to mimalloc v3.5.0")
    if normalized["repository"] != "https://github.com/microsoft/mimalloc.git" or normalized["tag"] != "v3.5.0":
        raise HarnessError("Milestone 0 must verify the microsoft/mimalloc v3.5.0 annotated tag")
    for key in ("sha256", "tag_object", "revision"):
        expected_length = 64 if key == "sha256" else 40
        if not re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", normalized[key]):
            raise HarnessError(f"mimalloc.{key} is not a lowercase hexadecimal identity")
    if normalized["archive_root"] != "mimalloc-3.5.0":
        raise HarnessError("mimalloc.archive_root must be mimalloc-3.5.0")
    return normalized


def load_pin(path: Path = UPSTREAMS) -> dict[str, str]:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HarnessError(f"invalid upstream pin file: {path}") from error
    return normalize_mimalloc_pin(raw)


# The upstream-stress producer owns execution.  This runner only consumes its
# one fixed, atomically-published full-matrix report.  Keep this validator here
# rather than importing the producer: a full M5 run must not make a nested
# upstream-stress invocation or silently acquire a second execution policy.
CANONICAL_UPSTREAM_STRESS_ARTIFACT_IDS = (
    "contract",
    "upstream_archive",
    "source_member",
    "owned_sysroot_manifest",
    "owned_sysroot_purity",
    "owned_compiler",
    "selected_loader",
    "staged_canonical_loader",
    "selected_libc",
    "selected_static_libc",
    "selected_backend_build_record",
    "stress_binary",
)
CANONICAL_UPSTREAM_STRESS_EXECUTION_SCOPED_ARTIFACT_IDS = (
    "staged_canonical_loader",
)
CANONICAL_UPSTREAM_STRESS_WORKERS = (1, 2, 4, 8)
CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_SCALE_THRESHOLD = 100
CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_MATRIX_SCALE = (
    CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_SCALE_THRESHOLD + 1
)
CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_MATRIX_ITERATIONS = 1
CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_STDOUT_SUFFIX = " (allow large objects)"


def canonical_upstream_stress_expected_scope() -> dict[str, Any]:
    """Keep the nonpromotion and first-fact boundary closed in the consumer."""

    return {
        "claim": (
            "one canonical executable inventory of the exact pinned upstream "
            "test/test-stress.c through the selected native-mimalloc-shadow crabc libc"
        ),
        "not_a_promotion_gate": True,
        "purpose": (
            "record the first unavailable prerequisite, build/link failure, or ordered "
            "matrix result without changing upstream scheduling, transfer ownership, or "
            "initial-thread cleanup"
        ),
        "first_fact_rule": (
            "Run each listed case in order in one fresh process with one watchdog. Stop "
            "after the first non-pass; do not retry, shrink, or reschedule a case. A "
            "blocked prerequisite starts no stress process."
        ),
    }


def canonical_upstream_stress_expected_source_adaptation() -> dict[str, Any]:
    """Pin the only permitted source/build adaptation and its ownership constraints."""

    return {
        "kind": "upstream-preprocessor-symbol-selection-only",
        "compile_defines": ["USE_STD_MALLOC"],
        "patches": [],
        "forbidden_changes": [
            "checked-in source copy or patch",
            "worker scheduling change",
            "transfer ownership change",
            "post-worker cleanup relocation",
            "initial-thread cleanup change",
        ],
        "explanation": (
            "USE_STD_MALLOC is an upstream conditional that binds custom allocation names "
            "to calloc, realloc, and free. The archived source is compiled byte-for-byte "
            "after its hash is verified. Worker count, scale, and iteration, including the "
            "source's SCALE > 100 large-object enablement, are source command-line "
            "arguments, never replacement compile-time scheduler or large-mode defines."
        ),
    }


def canonical_upstream_stress_expected_scheduler_and_ownership() -> list[str]:
    """Pin the unmodified upstream worker, transfer, and final-cleanup order."""

    return [
        "The unmodified upstream main_participates value remains false.",
        "The unmodified upstream run_os_threads creates and joins the requested pthread workers before returning to test_stress.",
        "The unmodified upstream shared transfer buffer carries live allocations between source workers and source iterations.",
        "After run_os_threads returns, the unmodified initial thread performs free_items cleanup of transferred objects in test_stress.",
    ]


def canonical_upstream_stress_exactly_matches(
    observed: object, expected: object
) -> bool:
    """Compare JSON values without allowing bool/int or shape coercion."""

    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(observed, dict)
        return set(observed) == set(expected) and all(
            canonical_upstream_stress_exactly_matches(observed[key], expected[key])
            for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(observed, list)
        return len(observed) == len(expected) and all(
            canonical_upstream_stress_exactly_matches(left, right)
            for left, right in zip(observed, expected)
        )
    return observed == expected


def canonical_upstream_stress_byte_record(
    record: object, subject: str
) -> bytes:
    """Decode a producer byte record only after checking its self-attestation."""

    if not isinstance(record, dict) or set(record) != {"bytes", "sha256", "hex"}:
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} byte record is invalid"
        )
    if (
        type(record.get("bytes")) is not int
        or record["bytes"] < 0
        or not isinstance(record.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        or not isinstance(record.get("hex"), str)
    ):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} byte record is invalid"
        )
    try:
        payload = bytes.fromhex(record["hex"])
    except ValueError as error:
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} byte record has invalid hex"
        ) from error
    if (
        len(payload) != record["bytes"]
        or hashlib.sha256(payload).hexdigest() != record["sha256"]
    ):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} byte record drifted"
        )
    return payload


def canonical_upstream_stress_relative_path(root: Path, path: Path) -> str:
    """Render a producer-compatible artifact path without accepting escapes."""

    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def canonical_upstream_stress_observed_file_record(
    root: Path, path: Path, subject: str
) -> dict[str, Any]:
    """Read one live regular file twice enough to reject a changing artifact."""

    try:
        if not path.is_file() or path.is_symlink():
            raise CanonicalUpstreamStressRejected(
                f"canonical upstream stress {subject} is absent or not a regular file"
            )
        before = path.stat()
        payload = path.read_bytes()
        after = path.stat()
    except OSError as error:
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress cannot read {subject}"
        ) from error
    if (
        before.st_size != len(payload)
        or after.st_size != len(payload)
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
    ):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} changed while being read"
        )
    return {
        "bytes": len(payload),
        "path": canonical_upstream_stress_relative_path(root, path),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def canonical_upstream_stress_live_file_record(
    root: Path,
    record: object,
    subject: str,
    *,
    expected_path: Path | None = None,
) -> dict[str, Any]:
    """Require a report artifact to be a current, non-symlinked named file."""

    if not isinstance(record, dict) or set(record) != {"bytes", "path", "sha256"}:
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} file record is invalid"
        )
    raw_path = record.get("path")
    if (
        type(record.get("bytes")) is not int
        or record["bytes"] < 0
        or not isinstance(raw_path, str)
        or not raw_path
        or not isinstance(record.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
    ):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} file record is invalid"
        )
    candidate = Path(raw_path)
    if candidate.is_absolute():
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} escapes the canonical workspace"
        )
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} has an unsafe relative path"
        )
    path = root / candidate
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} escapes the canonical workspace"
        ) from error
    observed = canonical_upstream_stress_observed_file_record(root, path, subject)
    if not canonical_upstream_stress_exactly_matches(record, observed):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} no longer matches its report artifact"
        )
    if expected_path is not None:
        expected = canonical_upstream_stress_relative_path(root, expected_path)
        if record["path"] != expected:
            raise CanonicalUpstreamStressRejected(
                f"canonical upstream stress {subject} has a noncanonical path"
            )
    return observed


def canonical_upstream_stress_execution_scoped_loader_record(
    record: object, selected_loader: Mapping[str, Any], canonical_loader: Path
) -> dict[str, Any]:
    """Validate the producer's transient staged-loader execution evidence.

    The owned test-suite launcher stages the canonical loader only for the
    producer container.  A later ``allocator --full`` runs elsewhere, so it
    must bind the recorded literal `/lib` path to the still-live selected
    loader rather than requiring that transient external file to remain.
    """

    if not isinstance(record, dict) or set(record) != {"bytes", "path", "sha256"}:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress staged canonical loader file record is invalid"
        )
    if (
        type(record.get("bytes")) is not int
        or record["bytes"] <= 0
        or record.get("path") != canonical_loader.as_posix()
        or not isinstance(record.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress staged canonical loader record is not the fixed execution path"
        )
    if (
        record["bytes"] != selected_loader["bytes"]
        or record["sha256"] != selected_loader["sha256"]
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress staged loader does not match the selected loader"
        )
    return dict(record)


def canonical_upstream_stress_read_json(
    root: Path, path: Path, subject: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read a current JSON artifact and retain the file identity used to read it."""

    record = canonical_upstream_stress_observed_file_record(root, path, subject)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} is not valid JSON"
        ) from error
    after = canonical_upstream_stress_observed_file_record(root, path, subject)
    if not canonical_upstream_stress_exactly_matches(record, after):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} changed while being decoded"
        )
    if not isinstance(value, dict):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} is not a JSON object"
        )
    return value, record


def canonical_current_git_source_state(root: Path) -> dict[str, Any]:
    """Read the live source state without taking an optional Git index lock."""

    git = shutil.which("git")
    if git is None:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress execution requires a clean Git source tree"
        )
    environment = dict(os.environ)
    environment.update(CANONICAL_UPSTREAM_STRESS_GIT_ENVIRONMENT)
    try:
        revision = subprocess.run(
            [git, "rev-parse", "--verify", "HEAD"],
            cwd=root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        status = subprocess.run(
            [git, "status", "--porcelain=v1", "--untracked-files=all", "-z"],
            cwd=root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress execution cannot read its Git source state"
        ) from error
    if revision.returncode != 0 or status.returncode != 0:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress execution requires an available Git source tree"
        )
    try:
        revision_text = revision.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress execution has an invalid Git revision"
        ) from error
    if re.fullmatch(r"[0-9a-f]{40}", revision_text) is None:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress execution has an invalid Git revision"
        )
    return {
        "kind": "git",
        "revision": revision_text,
        "worktree_clean": status.stdout == b"",
        "worktree_status": {
            "bytes": len(status.stdout),
            "hex": status.stdout.hex(),
            "sha256": hashlib.sha256(status.stdout).hexdigest(),
        },
    }


def canonical_upstream_stress_clean_git_source(
    state: object, subject: str
) -> dict[str, Any]:
    """Validate the producer's clean-Git current-head schema exactly."""

    if not isinstance(state, dict) or set(state) != {
        "kind",
        "revision",
        "worktree_clean",
        "worktree_status",
    }:
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} source state is invalid"
        )
    if (
        state.get("kind") != "git"
        or not isinstance(state.get("revision"), str)
        or re.fullmatch(r"[0-9a-f]{40}", state["revision"]) is None
        or type(state.get("worktree_clean")) is not bool
    ):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} source state is invalid"
        )
    worktree_status = canonical_upstream_stress_byte_record(
        state.get("worktree_status"), f"{subject} worktree status"
    )
    if state["worktree_clean"] != (worktree_status == b""):
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} source cleanliness is contradictory"
        )
    if not state["worktree_clean"]:
        raise CanonicalUpstreamStressRejected(
            f"canonical upstream stress {subject} requires a clean Git source tree"
        )
    return dict(state)


def canonical_upstream_stress_source_cli_enables_large_objects(scale: int) -> bool:
    """Mirror the archived source's strict ``SCALE > 100`` mode boundary."""

    return scale > CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_SCALE_THRESHOLD


def canonical_upstream_stress_expected_matrix_case(
    workers: int, scale: int, iterations: int
) -> dict[str, Any]:
    """Describe one unchanged-source CLI invocation in the fixed consumer mirror."""

    large_object_suffix = (
        CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_STDOUT_SUFFIX
        if canonical_upstream_stress_source_cli_enables_large_objects(scale)
        else ""
    )
    return {
        "id": f"workers-{workers}-scale-{scale}-iterations-{iterations}",
        "workers": workers,
        "scale": scale,
        "iterations": iterations,
        "arguments": [str(workers), str(scale), str(iterations)],
        "expected_stdout": (
            f"Using {workers} threads with a {scale}% load-per-thread and "
            f"{iterations} iterations{large_object_suffix}\n"
        ),
        "expected_stderr": "",
        "expected_exit_status": 0,
    }


def canonical_upstream_stress_expected_matrix() -> list[dict[str, Any]]:
    """Fix the producer's complete source schedule in this M5 consumer too."""

    matrix: list[dict[str, Any]] = []
    for scale, iterations in ((1, 1), (2, 2)):
        for workers in CANONICAL_UPSTREAM_STRESS_WORKERS:
            matrix.append(
                canonical_upstream_stress_expected_matrix_case(
                    workers, scale, iterations
                )
            )
    for workers in CANONICAL_UPSTREAM_STRESS_WORKERS:
        matrix.append(
            canonical_upstream_stress_expected_matrix_case(
                workers,
                CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_MATRIX_SCALE,
                CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_MATRIX_ITERATIONS,
            )
        )
    return matrix


def canonical_upstream_stress_expected_large_object_mode() -> dict[str, Any]:
    """Fix the producer's source-CLI large-object evidence shape in the consumer."""

    return {
        "status": "source-cli-enabled",
        "source_enablement": {
            "parameter": "SCALE",
            "operator": ">",
            "threshold": CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_SCALE_THRESHOLD,
            "expected_stdout_suffix": CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_STDOUT_SUFFIX,
        },
        "matrix_case_ids": [
            canonical_upstream_stress_expected_matrix_case(
                workers,
                CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_MATRIX_SCALE,
                CANONICAL_UPSTREAM_STRESS_LARGE_OBJECT_MATRIX_ITERATIONS,
            )["id"]
            for workers in CANONICAL_UPSTREAM_STRESS_WORKERS
        ],
        "reason": (
            "The unmodified pinned source sets allow_large_objects only after source CLI "
            "parsing when SCALE > 100. Each listed case uses SCALE=101; no compile-time "
            "large-mode define is accepted. A passing row records source-mode activation "
            "and completed bounded workload execution, not that every probabilistic large "
            "allocation succeeded."
        ),
    }


def validate_canonical_upstream_stress_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Validate only the fixed producer boundary that M5 may consume."""

    if not isinstance(contract, dict) or set(contract) != {
        "format",
        "schema",
        "scope",
        "upstream",
        "target_inventory",
        "backend_inventory",
        "fixture",
        "source_adaptation",
        "execution",
        "capability",
        "report",
        "compile_requirements",
    }:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract schema drifted"
        )
    if (
        contract.get("format") != 7
        or contract.get("schema") != "crabc-mimalloc-canonical-upstream-stress"
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract schema drifted"
        )
    if not canonical_upstream_stress_exactly_matches(
        contract.get("scope"), canonical_upstream_stress_expected_scope()
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract scope or nonpromotion policy drifted"
        )
    expected_upstream = {
        "project": "microsoft/mimalloc",
        "version": pin["version"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "revision": pin["revision"],
        "repository": pin["repository"],
        "archive_source": pin["source"],
        "archive_path": ".work/allocator-cache/mimalloc-3.5.0.tar.gz",
        "archive_root": pin["archive_root"],
        "archive_sha256": pin["sha256"],
    }
    if not canonical_upstream_stress_exactly_matches(
        contract.get("upstream"), expected_upstream
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract pin drifted"
        )
    target = {
        "id": "linux-aarch64-little-endian",
        "architecture": "aarch64",
        "byte_order": "little",
        "execution": "native-only",
        "kernel_baseline": "5.10",
        "status": "applicable",
        "system": "Linux",
    }
    if not canonical_upstream_stress_exactly_matches(
        contract.get("target_inventory"),
        {"selected": target["id"], "targets": [target]},
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract target inventory drifted"
        )
    backend_inventory = contract.get("backend_inventory")
    if not isinstance(backend_inventory, dict):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract backend inventory is invalid"
        )
    backend_id = "crabc-libc-native-mimalloc-shadow"
    backends = backend_inventory.get("backends")
    if (
        backend_inventory.get("selected") != backend_id
        or not isinstance(backends, list)
        or len(backends) != 1
        or not isinstance(backends[0], dict)
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract backend inventory drifted"
        )
    backend = backends[0]
    if (
        backend.get("id") != backend_id
        or backend.get("target") != target["id"]
        or backend.get("status") != "applicable-nondefault"
        or backend.get("allocator_feature") != "native-mimalloc-shadow"
        or backend.get("c_backend_fallback") is not False
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract backend selection drifted"
        )
    attestation = backend.get("artifact_attestation")
    if not isinstance(attestation, dict) or set(attestation) != {
        "cargo_compiler_artifact",
        "exported_free_route",
    }:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract backend attestation drifted"
        )
    cargo = attestation["cargo_compiler_artifact"]
    expected_cargo = {
        "build_record_format": 1,
        "build_record_schema": "crabc-selected-libc-cargo-build",
        "cargo_command": [
            "cargo",
            "build",
            "--locked",
            "-p",
            "crabc-libc",
            "--features",
            "native-mimalloc-shadow",
            "--profile",
            "dev",
            "--message-format=json-render-diagnostics",
        ],
        "package_id_suffix": "#crabc-libc@0.3.0",
        "manifest_path": "libc/Cargo.toml",
        "target": {
            "kind": ["cdylib", "staticlib"],
            "crate_types": ["cdylib", "staticlib"],
            "name": "c",
            "src_path": "libc/src/lib.rs",
            "edition": "2021",
            "doc": True,
            "doctest": False,
            "test": False,
        },
        "semantic_profile": "dev",
        "profile": {
            "opt_level": "2",
            "debuginfo": 2,
            "debug_assertions": True,
            "overflow_checks": False,
            "test": False,
        },
        "exact_features": ["default", "native-mimalloc-shadow"],
        "artifacts": {
            "selected_shared_libc": "libc.so",
            "selected_static_libc": "libc.a",
        },
    }
    if not canonical_upstream_stress_exactly_matches(cargo, expected_cargo):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract Cargo attestation drifted"
        )
    expected_route = {
        "symbol": "free",
        "required_callee_suffix": "native_free>",
        "forbidden_callee_suffix": "mi_free>",
    }
    if not canonical_upstream_stress_exactly_matches(
        attestation["exported_free_route"], expected_route
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract free-route attestation drifted"
        )
    fixture = contract.get("fixture")
    if (
        not isinstance(fixture, dict)
        or fixture.get("archive_member") != "test/test-stress.c"
        or fixture.get("sha256")
        != "e2bed5f2be12239b1fa696dafffda384d19140cb50a6ee2f6e096f70934d73df"
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract fixture drifted"
        )
    if not canonical_upstream_stress_exactly_matches(
        contract.get("source_adaptation"),
        canonical_upstream_stress_expected_source_adaptation(),
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract source adaptation drifted"
        )
    execution = contract.get("execution")
    if not isinstance(execution, dict) or not canonical_upstream_stress_exactly_matches(
        execution.get("matrix"), canonical_upstream_stress_expected_matrix()
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract matrix drifted"
        )
    if (
        execution.get("process_attempts_per_case") != 1
        or execution.get("stop_after_first_nonpass") is not True
        or not isinstance(execution.get("source_randomness"), dict)
        or not isinstance(execution.get("watchdog"), dict)
        or execution["watchdog"].get("seconds") != 30
        or execution["watchdog"].get("process_retries") != 0
        or not canonical_upstream_stress_exactly_matches(
            execution.get("scheduler_and_ownership"),
            canonical_upstream_stress_expected_scheduler_and_ownership(),
        )
        or not canonical_upstream_stress_exactly_matches(
            execution.get("large_object_mode"),
            canonical_upstream_stress_expected_large_object_mode(),
        )
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract execution policy drifted"
        )
    capability = contract.get("capability")
    if (
        not isinstance(capability, dict)
        or capability.get("id") != "canonical-unmodified-upstream-pthread-stress"
        or capability.get("evidence_scope") != "shadow_subset"
        or capability.get("blocked_is_failure_closed") is not True
        or capability.get("required_worker_counts") != list(CANONICAL_UPSTREAM_STRESS_WORKERS)
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract capability policy drifted"
        )
    report_contract = contract.get("report")
    expected_current_head = {
        "build_record_format": 1,
        "build_record_schema": "crabc-selected-libc-current-head-build",
        "required_before_stress_compile": True,
        "git_read_environment": dict(CANONICAL_UPSTREAM_STRESS_GIT_ENVIRONMENT),
        "capture_source": {
            "kind": "git",
            "worktree_clean": True,
            "unchanged_during_selected_libc_build": True,
        },
        "execution_source": {
            "kind": "git",
            "worktree_clean": True,
            "matches_selected_libc_build": True,
        },
        "report_fields": ["status", "record", "source"],
        "status_values": ["not-attested", "attested"],
    }
    if (
        not isinstance(report_contract, dict)
        or report_contract.get("format") != 7
        or report_contract.get("schema")
        != "crabc-mimalloc-canonical-upstream-stress-report"
        or report_contract.get("path")
        != ".work/reports/allocator/upstream-stress/latest.json"
        or report_contract.get("atomic_publish") is not True
        or report_contract.get("artifact_ids")
        != list(CANONICAL_UPSTREAM_STRESS_ARTIFACT_IDS)
        or report_contract.get("execution_scoped_artifact_ids")
        != list(CANONICAL_UPSTREAM_STRESS_EXECUTION_SCOPED_ARTIFACT_IDS)
        or not canonical_upstream_stress_exactly_matches(
            report_contract.get("current_head"), expected_current_head
        )
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract report policy drifted"
        )
    requirements = contract.get("compile_requirements")
    expected_sysroot_purity = {
        "required_crt_sysroot_pure_rust": True,
        "allowed_full_runtime_purity": [
            {
                "full_runtime_pure_rust": True,
                "full_runtime_purity_status": "passed",
            },
            {
                "full_runtime_pure_rust": False,
                "full_runtime_purity_status": "blocked_by_native_allocator",
            },
        ],
        "reason": (
            "The installed driver and CRT/sysroot boundary must pass their owned purity "
            "audit. The separately recorded native-allocator blocker is only accepted "
            "in its exact documented form because this lane dynamically selects the "
            "native-mimalloc-shadow libc after the owned sysroot is built."
        ),
    }
    if (
        not isinstance(requirements, dict)
        or requirements.get("allocator_feature") != "native-mimalloc-shadow"
        or requirements.get("selected_runtime_directory") != "target/debug"
        or requirements.get("selected_libc_build_record")
        != ".work/target/compat/allocator/upstream-stress/selected-libc-build.json"
        or requirements.get("isolated_output_directory")
        != ".work/target/compat/allocator/upstream-stress"
        or requirements.get("expected_dynamic_dependencies") != ["libc.so"]
        or requirements.get("expected_interpreter") != "/lib/ld-crabc-aarch64.so.1"
        or requirements.get("canonical_loader") != "/lib/ld-crabc-aarch64.so.1"
        or requirements.get("canonical_loader") != requirements.get("expected_interpreter")
        or requirements.get("expected_elf_identity")
        != {"class": "ELF64", "endianness": "little", "machine": "AArch64"}
        or not canonical_upstream_stress_exactly_matches(
            requirements.get("sysroot_purity"), expected_sysroot_purity
        )
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract canonical loader or sysroot purity policy drifted"
        )
    return {
        "backend": backend,
        "backend_id": backend_id,
        "cargo": expected_cargo,
        "fixture": fixture,
        "matrix": canonical_upstream_stress_expected_matrix(),
        "target": target,
        "requirements": requirements,
        "report": report_contract,
        "execution": execution,
    }


def canonical_upstream_stress_canonical_loader_path(
    requirements: Mapping[str, Any],
) -> Path:
    """Return the contract-pinned staged loader after static validation."""

    value = requirements["canonical_loader"]
    assert isinstance(value, str)
    return Path(value)


def canonical_upstream_stress_normalized_cargo_artifact(
    artifact: object, root: Path, cargo: Mapping[str, Any]
) -> dict[str, Any]:
    """Check the raw Cargo message before comparing its normalized report form."""

    expected_fields = {
        "reason",
        "package_id",
        "manifest_path",
        "target",
        "profile",
        "features",
        "filenames",
        "executable",
        "fresh",
    }
    if not isinstance(artifact, dict) or set(artifact) != expected_fields:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc Cargo artifact schema drifted"
        )
    package_id = artifact.get("package_id")
    if (
        artifact.get("reason") != "compiler-artifact"
        or not isinstance(package_id, str)
        or not package_id.endswith(str(cargo["package_id_suffix"]))
        or Path(str(artifact.get("manifest_path"))).resolve()
        != (root / str(cargo["manifest_path"])).resolve()
        or artifact.get("profile") != cargo["profile"]
        or artifact.get("executable") is not None
        or type(artifact.get("fresh")) is not bool
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc Cargo artifact drifted"
        )
    raw_target = artifact.get("target")
    if not isinstance(raw_target, dict):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc Cargo target is invalid"
        )
    normalized_target = dict(raw_target)
    source_path = normalized_target.get("src_path")
    if (
        not isinstance(source_path, str)
        or Path(source_path).resolve() != (root / "libc/src/lib.rs").resolve()
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc Cargo source path drifted"
        )
    normalized_target["src_path"] = "libc/src/lib.rs"
    if not canonical_upstream_stress_exactly_matches(
        normalized_target, cargo["target"]
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc Cargo target drifted"
        )
    features = artifact.get("features")
    if (
        not isinstance(features, list)
        or not all(isinstance(feature, str) and feature for feature in features)
        or len(features) != len(set(features))
        or sorted(features) != sorted(cargo["exact_features"])
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc Cargo features drifted"
        )
    filenames = artifact.get("filenames")
    expected_filenames = [
        (root / "target/debug" / cargo["artifacts"]["selected_shared_libc"]).resolve(),
        (root / "target/debug" / cargo["artifacts"]["selected_static_libc"]).resolve(),
    ]
    if (
        not isinstance(filenames, list)
        or [Path(str(name)).resolve() for name in filenames] != expected_filenames
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc Cargo output paths drifted"
        )
    return {
        "package_id": package_id,
        "target": normalized_target,
        "profile": dict(cargo["profile"]),
        "features": list(features),
        "filenames": [
            "target/debug/libc.so",
            "target/debug/libc.a",
        ],
        "fresh": artifact["fresh"],
    }


def canonical_upstream_stress_validate_build_record(
    root: Path,
    record: Mapping[str, Any],
    cargo: Mapping[str, Any],
    shared: Mapping[str, Any],
    static: Mapping[str, Any],
    output: Path,
) -> dict[str, Any]:
    """Bind live selected libc outputs to the current Cargo record."""

    path = output / "selected-libc-build.json"
    observed_record = canonical_upstream_stress_live_file_record(
        root, record, "selected libc build record", expected_path=path
    )
    payload, parsed_record = canonical_upstream_stress_read_json(
        root, path, "selected libc build record"
    )
    if not canonical_upstream_stress_exactly_matches(parsed_record, observed_record):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc build record changed while being read"
        )
    if not isinstance(payload, dict) or set(payload) != {
        "format",
        "schema",
        "cargo_command",
        "semantic_profile",
        "compiler_artifact",
        "artifacts",
    }:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc build record schema drifted"
        )
    if (
        payload.get("format") != cargo["build_record_format"]
        or payload.get("schema") != cargo["build_record_schema"]
        or not canonical_upstream_stress_exactly_matches(
            payload.get("cargo_command"), cargo["cargo_command"]
        )
        or payload.get("semantic_profile") != cargo["semantic_profile"]
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc build record contract drifted"
        )
    normalized = canonical_upstream_stress_normalized_cargo_artifact(
        payload.get("compiler_artifact"), root, cargo
    )
    artifacts = payload.get("artifacts")
    expected_artifacts = {
        "selected_shared_libc": dict(shared),
        "selected_static_libc": dict(static),
    }
    if not canonical_upstream_stress_exactly_matches(artifacts, expected_artifacts):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress selected libc build record artifacts drifted"
        )
    return {
        "record": observed_record,
        "normalized_artifact": normalized,
        "artifacts": expected_artifacts,
    }


def canonical_upstream_stress_archive_source_member(
    root: Path,
    archive: Path,
    pin: Mapping[str, str],
    fixture: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Re-read the pinned archive and its exact source member from live bytes.

    The report's archive and source-member records are only claims until this
    consumer independently checks the archive against the pinned digest and
    extracts the exact member named by the fixed contract.  Do not accept a
    report that merely relabels another in-worktree tarball or source file.
    """

    archive_record = canonical_upstream_stress_observed_file_record(
        root, archive, "upstream archive"
    )
    if archive_record["sha256"] != pin["sha256"]:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress live upstream archive does not match the pinned digest"
        )
    member_path = f"{pin['archive_root']}/{fixture['archive_member']}"
    try:
        with tarfile.open(archive, mode="r:gz") as stream:
            members = [member for member in stream.getmembers() if member.name == member_path]
            if len(members) != 1 or not members[0].isfile():
                raise CanonicalUpstreamStressRejected(
                    "canonical upstream stress pinned archive has no unique regular test-stress.c member"
                )
            extracted = stream.extractfile(members[0])
            if extracted is None:
                raise CanonicalUpstreamStressRejected(
                    "canonical upstream stress cannot extract pinned test-stress.c"
                )
            with extracted:
                payload = extracted.read()
    except (OSError, tarfile.TarError) as error:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress cannot read the pinned upstream archive"
        ) from error
    after = canonical_upstream_stress_observed_file_record(
        root, archive, "upstream archive"
    )
    if not canonical_upstream_stress_exactly_matches(archive_record, after):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress upstream archive changed while its source member was read"
        )
    member_record = {
        "bytes": len(payload),
        "path": member_path,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    if (
        not payload
        or member_record["sha256"] != fixture["sha256"]
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress pinned test-stress.c member does not match its fixture digest"
        )
    return archive_record, member_record


def canonical_upstream_stress_validate_report(
    report: Mapping[str, Any],
    *,
    root: Path,
    work_root: Path,
    contract: Mapping[str, Any],
    contract_record: Mapping[str, Any],
    summary: Mapping[str, Any],
    pin: Mapping[str, str],
) -> dict[str, Any]:
    """Reject every partial, stale, or unbound canonical report shape."""

    report_contract = summary["report"]
    requirements = summary["requirements"]
    matrix = summary["matrix"]
    backend_id = summary["backend_id"]
    cargo = summary["cargo"]
    output = work_root / "target/compat/allocator/upstream-stress"
    if (
        report.get("format") != report_contract["format"]
        or report.get("schema") != report_contract["schema"]
        or report.get("status") != "passed"
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report schema or passed status is invalid"
        )
    expected_contract_record = {**dict(contract_record), "upstream": dict(contract["upstream"])}
    if not canonical_upstream_stress_exactly_matches(
        report.get("contract"), expected_contract_record
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report contract binding drifted"
        )
    expected_pin = {
        "archive_root": pin["archive_root"],
        "repository": pin["repository"],
        "revision": pin["revision"],
        "sha256": pin["sha256"],
        "source": pin["source"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "version": pin["version"],
    }
    if not canonical_upstream_stress_exactly_matches(report.get("upstream_pin"), expected_pin):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report pin binding drifted"
        )
    expected_runtime = {
        "allocator_feature": requirements["allocator_feature"],
        "backend": backend_id,
        "target_dir": "target/debug",
        "output_dir": canonical_upstream_stress_relative_path(root, output),
        "selected_libc_build_record": canonical_upstream_stress_relative_path(
            root, output / "selected-libc-build.json"
        ),
        "current_head_build_record": canonical_upstream_stress_relative_path(
            root, output / "selected-libc-build-current-head.json"
        ),
    }
    if not canonical_upstream_stress_exactly_matches(
        report.get("requested_runtime"), expected_runtime
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report runtime selection drifted"
        )
    if not canonical_upstream_stress_exactly_matches(
        report.get("selection"), {"target": summary["target"], "backend": backend_id}
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report target/backend selection drifted"
        )
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(
        CANONICAL_UPSTREAM_STRESS_ARTIFACT_IDS
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report artifact inventory drifted"
        )
    if not canonical_upstream_stress_exactly_matches(artifacts["contract"], contract_record):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report contract artifact drifted"
        )
    runtime = report.get("runtime")
    if not isinstance(runtime, dict) or not isinstance(
        runtime.get("backend_attestation"), dict
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report backend attestation is absent"
        )
    sysroot = root / "target/crabc-sysroot"
    canonical_loader = canonical_upstream_stress_canonical_loader_path(requirements)
    if (
        runtime.get("sysroot") != canonical_upstream_stress_relative_path(root, sysroot)
        or runtime.get("compiler")
        != canonical_upstream_stress_relative_path(root, sysroot / "bin/crabc-cc")
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report runtime sysroot selection drifted"
        )
    # The contract's sole execution-scoped record is validated below.  The
    # contract/source-member bindings are reread separately; every remaining
    # artifact must still be a live, canonical workspace file here.
    expected_paths = {
        "upstream_archive": work_root / "allocator-cache/mimalloc-3.5.0.tar.gz",
        "owned_sysroot_manifest": sysroot / "share/crabc/manifest.json",
        "owned_sysroot_purity": sysroot / "share/crabc/purity.json",
        "owned_compiler": sysroot / "bin/crabc-cc",
        "selected_loader": root / "target/debug/libldso.so",
        "selected_libc": root / "target/debug/libc.so",
        "selected_static_libc": root / "target/debug/libc.a",
        "selected_backend_build_record": output / "selected-libc-build.json",
        "stress_binary": output / "canonical-upstream-test-stress",
    }
    names = {
        "upstream_archive": "upstream archive",
        "owned_sysroot_manifest": "owned sysroot manifest",
        "owned_sysroot_purity": "owned sysroot purity",
        "owned_compiler": "owned compiler",
        "selected_loader": "selected loader",
        "selected_libc": "selected shared libc",
        "selected_static_libc": "selected static libc",
        "selected_backend_build_record": "selected libc build record",
        "stress_binary": "stress binary",
    }
    live_artifacts: dict[str, dict[str, Any]] = {"contract": dict(contract_record)}
    for artifact_id, name in names.items():
        live_artifacts[artifact_id] = canonical_upstream_stress_live_file_record(
            root,
            artifacts[artifact_id],
            name,
            expected_path=expected_paths[artifact_id],
        )
    live_artifacts["staged_canonical_loader"] = (
        canonical_upstream_stress_execution_scoped_loader_record(
            artifacts["staged_canonical_loader"],
            live_artifacts["selected_loader"],
            canonical_loader,
        )
    )
    archive_record, source_member = canonical_upstream_stress_archive_source_member(
        root,
        expected_paths["upstream_archive"],
        pin,
        summary["fixture"],
    )
    if not canonical_upstream_stress_exactly_matches(
        live_artifacts["upstream_archive"], archive_record
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress upstream archive changed while its source member was read"
        )
    if not canonical_upstream_stress_exactly_matches(
        artifacts["source_member"], source_member
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report source-member attestation drifted"
        )
    live_artifacts["source_member"] = source_member
    purity, purity_record = canonical_upstream_stress_read_json(
        root, expected_paths["owned_sysroot_purity"], "owned sysroot purity"
    )
    if not canonical_upstream_stress_exactly_matches(
        live_artifacts["owned_sysroot_purity"], purity_record
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress owned sysroot purity changed while being read"
        )
    purity_requirement = requirements.get("sysroot_purity")
    if not isinstance(purity_requirement, dict):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress contract lacks owned sysroot purity requirements"
        )
    runtime_purity = {
        "crt_sysroot_pure_rust": purity.get("crt_sysroot_pure_rust"),
        "full_runtime_pure_rust": purity.get("full_runtime_pure_rust"),
        "full_runtime_purity_status": purity.get("full_runtime_purity_status"),
    }
    allowed_purity = purity_requirement.get("allowed_full_runtime_purity")
    if (
        runtime_purity["crt_sysroot_pure_rust"]
        is not purity_requirement.get("required_crt_sysroot_pure_rust")
        or not isinstance(allowed_purity, list)
        or not any(
            canonical_upstream_stress_exactly_matches(
                {
                    "full_runtime_pure_rust": runtime_purity["full_runtime_pure_rust"],
                    "full_runtime_purity_status": runtime_purity[
                        "full_runtime_purity_status"
                    ],
                },
                candidate,
            )
            for candidate in allowed_purity
        )
        or not canonical_upstream_stress_exactly_matches(
            runtime.get("sysroot_purity"), runtime_purity
        )
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress owned sysroot purity binding drifted"
        )
    shared = live_artifacts["selected_libc"]
    static = live_artifacts["selected_static_libc"]
    build = canonical_upstream_stress_validate_build_record(
        root,
        live_artifacts["selected_backend_build_record"],
        cargo,
        shared,
        static,
        output,
    )
    backend_attestation = runtime["backend_attestation"]
    expected_backend_fields = {
        "backend",
        "build_record",
        "semantic_profile",
        "cargo_features",
        "compiler_artifact",
        "artifacts",
        "exported_free",
        "status",
    }
    if set(backend_attestation) != expected_backend_fields or (
        backend_attestation.get("backend") != backend_id
        or backend_attestation.get("status") != "passed"
        or backend_attestation.get("semantic_profile") != cargo["semantic_profile"]
        or not canonical_upstream_stress_exactly_matches(
            backend_attestation.get("build_record"), build["record"]
        )
        or not canonical_upstream_stress_exactly_matches(
            backend_attestation.get("cargo_features"), build["normalized_artifact"]["features"]
        )
        or not canonical_upstream_stress_exactly_matches(
            backend_attestation.get("compiler_artifact"), build["normalized_artifact"]
        )
        or not canonical_upstream_stress_exactly_matches(
            backend_attestation.get("artifacts"), build["artifacts"]
        )
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report backend attestation drifted"
        )
    route = backend_attestation.get("exported_free")
    expected_route = summary["backend"]["artifact_attestation"]["exported_free_route"]
    if (
        not isinstance(route, dict)
        or set(route) != {
            "symbol",
            "required_callee_suffix",
            "forbidden_callee_suffix",
            "disassembly_sha256",
        }
        or route.get("symbol") != expected_route["symbol"]
        or route.get("required_callee_suffix")
        != expected_route["required_callee_suffix"]
        or route.get("forbidden_callee_suffix")
        != expected_route["forbidden_callee_suffix"]
        or not isinstance(route.get("disassembly_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", route["disassembly_sha256"]) is None
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report free-route attestation drifted"
        )
    fixture = report.get("fixture")
    if (
        not isinstance(fixture, dict)
        or fixture.get("archive_member") != summary["fixture"]["archive_member"]
        or fixture.get("expected_sha256") != summary["fixture"]["sha256"]
        or not canonical_upstream_stress_exactly_matches(
            fixture.get("source_adaptation"),
            {
                "compile_defines": ["USE_STD_MALLOC"],
                "patches": [],
            },
        )
        or not canonical_upstream_stress_exactly_matches(
            fixture.get("observed_source"), source_member
        )
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report source adaptation binding drifted"
        )
    execution = report.get("execution")
    if (
        not isinstance(execution, dict)
        or execution.get("attempted") is not True
        or execution.get("attempted_process_count") != len(matrix)
        or execution.get("case_count") != len(matrix)
        or execution.get("process_attempts_per_case") != 1
        or not canonical_upstream_stress_exactly_matches(
            execution.get("source_randomness"), summary["execution"]["source_randomness"]
        )
        or not canonical_upstream_stress_exactly_matches(
            execution.get("watchdog"), summary["execution"]["watchdog"]
        )
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report execution policy drifted"
        )
    results = execution.get("case_results")
    if not isinstance(results, list) or len(results) != len(matrix):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report has a partial matrix"
        )
    binary = output / "canonical-upstream-test-stress"
    for attempt, (result, case) in enumerate(zip(results, matrix), start=1):
        inventory = {
            field: case[field]
            for field in ("id", "workers", "scale", "iterations", "arguments")
        }
        if not isinstance(result, dict) or set(result) != {
            "case",
            "process_attempt",
            "state",
            "observation",
        }:
            raise CanonicalUpstreamStressRejected(
                "canonical upstream stress report matrix result schema drifted"
            )
        observation = result.get("observation")
        if (
            not canonical_upstream_stress_exactly_matches(result.get("case"), inventory)
            or result.get("process_attempt") != attempt
            or result.get("state") != "passed"
            or not isinstance(observation, dict)
            or set(observation) != {"command", "kind", "status", "stdout", "stderr"}
            or observation.get("command") != [str(binary), *case["arguments"]]
            or observation.get("kind") != "process"
            or observation.get("status") != case["expected_exit_status"]
            or canonical_upstream_stress_byte_record(
                observation.get("stdout"), f"matrix case {case['id']} stdout"
            )
            != case["expected_stdout"].encode()
            or canonical_upstream_stress_byte_record(
                observation.get("stderr"), f"matrix case {case['id']} stderr"
            )
            != case["expected_stderr"].encode()
        ):
            raise CanonicalUpstreamStressRejected(
                "canonical upstream stress report matrix result drifted"
            )
    expected_capability = {
        "id": "canonical-unmodified-upstream-pthread-stress",
        "status": "passed",
        "failure_closed": True,
        "native_execution_started": True,
        "native_execution_completed": True,
        "passed_case_count": len(matrix),
        "required_case_count": len(matrix),
        "fully_verified_worker_counts": list(CANONICAL_UPSTREAM_STRESS_WORKERS),
        "required_worker_counts": list(CANONICAL_UPSTREAM_STRESS_WORKERS),
    }
    if not canonical_upstream_stress_exactly_matches(
        report.get("capability"), expected_capability
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report capability is not a complete failure-closed pass"
        )
    if report.get("blocked") is not None or not canonical_upstream_stress_exactly_matches(
        report.get("first_fact"),
        {"kind": "pass", "stage": "matrix", "completed_case_count": len(matrix)},
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report first-fact policy drifted"
        )
    fixture_elf = {
        "dynamic_dependencies": requirements["expected_dynamic_dependencies"],
        "elf_identity": requirements["expected_elf_identity"],
        "interpreter": requirements["expected_interpreter"],
    }
    if (
        not canonical_upstream_stress_exactly_matches(report.get("fixture_elf"), fixture_elf)
        or report.get("dynamic_dependencies") != requirements["expected_dynamic_dependencies"]
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress report fixture ELF binding drifted"
        )
    current_head = report.get("current_head")
    companion_path = output / "selected-libc-build-current-head.json"
    if (
        not isinstance(current_head, dict)
        or set(current_head) != {"status", "record", "source"}
        or current_head.get("status") != "attested"
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress current-head report schema drifted"
        )
    companion_record = canonical_upstream_stress_live_file_record(
        root,
        current_head.get("record"),
        "current-head companion",
        expected_path=companion_path,
    )
    companion, observed_companion_record = canonical_upstream_stress_read_json(
        root, companion_path, "current-head companion"
    )
    if not canonical_upstream_stress_exactly_matches(
        companion_record, observed_companion_record
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress current-head companion changed while being read"
        )
    if not isinstance(companion, dict) or set(companion) != {
        "format",
        "schema",
        "source_before",
        "source_after",
        "source_unchanged_during_build",
        "selected_libc_build_record",
        "artifacts",
    }:
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress current-head companion schema drifted"
        )
    before = canonical_upstream_stress_clean_git_source(
        companion.get("source_before"), "current-head companion before capture"
    )
    after = canonical_upstream_stress_clean_git_source(
        companion.get("source_after"), "current-head companion after capture"
    )
    if (
        companion.get("format") != 1
        or companion.get("schema") != "crabc-selected-libc-current-head-build"
        or companion.get("source_unchanged_during_build") is not True
        or not canonical_upstream_stress_exactly_matches(before, after)
        or not canonical_upstream_stress_exactly_matches(
            companion.get("selected_libc_build_record"), build["record"]
        )
        or not canonical_upstream_stress_exactly_matches(
            companion.get("artifacts"), build["artifacts"]
        )
        or not canonical_upstream_stress_exactly_matches(current_head.get("source"), after)
    ):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress current-head companion binding drifted"
        )
    observed_source = canonical_upstream_stress_clean_git_source(
        canonical_current_git_source_state(root), "execution"
    )
    if not canonical_upstream_stress_exactly_matches(observed_source, after):
        raise CanonicalUpstreamStressRejected(
            "canonical upstream stress execution source no longer matches the selected libc build"
        )
    return {
        "current_head": {"record": companion_record, "source": after},
        "evidence_scope": "shadow_subset",
        "large_object_mode": dict(summary["execution"]["large_object_mode"]),
        "matrix": {
            "case_count": len(matrix),
            "worker_counts": list(CANONICAL_UPSTREAM_STRESS_WORKERS),
        },
    }


def consume_canonical_upstream_stress_evidence(
    *,
    contract_path: Path = CANONICAL_UPSTREAM_STRESS_CONTRACT,
    report_path: Path = CANONICAL_UPSTREAM_STRESS_REPORT,
    root: Path = ROOT,
    work_root: Path = WORK_ROOT,
    pin: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Classify the one canonical report without compiling or executing it."""

    root = root.resolve()
    work_root = work_root.resolve()
    expected_contract_path = root / "compat/allocator/upstream-stress-v3.5.0.json"
    expected_report_path = work_root / "reports/allocator/upstream-stress/latest.json"
    base: dict[str, Any] = {
        "format": 1,
        "schema": "crabc-mimalloc-canonical-upstream-stress-consumer",
        "status": "rejected",
        "report_path": canonical_upstream_stress_relative_path(root, expected_report_path),
        "report": None,
        "contract": None,
        "evidence_scope": None,
        "large_object_mode": {"status": "not-verified"},
        "matrix": None,
        "current_head": None,
    }
    if contract_path.resolve() != expected_contract_path or report_path.resolve() != expected_report_path:
        base["reason"] = "canonical upstream stress consumer accepts only its fixed report path"
        return base
    if not report_path.exists():
        base["status"] = "unavailable"
        base["reason"] = "canonical upstream stress report is unavailable"
        return base
    try:
        actual_pin = dict(load_pin() if pin is None else pin)
        contract, contract_record = canonical_upstream_stress_read_json(
            root, contract_path, "contract"
        )
        summary = validate_canonical_upstream_stress_contract(contract, actual_pin)
        base["contract"] = {
            **contract_record,
            "format": contract["format"],
            "schema": contract["schema"],
            "upstream": {
                "revision": actual_pin["revision"],
                "version": actual_pin["version"],
            },
        }
        report, report_record = canonical_upstream_stress_read_json(
            root, report_path, "report"
        )
        verified = canonical_upstream_stress_validate_report(
            report,
            root=root,
            work_root=work_root,
            contract=contract,
            contract_record=contract_record,
            summary=summary,
            pin=actual_pin,
        )
    except (CanonicalUpstreamStressRejected, HarnessError) as error:
        base["reason"] = str(error)
        return base
    base.update(
        {
            "status": "verified",
            "reason": None,
            "report": report_record,
            **verified,
        }
    )
    return base


def validate_m5_gate_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Validate the reviewed M5 full-lane contract without claiming a pass.

    The current contract deliberately distinguishes passing bounded evidence
    from the still-open Gate 5C--5E acceptance work.  Keeping that distinction
    checked-in prevents `allocator --full` from collapsing real lifecycle
    work into one permanent synthetic error message.
    """

    if (
        contract.get("schema") != "crabc-mimalloc-m5-gate"
        or contract.get("format") != 1
    ):
        raise HarnessError("unsupported M5 allocator gate contract")

    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping):
        raise HarnessError("M5 allocator gate contract lacks upstream identity")
    if upstream.get("version") != pin["version"] or upstream.get("revision") != pin["revision"]:
        raise HarnessError("M5 allocator gate upstream identity mismatch")

    full_lane = contract.get("full_lane")
    if not isinstance(full_lane, Mapping):
        raise HarnessError("M5 allocator gate contract lacks a full-lane record")
    expected_full_lane = {
        "routes_per_cycle": RUNTIME_TICKET_ZERO_WORKER_ROUTES_PER_CYCLE,
        "stress_seed": f"0x{RUNTIME_TICKET_ZERO_CHURN_STRESS_SEED:016x}",
        "watchdog_seconds": RUNTIME_TICKET_ZERO_CHURN_WATCHDOG_SECONDS,
        "worker_cycles": RUNTIME_TICKET_ZERO_CHURN_WORKER_CYCLES,
    }
    if dict(full_lane) != expected_full_lane:
        raise HarnessError("M5 allocator full-lane contract differs from the recorded churn lane")

    gates = contract.get("gates")
    if not isinstance(gates, list) or len(gates) != len(M5_GATE_IDS):
        raise HarnessError("M5 allocator gate contract has an unexpected gate inventory")

    gate_ids: list[str] = []
    for index, gate in enumerate(gates):
        if not isinstance(gate, Mapping):
            raise HarnessError(f"M5 allocator gate {index} is not an object")
        gate_id = gate.get("id")
        if gate_id != M5_GATE_IDS[index]:
            raise HarnessError("M5 allocator gate order or identity changed")
        gate_ids.append(gate_id)
        if gate.get("required") is not True:
            raise HarnessError(f"M5 allocator gate {gate_id} must remain required")
        acceptance = gate.get("acceptance")
        if not isinstance(acceptance, str) or not acceptance:
            raise HarnessError(f"M5 allocator gate {gate_id} lacks an acceptance contract")
        evidence = gate.get("evidence")
        if (
            not isinstance(evidence, list)
            or not evidence
            or not all(isinstance(entry, str) and entry for entry in evidence)
            or len(set(evidence)) != len(evidence)
        ):
            raise HarnessError(f"M5 allocator gate {gate_id} has an invalid evidence inventory")
        blockers = gate.get("blocked_by")
        if gate_id in M5_STATIC_BLOCKED_GATE_IDS:
            if (
                not isinstance(blockers, list)
                or not blockers
                or not all(isinstance(blocker, str) and blocker for blocker in blockers)
            ):
                raise HarnessError(f"M5 allocator gate {gate_id} lacks a current blocker")
        elif blockers is not None:
            raise HarnessError(f"M5 allocator gate {gate_id} must not predeclare a blocker")
        if gate_id == "m5.5d" and evidence != list(M5_5D_EVIDENCE):
            raise HarnessError(
                "M5 allocator gate m5.5d must retain its bounded, high-water, "
                "source-derived, and canonical-upstream evidence inventory"
            )

    return {
        "full_lane": expected_full_lane,
        "gate_count": len(gate_ids),
        "gate_ids": gate_ids,
    }


def _m1_foundations_port_map_record(
    port_map: Mapping[str, Any], reference: Mapping[str, Any]
) -> Mapping[str, Any]:
    """Resolve one reviewed M1 source-map reference without widening its scope."""

    kind = reference["kind"]
    upstream = reference["upstream"]
    records = port_map["unit"] if kind == "unit" else port_map.get("item", [])
    matches = [
        record
        for record in records
        if record.get("upstream") == upstream
        and (kind == "unit" or record.get("name") == reference["name"])
    ]
    if len(matches) != 1:
        name = "" if kind == "unit" else f":{reference['name']}"
        raise HarnessError(f"M1 foundations source-map record is absent or ambiguous: {kind}:{upstream}{name}")
    return matches[0]


def _m1_foundations_source_test_exists(target: str, check_id: str) -> None:
    """Refuse a checked-in M1 filter once its current source witness is gone."""

    target_parts = target.split("::")
    if len(target_parts) == 3 and target_parts[1] == "tests":
        module, _, test = target_parts
        source = ROOT / "crabc-mimalloc" / "src" / f"{module}.rs"
    elif target_parts[:3] == ["types", "page_queue", "tests"] and len(target_parts) == 4:
        # `types.rs` includes this private sibling with an explicit `#[path]`,
        # so Cargo names the focused unit test through `types::page_queue`
        # while the durable source witness remains `page_queue.rs`.
        test = target_parts[3]
        source = ROOT / "crabc-mimalloc" / "src" / "page_queue.rs"
    else:
        raise HarnessError(
            f"M1 foundations check {check_id} has an unsupported source test filter: {target}"
        )
    if not source.is_file():
        raise HarnessError(
            f"M1 foundations check {check_id} names no current source test filter: {target}"
        )
    source_text = source.read_text(encoding="utf-8")
    if not re.search(
        rf"(?m)^\s*fn\s+{re.escape(test)}\s*(?:<[^>]*>)?\s*\(", source_text
    ):
        raise HarnessError(
            f"M1 foundations check {check_id} names no current source test filter: {target}"
        )


def _m2_memory_substrate_source_test_exists(target: str, check_id: str) -> None:
    """Refuse the M2 filter if its current PageMap witness disappears."""

    target_parts = target.split("::")
    if len(target_parts) != 3 or target_parts[1] != "tests":
        raise HarnessError(
            f"M2 memory-substrate check {check_id} has an unsupported source test filter: {target}"
        )
    source = ROOT / "crabc-mimalloc" / "src" / f"{target_parts[0]}.rs"
    if not source.is_file():
        raise HarnessError(
            f"M2 memory-substrate check {check_id} names no current source test filter: {target}"
        )
    source_text = source.read_text(encoding="utf-8")
    if not re.search(
        rf"(?m)^\s*fn\s+{re.escape(target_parts[2])}\s*(?:<[^>]*>)?\s*\(",
        source_text,
    ):
        raise HarnessError(
            f"M2 memory-substrate check {check_id} names no current source test filter: {target}"
        )


def validate_m2_memory_substrate_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Validate the fixed, deliberately partial M2 memory-substrate contract."""

    expected_keys = {
        "components",
        "exclusions",
        "execution",
        "format",
        "milestone",
        "schema",
        "target",
        "upstream",
    }
    if set(contract) != expected_keys or contract.get("format") != 1 or contract.get(
        "schema"
    ) != "crabc-mimalloc-m2-memory-substrate":
        raise HarnessError("unsupported M2 memory-substrate contract")

    upstream = contract.get("upstream")
    expected_upstream = {
        "archive_sha256": pin["sha256"],
        "revision": pin["revision"],
        "version": pin["version"],
    }
    if not isinstance(upstream, Mapping) or dict(upstream) != expected_upstream:
        raise HarnessError("M2 memory-substrate contract upstream identity mismatch")

    target = contract.get("target")
    expected_target = {
        "architecture": "aarch64",
        "endianness": "little",
        "kernel_baseline": "5.10",
        "os": "linux",
        "rust_target": "aarch64-unknown-linux-musl",
    }
    if not isinstance(target, Mapping) or dict(target) != expected_target:
        raise HarnessError("M2 memory-substrate contract target changed")

    execution = contract.get("execution")
    expected_execution = {
        "features": [],
        "package": "crabc-mimalloc",
        "test_threads": 1,
        "timeout_seconds": 300,
    }
    if not isinstance(execution, Mapping) or dict(execution) != expected_execution:
        raise HarnessError("M2 memory-substrate execution contract changed")

    milestone = contract.get("milestone")
    if not isinstance(milestone, Mapping) or set(milestone) != {
        "completion_rule",
        "id",
        "nonclaims",
        "status",
    }:
        raise HarnessError("M2 memory-substrate contract lacks a milestone record")
    if milestone.get("id") != "m2" or milestone.get("status") not in M2_MEMORY_SUBSTRATE_COMPONENT_STATUSES:
        raise HarnessError("M2 memory-substrate milestone identity or status is invalid")
    if not isinstance(milestone.get("completion_rule"), str) or not milestone["completion_rule"]:
        raise HarnessError("M2 memory-substrate milestone lacks a completion rule")
    nonclaims = milestone.get("nonclaims")
    if (
        not isinstance(nonclaims, list)
        or not nonclaims
        or not all(isinstance(nonclaim, str) and nonclaim for nonclaim in nonclaims)
        or len(set(nonclaims)) != len(nonclaims)
    ):
        raise HarnessError("M2 memory-substrate milestone lacks a valid nonclaim inventory")

    raw_components = contract.get("components")
    if not isinstance(raw_components, list) or len(raw_components) != len(
        M2_MEMORY_SUBSTRATE_COMPONENT_IDS
    ):
        raise HarnessError("M2 memory-substrate component inventory changed")
    components: list[dict[str, Any]] = []
    for index, raw_component in enumerate(raw_components):
        if not isinstance(raw_component, Mapping) or set(raw_component) != {
            "checks",
            "completion_status",
            "id",
            "remaining_conditions",
            "source_units",
        }:
            raise HarnessError(f"M2 memory-substrate component {index} has unexpected fields")
        component_id = raw_component.get("id")
        if component_id != M2_MEMORY_SUBSTRATE_COMPONENT_IDS[index]:
            raise HarnessError("M2 memory-substrate component order or identity changed")
        status = raw_component.get("completion_status")
        if status not in M2_MEMORY_SUBSTRATE_COMPONENT_STATUSES:
            raise HarnessError(f"M2 memory-substrate component {component_id} has an invalid status")
        remaining = raw_component.get("remaining_conditions")
        if (
            not isinstance(remaining, list)
            or not all(isinstance(condition, str) and condition for condition in remaining)
            or len(set(remaining)) != len(remaining)
        ):
            raise HarnessError(
                f"M2 memory-substrate component {component_id} must name unique remaining conditions"
            )
        if status == "partial" and not remaining:
            raise HarnessError(
                f"M2 memory-substrate partial component {component_id} must name remaining conditions"
            )
        if status == "complete" and remaining:
            raise HarnessError(
                f"M2 memory-substrate complete component {component_id} retains conditions"
            )
        source_units = raw_component.get("source_units")
        if (
            not isinstance(source_units, list)
            or not source_units
            or not all(isinstance(unit, str) and unit for unit in source_units)
            or len(set(source_units)) != len(source_units)
        ):
            raise HarnessError(f"M2 memory-substrate component {component_id} has invalid source units")
        raw_checks = raw_component.get("checks")
        if not isinstance(raw_checks, list):
            raise HarnessError(f"M2 memory-substrate component {component_id} has invalid checks")
        checks: list[dict[str, Any]] = []
        check_ids: set[str] = set()
        for raw_check in raw_checks:
            if not isinstance(raw_check, Mapping) or set(raw_check) != {
                "expected_passed_test_count",
                "id",
                "kind",
                "target",
            }:
                raise HarnessError(f"M2 memory-substrate component {component_id} has an invalid check")
            check_id = raw_check.get("id")
            target_name = raw_check.get("target")
            if (
                not isinstance(check_id, str)
                or not re.fullmatch(r"[a-z][a-z0-9-]*", check_id)
                or check_id in check_ids
                or raw_check.get("kind")
                not in {
                    "rust-unit",
                    "rust-page-map-success-trace",
                    "c-rust-detached-tld-static-preimage-differential",
                    "c-rust-normal-tld-direct-differential",
                    "c-rust-static-first-tld-create-differential",
                    "c-rust-bitmap-abandoned-claim-differential",
                    "c-rust-bitmap-clear-range-differential",
                    "c-rust-bitmap-rangesn-differential",
                    "c-rust-bitmap-set-differential",
                    "c-rust-binned-bitmap-bsr-inv-differential",
                    "c-rust-page-map-success-differential",
                    "c-rust-page-map-lazy-commit-failure-differential",
                    "c-rust-page-map-cold-init-differential",
                }
                or not isinstance(target_name, str)
                or not isinstance(raw_check.get("expected_passed_test_count"), int)
                or isinstance(raw_check.get("expected_passed_test_count"), bool)
                or raw_check["expected_passed_test_count"] <= 0
            ):
                raise HarnessError(f"M2 memory-substrate component {component_id} has an invalid check")
            _m2_memory_substrate_source_test_exists(target_name, check_id)
            check_ids.add(check_id)
            checks.append(
                {
                    "expected_passed_test_count": raw_check["expected_passed_test_count"],
                    "id": check_id,
                    "kind": raw_check["kind"],
                    "target": target_name,
                }
            )
        components.append(
            {
                "checks": checks,
                "completion_status": status,
                "id": component_id,
                "remaining_conditions": list(remaining),
                "source_units": list(source_units),
            }
        )

    if (milestone["status"] == "complete") != all(
        component["completion_status"] == "complete" and not component["remaining_conditions"]
        for component in components
    ):
        raise HarnessError("M2 memory-substrate milestone status must match component completion states")

    raw_exclusions = contract.get("exclusions")
    if not isinstance(raw_exclusions, list) or not raw_exclusions:
        raise HarnessError("M2 memory-substrate contract lacks explicit exclusions")
    exclusions: list[dict[str, Any]] = []
    exclusion_ids: set[str] = set()
    for index, raw_exclusion in enumerate(raw_exclusions):
        if not isinstance(raw_exclusion, Mapping) or set(raw_exclusion) != {
            "disposition",
            "id",
            "reason",
            "source_units",
        }:
            raise HarnessError(f"M2 memory-substrate exclusion {index} has unexpected fields")
        exclusion_id = raw_exclusion.get("id")
        disposition = raw_exclusion.get("disposition")
        reason = raw_exclusion.get("reason")
        source_units = raw_exclusion.get("source_units")
        if (
            not isinstance(exclusion_id, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]*", exclusion_id)
            or exclusion_id in exclusion_ids
            or exclusion_id in M2_MEMORY_SUBSTRATE_COMPONENT_IDS
            or disposition not in M2_MEMORY_SUBSTRATE_EXCLUSION_DISPOSITIONS
            or not isinstance(reason, str)
            or not reason
            or not isinstance(source_units, list)
            or not source_units
            or not all(isinstance(unit, str) and unit for unit in source_units)
            or len(set(source_units)) != len(source_units)
        ):
            raise HarnessError(f"M2 memory-substrate exclusion {index} is invalid")
        exclusion_ids.add(exclusion_id)
        exclusions.append(
            {
                "disposition": disposition,
                "id": exclusion_id,
                "reason": reason,
                "source_units": list(source_units),
            }
        )
    return {
        "components": components,
        "exclusions": exclusions,
        "execution": expected_execution,
        "milestone": {
            "completion_rule": milestone["completion_rule"],
            "id": "m2",
            "nonclaims": list(nonclaims),
            "status": milestone["status"],
        },
        "target": expected_target,
    }


def m2_memory_substrate_contract_record(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Bind an M2 report to the checked contract and pinned source."""

    return {
        "format": contract["format"],
        "path": relative(M2_MEMORY_SUBSTRATE_CONTRACT),
        "schema": contract["schema"],
        "sha256": file_digest(M2_MEMORY_SUBSTRATE_CONTRACT),
        "upstream": {
            "archive_sha256": pin["sha256"],
            "revision": pin["revision"],
            "version": pin["version"],
        },
    }


def m2_memory_substrate_check_command(
    execution: Mapping[str, Any], check: Mapping[str, Any]
) -> list[str]:
    """Build one focused M2 Rust unit-test invocation."""

    command = ["cargo", "test", "-p", str(execution["package"])]
    if execution["features"]:
        command.extend(("--features", ",".join(str(feature) for feature in execution["features"])))
    command.extend(("--locked", "--lib", str(check["target"])))
    command.extend(("--", f"--test-threads={execution['test_threads']}", "--nocapture"))
    return command


def run_m2_detached_tld_static_preimage_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the exact detached static-preimage `mi_tld_init` substep."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-detached-tld-static-preimage-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_detached_tld_static_preimage_trace(
            compiler,
            source,
            M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "types::tests::emit_m2_detached_tld_static_preimage_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 detached-TLD static-preimage trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_detached_tld_static_preimage_trace(rust_output, source="Rust")
    validate_m2_detached_tld_static_preimage_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 detached-TLD static-preimage trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_detached_tld_static_preimage_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one direct pinned-C/Rust detached-TLD static-preimage substep: a fresh source-shaped "
            "MI_MEMID_STATIC image receives only src/init.c:192's kind-only static-memid predecessor, "
            "then direct file-static src/init.c:236-250 mi_tld_init writes its subprocess, null Theap "
            "head, fresh lock, and detached NUMA sentinel. The address-free record checks preserved "
            "static fields/provenance, pointer identity only as a relation, lock acquire/release behavior, "
            "and both zero source counters before and after. Its subprocess is a fresh zero-initialized "
            "address-only fixture valid only for this helper, not _mi_subproc_main_init() or main-subprocess "
            "initialization. It does not establish general mi_tld_init or mi_tld_create, the normal branch, "
            "generic/later TLDs, Heap/Theap/list/TLS/root publication, "
            "options or NUMA policy, pthread lock ABI/layout, shutdown/free, races, or allocator integration."
        ),
        "status": comparison["status"],
    }


def run_m2_normal_tld_direct_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the direct normal `mi_tld_init` helper boundary only."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-normal-tld-direct-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_normal_tld_direct_trace(
            compiler,
            source,
            M2_NORMAL_TLD_DIRECT_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "subproc::tests::emit_m2_normal_tld_direct_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 normal-TLD direct-helper trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_normal_tld_direct_trace(rust_output, source="Rust")
    validate_m2_normal_tld_direct_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 normal-TLD direct-helper trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_normal_tld_direct_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one direct pinned-C/Rust non-detached mi_tld_init helper record for src/init.c:236-250: "
            "a fresh all-zero TLD/subprocess minimal read/write preimage receives caller-owned "
            "post-ticket total=8 and tseq=7 context, then proves input identity preservation, field "
            "poststate, unchanged MI_MEM_NONE provenance, total unchanged, and live 0-to-1. Pinned C "
            "independently hooks lock/NUMA/ID/pool/live call order with fixture-injected normalized NUMA=3; "
            "Rust records its production-helper field/counter order after outer prevalidated LiveThreadId "
            "and proves in-place input identity (its test API returns a lease, not a TLD reference). "
            "This does not compare or establish C caller ticket issuance or mi_tld_create allocation, "
            "static-main or metadata construction, _mi_subproc_main_init, Theap/list/TLS/root publication, "
            "general NUMA/options policy, "
            "pthread ABI/layout, teardown/free, races, or allocator integration."
        ),
        "status": comparison["status"],
    }


def run_m2_static_first_tld_create_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the selected first-main static `mi_tld_create` success arm."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-static-first-tld-create-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_static_first_tld_create_trace(
            compiler,
            source,
            M2_STATIC_FIRST_TLD_CREATE_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "main_theap::tests::emit_m2_static_first_tld_create_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 static-first mi_tld_create trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_static_first_tld_create_trace(rust_output, source="Rust")
    validate_m2_static_first_tld_create_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 static-first mi_tld_create trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_static_first_tld_create_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one direct pinned-C/Rust first-main static-TLD create success arm: C directly calls "
            "file-static src/init.c:253-272 mi_tld_create(_mi_subproc_main()) once with the source "
            "main-subprocess/static-TLD identities, zero total/live counters, and only a non-null inert "
            "theap_meta placeholder. It independently proves the selected C order total ticket -> real "
            "main predicate -> concrete static memid -> normal lock/NUMA=3/ID/pool -> live registration, "
            "and that _mi_meta_zalloc was not called. Rust uses its production static ticket/slot path "
            "after its separately modeled heap foundation; the shared address-free record compares the "
            "ticket-zero/static-memid boundary, semantic static-memid fields, selected modeled "
            "normal-body poststate, and a "
            "labeled result-visibility relation: C observes return after live registration while Rust "
            "records the immediately following MAIN_TLD_LIVE Release before an owner can be returned. "
            "It does not claim a common predicate, caller, preflight, primitive, or return-boundary "
            "order: C invokes its thread-ID primitive after NUMA while Rust validates identity before "
            "ticket issue. Nor does it claim literal parity for C predicate timing, source-static byte layout, "
            "_mi_subproc_main_init or actual Theap/metadata initialization, "
            "generic/later or failed arms, Heap/Theap/list/TLS/root publication, teardown/free, races, "
            "pthread ABI/layout, NUMA discovery/options policy, or allocator integration."
        ),
        "status": comparison["status"],
    }


def run_m2_bitmap_abandoned_claim_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the selected pinned-C/Rust abandoned-page bitmap visitor."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-bitmap-claim-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_bitmap_abandoned_claim_trace(
            compiler,
            source,
            M2_BITMAP_ABANDONED_CLAIM_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "bitmap::tests::emit_m2_bitmap_abandoned_claim_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 bitmap abandoned-claim trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_bitmap_abandoned_claim_trace(rust_output, source="Rust")
    validate_m2_bitmap_abandoned_claim_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 bitmap abandoned-claim trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_bitmap_abandoned_claim_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one pinned-C/Rust one-chunk source-snapshot abandoned-page bitmap claim: "
            "a rejected keep-set callback restores bit 17 and its conservative map, a "
            "later accepting callback clears the bit but retains the conservative map, and "
            "a drained probe invokes no callback while repairing that stale map bit. This "
            "does not cover keep-set-false rejection, multi-chunk or tseq distribution, "
            "arena/subprocess ownership, races, clear-once-set, visitors, statistics, "
            "binned bitmaps, or flexible-array allocation ownership."
        ),
        "status": comparison["status"],
    }


def run_m2_bitmap_clear_range_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the selected pinned-C/Rust scalar bitmap range visitor."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-bitmap-range-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_bitmap_clear_range_trace(
            compiler,
            source,
            M2_BITMAP_CLEAR_RANGE_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "bitmap::tests::emit_m2_bitmap_clear_range_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 bitmap clear-range trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_bitmap_clear_range_trace(rust_output, source="Rust")
    validate_m2_bitmap_clear_range_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 bitmap clear-range trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_bitmap_clear_range_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one pinned-C/Rust scalar one-chunk `_mi_bitmap_forall_setc_ranges` "
            "trace: the completed walk emits two ordinary runs and one source-64-bit "
            "field-boundary split while retaining the conservative map; a stopped "
            "walk leaves its visited range clear, restores only its unvisited same-field "
            "residual, and leaves its later field untouched. This does not cover "
            "multi-chunk traversal, `_mi_bitmap_forall_setc_rangesn` policy beyond its "
            "default scalar dispatch, binned bitmaps, arena/subprocess ownership, races, "
            "statistics, or allocator integration."
        ),
        "status": comparison["status"],
    }


def run_m2_bitmap_rangesn_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the selected pinned-C/Rust scalar rangesn wrapper."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-bitmap-rangesn-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_bitmap_rangesn_trace(
            compiler,
            source,
            M2_BITMAP_RANGESN_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "bitmap::tests::emit_m2_bitmap_rangesn_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 bitmap rangesn trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_bitmap_rangesn_trace(rust_output, source="Rust")
    validate_m2_bitmap_rangesn_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 bitmap rangesn trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_bitmap_rangesn_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one pinned-C/Rust scalar one-chunk `_mi_bitmap_forall_setc_rangesn` "
            "trace: fresh `rngslices == 3` images prove aligned completed windows, "
            "partial-window and non-divisible top-suffix restoration, and a stopped "
            "callback restoring its earlier skipped window plus all later snapshot bits; "
            "fresh `0` and `1` calls prove generic maximal-range delegation, and a `65` "
            "call proves the source cap at 64. It does not cover actual minimal-purge/"
            "transparent-huge-page policy, arena/subprocess ownership, multi-chunk or "
            "binned bitmaps, races, statistics, general purge integration, or allocator "
            "integration."
        ),
        "status": comparison["status"],
    }


def run_m2_bitmap_set_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the selected pinned-C/Rust read-only bitmap set-bit visitor."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-bitmap-set-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_bitmap_set_trace(
            compiler,
            source,
            M2_BITMAP_SET_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "bitmap::tests::emit_m2_bitmap_forall_set_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 bitmap set-bit trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_bitmap_set_trace(rust_output, source="Rust")
    validate_m2_bitmap_set_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 bitmap set-bit trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_bitmap_set_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one pinned-C/Rust scalar read-only `_mi_bitmap_forall_set` trace on "
            "fresh valid 65-chunk bitmaps: low-to-high callbacks cross the first "
            "chunk-map field boundary, and a second-callback stop leaves all selected "
            "data and conservative-map fields unchanged. It does not cover Heap/Page/"
            "Arena pointers, `_mi_heap_visit_blocks`, callback mutation, binned "
            "behavior, flexible allocation ownership, arena/subprocess ownership, "
            "races, statistics, or allocator integration."
        ),
        "status": comparison["status"],
    }


def run_m2_binned_bitmap_bsr_inv_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the selected pinned-C/Rust binned inverse-BSR observer."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-binned-bitmap-bsr-inv-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_binned_bitmap_bsr_inv_trace(
            compiler,
            source,
            M2_BINNED_BITMAP_BSR_INV_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "bitmap::tests::emit_m2_binned_bitmap_bsr_inv_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 binned bitmap inverse-BSR trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_binned_bitmap_bsr_inv_trace(rust_output, source="Rust")
    validate_m2_binned_bitmap_bsr_inv_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 binned bitmap inverse-BSR trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_binned_bitmap_bsr_inv_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one pinned-C/Rust binned `mi_bbitmap_bsr_inv` observer trace: a fresh "
            "logical 513-bit image rounds to two chunks and exposes padded bit 1023 "
            "while its conservative chunk map remains empty; a separate fresh two-chunk "
            "image with three cleared bits returns 963, 585, 511, then no result as each "
            "bit is restored without changing that map. This does not cover binned "
            "allocation search, try-find-and-clear/claim paths, chunk-map maintenance or "
            "rollback, stats/subprocess, flexible-array ownership beyond these valid "
            "images, callbacks, races, Heap/Page/Arena integration, allocator routing, "
            "or general bitmap completion."
        ),
        "status": comparison["status"],
    }


def run_m2_page_map_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the selected source-private C PageMap lifecycle with Rust."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-page-map-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_page_map_trace(
            compiler,
            source,
            M2_PAGE_MAP_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "page_map::tests::emit_m2_page_map_init_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 PageMap success trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_page_map_trace(rust_output, source="Rust")
    validate_m2_page_map_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 PageMap success trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_page_map_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "controlled pinned-C src/os.c, src/page-map.c, and src/init.c source-order "
            "producer compared with the Rust PageMap success lifecycle: initial partial "
            "commitment, two-submap lazy extension, lookup/unregister, natural final-boundary "
            "rollback, and an absent post-destroy root. Header-dependent raw counts and the "
            "C-global versus Rust-owner root-unpublication order remain explicit recorded "
            "differences; the cold static-empty-root/once failure difference is excluded."
        ),
        "status": comparison["status"],
    }


def run_m2_page_map_lazy_commit_failure_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Compare the selected initialized PageMap commit failure with Rust."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-page-map-lazy-commit-failure-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_page_map_lazy_commit_failure_trace(
            compiler,
            source,
            M2_PAGE_MAP_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "page_map::tests::emit_m2_page_map_lazy_commit_failure_c_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 PageMap lazy-commit failure trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_page_map_lazy_commit_failure_trace(rust_output, source="Rust")
    validate_m2_page_map_lazy_commit_failure_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 PageMap lazy-commit failure trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_page_map_lazy_commit_failure_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one initialized two-level PageMap lazy-extension commit failure: a test-only "
            "pinned-C lexical `_mi_os_commit` wrapper and Rust's pre-`mprotect` seam each "
            "fail one attempt before committed-prefix publication or submap allocation, retain "
            "the same top-level owner, then retry and publish exactly one submap. It excludes "
            "cold initialization, range rollback, lazy submap-map failure, CAS losers, release "
            "failure, locking/races, allocator routing, and live-kernel or diagnostic parity."
        ),
        "status": comparison["status"],
    }


def run_m2_page_map_cold_init_differential(
    pin: Mapping[str, str], *, offline: bool, timeout_seconds: int
) -> dict[str, Any]:
    """Record the selected C/Rust failed-first PageMap initialization boundary."""

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m2-page-map-cold-init-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m2_page_map_cold_init_trace(
            compiler,
            source,
            M2_PAGE_MAP_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--locked",
        "--lib",
        "process_page_map::tests::emit_m2_page_map_cold_init_failure_rust_trace",
        "--",
        "--test-threads=1",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    rust_result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=timeout_seconds,
    )
    require_success(rust_result, "Rust M2 PageMap cold-init trace")
    rust_output = str(rust_result["stdout"]) + "\n" + str(rust_result["stderr"])
    rust_trace = parse_m2_page_map_cold_init_trace(rust_output, source="Rust")
    validate_m2_page_map_cold_init_trace(rust_trace, source="Rust")
    passed_test_count = parse_rust_test_count(rust_output)
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M2 PageMap cold-init trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m2_page_map_cold_init_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": command,
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "one source-private pinned-C first PageMap allocation failure compared with "
            "the Rust typed process owner. Both records prove one failed init body, no "
            "published dynamic map, and no replay. The C static empty-root/null-lookup "
            "and later-success result versus Rust absent-root/no-cold-lookup-route and typed "
            "poison are explicit safety-divergence fields, not equality claims."
        ),
        "status": comparison["status"],
    }


def run_m2_memory_substrate_checks(
    summary: Mapping[str, Any], pin: Mapping[str, str], *, offline: bool
) -> list[dict[str, Any]]:
    """Run only the explicitly selected M2 checks in a private target directory."""

    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M2_MEMORY_SUBSTRATE_CARGO_TARGET)
    records: list[dict[str, Any]] = []
    for component in summary["components"]:
        for check in component["checks"]:
            if check["kind"] == "c-rust-detached-tld-static-preimage-differential":
                differential = run_m2_detached_tld_static_preimage_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-normal-tld-direct-differential":
                differential = run_m2_normal_tld_direct_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-static-first-tld-create-differential":
                differential = run_m2_static_first_tld_create_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-bitmap-abandoned-claim-differential":
                differential = run_m2_bitmap_abandoned_claim_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-bitmap-clear-range-differential":
                differential = run_m2_bitmap_clear_range_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-bitmap-rangesn-differential":
                differential = run_m2_bitmap_rangesn_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-bitmap-set-differential":
                differential = run_m2_bitmap_set_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-binned-bitmap-bsr-inv-differential":
                differential = run_m2_binned_bitmap_bsr_inv_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-page-map-success-differential":
                differential = run_m2_page_map_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-page-map-lazy-commit-failure-differential":
                differential = run_m2_page_map_lazy_commit_failure_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            if check["kind"] == "c-rust-page-map-cold-init-differential":
                differential = run_m2_page_map_cold_init_differential(
                    pin,
                    offline=offline,
                    timeout_seconds=summary["execution"]["timeout_seconds"],
                )
                records.append(
                    {
                        "c_oracle": differential["c_oracle"],
                        "comparison": differential["comparison"],
                        "component": component["id"],
                        "command": differential["rust"]["command"],
                        "evidence_scope": differential["scope"],
                        "id": check["id"],
                        "passed_test_count": differential["rust"]["passed_test_count"],
                        "target": check["target"],
                        "trace": differential["rust"]["record"],
                    }
                )
                continue
            command = m2_memory_substrate_check_command(summary["execution"], check)
            result = command_record(
                command,
                cwd=ROOT,
                env=environment,
                timeout_seconds=summary["execution"]["timeout_seconds"],
            )
            require_success(result, f"M2 memory-substrate check {check['id']}")
            output = str(result["stdout"]) + "\n" + str(result["stderr"])
            passed_test_count = parse_rust_test_count(output)
            if passed_test_count != check["expected_passed_test_count"]:
                raise HarnessError(
                    f"M2 memory-substrate check {check['id']} passed {passed_test_count} tests; "
                    f"expected {check['expected_passed_test_count']}"
                )
            trace: dict[str, int] | None = None
            if check["kind"] == "rust-page-map-success-trace":
                trace = parse_m2_page_map_trace(output, source="Rust")
                validate_m2_page_map_trace(trace, source="Rust")
            records.append(
                {
                    "component": component["id"],
                    "command": command,
                    "evidence_scope": (
                        "Rust PageMap success lifecycle only"
                        if check["kind"] == "rust-page-map-success-trace"
                        else "focused source test"
                    ),
                    "id": check["id"],
                    "passed_test_count": passed_test_count,
                    "target": check["target"],
                }
            )
            if trace is not None:
                records[-1]["trace"] = trace
    return records


def m2_memory_substrate_source_state() -> dict[str, Any]:
    """Capture a clean current commit before or after the M2 gate."""

    state = runtime_ticket_zero_soak_source_state()
    return validate_runtime_ticket_zero_soak_source_state(state, "M2 memory-substrate source")


def m2_memory_substrate_source_attestation(before: object, after: object) -> dict[str, Any]:
    """Require the report to bind every M2 observation to one clean commit."""

    source_before = validate_runtime_ticket_zero_soak_source_state(
        before, "M2 memory-substrate source before"
    )
    source_after = validate_runtime_ticket_zero_soak_source_state(
        after, "M2 memory-substrate source after"
    )
    if not source_before["worktree_clean"] or not source_after["worktree_clean"]:
        raise HarnessError("M2 memory-substrate requires a clean Git source")
    if source_before != source_after:
        raise HarnessError("M2 memory-substrate source changed during execution")
    return {
        "after": source_after,
        "before": source_before,
        "git_read_environment": dict(RUNTIME_TICKET_ZERO_SOAK_GIT_READ_ENVIRONMENT),
        "unchanged_during_execution": True,
    }


def m2_memory_substrate_report(
    *,
    contract: Mapping[str, Any],
    pin: Mapping[str, str],
    summary: Mapping[str, Any],
    source_attestation: Mapping[str, Any],
    focused_checks: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Render partial M2 evidence without promoting unproved categories."""

    checks_by_component: dict[str, list[dict[str, Any]]] = {
        component["id"]: [] for component in summary["components"]
    }
    for check in focused_checks:
        component_id = check.get("component")
        if component_id not in checks_by_component:
            raise HarnessError("M2 memory-substrate focused check has an unknown component")
        checks_by_component[component_id].append(dict(check))
    components: list[dict[str, Any]] = []
    unmet: list[str] = []
    for component in summary["components"]:
        component_id = component["id"]
        checks = checks_by_component[component_id]
        expected_checks = component["checks"]
        if len(checks) != len(expected_checks):
            raise HarnessError(f"M2 memory-substrate component {component_id} lacks an executed focused check")
        complete = (
            component["completion_status"] == "complete"
            and not component["remaining_conditions"]
        )
        if not complete:
            unmet.append(component_id)
        components.append(
            {
                "completion_status": component["completion_status"],
                "executed_checks": checks,
                "id": component_id,
                "remaining_conditions": list(component["remaining_conditions"]),
                "source_units": list(component["source_units"]),
                "status": "complete" if complete else "partial",
            }
        )
    milestone_complete = summary["milestone"]["status"] == "complete" and not unmet
    return {
        "components": components,
        "contract": m2_memory_substrate_contract_record(contract, pin),
        "exclusions": list(summary["exclusions"]),
        "format": 1,
        "milestone": {
            "completion_rule": summary["milestone"]["completion_rule"],
            "id": "m2",
            "nonclaims": list(summary["milestone"]["nonclaims"]),
            "status": "complete" if milestone_complete else "partial",
            "unmet_component_ids": unmet,
        },
        "schema": "crabc-mimalloc-m2-memory-substrate-report",
        "source": dict(source_attestation),
        "target": dict(summary["target"]),
    }


def m2_memory_substrate_unmet_message(report: Mapping[str, Any]) -> str:
    """Explain an intentional partial M2 result."""

    milestone = report.get("milestone")
    if not isinstance(milestone, Mapping):
        return "M2 memory-substrate report is invalid"
    components = milestone.get("unmet_component_ids")
    if not isinstance(components, list) or not all(isinstance(component, str) for component in components):
        return "M2 memory-substrate report has no valid unmet-component record"
    return (
        "M2 memory substrate remains partial for "
        + ", ".join(components)
        + f"; review {relative(M2_MEMORY_SUBSTRATE_REPORT)}"
    )


def run_m2_memory_substrate(*, offline: bool) -> dict[str, Any]:
    """Execute the current partial M2 gate and bind it to one clean commit."""

    source_before = m2_memory_substrate_source_state()
    pin = load_pin()
    contract = read_json(M2_MEMORY_SUBSTRATE_CONTRACT)
    summary = validate_m2_memory_substrate_contract(contract, pin)
    focused_checks = run_m2_memory_substrate_checks(summary, pin, offline=offline)
    source_after = m2_memory_substrate_source_state()
    report = m2_memory_substrate_report(
        contract=contract,
        pin=pin,
        summary=summary,
        source_attestation=m2_memory_substrate_source_attestation(source_before, source_after),
        focused_checks=focused_checks,
    )
    write_json(M2_MEMORY_SUBSTRATE_REPORT, report)
    return report


def validate_m1_foundations_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str], port_map: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate the finite M1 acceptance contract without promoting M1.

    M1 names only reviewable foundations.  In particular, a true item row in
    ``port-map.toml`` is evidence for that source-shaped item, never an
    implicit claim that the enclosing upstream header or translation unit is
    complete.  The contract therefore carries the selected references,
    focused source tests, and explicit deferred exclusions together.
    """

    expected_keys = {
        "components",
        "exclusions",
        "execution",
        "format",
        "global_evidence",
        "milestone",
        "schema",
        "target",
        "upstream",
    }
    if set(contract) != expected_keys or contract.get("format") != 1 or contract.get(
        "schema"
    ) != "crabc-mimalloc-m1-foundations":
        raise HarnessError("unsupported M1 foundations contract")

    upstream = contract.get("upstream")
    expected_upstream = {
        "archive_sha256": pin["sha256"],
        "revision": pin["revision"],
        "version": pin["version"],
    }
    if not isinstance(upstream, Mapping) or dict(upstream) != expected_upstream:
        raise HarnessError("M1 foundations contract upstream identity mismatch")

    target = contract.get("target")
    expected_target = {
        "architecture": "aarch64",
        "endianness": "little",
        "kernel_baseline": "5.10",
        "os": "linux",
        "rust_target": "aarch64-unknown-linux-musl",
    }
    if not isinstance(target, Mapping) or dict(target) != expected_target:
        raise HarnessError("M1 foundations contract target changed")

    execution = contract.get("execution")
    expected_execution = {
        "features": [],
        "package": "crabc-mimalloc",
        "test_threads": 1,
        "timeout_seconds": 300,
    }
    if not isinstance(execution, Mapping) or dict(execution) != expected_execution:
        raise HarnessError("M1 foundations execution contract changed")

    global_evidence = contract.get("global_evidence")
    if global_evidence != list(M1_FOUNDATIONS_GLOBAL_EVIDENCE):
        raise HarnessError("M1 foundations global evidence inventory changed")

    milestone = contract.get("milestone")
    if not isinstance(milestone, Mapping) or set(milestone) != {
        "completion_rule",
        "id",
        "nonclaims",
        "status",
    }:
        raise HarnessError("M1 foundations contract lacks a milestone record")
    if milestone.get("id") != "m1" or milestone.get("status") not in M1_FOUNDATIONS_COMPONENT_STATUSES:
        raise HarnessError("M1 foundations milestone identity or status is invalid")
    if not isinstance(milestone.get("completion_rule"), str) or not milestone["completion_rule"]:
        raise HarnessError("M1 foundations milestone lacks a completion rule")
    nonclaims = milestone.get("nonclaims")
    if (
        not isinstance(nonclaims, list)
        or not nonclaims
        or not all(isinstance(nonclaim, str) and nonclaim for nonclaim in nonclaims)
        or len(set(nonclaims)) != len(nonclaims)
    ):
        raise HarnessError("M1 foundations milestone lacks a valid nonclaim inventory")

    raw_components = contract.get("components")
    if not isinstance(raw_components, list) or len(raw_components) != len(
        M1_FOUNDATIONS_COMPONENT_IDS
    ):
        raise HarnessError("M1 foundations component inventory changed")

    components: list[dict[str, Any]] = []
    seen_check_ids: set[str] = set()
    for index, raw_component in enumerate(raw_components):
        if not isinstance(raw_component, Mapping):
            raise HarnessError(f"M1 foundations component {index} has unexpected fields")
        component_id = raw_component.get("id")
        expected_component_keys = {
            "checks",
            "completion_status",
            "id",
            "layout_keys",
            "remaining_conditions",
            "source_map_records",
        }
        if component_id == "atomics-locks-once-and-bootstrap":
            expected_component_keys.add("once_call_site_dispositions")
        if component_id == "linux-raw-primitives":
            expected_component_keys.add("prim_h_declaration_inventory")
        if set(raw_component) != expected_component_keys:
            raise HarnessError(f"M1 foundations component {index} has unexpected fields")
        if component_id != M1_FOUNDATIONS_COMPONENT_IDS[index]:
            raise HarnessError("M1 foundations component order or identity changed")
        completion_status = raw_component.get("completion_status")
        if completion_status not in M1_FOUNDATIONS_COMPONENT_STATUSES:
            raise HarnessError(f"M1 foundations component {component_id} has an invalid status")

        raw_remaining_conditions = raw_component.get("remaining_conditions")
        if (
            not isinstance(raw_remaining_conditions, list)
            or not all(
                isinstance(condition, str) and condition
                for condition in raw_remaining_conditions
            )
            or len(set(raw_remaining_conditions)) != len(raw_remaining_conditions)
        ):
            raise HarnessError(
                f"M1 foundations component {component_id} has invalid remaining conditions"
            )
        if completion_status == "partial" and not raw_remaining_conditions:
            raise HarnessError(
                f"M1 foundations partial component {component_id} must name its remaining conditions"
            )
        if completion_status == "complete" and raw_remaining_conditions:
            raise HarnessError(
                f"M1 foundations complete component {component_id} retains conditions"
            )

        raw_layout_keys = raw_component.get("layout_keys")
        if (
            not isinstance(raw_layout_keys, list)
            or not all(isinstance(key, str) and key for key in raw_layout_keys)
            or len(set(raw_layout_keys)) != len(raw_layout_keys)
        ):
            raise HarnessError(f"M1 foundations component {component_id} has invalid layout keys")
        if (
            component_id == "configuration-and-arithmetic"
            and raw_layout_keys != list(M1_CONFIGURATION_AND_ARITHMETIC_LAYOUT_KEYS)
        ):
            raise HarnessError(
                "M1 configuration-and-arithmetic must retain the complete "
                "frozen configuration and scalar layout inventory"
            )
        if (
            component_id == "atomics-locks-once-and-bootstrap"
            and raw_layout_keys != list(M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEYS)
        ):
            raise HarnessError(
                "M1 bootstrap must retain the complete immutable static-image "
                "relational vector"
            )

        once_call_site_dispositions: list[dict[str, str]] = []
        if component_id == "atomics-locks-once-and-bootstrap":
            raw_once_call_site_dispositions = raw_component.get(
                "once_call_site_dispositions"
            )
            if raw_once_call_site_dispositions != list(
                M1_BOOTSTRAP_ATOMIC_ONCE_CALL_SITE_DISPOSITIONS
            ):
                raise HarnessError(
                    "M1 bootstrap must retain every pinned mi_atomic_do_once "
                    "call-site disposition"
                )
            once_call_site_dispositions = [
                dict(disposition)
                for disposition in M1_BOOTSTRAP_ATOMIC_ONCE_CALL_SITE_DISPOSITIONS
            ]

        raw_references = raw_component.get("source_map_records")
        if not isinstance(raw_references, list) or not raw_references:
            raise HarnessError(f"M1 foundations component {component_id} lacks source-map records")
        references: list[dict[str, Any]] = []
        reference_keys: set[tuple[str, str, str]] = set()
        for reference_index, raw_reference in enumerate(raw_references):
            if not isinstance(raw_reference, Mapping):
                raise HarnessError(
                    f"M1 foundations component {component_id} source-map record {reference_index} is not an object"
                )
            kind = raw_reference.get("kind")
            expected_reference_keys = (
                {"kind", "required_statuses", "upstream"}
                if kind == "unit"
                else {"kind", "name", "required_statuses", "upstream"}
            )
            if kind not in {"item", "unit"} or set(raw_reference) != expected_reference_keys:
                raise HarnessError(
                    f"M1 foundations component {component_id} source-map record {reference_index} has unexpected fields"
                )
            upstream_path = raw_reference.get("upstream")
            name = raw_reference.get("name", "")
            if not isinstance(upstream_path, str) or not upstream_path:
                raise HarnessError(
                    f"M1 foundations component {component_id} source-map record {reference_index} has invalid upstream path"
                )
            if kind == "item" and (not isinstance(name, str) or not name):
                raise HarnessError(
                    f"M1 foundations component {component_id} source-map record {reference_index} has invalid name"
                )
            reference_key = (kind, upstream_path, str(name))
            if reference_key in reference_keys:
                raise HarnessError(
                    f"M1 foundations component {component_id} repeats source-map record {kind}:{upstream_path}:{name}"
                )
            reference_keys.add(reference_key)
            statuses = raw_reference.get("required_statuses")
            if (
                not isinstance(statuses, list)
                or not statuses
                or not all(status in STATUS_FIELDS for status in statuses)
                or len(set(statuses)) != len(statuses)
            ):
                raise HarnessError(
                    f"M1 foundations component {component_id} source-map record {reference_index} has invalid statuses"
                )
            reference = {
                "kind": kind,
                "required_statuses": list(statuses),
                "upstream": upstream_path,
            }
            if kind == "item":
                reference["name"] = name
            port_record = _m1_foundations_port_map_record(port_map, reference)
            missing_statuses = [
                status for status in statuses if port_record.get(status) is not True
            ]
            if missing_statuses:
                record_name = "" if kind == "unit" else f":{name}"
                raise HarnessError(
                    "M1 foundations source-map record lacks required status "
                    f"{kind}:{upstream_path}{record_name}: {', '.join(missing_statuses)}"
                )
            references.append(reference)

        declaration_inventory: list[dict[str, str]] = []
        if component_id == "linux-raw-primitives":
            raw_declaration_inventory = raw_component.get("prim_h_declaration_inventory")
            if not isinstance(raw_declaration_inventory, list):
                raise HarnessError(
                    "M1 foundations raw primitive declaration inventory is invalid"
                )
            source_map_item_names = {
                reference["name"]
                for reference in references
                if reference["kind"] == "item"
            }
            for declaration_index, raw_declaration in enumerate(raw_declaration_inventory):
                if not isinstance(raw_declaration, Mapping) or set(raw_declaration) != {
                    "classification",
                    "name",
                    "record_id",
                }:
                    raise HarnessError(
                        "M1 foundations raw primitive declaration "
                        f"{declaration_index} has unexpected fields"
                    )
                name = raw_declaration.get("name")
                classification = raw_declaration.get("classification")
                record_id = raw_declaration.get("record_id")
                if (
                    not isinstance(name, str)
                    or not isinstance(record_id, str)
                    or classification not in M1_RAW_PRIMITIVE_DECLARATION_CLASSIFICATIONS
                ):
                    raise HarnessError(
                        "M1 foundations raw primitive declaration "
                        f"{declaration_index} is invalid"
                    )
                if (
                    classification == "m1-raw-boundary"
                    and record_id not in source_map_item_names
                ):
                    raise HarnessError(
                        "M1 foundations raw primitive declaration "
                        f"{name} lacks a current source-map witness"
                    )
                declaration_inventory.append(
                    {
                        "classification": classification,
                        "name": name,
                        "record_id": record_id,
                    }
                )
            if [declaration["name"] for declaration in declaration_inventory] != list(
                M1_RAW_PRIMITIVE_DECLARATIONS
            ):
                raise HarnessError(
                    "M1 foundations raw primitive declaration inventory changed"
                )

        raw_checks = raw_component.get("checks")
        if not isinstance(raw_checks, list) or not raw_checks:
            raise HarnessError(f"M1 foundations component {component_id} lacks checks")
        checks: list[dict[str, Any]] = []
        for check_index, raw_check in enumerate(raw_checks):
            if not isinstance(raw_check, Mapping) or set(raw_check) != {
                "expected_passed_test_count",
                "id",
                "target",
            }:
                raise HarnessError(
                    f"M1 foundations component {component_id} check {check_index} has unexpected fields"
                )
            check_id = raw_check.get("id")
            target_name = raw_check.get("target")
            expected_passed_test_count = raw_check.get("expected_passed_test_count")
            if (
                not isinstance(check_id, str)
                or not re.fullmatch(r"[a-z][a-z0-9-]*", check_id)
                or check_id in seen_check_ids
            ):
                raise HarnessError(
                    f"M1 foundations component {component_id} check {check_index} has an invalid id"
                )
            if (
                not isinstance(target_name, str)
                or not re.fullmatch(r"[a-z_][a-z0-9_]*(?:::[a-z_][a-z0-9_]*)+", target_name)
            ):
                raise HarnessError(
                    f"M1 foundations component {component_id} check {check_id} has an invalid target"
                )
            if (
                not isinstance(expected_passed_test_count, int)
                or isinstance(expected_passed_test_count, bool)
                or expected_passed_test_count <= 0
            ):
                raise HarnessError(
                    f"M1 foundations component {component_id} check {check_id} has an invalid expected test count"
                )
            _m1_foundations_source_test_exists(target_name, check_id)
            seen_check_ids.add(check_id)
            checks.append(
                {
                    "expected_passed_test_count": expected_passed_test_count,
                    "id": check_id,
                    "target": target_name,
                }
            )

        component = {
            "checks": checks,
            "completion_status": completion_status,
            "id": component_id,
            "layout_keys": list(raw_layout_keys),
            "remaining_conditions": list(raw_remaining_conditions),
            "source_map_records": references,
        }
        if component_id == "atomics-locks-once-and-bootstrap":
            component["once_call_site_dispositions"] = once_call_site_dispositions
        if component_id == "linux-raw-primitives":
            component["prim_h_declaration_inventory"] = declaration_inventory
        components.append(component)

    complete_components = all(
        component["completion_status"] == "complete" for component in components
    )
    if (milestone["status"] == "complete") != complete_components:
        raise HarnessError(
            "M1 foundations milestone status must match its component completion states"
        )

    raw_exclusions = contract.get("exclusions")
    if not isinstance(raw_exclusions, list) or not raw_exclusions:
        raise HarnessError("M1 foundations contract lacks explicit exclusions")
    exclusions: list[dict[str, Any]] = []
    exclusion_ids: set[str] = set()
    for index, raw_exclusion in enumerate(raw_exclusions):
        if not isinstance(raw_exclusion, Mapping) or set(raw_exclusion) != {
            "disposition",
            "id",
            "reason",
            "upstream_paths",
        }:
            raise HarnessError(f"M1 foundations exclusion {index} has unexpected fields")
        exclusion_id = raw_exclusion.get("id")
        disposition = raw_exclusion.get("disposition")
        reason = raw_exclusion.get("reason")
        paths = raw_exclusion.get("upstream_paths")
        if (
            not isinstance(exclusion_id, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]*", exclusion_id)
            or exclusion_id in exclusion_ids
            or exclusion_id in M1_FOUNDATIONS_COMPONENT_IDS
        ):
            raise HarnessError(f"M1 foundations exclusion {index} has an invalid id")
        if disposition not in M1_FOUNDATIONS_EXCLUSION_DISPOSITIONS:
            raise HarnessError(f"M1 foundations exclusion {exclusion_id} has an invalid disposition")
        if not isinstance(reason, str) or not reason:
            raise HarnessError(f"M1 foundations exclusion {exclusion_id} has no reason")
        if (
            not isinstance(paths, list)
            or not paths
            or not all(isinstance(path, str) and path for path in paths)
            or len(set(paths)) != len(paths)
        ):
            raise HarnessError(f"M1 foundations exclusion {exclusion_id} has invalid upstream paths")
        exclusion_ids.add(exclusion_id)
        exclusions.append(
            {
                "disposition": disposition,
                "id": exclusion_id,
                "reason": reason,
                "upstream_paths": list(paths),
            }
        )

    exclusions_by_id = {exclusion["id"]: exclusion for exclusion in exclusions}
    raw_primitive_component = next(
        component
        for component in components
        if component["id"] == "linux-raw-primitives"
    )
    for declaration in raw_primitive_component["prim_h_declaration_inventory"]:
        if declaration["classification"] != "later-milestone-exclusion":
            continue
        exclusion = exclusions_by_id.get(declaration["record_id"])
        if exclusion is None:
            raise HarnessError(
                "M1 foundations raw primitive declaration "
                f"{declaration['name']} lacks an explicit exclusion"
            )
        if not exclusion["disposition"].startswith("deferred-to-m"):
            raise HarnessError(
                "M1 foundations raw primitive declaration "
                f"{declaration['name']} lacks a later-milestone exclusion"
            )

    return {
        "components": components,
        "exclusions": exclusions,
        "execution": expected_execution,
        "global_evidence": list(M1_FOUNDATIONS_GLOBAL_EVIDENCE),
        "milestone": {
            "completion_rule": milestone["completion_rule"],
            "id": "m1",
            "nonclaims": list(nonclaims),
            "status": milestone["status"],
        },
        "target": expected_target,
    }


def _m1_x86_64_neutral_inventory() -> list[dict[str, Any]]:
    """Read only target-neutral M1 inputs from the preserved AArch64 record.

    The old M1 manifest is retained as the canonical spelling of the finite
    source filters and selected C/Rust layout vectors.  This helper
    intentionally does not read its target, component statuses, source-map
    claims, exclusions, or report state: those belong to the paused AArch64
    contract and cannot establish any native x86 result.
    """

    contract = read_json(M1_FOUNDATIONS_CONTRACT)
    raw_components = contract.get("components")
    if not isinstance(raw_components, list) or len(raw_components) != len(
        M1_FOUNDATIONS_COMPONENT_IDS
    ):
        raise HarnessError("shared M1 source inventory has an invalid component count")

    inventory: list[dict[str, Any]] = []
    seen_checks: set[str] = set()
    for index, raw_component in enumerate(raw_components):
        if not isinstance(raw_component, Mapping):
            raise HarnessError("shared M1 source inventory has an invalid component")
        component_id = raw_component.get("id")
        if component_id != M1_FOUNDATIONS_COMPONENT_IDS[index]:
            raise HarnessError("shared M1 source inventory component order changed")
        raw_checks = raw_component.get("checks")
        raw_layout_keys = raw_component.get("layout_keys")
        if not isinstance(raw_checks, list) or not isinstance(raw_layout_keys, list):
            raise HarnessError(f"shared M1 source inventory {component_id} is incomplete")

        checks: list[dict[str, Any]] = []
        for check in raw_checks:
            if not isinstance(check, Mapping) or set(check) != {
                "expected_passed_test_count",
                "id",
                "target",
            }:
                raise HarnessError(
                    f"shared M1 source inventory {component_id} has an invalid test check"
                )
            check_id = check.get("id")
            target = check.get("target")
            expected_passed_test_count = check.get("expected_passed_test_count")
            if (
                not isinstance(check_id, str)
                or not check_id
                or check_id in seen_checks
                or not isinstance(target, str)
                or not target
                or type(expected_passed_test_count) is not int
                or expected_passed_test_count <= 0
            ):
                raise HarnessError(
                    f"shared M1 source inventory {component_id} has an invalid test check"
                )
            _m1_foundations_source_test_exists(target, check_id)
            seen_checks.add(check_id)
            checks.append(
                {
                    "expected_passed_test_count": expected_passed_test_count,
                    "id": check_id,
                    "target": target,
                }
            )
        if (
            not all(isinstance(key, str) and key for key in raw_layout_keys)
            or len(set(raw_layout_keys)) != len(raw_layout_keys)
        ):
            raise HarnessError(
                f"shared M1 source inventory {component_id} has an invalid layout vector"
            )
        inventory.append(
            {
                "checks": checks,
                "id": component_id,
                "layout_keys": list(raw_layout_keys),
            }
        )
    return inventory


def _m1_inventory_digest(value: object) -> str:
    """Hash one exact, order-independent JSON source inventory value."""

    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    ).hexdigest()


def validate_x86_64_m1_foundations_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Validate the native x86 M1 execution contract without importing closure.

    This contract deliberately records a *ready* implementation boundary. A
    completion result is created only by `run_x86_64_m1_foundations` after its
    native oracle, Rust target, and clean-source observations have all passed.
    """

    expected_keys = {
        "components",
        "execution",
        "format",
        "global_evidence",
        "milestone",
        "neutral_inventory",
        "schema",
        "source_contracts",
        "target",
        "upstream",
    }
    if (
        set(contract) != expected_keys
        or contract.get("format") != 1
        or contract.get("schema") != "crabc-mimalloc-x86_64-m1-foundations"
    ):
        raise HarnessError("unsupported native x86 M1 foundations contract")

    expected_upstream = {
        "archive_sha256": pin["sha256"],
        "revision": pin["revision"],
        "version": pin["version"],
    }
    if contract.get("upstream") != expected_upstream:
        raise HarnessError("native x86 M1 foundations upstream identity mismatch")
    expected_target = {
        "architecture": "x86_64",
        "endianness": "little",
        "kernel_baseline": "5.10",
        "os": "linux",
        "rust_target": X86_64_RUST_TARGET,
    }
    if contract.get("target") != expected_target:
        raise HarnessError("native x86 M1 foundations target changed")
    expected_execution = {
        "features": [],
        "no_default_features": True,
        "package": "crabc-mimalloc",
        "rust_target": X86_64_RUST_TARGET,
        "test_threads": 1,
        "timeout_seconds": 300,
    }
    if contract.get("execution") != expected_execution:
        raise HarnessError("native x86 M1 foundations execution contract changed")

    expected_evidence = [
        "release-c-rust-layout",
        "release-static-bootstrap-image",
        "raw-primitive-c-rust-trace",
        "compiler-tls-c-rust-trace",
        "compiler-tls-same-tld-terminal-c-rust-trace",
        "compiler-tls-codegen",
        "x86-64-normal-engine-dependency-graph",
        "x86-64-source-contract-inventories",
    ]
    if contract.get("global_evidence") != expected_evidence:
        raise HarnessError("native x86 M1 foundations global evidence inventory changed")

    milestone = contract.get("milestone")
    if not isinstance(milestone, Mapping) or set(milestone) != {
        "completion_rule",
        "id",
        "nonclaims",
        "status",
    }:
        raise HarnessError("native x86 M1 foundations lacks a milestone record")
    if (
        milestone.get("id") != "m1"
        or milestone.get("status") != M1_X86_64_FOUNDATIONS_COMPONENT_STATUS
        or not isinstance(milestone.get("completion_rule"), str)
        or not milestone["completion_rule"]
    ):
        raise HarnessError("native x86 M1 foundations milestone identity or state changed")
    nonclaims = milestone.get("nonclaims")
    if (
        not isinstance(nonclaims, list)
        or len(nonclaims) != 4
        or not all(isinstance(nonclaim, str) and nonclaim for nonclaim in nonclaims)
        or len(set(nonclaims)) != len(nonclaims)
    ):
        raise HarnessError("native x86 M1 foundations nonclaim inventory changed")

    neutral_inventory = _m1_x86_64_neutral_inventory()
    expected_inventory_components = [
        {
            "check_count": len(component["checks"]),
            "checks_sha256": _m1_inventory_digest(component["checks"]),
            "id": component["id"],
            "layout_key_count": len(component["layout_keys"]),
            "layout_keys_sha256": _m1_inventory_digest(component["layout_keys"]),
        }
        for component in neutral_inventory
    ]
    expected_neutral_inventory = {
        "components": expected_inventory_components,
        "purpose": (
            "Exact check filters and selected layout-key vectors shared as source-shaped M1 "
            "inputs only. Their canonical JSON counts and digests are checked before x86 "
            "execution; no AArch64 component status, report, or source-map status is imported."
        ),
        "source_contract": {
            "path": relative(M1_FOUNDATIONS_CONTRACT),
            "sha256": file_digest(M1_FOUNDATIONS_CONTRACT),
        },
    }
    if contract.get("neutral_inventory") != expected_neutral_inventory:
        raise HarnessError("native x86 M1 exact source-check or layout inventory changed")

    raw_components = contract.get("components")
    if not isinstance(raw_components, list) or len(raw_components) != len(neutral_inventory):
        raise HarnessError("native x86 M1 component inventory changed")
    components: list[dict[str, Any]] = []
    for index, raw_component in enumerate(raw_components):
        if not isinstance(raw_component, Mapping) or set(raw_component) != {
            "id",
            "native_status",
            "remaining_conditions",
        }:
            raise HarnessError(f"native x86 M1 component {index} has unexpected fields")
        neutral_component = neutral_inventory[index]
        component_id = raw_component.get("id")
        if component_id != neutral_component["id"]:
            raise HarnessError("native x86 M1 component order or identity changed")
        if raw_component.get("native_status") != M1_X86_64_FOUNDATIONS_COMPONENT_STATUS:
            raise HarnessError(f"native x86 M1 component {component_id} has an invalid readiness state")
        if raw_component.get("remaining_conditions") != []:
            raise HarnessError(f"native x86 M1 component {component_id} has unreviewed conditions")
        components.append(
            {
                "checks": list(neutral_component["checks"]),
                "id": component_id,
                "layout_keys": list(neutral_component["layout_keys"]),
                "native_status": M1_X86_64_FOUNDATIONS_COMPONENT_STATUS,
                "remaining_conditions": [],
                "source_map_records": [],
            }
        )

    expected_source_contracts = [
        relative(X86_64_API_CONTRACT),
        relative(X86_64_API_COVERAGE_CONTRACT),
        relative(X86_64_SOURCE_MAP_CONTRACT),
    ]
    if contract.get("source_contracts") != expected_source_contracts:
        raise HarnessError("native x86 M1 source-contract inventory changed")
    for source_contract in (
        X86_64_API_CONTRACT,
        X86_64_API_COVERAGE_CONTRACT,
        X86_64_SOURCE_MAP_CONTRACT,
    ):
        if not source_contract.is_file():
            raise HarnessError(f"native x86 M1 source contract is absent: {source_contract}")

    return {
        "components": components,
        "execution": expected_execution,
        "global_evidence": expected_evidence,
        "exclusions": [],
        "milestone": {
            "completion_rule": milestone["completion_rule"],
            "id": "m1",
            "nonclaims": list(nonclaims),
            "status": M1_X86_64_FOUNDATIONS_COMPONENT_STATUS,
        },
        "source_contracts": expected_source_contracts,
        "target": expected_target,
    }


def m1_foundations_contract_record(
    contract: Mapping[str, Any], pin: Mapping[str, str], *, contract_path: Path = M1_FOUNDATIONS_CONTRACT
) -> dict[str, Any]:
    """Render the checked contract identity retained in each M1 report."""

    return {
        "format": contract["format"],
        "path": relative(contract_path),
        "schema": contract["schema"],
        "sha256": file_digest(contract_path),
        "upstream": {
            "archive_sha256": pin["sha256"],
            "revision": pin["revision"],
            "version": pin["version"],
        },
    }


def m1_foundations_check_command(
    execution: Mapping[str, Any], check: Mapping[str, Any]
) -> list[str]:
    """Build one focused, source-filtered M1 Cargo invocation."""

    command = ["cargo", "test", "-p", str(execution["package"])]
    if execution.get("no_default_features") is True:
        command.append("--no-default-features")
    rust_target = execution.get("rust_target")
    if rust_target is not None:
        if not isinstance(rust_target, str) or not rust_target:
            raise HarnessError("M1 foundations execution has an invalid Rust target")
        command.extend(("--target", rust_target))
    features = execution["features"]
    if features:
        command.extend(("--features", ",".join(str(feature) for feature in features)))
    command.extend(("--locked", "--lib", str(check["target"])))
    command.extend(("--", f"--test-threads={execution['test_threads']}"))
    return command


def _m1_foundations_test_program(
    execution: Mapping[str, Any], cargo_target: Path
) -> dict[str, Any]:
    """Build the M1 unit binary once in a target-private Cargo directory.

    M1 names many small source-shaped assertions. Building Cargo separately
    for each would turn test accounting into a cache-timing accident.  The
    gate instead records one `--no-run` build, lists that exact binary, and
    runs a closed batch after explicitly skipping every non-M1 test.
    """

    command = ["cargo", "test", "-p", str(execution["package"])]
    if execution.get("no_default_features") is True:
        command.append("--no-default-features")
    rust_target = execution.get("rust_target")
    if rust_target is not None:
        command.extend(("--target", str(rust_target)))
    command.extend(("--locked", "--lib", "--no-run", "--message-format=json"))
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_TARGET_DIR"] = str(cargo_target)
    result = command_record(
        command,
        cwd=ROOT,
        env=environment,
        timeout_seconds=execution["timeout_seconds"],
    )
    require_success(result, "M1 foundations unit-binary build")
    candidates: list[Path] = []
    for line in (str(result["stdout"]) + "\n" + str(result["stderr"])).splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, Mapping) or event.get("reason") != "compiler-artifact":
            continue
        target = event.get("target")
        profile = event.get("profile")
        executable = event.get("executable")
        if (
            isinstance(target, Mapping)
            and target.get("name") == "crabc_mimalloc"
            and target.get("kind") == ["lib"]
            and isinstance(profile, Mapping)
            and profile.get("test") is True
            and isinstance(executable, str)
        ):
            candidates.append(Path(executable))
    if len(candidates) != 1 or not candidates[0].is_file():
        raise HarnessError("M1 foundations build did not produce exactly one library test binary")
    return {
        "build_command": command,
        "cargo_target": str(cargo_target),
        "execution": dict(execution),
        "path": candidates[0],
    }


def _m1_foundations_test_names(
    test_program: Mapping[str, Any], *, timeout_seconds: int
) -> set[str]:
    """List all test names in the one already-built M1 unit binary."""

    path = test_program.get("path")
    if not isinstance(path, Path) or not path.is_file():
        raise HarnessError("M1 foundations test program is unavailable")
    command = [str(path), "--list"]
    result = command_record(command, cwd=ROOT, timeout_seconds=timeout_seconds)
    require_success(result, "M1 foundations unit-binary test inventory")
    names = {
        line.removesuffix(": test")
        for line in str(result["stdout"]).splitlines()
        if line.endswith(": test")
    }
    if not names:
        raise HarnessError("M1 foundations unit-binary test inventory is empty")
    return names


def _m1_foundations_program_check_command(
    test_program: Mapping[str, Any], target: str, *, nocapture: bool
) -> list[str]:
    """Run one exact named source witness from the prepared M1 binary."""

    path = test_program.get("path")
    if not isinstance(path, Path) or not path.is_file():
        raise HarnessError("M1 foundations test program is unavailable")
    execution = test_program.get("execution")
    if not isinstance(execution, Mapping):
        raise HarnessError("M1 foundations test program lacks its execution contract")
    command = [
        str(path),
        target,
        "--exact",
        f"--test-threads={execution['test_threads']}",
    ]
    if nocapture:
        command.append("--nocapture")
    return command


def _m1_foundations_run_exact_program_check(
    test_program: Mapping[str, Any], check: Mapping[str, Any], *, nocapture: bool
) -> tuple[dict[str, Any], str]:
    """Execute and account for one existing M1 test binary filter."""

    execution = test_program["execution"]
    assert isinstance(execution, Mapping)
    command = _m1_foundations_program_check_command(
        test_program, str(check["target"]), nocapture=nocapture
    )
    result = command_record(
        command,
        cwd=ROOT,
        timeout_seconds=int(execution["timeout_seconds"]),
    )
    require_success(result, f"M1 foundations check {check['id']}")
    output = str(result["stdout"]) + "\n" + str(result["stderr"])
    passed_test_count = parse_rust_test_count(output)
    if passed_test_count != check["expected_passed_test_count"]:
        raise HarnessError(
            f"M1 foundations check {check['id']} passed {passed_test_count} tests; "
            f"expected {check['expected_passed_test_count']}"
        )
    return {
        "command": command,
        "passed_test_count": passed_test_count,
        "target": check["target"],
    }, output


def run_m1_foundations_checks(
    summary: Mapping[str, Any],
    test_program: Mapping[str, Any],
    *,
    already_executed_check_ids: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Run all remaining M1 source checks in one closed unit-binary batch."""

    execution = summary["execution"]
    assert isinstance(execution, Mapping)
    all_checks = [
        (component["id"], check)
        for component in summary["components"]
        for check in component["checks"]
    ]
    all_check_ids = [str(check["id"]) for _, check in all_checks]
    if len(set(all_check_ids)) != len(all_check_ids):
        raise HarnessError("M1 foundations has duplicate focused check identities")
    unknown_preexecuted = sorted(set(already_executed_check_ids) - set(all_check_ids))
    if unknown_preexecuted:
        raise HarnessError(
            "M1 foundations batch received unknown pre-executed checks: "
            + ", ".join(unknown_preexecuted)
        )
    selected = [
        (component_id, check)
        for component_id, check in all_checks
        if check["id"] not in already_executed_check_ids
    ]
    if not selected:
        return []

    test_names = _m1_foundations_test_names(
        test_program, timeout_seconds=int(execution["timeout_seconds"])
    )
    selected_targets = {str(check["target"]) for _, check in selected}
    missing = sorted(selected_targets - test_names)
    if missing:
        raise HarnessError(
            "M1 foundations unit binary lacks selected source tests: " + ", ".join(missing)
        )
    command = [
        str(test_program["path"]),
        f"--test-threads={execution['test_threads']}",
        *(entry for test_name in sorted(test_names - selected_targets) for entry in ("--skip", test_name)),
    ]
    result = command_record(
        command,
        cwd=ROOT,
        timeout_seconds=int(execution["timeout_seconds"]),
    )
    require_success(result, "M1 foundations focused source-test batch")
    output = str(result["stdout"]) + "\n" + str(result["stderr"])
    expected_count = sum(int(check["expected_passed_test_count"]) for _, check in selected)
    passed_test_count = parse_rust_test_count(output)
    if passed_test_count != expected_count:
        raise HarnessError(
            f"M1 foundations focused batch passed {passed_test_count} tests; expected {expected_count}"
        )
    passed_targets = set(
        re.findall(r"(?m)^test ([^\s]+) \.\.\. ok$", output)
    )
    absent_targets = sorted(selected_targets - passed_targets)
    if absent_targets:
        raise HarnessError(
            "M1 foundations focused batch did not pass every selected source test: "
            + ", ".join(absent_targets)
        )
    return [
        {
            "component": component_id,
            "command": command,
            "evidence_scope": "focused-source-test-batch",
            "id": check["id"],
            "passed_test_count": check["expected_passed_test_count"],
            "target": check["target"],
        }
        for component_id, check in selected
    ]


def run_m1_raw_primitive_differential(
    pin: Mapping[str, str],
    *,
    offline: bool,
    timeout_seconds: int,
    architecture: str = "aarch64",
    artifact_root: Path = M1_RAW_PRIMITIVE_TRACE_ARTIFACT_ROOT,
    test_program: Mapping[str, Any] | None = None,
    check: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare the finite raw M1 record against a freshly extracted C oracle.

    The C and Rust executions are separate processes by design.  Their record
    compares only stable source-relative values, so no process address, random
    byte sequence, or timestamp is treated as differential evidence.
    """

    require_native_architecture(architecture)
    if test_program is None or check is None:
        raise HarnessError("M1 raw differential requires its prepared Rust test program")
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m1-raw-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m1_raw_primitive_trace(
            compiler,
            source,
            artifact_root,
            CONFIGURATION_PROFILES["release"],
        )

    if check.get("target") != "os::tests::emit_m1_raw_c_rust_trace":
        raise HarnessError("M1 raw differential lost its exact Rust source witness")
    rust, rust_output = _m1_foundations_run_exact_program_check(
        test_program, check, nocapture=True
    )
    rust_trace = parse_m1_raw_primitive_trace(rust_output)
    validate_m1_raw_primitive_trace_schema(rust_trace, source="Rust")
    passed_test_count = rust["passed_test_count"]
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M1 raw-primitive trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m1_raw_primitive_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": rust["command"],
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "pinned C src/os.c and selected Unix primitive normal-success paths only; "
            "no addresses, random bytes, exact clocks, errno/fallback branches, options, "
            "hints, huge/THP routes, or allocator lifecycle integration"
        ),
        "status": comparison["status"],
    }


def run_m1_compiler_tls_differential(
    pin: Mapping[str, str],
    *,
    offline: bool,
    timeout_seconds: int,
    architecture: str = "aarch64",
    artifact_root: Path = M1_COMPILER_TLS_TRACE_ARTIFACT_ROOT,
    test_program: Mapping[str, Any] | None = None,
    check: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare the finite compiler-TLS roots/primitives with pinned C.

    The initial root image is intentionally a constructor-suppressed C
    reader, while the regular-reset and cached-root pair run in a normal C
    artifact. The Rust test emits their fixed address-independent union, but
    makes no composite ``mi_thread_theaps_done`` lifecycle claim.
    """

    require_native_architecture(architecture)
    if test_program is None or check is None:
        raise HarnessError("M1 compiler-TLS differential requires its prepared Rust test program")
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m1-compiler-tls-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m1_compiler_tls_trace(
            compiler,
            source,
            artifact_root,
            CONFIGURATION_PROFILES["release"],
        )

    if check.get("target") != "dynamic_theap::tests::emit_m1_compiler_tls_c_rust_trace":
        raise HarnessError("M1 compiler-TLS differential lost its exact Rust source witness")
    rust, rust_output = _m1_foundations_run_exact_program_check(
        test_program, check, nocapture=True
    )
    rust_trace = parse_m1_compiler_tls_trace(rust_output)
    validate_m1_compiler_tls_full_trace(rust_trace, source="Rust")
    passed_test_count = rust["passed_test_count"]
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M1 compiler-TLS trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m1_compiler_tls_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": rust["command"],
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "constructor-suppressed pinned-C root image plus ordinary pinned-C "
            "threadlocal.c positive-count regular reset and a controlled no-page C "
            "prim-tls.c cached-root/reference pair only; no _mi_thread_done, "
            "mi_thread_theaps_done, same-TLD default/cached terminal reset, shared-list "
            "detach, page-bearing owner, pthread/process hook, or public allocator lifecycle"
        ),
        "status": comparison["status"],
    }


def run_m1_compiler_tls_same_tld_differential(
    pin: Mapping[str, str],
    *,
    offline: bool,
    timeout_seconds: int,
    architecture: str = "aarch64",
    artifact_root: Path = M1_COMPILER_TLS_SAME_TLD_TRACE_ARTIFACT_ROOT,
    test_program: Mapping[str, Any] | None = None,
    check: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare the selected page-free same-TLD terminal body with pinned C.

    This remains separate from the 32-field compiler-TLS trace: that trace
    proves the constructor-suppressed root image and independent regular
    backing/cached-reference transitions, while this normal-artifact trace
    reaches the exact file-static `mi_thread_theaps_done` body on one finite
    D/A list. Neither record substitutes for the other.
    """

    require_native_architecture(architecture)
    if test_program is None or check is None:
        raise HarnessError(
            "M1 compiler-TLS same-TLD differential requires its prepared Rust test program"
        )
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m1-compiler-tls-same-tld-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m1_compiler_tls_same_tld_trace(
            compiler,
            source,
            artifact_root,
            CONFIGURATION_PROFILES["release"],
        )

    if check.get("target") != "main_theap::tests::emit_m1_same_tld_terminal_c_rust_trace":
        raise HarnessError("M1 compiler-TLS same-TLD differential lost its exact Rust source witness")
    rust, rust_output = _m1_foundations_run_exact_program_check(
        test_program, check, nocapture=True
    )
    rust_trace = parse_m1_compiler_tls_same_tld_trace(rust_output)
    validate_m1_compiler_tls_same_tld_trace(rust_trace, source="Rust")
    passed_test_count = rust["passed_test_count"]
    if passed_test_count != 1:
        raise HarnessError(
            "Rust M1 compiler-TLS same-TLD terminal trace passed an unexpected test count: "
            f"{passed_test_count}"
        )
    comparison = compare_m1_compiler_tls_same_tld_trace(c_oracle["record"], rust_trace)
    return {
        "c_oracle": c_oracle,
        "comparison": comparison,
        "rust": {
            "command": rust["command"],
            "passed_test_count": passed_test_count,
            "record": rust_trace,
        },
        "scope": (
            "normal-artifact probe direct-includes pinned src/init.c and invokes file-static "
            "mi_thread_theaps_done on one page-free D/A same-TLD fixture, comparing 40 "
            "address-independent terminal relations. Rust exercises the generic queue-half "
            "empty branch with ordered empty-prepass witnesses, not production prepasses. "
            "C bounds main-Heap membership as "
            "metadata+D then metadata-only; Rust's selected static image is D then empty, "
            "so only common D membership/absence relations compare. Rust metadata/key/backing "
            "retirement is post-trace fixture cleanup. Setup plus _Exit deliberately exclude "
            "_mi_thread_done, regular-backing/fast teardown, stats, TLD free, process hooks, "
            "page-bearing collection, production deferred/retired prepasses, and public heap lifecycle"
        ),
        "status": comparison["status"],
    }


def m1_foundations_layout_evidence(
    components: Sequence[Mapping[str, Any]],
    c_layout: Mapping[str, int],
    rust_layout: Mapping[str, int],
    *,
    static_image_c_layout: Mapping[str, int],
) -> dict[str, dict[str, Any]]:
    """Classify declared M1 keys against their exact C reader boundary."""

    evidence: dict[str, dict[str, Any]] = {}
    for component in components:
        keys = component["layout_keys"]
        if not keys:
            evidence[component["id"]] = {
                "keys": [],
                "status": "not-applicable",
            }
            continue
        component_c_layout = (
            static_image_c_layout
            if component["id"] == "atomics-locks-once-and-bootstrap"
            else c_layout
        )
        missing_from_c = sorted(key for key in keys if key not in component_c_layout)
        if missing_from_c:
            raise HarnessError(
                "M1 foundations required C layout keys are absent for "
                f"{component['id']}: {', '.join(missing_from_c)}"
            )
        missing_from_rust = sorted(key for key in keys if key not in rust_layout)
        mismatches = [
            f"{key} (C={component_c_layout[key]}, Rust={rust_layout[key]})"
            for key in keys
            if key in rust_layout and component_c_layout[key] != rust_layout[key]
        ]
        evidence[component["id"]] = {
            "keys": list(keys),
            "missing_from_rust": missing_from_rust,
            "mismatches": mismatches,
            "status": "matched" if not missing_from_rust and not mismatches else "pending",
        }
    return evidence


def m1_foundations_source_state() -> dict[str, Any]:
    """Capture a clean current commit before or after the finite M1 gate."""

    state = runtime_ticket_zero_soak_source_state()
    return validate_runtime_ticket_zero_soak_source_state(state, "M1 foundations source")


def m1_foundations_source_attestation(before: object, after: object) -> dict[str, Any]:
    """Require the report to bind every M1 observation to one clean commit."""

    source_before = validate_runtime_ticket_zero_soak_source_state(
        before, "M1 foundations source before"
    )
    source_after = validate_runtime_ticket_zero_soak_source_state(
        after, "M1 foundations source after"
    )
    if not source_before["worktree_clean"] or not source_after["worktree_clean"]:
        raise HarnessError("M1 foundations requires a clean Git source")
    if source_before != source_after:
        raise HarnessError("M1 foundations source changed during execution")
    return {
        "after": source_after,
        "before": source_before,
        "git_read_environment": dict(RUNTIME_TICKET_ZERO_SOAK_GIT_READ_ENVIRONMENT),
        "unchanged_during_execution": True,
    }


def m1_foundations_report(
    *,
    contract: Mapping[str, Any],
    pin: Mapping[str, str],
    summary: Mapping[str, Any],
    source_attestation: Mapping[str, Any],
    shared_oracle: Mapping[str, Any],
    raw_primitive_differential: Mapping[str, Any],
    compiler_tls_differential: Mapping[str, Any],
    compiler_tls_same_tld_differential: Mapping[str, Any],
    focused_checks: Sequence[Mapping[str, Any]],
    contract_path: Path = M1_FOUNDATIONS_CONTRACT,
    report_schema: str = "crabc-mimalloc-m1-foundations-report",
    component_status_key: str = "completion_status",
    completion_ready_statuses: frozenset[str] = frozenset({"complete"}),
    dependency_graph_key: str = "production_dependency_graph",
) -> dict[str, Any]:
    """Render a current-commit M1 evidence report without changing its status."""

    c_oracle = shared_oracle.get("c_oracle")
    rust_release_layout = shared_oracle.get("rust_release_layout")
    if not isinstance(c_oracle, Mapping) or not isinstance(rust_release_layout, Mapping):
        raise HarnessError("M1 foundations shared oracle lacks release layout evidence")
    profiles = c_oracle.get("profiles")
    if not isinstance(profiles, Mapping) or not isinstance(profiles.get("release"), Mapping):
        raise HarnessError("M1 foundations shared oracle lacks the release profile")
    release = profiles["release"]
    c_layout = release.get("layout")
    rust_layout = rust_release_layout.get("layout")
    if not isinstance(c_layout, Mapping) or not isinstance(rust_layout, Mapping):
        raise HarnessError("M1 foundations shared oracle release layout is invalid")
    static_image_probe = release.get("m1_static_image_probe")
    if not isinstance(static_image_probe, Mapping):
        raise HarnessError("M1 foundations shared oracle lacks the static-image reader")
    static_image_c_layout = static_image_probe.get("layout")
    if not isinstance(static_image_c_layout, Mapping):
        raise HarnessError("M1 foundations static-image reader layout is invalid")
    if static_image_probe.get("defines") != list(M1_BOOTSTRAP_STATIC_IMAGE_PROBE_DEFINES):
        raise HarnessError("M1 foundations static-image reader define boundary changed")
    layout_evidence = m1_foundations_layout_evidence(
        summary["components"],
        c_layout,
        rust_layout,
        static_image_c_layout=static_image_c_layout,
    )

    compiler_tls = shared_oracle.get("compiler_tls_codegen")
    dependency_graph = shared_oracle.get(dependency_graph_key)
    if not isinstance(compiler_tls, Mapping) or compiler_tls.get("status") != "passed":
        raise HarnessError("M1 foundations compiler-TLS codegen evidence did not pass")
    if not isinstance(dependency_graph, Mapping):
        raise HarnessError("M1 foundations target dependency evidence is absent")
    if (
        not isinstance(raw_primitive_differential, Mapping)
        or raw_primitive_differential.get("status") != "matched"
    ):
        raise HarnessError("M1 foundations raw C/Rust differential evidence did not match")
    raw_comparison = raw_primitive_differential.get("comparison")
    raw_c_oracle = raw_primitive_differential.get("c_oracle")
    raw_rust = raw_primitive_differential.get("rust")
    if (
        not isinstance(raw_comparison, Mapping)
        or raw_comparison.get("status") != "matched"
        or not isinstance(raw_c_oracle, Mapping)
        or not isinstance(raw_rust, Mapping)
    ):
        raise HarnessError("M1 foundations raw C/Rust differential record is invalid")
    if (
        not isinstance(compiler_tls_differential, Mapping)
        or compiler_tls_differential.get("status") != "matched"
    ):
        raise HarnessError("M1 foundations compiler-TLS C/Rust differential did not match")
    compiler_tls_comparison = compiler_tls_differential.get("comparison")
    compiler_tls_c_oracle = compiler_tls_differential.get("c_oracle")
    compiler_tls_rust = compiler_tls_differential.get("rust")
    if (
        not isinstance(compiler_tls_comparison, Mapping)
        or compiler_tls_comparison.get("status") != "matched"
        or not isinstance(compiler_tls_c_oracle, Mapping)
        or not isinstance(compiler_tls_rust, Mapping)
    ):
        raise HarnessError("M1 foundations compiler-TLS C/Rust differential record is invalid")
    if (
        not isinstance(compiler_tls_same_tld_differential, Mapping)
        or compiler_tls_same_tld_differential.get("status") != "matched"
    ):
        raise HarnessError(
            "M1 foundations compiler-TLS same-TLD terminal C/Rust differential did not match"
        )
    compiler_tls_same_tld_comparison = compiler_tls_same_tld_differential.get("comparison")
    compiler_tls_same_tld_c_oracle = compiler_tls_same_tld_differential.get("c_oracle")
    compiler_tls_same_tld_rust = compiler_tls_same_tld_differential.get("rust")
    if (
        not isinstance(compiler_tls_same_tld_comparison, Mapping)
        or compiler_tls_same_tld_comparison.get("status") != "matched"
        or not isinstance(compiler_tls_same_tld_c_oracle, Mapping)
        or not isinstance(compiler_tls_same_tld_rust, Mapping)
    ):
        raise HarnessError(
            "M1 foundations compiler-TLS same-TLD terminal C/Rust differential record is invalid"
        )

    checks_by_component: dict[str, list[dict[str, Any]]] = {
        component["id"]: [] for component in summary["components"]
    }
    for check in focused_checks:
        component_id = check.get("component")
        if component_id not in checks_by_component:
            raise HarnessError("M1 foundations focused check has an unknown component")
        checks_by_component[component_id].append(dict(check))

    components: list[dict[str, Any]] = []
    incomplete_components: list[str] = []
    for component in summary["components"]:
        component_id = component["id"]
        checks = checks_by_component[component_id]
        if len(checks) != len(component["checks"]):
            raise HarnessError(
                f"M1 foundations component {component_id} lacks an executed focused check"
            )
        layout = layout_evidence[component_id]
        raw_trace_matched = (
            component_id != "linux-raw-primitives" or raw_comparison["status"] == "matched"
        )
        compiler_tls_trace_matched = (
            component_id != "compiler-tls-roots"
            or compiler_tls_comparison["status"] == "matched"
        )
        compiler_tls_same_tld_trace_matched = (
            component_id != "compiler-tls-roots"
            or compiler_tls_same_tld_comparison["status"] == "matched"
        )
        component_status = component.get(component_status_key)
        complete = (
            component_status in completion_ready_statuses
            and not component["remaining_conditions"]
            and layout["status"] in {"matched", "not-applicable"}
            and raw_trace_matched
            and compiler_tls_trace_matched
            and compiler_tls_same_tld_trace_matched
        )
        if not complete:
            incomplete_components.append(component_id)
        report_component = {
            "completion_status": component_status,
            "executed_checks": checks,
            "id": component_id,
            "layout_evidence": layout,
            "remaining_conditions": list(component["remaining_conditions"]),
            "source_map_records": list(component["source_map_records"]),
            "status": "complete" if complete else "partial",
        }
        if (
            component_id == "atomics-locks-once-and-bootstrap"
            and "once_call_site_dispositions" in component
        ):
            report_component["once_call_site_dispositions"] = list(
                component["once_call_site_dispositions"]
            )
        if component_id == "linux-raw-primitives":
            if "prim_h_declaration_inventory" in component:
                report_component["prim_h_declaration_inventory"] = list(
                    component["prim_h_declaration_inventory"]
                )
            report_component["c_rust_differential"] = {
                "compared_value_count": raw_comparison.get("compared_value_count"),
                "status": raw_comparison["status"],
            }
        if component_id == "compiler-tls-roots":
            report_component["c_rust_differential"] = {
                "compared_value_count": compiler_tls_comparison.get("compared_value_count"),
                "status": compiler_tls_comparison["status"],
            }
            report_component["same_tld_terminal_c_rust_differential"] = {
                "compared_value_count": compiler_tls_same_tld_comparison.get(
                    "compared_value_count"
                ),
                "status": compiler_tls_same_tld_comparison["status"],
            }
        components.append(report_component)

    milestone_complete = summary["milestone"]["status"] in completion_ready_statuses and not incomplete_components
    release_layout_artifact = release.get("artifact")
    if not isinstance(release_layout_artifact, Mapping):
        raise HarnessError("M1 foundations shared release profile lacks its artifact record")
    generic_rust_layout = generic_layout_without_m1_static_reader_fields(rust_layout)
    return {
        "components": components,
        "contract": m1_foundations_contract_record(contract, pin, contract_path=contract_path),
        "exclusions": list(summary["exclusions"]),
        "format": 1,
        "milestone": {
            "completion_rule": summary["milestone"]["completion_rule"],
            "id": "m1",
            "nonclaims": list(summary["milestone"]["nonclaims"]),
            "status": "complete" if milestone_complete else "partial",
            "unmet_component_ids": incomplete_components,
        },
        "schema": report_schema,
        "shared_evidence": {
            "compiler_tls_codegen": {
                "status": compiler_tls["status"],
            },
            "compiler_tls_c_rust_trace": {
                "c_source_files": compiler_tls_c_oracle.get("source_files"),
                "compared_value_count": compiler_tls_comparison.get("compared_value_count"),
                "rust_passed_test_count": compiler_tls_rust.get("passed_test_count"),
                "scope": compiler_tls_differential.get("scope"),
                "status": compiler_tls_comparison["status"],
            },
            "compiler_tls_same_tld_terminal_c_rust_trace": {
                "c_source_files": compiler_tls_same_tld_c_oracle.get("source_files"),
                "compared_value_count": compiler_tls_same_tld_comparison.get(
                    "compared_value_count"
                ),
                "rust_passed_test_count": compiler_tls_same_tld_rust.get("passed_test_count"),
                "scope": compiler_tls_same_tld_differential.get("scope"),
                "status": compiler_tls_same_tld_comparison["status"],
            },
            dependency_graph_key: {
                "status": "recorded",
            },
            "raw_primitive_c_rust_trace": {
                "c_source_files": raw_c_oracle.get("source_files"),
                "compared_value_count": raw_comparison.get("compared_value_count"),
                "rust_passed_test_count": raw_rust.get("passed_test_count"),
                "scope": raw_primitive_differential.get("scope"),
                "status": raw_comparison["status"],
            },
            "release_c_rust_layout": {
                "c_layout_key_count": len(c_layout),
                "c_release_artifact": dict(release_layout_artifact),
                "rust_layout_key_count": len(generic_rust_layout),
                "rust_subset_comparison": rust_release_layout.get("comparison"),
                "scope": (
                    "The ordinary release artifact and generic layout reader retain their "
                    "normal automatic-attach configuration. M1 consumes only the "
                    "component-declared generic keys; the shared oracle's broader M0/M3/M4 "
                    "traces are supporting producers, not M1 closure."
                ),
            },
            "release_static_bootstrap_image": {
                "c_layout_key_count": len(static_image_c_layout),
                "defines": list(M1_BOOTSTRAP_STATIC_IMAGE_PROBE_DEFINES),
                "rust_layout_key_count": len(M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEYS),
                "scope": (
                    "A separate static-image-only C reader defines "
                    "MI_PRIM_HAS_PROCESS_ATTACH=1 only to observe the src/init.c "
                    "initializer before prim.c auto-attach; it is not an artifact, "
                    "generic-layout, runtime, or lifecycle claim."
                ),
            },
        },
        "source": dict(source_attestation),
        "target": dict(summary["target"]),
    }


def _m1_foundations_check_by_id(
    summary: Mapping[str, Any], check_id: str
) -> tuple[str, Mapping[str, Any]]:
    """Resolve one named M1 differential witness from the validated inventory."""

    matches = [
        (str(component["id"]), check)
        for component in summary["components"]
        for check in component["checks"]
        if check["id"] == check_id
    ]
    if len(matches) != 1:
        raise HarnessError(f"M1 foundations lacks exactly one required differential check: {check_id}")
    return matches[0]


def _m1_foundations_differential_check_record(
    component_id: str, check: Mapping[str, Any], differential: Mapping[str, Any]
) -> dict[str, Any]:
    """Retain a trace test as one exact focused M1 check without rerunning it."""

    rust = differential.get("rust")
    if not isinstance(rust, Mapping):
        raise HarnessError(f"M1 foundations differential {check['id']} lacks a Rust record")
    if rust.get("passed_test_count") != check["expected_passed_test_count"]:
        raise HarnessError(f"M1 foundations differential {check['id']} has an invalid Rust count")
    return {
        "component": component_id,
        "command": list(rust["command"]),
        "evidence_scope": "focused-source-test-and-c-rust-differential",
        "id": check["id"],
        "passed_test_count": rust["passed_test_count"],
        "target": check["target"],
    }


def run_m1_foundations(*, offline: bool) -> dict[str, Any]:
    """Execute and record the finite M1 gate, including a clean-commit binding."""

    source_before = m1_foundations_source_state()
    pin = load_pin()
    contract = read_json(M1_FOUNDATIONS_CONTRACT)
    port_map = load_port_map()
    summary = validate_m1_foundations_contract(contract, pin, port_map)
    test_program = _m1_foundations_test_program(summary["execution"], M1_FOUNDATIONS_CARGO_TARGET)
    shared_oracle = run_milestone0(
        offline=offline,
        generate_contracts=False,
        check_only=False,
        architecture="aarch64",
        write_report=False,
    )
    raw_primitive_differential = run_m1_raw_primitive_differential(
        pin,
        offline=offline,
        timeout_seconds=summary["execution"]["timeout_seconds"],
        test_program=test_program,
        check=_m1_foundations_check_by_id(summary, "raw-primitive-c-rust-trace")[1],
    )
    compiler_tls_differential = run_m1_compiler_tls_differential(
        pin,
        offline=offline,
        timeout_seconds=summary["execution"]["timeout_seconds"],
        test_program=test_program,
        check=_m1_foundations_check_by_id(summary, "compiler-tls-c-rust-trace")[1],
    )
    compiler_tls_same_tld_differential = run_m1_compiler_tls_same_tld_differential(
        pin,
        offline=offline,
        timeout_seconds=summary["execution"]["timeout_seconds"],
        test_program=test_program,
        check=_m1_foundations_check_by_id(
            summary, "compiler-tls-same-tld-terminal-c-rust-trace"
        )[1],
    )
    raw_component, raw_check = _m1_foundations_check_by_id(
        summary, "raw-primitive-c-rust-trace"
    )
    compiler_tls_component, compiler_tls_check = _m1_foundations_check_by_id(
        summary, "compiler-tls-c-rust-trace"
    )
    same_tld_component, same_tld_check = _m1_foundations_check_by_id(
        summary, "compiler-tls-same-tld-terminal-c-rust-trace"
    )
    focused_checks = [
        _m1_foundations_differential_check_record(
            raw_component, raw_check, raw_primitive_differential
        ),
        _m1_foundations_differential_check_record(
            compiler_tls_component, compiler_tls_check, compiler_tls_differential
        ),
        _m1_foundations_differential_check_record(
            same_tld_component, same_tld_check, compiler_tls_same_tld_differential
        ),
        *run_m1_foundations_checks(
            summary,
            test_program,
            already_executed_check_ids=frozenset(
                {
                    raw_check["id"],
                    compiler_tls_check["id"],
                    same_tld_check["id"],
                }
            ),
        ),
    ]
    source_after = m1_foundations_source_state()
    report = m1_foundations_report(
        contract=contract,
        pin=pin,
        summary=summary,
        source_attestation=m1_foundations_source_attestation(source_before, source_after),
        shared_oracle=shared_oracle,
        raw_primitive_differential=raw_primitive_differential,
        compiler_tls_differential=compiler_tls_differential,
        compiler_tls_same_tld_differential=compiler_tls_same_tld_differential,
        focused_checks=focused_checks,
    )
    write_json(M1_FOUNDATIONS_REPORT, report)
    return report


def _m1_x86_64_source_contract_evidence(shared_oracle: Mapping[str, Any]) -> dict[str, Any]:
    """Bind M1 to the target-local source inventories checked by the x86 oracle."""

    api_inventory = shared_oracle.get("x86_64_source_api_inventory")
    api_coverage = shared_oracle.get("x86_64_api_coverage")
    source_map = shared_oracle.get("x86_64_source_map")
    if (
        not isinstance(api_inventory, Mapping)
        or api_inventory.get("status") != "passed"
        or not isinstance(api_coverage, Mapping)
        or api_coverage.get("status") != "passed"
        or not isinstance(source_map, Mapping)
        or source_map.get("status") != "passed"
    ):
        raise HarnessError("native x86 M1 source-contract inventories did not pass")
    # The target-wide maps intentionally remain incomplete. Their successful
    # validation proves exact source accounting, not M1 closure; the finite
    # M1 source tests and native C/Rust records above carry that behavior proof.
    if api_coverage.get("overall_status") != "incomplete" or source_map.get("overall_status") != "incomplete":
        raise HarnessError("native x86 M1 source-contract inventory scope changed")
    return {
        "api_coverage": {
            "contract": artifact_record(X86_64_API_COVERAGE_CONTRACT),
            "overall_status": api_coverage["overall_status"],
            "status": api_coverage["status"],
        },
        "api_inventory": {
            "contract": artifact_record(X86_64_API_CONTRACT),
            "declaration_count": api_inventory["declaration_count"],
            "status": api_inventory["status"],
        },
        "scope": (
            "target-local checked source inventories; their incomplete whole-engine "
            "status is explicit and does not reduce the finite M1 native evidence gate"
        ),
        "source_map": {
            "contract": artifact_record(X86_64_SOURCE_MAP_CONTRACT),
            "overall_status": source_map["overall_status"],
            "status": source_map["status"],
        },
        "status": "passed",
    }


def _m1_x86_64_static_image_baseline(
    pin: Mapping[str, str], *, offline: bool
) -> dict[str, Any]:
    """Build the x86-only C static-image reader without re-running quick.

    The native quick oracle already supplies the ordinary release C artifact,
    layout, traces, adapter, and direct Rust evidence. M1 adds this one
    constructor-suppressed reader because its pre-attach static image is a
    different C boundary, not because x86 inherits the AArch64 reader.
    """

    require_native_x86_64()
    compiler = require_tool("musl-gcc")
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m1-x86_64-static-image-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        return build_m1_static_image_probe(
            compiler,
            source,
            M1_X86_64_STATIC_IMAGE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )


def run_x86_64_m1_foundations(*, offline: bool) -> dict[str, Any]:
    """Execute the native x86 M1 contract and write only x86 evidence.

    This path intentionally consumes the full native x86 M0 oracle rather
    than an AArch64 report or a source-only check. It therefore waits for the
    private x86 adapter baseline as well as the exact M1 C/Rust witnesses.
    """

    require_native_x86_64()
    source_before = m1_foundations_source_state()
    pin = load_pin()
    contract = read_json(M1_X86_64_FOUNDATIONS_CONTRACT)
    summary = validate_x86_64_m1_foundations_contract(contract, pin)
    test_program = _m1_foundations_test_program(
        summary["execution"], M1_X86_64_FOUNDATIONS_CARGO_TARGET
    )
    shared_oracle = run_milestone0(
        offline=offline,
        generate_contracts=False,
        check_only=False,
        architecture="x86_64",
        write_report=False,
    )
    if shared_oracle.get("architecture_profile") != "x86_64-native-c-oracle":
        raise HarnessError("native x86 M1 received a non-x86 shared oracle")
    source_contract_evidence = _m1_x86_64_source_contract_evidence(shared_oracle)
    c_oracle = shared_oracle.get("c_oracle")
    if not isinstance(c_oracle, Mapping):
        raise HarnessError("native x86 M1 shared oracle lacks C evidence")
    profiles = c_oracle.get("profiles")
    if not isinstance(profiles, Mapping) or not isinstance(profiles.get("release"), dict):
        raise HarnessError("native x86 M1 shared oracle lacks its release profile")
    profiles["release"]["m1_static_image_probe"] = _m1_x86_64_static_image_baseline(
        pin, offline=offline
    )

    raw_component, raw_check = _m1_foundations_check_by_id(
        summary, "raw-primitive-c-rust-trace"
    )
    compiler_tls_component, compiler_tls_check = _m1_foundations_check_by_id(
        summary, "compiler-tls-c-rust-trace"
    )
    same_tld_component, same_tld_check = _m1_foundations_check_by_id(
        summary, "compiler-tls-same-tld-terminal-c-rust-trace"
    )
    raw_primitive_differential = run_m1_raw_primitive_differential(
        pin,
        offline=offline,
        timeout_seconds=summary["execution"]["timeout_seconds"],
        architecture="x86_64",
        artifact_root=M1_X86_64_RAW_PRIMITIVE_TRACE_ARTIFACT_ROOT,
        test_program=test_program,
        check=raw_check,
    )
    compiler_tls_differential = run_m1_compiler_tls_differential(
        pin,
        offline=offline,
        timeout_seconds=summary["execution"]["timeout_seconds"],
        architecture="x86_64",
        artifact_root=M1_X86_64_COMPILER_TLS_TRACE_ARTIFACT_ROOT,
        test_program=test_program,
        check=compiler_tls_check,
    )
    compiler_tls_same_tld_differential = run_m1_compiler_tls_same_tld_differential(
        pin,
        offline=offline,
        timeout_seconds=summary["execution"]["timeout_seconds"],
        architecture="x86_64",
        artifact_root=M1_X86_64_COMPILER_TLS_SAME_TLD_TRACE_ARTIFACT_ROOT,
        test_program=test_program,
        check=same_tld_check,
    )
    focused_checks = [
        _m1_foundations_differential_check_record(
            raw_component, raw_check, raw_primitive_differential
        ),
        _m1_foundations_differential_check_record(
            compiler_tls_component, compiler_tls_check, compiler_tls_differential
        ),
        _m1_foundations_differential_check_record(
            same_tld_component, same_tld_check, compiler_tls_same_tld_differential
        ),
        *run_m1_foundations_checks(
            summary,
            test_program,
            already_executed_check_ids=frozenset(
                {
                    raw_check["id"],
                    compiler_tls_check["id"],
                    same_tld_check["id"],
                }
            ),
        ),
    ]
    source_after = m1_foundations_source_state()
    normalized_shared_oracle = {
        "c_oracle": c_oracle,
        "compiler_tls_codegen": shared_oracle.get("compiler_tls_codegen"),
        "rust_release_layout": shared_oracle.get("rust_direct_engine"),
        "x86_64_normal_engine_dependency_graph": shared_oracle.get(
            "x86_64_engine_dependency_graph"
        ),
    }
    report = m1_foundations_report(
        contract=contract,
        pin=pin,
        summary=summary,
        source_attestation=m1_foundations_source_attestation(source_before, source_after),
        shared_oracle=normalized_shared_oracle,
        raw_primitive_differential=raw_primitive_differential,
        compiler_tls_differential=compiler_tls_differential,
        compiler_tls_same_tld_differential=compiler_tls_same_tld_differential,
        focused_checks=focused_checks,
        contract_path=M1_X86_64_FOUNDATIONS_CONTRACT,
        report_schema="crabc-mimalloc-x86_64-m1-foundations-report",
        component_status_key="native_status",
        completion_ready_statuses=frozenset({M1_X86_64_FOUNDATIONS_COMPONENT_STATUS}),
        dependency_graph_key="x86_64_normal_engine_dependency_graph",
    )
    report["shared_evidence"]["x86-64-source-contract-inventories"] = source_contract_evidence
    report["source_contracts"] = source_contract_evidence
    write_json(M1_X86_64_FOUNDATIONS_REPORT, report)
    return report


def m1_foundations_unmet_message(
    report: Mapping[str, Any], *, report_path: Path = M1_FOUNDATIONS_REPORT
) -> str:
    """Explain an intentional M1 partial result without calling it a test failure."""

    milestone = report.get("milestone")
    if not isinstance(milestone, Mapping):
        return "M1 foundations report is invalid"
    components = milestone.get("unmet_component_ids")
    if not isinstance(components, list) or not all(isinstance(component, str) for component in components):
        return "M1 foundations report has no valid unmet-component record"
    return (
        "M1 foundations remain partial for "
        + ", ".join(components)
        + f"; review {relative(report_path)}"
    )


def source_function_body(source_text: str, *, path: str, function: str) -> str:
    """Return one simple C function body from pinned source text.

    This is deliberately only an audit helper, not a C parser. The owner-exit
    anchors are ordinary v3.5.0 definitions with one balanced outer body. By
    refusing an absent or ambiguous definition, it fails closed if the pinned
    source shape changes instead of scanning unrelated call sites.
    """

    definition = re.compile(
        rf"\b{re.escape(function)}\s*\([^{{}};]*\)\s*\{{",
        re.DOTALL,
    )
    matches = list(definition.finditer(source_text))
    if len(matches) != 1:
        raise HarnessError(
            f"owner-exit source fact {path}:{function} has no unique C definition"
        )
    opening = matches[0].end() - 1
    depth = 0
    for index in range(opening, len(source_text)):
        character = source_text[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source_text[opening + 1 : index]
    raise HarnessError(f"owner-exit source fact {path}:{function} has an unclosed body")


def validate_owner_exit_publication_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str], source: Path
) -> dict[str, int]:
    """Audit the pinned owner-exit publication order without claiming a port.

    A page that survives collection cannot be exposed as merely "old raw page
    plus block": queue membership has been detached, `xthread_id` now carries
    an abandoned identity, and the route has either published its exact arena
    bitmap/count capability or its exact non-arena OS-list member before the
    common unown operation. An empty page instead takes its terminal release
    branch. The contract keeps the old Wave 03/W07 Loom-only claim from being
    promoted into a reconstruction authority after any of those transitions.
    """

    if (
        contract.get("schema") != "crabc-mimalloc-owner-exit-publication-contract"
        or contract.get("format") != 1
    ):
        raise HarnessError("unsupported owner-exit publication contract")
    upstream = contract.get("upstream")
    expected_upstream = {
        "archive_sha256": pin["sha256"],
        "revision": pin["revision"],
        "version": pin["version"],
    }
    if not isinstance(upstream, Mapping) or dict(upstream) != expected_upstream:
        raise HarnessError("owner-exit publication contract upstream identity mismatch")

    expected_scope = {
        "candidate_evidence": False,
        "completion_status": "blocked",
        "general_owner_exit_claimed": False,
        "private_source_order_contract": True,
        "public_allocator_backend": False,
    }
    if contract.get("scope") != expected_scope:
        raise HarnessError("owner-exit publication contract scope changed")

    raw_facts = contract.get("source_facts")
    if not isinstance(raw_facts, list) or len(raw_facts) != len(
        OWNER_EXIT_PUBLICATION_SOURCE_FACT_SHAPES
    ):
        raise HarnessError("owner-exit publication contract has an invalid source-fact inventory")
    facts: dict[str, Mapping[str, Any]] = {}
    for index, fact in enumerate(raw_facts):
        if not isinstance(fact, Mapping) or set(fact) != {
            "function",
            "id",
            "ordered_markers",
            "path",
        }:
            raise HarnessError(f"owner-exit source fact {index} has unexpected fields")
        fact_id = fact.get("id")
        if (
            not isinstance(fact_id, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]*", fact_id)
            or fact_id in facts
            or fact_id not in OWNER_EXIT_PUBLICATION_SOURCE_FACT_SHAPES
        ):
            raise HarnessError(f"owner-exit source fact {index} has an invalid id")
        expected_path, expected_function = OWNER_EXIT_PUBLICATION_SOURCE_FACT_SHAPES[fact_id]
        if fact.get("path") != expected_path or fact.get("function") != expected_function:
            raise HarnessError(f"owner-exit source fact {fact_id} changed its pinned anchor")
        markers = fact.get("ordered_markers")
        if (
            not isinstance(markers, list)
            or len(markers) < 3
            or not all(isinstance(marker, str) and marker for marker in markers)
            or len(set(markers)) != len(markers)
        ):
            raise HarnessError(f"owner-exit source fact {fact_id} has invalid ordered markers")
        facts[fact_id] = fact
    if set(facts) != set(OWNER_EXIT_PUBLICATION_SOURCE_FACT_SHAPES):
        raise HarnessError("owner-exit publication contract omits a required source fact")

    raw_transition = contract.get("transition")
    if not isinstance(raw_transition, Mapping) or set(raw_transition) != {
        "empty_terminal_release",
        "publication_routes",
        "unmapped_nonpublication",
    }:
        raise HarnessError("owner-exit publication contract has an invalid transition inventory")

    raw_routes = raw_transition.get("publication_routes")
    if not isinstance(raw_routes, list) or len(raw_routes) != len(
        OWNER_EXIT_PUBLICATION_ROUTE_SHAPES
    ):
        raise HarnessError("owner-exit publication contract has an invalid publication-route inventory")
    routes: dict[str, Mapping[str, Any]] = {}
    for index, route in enumerate(raw_routes):
        if not isinstance(route, Mapping) or set(route) != {
            "id",
            "sequence",
            "source_fact_ids",
        }:
            raise HarnessError(f"owner-exit publication route {index} has unexpected fields")
        route_id = route.get("id")
        if not isinstance(route_id, str) or route_id in routes:
            raise HarnessError(f"owner-exit publication route {index} has an invalid id")
        expected_route = OWNER_EXIT_PUBLICATION_ROUTE_SHAPES.get(route_id)
        if expected_route is None:
            raise HarnessError(f"owner-exit publication route {route_id} is not pinned")
        if (
            route.get("sequence") != expected_route["sequence"]
            or route.get("source_fact_ids") != expected_route["source_fact_ids"]
        ):
            raise HarnessError(
                f"owner-exit publication route {route_id} changed its source order"
            )
        routes[route_id] = route
    if set(routes) != set(OWNER_EXIT_PUBLICATION_ROUTE_SHAPES):
        raise HarnessError("owner-exit publication contract omits a publication route")

    empty_terminal = raw_transition.get("empty_terminal_release")
    expected_empty_terminal = {
        "disposition": "terminal-release-without-abandon-publication",
        "forbidden_transition_events": OWNER_EXIT_EMPTY_TERMINAL_FORBIDDEN_EVENTS,
        "source_fact_ids": [
            "empty-owner-exit-terminal-release",
            "empty-abandoned-terminal-release",
        ],
    }
    if empty_terminal != expected_empty_terminal:
        raise HarnessError("owner-exit empty terminal release contract changed")
    unmapped_nonpublication = raw_transition.get("unmapped_nonpublication")
    if (
        not isinstance(unmapped_nonpublication, Mapping)
        or set(unmapped_nonpublication) != {"counts_as_publication_route", "meaning"}
        or unmapped_nonpublication.get("counts_as_publication_route") is not False
        or not isinstance(unmapped_nonpublication.get("meaning"), str)
        or not unmapped_nonpublication["meaning"]
    ):
        raise HarnessError("owner-exit unmapped nonpublication boundary changed")

    stale_w07_claim = contract.get("stale_w07_claim")
    expected_stale_w07_keys = {
        "claim_reconstruction",
        "forbidden_evidence",
        "forbidden_reconstruction_inputs",
        "required_authority",
        "status",
    }
    if not isinstance(stale_w07_claim, Mapping) or set(stale_w07_claim) != expected_stale_w07_keys:
        raise HarnessError("stale W07 claim contract has unexpected fields")
    if (
        stale_w07_claim.get("claim_reconstruction") != "forbidden"
        or stale_w07_claim.get("status") != "prohibited"
        or stale_w07_claim.get("forbidden_reconstruction_inputs")
        != OWNER_EXIT_STALE_W07_FORBIDDEN_INPUTS
        or stale_w07_claim.get("forbidden_evidence")
        != ["loom-only-lifetime-model", "raw-page-or-block-snapshot"]
        or stale_w07_claim.get("required_authority")
        != [
            "typed-owner-exit-drain",
            "current-page-map-resolution",
            "publication-specific-capability",
        ]
    ):
        raise HarnessError("stale W07 claim cannot be reconstructed from raw page or block")

    source_texts: dict[str, str] = {}
    function_bodies: dict[tuple[str, str], str] = {}
    for fact_id, fact in facts.items():
        path = str(fact["path"])
        source_path = source / path
        if not source_path.is_file():
            raise HarnessError(f"owner-exit source fact {fact_id} is missing {path}")
        source_text = source_texts.setdefault(path, source_path.read_text(encoding="utf-8"))
        function = str(fact["function"])
        body = function_bodies.setdefault(
            (path, function),
            source_function_body(source_text, path=path, function=function),
        )
        cursor = 0
        for marker in fact["ordered_markers"]:
            assert isinstance(marker, str)
            offset = body.find(marker, cursor)
            if offset < 0:
                raise HarnessError(
                    f"owner-exit source fact {fact_id} no longer preserves marker order at {marker!r}"
                )
            cursor = offset + len(marker)

    return {
        "forbidden_reconstruction_input_count": len(OWNER_EXIT_STALE_W07_FORBIDDEN_INPUTS),
        "publication_route_count": len(routes),
        "source_fact_count": len(facts),
    }


def validate_native_owner_exit_lifecycle_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Validate the executable owner-exit evidence boundary.

    Gate 5C is intentionally narrower than a generic cross-thread allocator:
    each checked target proves one source-shaped condition while keeping client
    addresses and page capabilities private. Requiring both integration
    targets and focused source filters keeps the acceptance record tied to the
    runtime boundary and to the general traversal below it.
    """

    if (
        contract.get("schema") != "crabc-mimalloc-native-owner-exit-lifecycle"
        or contract.get("format") != 1
    ):
        raise HarnessError("unsupported native owner-exit lifecycle contract")

    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping):
        raise HarnessError("native owner-exit lifecycle contract lacks upstream identity")
    if upstream.get("version") != pin["version"] or upstream.get("revision") != pin["revision"]:
        raise HarnessError("native owner-exit lifecycle upstream identity mismatch")

    execution = contract.get("execution")
    expected_execution = {
        "features": [
            "native-runtime-test-audit",
            "native-runtime-test-fault",
        ],
        "package": "crabc-mimalloc",
        "test_threads": 1,
        "timeout_seconds": 300,
    }
    if not isinstance(execution, Mapping) or dict(execution) != expected_execution:
        raise HarnessError("native owner-exit lifecycle execution contract changed")

    raw_checks = contract.get("checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        raise HarnessError("native owner-exit lifecycle contract lacks checks")

    checks: list[dict[str, Any]] = []
    check_ids: set[str] = set()
    scenario_coverage: set[str] = set()
    check_kinds: set[str] = set()
    for index, raw_check in enumerate(raw_checks):
        if not isinstance(raw_check, Mapping):
            raise HarnessError(f"native owner-exit lifecycle check {index} is not an object")
        if set(raw_check) != {
            "expected_passed_test_count",
            "id",
            "kind",
            "scenarios",
            "target",
        }:
            raise HarnessError(f"native owner-exit lifecycle check {index} has unexpected fields")
        check_id = raw_check.get("id")
        if (
            not isinstance(check_id, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]*", check_id)
            or check_id in check_ids
        ):
            raise HarnessError(f"native owner-exit lifecycle check {index} has an invalid id")
        kind = raw_check.get("kind")
        if kind not in {"integration-test", "unit-test-filter"}:
            raise HarnessError(f"native owner-exit lifecycle check {check_id} has an invalid kind")
        target = raw_check.get("target")
        target_pattern = (
            r"[a-z][a-z0-9_]*"
            if kind == "integration-test"
            else r"[a-z_][a-z0-9_]*(?:::[a-z_][a-z0-9_]*)+"
        )
        if not isinstance(target, str) or not re.fullmatch(target_pattern, target):
            raise HarnessError(f"native owner-exit lifecycle check {check_id} has an invalid target")
        if kind == "integration-test":
            # The contract intentionally names direct first-party test targets,
            # rather than accepting a Cargo target string that could survive
            # after its source witness was removed.  This keeps Gate 5C from
            # spending a full lane on a retired session route before failing.
            integration_target = ROOT / "crabc-mimalloc" / "tests" / f"{target}.rs"
            if not integration_target.is_file():
                raise HarnessError(
                    "native owner-exit lifecycle check "
                    f"{check_id} names no current integration test target: {target}"
                )
        else:
            unit_target_parts = target.split("::")
            if len(unit_target_parts) != 3 or unit_target_parts[1] != "tests":
                raise HarnessError(
                    "native owner-exit lifecycle check "
                    f"{check_id} has an unsupported source test filter: {target}"
                )
            unit_module, _, unit_test = unit_target_parts
            unit_source = ROOT / "crabc-mimalloc" / "src" / f"{unit_module}.rs"
            if not unit_source.is_file():
                raise HarnessError(
                    "native owner-exit lifecycle check "
                    f"{check_id} names no current source test filter: {target}"
                )
            unit_source_text = unit_source.read_text(encoding="utf-8")
            if not re.search(
                rf"(?m)^\s*fn\s+{re.escape(unit_test)}\s*(?:<[^>]*>)?\s*\(",
                unit_source_text,
            ):
                raise HarnessError(
                    "native owner-exit lifecycle check "
                    f"{check_id} names no current source test filter: {target}"
                )
        expected_passed_test_count = raw_check.get("expected_passed_test_count")
        if (
            not isinstance(expected_passed_test_count, int)
            or isinstance(expected_passed_test_count, bool)
            or expected_passed_test_count <= 0
        ):
            raise HarnessError(
                f"native owner-exit lifecycle check {check_id} has an invalid expected test count"
            )
        scenarios = raw_check.get("scenarios")
        if (
            not isinstance(scenarios, list)
            or not scenarios
            or not all(
                isinstance(scenario, str)
                and scenario in NATIVE_OWNER_EXIT_REQUIRED_SCENARIOS
                for scenario in scenarios
            )
            or len(set(scenarios)) != len(scenarios)
        ):
            raise HarnessError(f"native owner-exit lifecycle check {check_id} has invalid scenarios")
        check_ids.add(check_id)
        check_kinds.add(kind)
        scenario_coverage.update(scenarios)
        checks.append(
            {
                "expected_passed_test_count": expected_passed_test_count,
                "id": check_id,
                "kind": kind,
                "scenarios": list(scenarios),
                "target": target,
            }
        )

    if check_kinds != {"integration-test", "unit-test-filter"}:
        raise HarnessError(
            "native owner-exit lifecycle contract must include integration and source-level checks"
        )
    if scenario_coverage != NATIVE_OWNER_EXIT_REQUIRED_SCENARIOS:
        missing = sorted(NATIVE_OWNER_EXIT_REQUIRED_SCENARIOS - scenario_coverage)
        unexpected = sorted(scenario_coverage - NATIVE_OWNER_EXIT_REQUIRED_SCENARIOS)
        details = [
            *(f"missing {scenario}" for scenario in missing),
            *(f"unexpected {scenario}" for scenario in unexpected),
        ]
        raise HarnessError(
            "native owner-exit lifecycle scenario coverage differs: " + ", ".join(details)
        )

    return {
        "check_count": len(checks),
        "checks": checks,
        "execution": expected_execution,
        "scenario_coverage": sorted(scenario_coverage),
    }


def _m5_report_mapping(
    report: Mapping[str, Any], *path: str
) -> Mapping[str, Any] | None:
    current: Any = report
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current if isinstance(current, Mapping) else None


def _m5_base_evidence_passed(report: Mapping[str, Any]) -> bool:
    compiler_tls = _m5_report_mapping(report, "compiler_tls_codegen")
    loom = _m5_report_mapping(report, "remote_free_loom_model")
    adapter_summary = _m5_report_mapping(
        report,
        "m4_test_adapter",
        "fixtures",
        "adapted_upstream_api",
        "summary",
    )
    return (
        compiler_tls is not None
        and compiler_tls.get("status") == "passed"
        and loom is not None
        and loom.get("status") == "passed"
        and adapter_summary is not None
        and adapter_summary.get("failed") == 0
        and isinstance(adapter_summary.get("succeeded"), int)
        and adapter_summary["succeeded"] > 0
    )


def _m5_full_lane_evidence_passed(
    report: Mapping[str, Any], full_lane: Mapping[str, Any]
) -> bool:
    fixture = _m5_report_mapping(report, "runtime_ticket_zero_test_adapter", "fixture")
    if fixture is None:
        return False
    watchdog = fixture.get("watchdog")
    schedule = fixture.get("stress_schedule")
    lifecycle_stability = fixture.get("lifecycle_stability")
    if (
        not isinstance(watchdog, Mapping)
        or not isinstance(schedule, Mapping)
        or not isinstance(lifecycle_stability, Mapping)
    ):
        return False
    warm_baseline = lifecycle_stability.get("warm_baseline")
    if not isinstance(warm_baseline, Mapping):
        return False
    required_quiescent_values = {
        "process_active": 1,
        "page_owner_ready": 1,
        "page_map_registered_entries": 0,
        "arena_registry_entries": 1,
        "live_tlds": 1,
        "metadata_live_capabilities": 0,
        "shared_later_theaps": 0,
        "abandoned_regular_pages": 0,
        "os_abandoned_pages_empty": 1,
    }
    return (
        fixture.get("worker_cycles") == full_lane["worker_cycles"]
        and watchdog.get("status") == "passed"
        and watchdog.get("seconds") == full_lane["watchdog_seconds"]
        and schedule.get("seed") == full_lane["stress_seed"]
        and schedule.get("worker_routes_per_cycle") == full_lane["routes_per_cycle"]
        and schedule.get("worker_route_invocation_count")
        == full_lane["worker_cycles"] * full_lane["routes_per_cycle"]
        and lifecycle_stability.get("status") == "passed"
        and lifecycle_stability.get("audit_snapshot_count")
        == full_lane["worker_cycles"] + 1
        and lifecycle_stability.get("post_warm_cycle_count")
        == full_lane["worker_cycles"] - 1
        and warm_baseline.get("worker_cycles") == full_lane["worker_cycles"]
        and all(
            warm_baseline.get(name) == value
            for name, value in required_quiescent_values.items()
        )
    )


def native_owner_exit_lifecycle_contract_record(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Render the stable contract identity retained in an executed report."""

    return {
        "format": contract["format"],
        "path": relative(NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT),
        "schema": contract["schema"],
        "upstream": {
            "revision": pin["revision"],
            "version": pin["version"],
        },
    }


def _m5_native_owner_exit_lifecycle_evidence_passed(report: Mapping[str, Any]) -> bool:
    """Recognize only the complete reviewed Gate 5C execution record."""

    suite = _m5_report_mapping(report, "native_owner_exit_lifecycle")
    if suite is None or suite.get("status") != "passed":
        return False
    pin = load_pin()
    contract = read_json(NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
    summary = validate_native_owner_exit_lifecycle_contract(contract, pin)
    if suite.get("contract") != native_owner_exit_lifecycle_contract_record(contract, pin):
        return False
    if suite.get("check_count") != summary["check_count"]:
        return False
    if suite.get("scenario_coverage") != summary["scenario_coverage"]:
        return False
    raw_checks = suite.get("checks")
    if not isinstance(raw_checks, list) or len(raw_checks) != summary["check_count"]:
        return False
    for observed, expected in zip(raw_checks, summary["checks"], strict=True):
        if not isinstance(observed, Mapping):
            return False
        if (
            observed.get("id") != expected["id"]
            or observed.get("kind") != expected["kind"]
            or observed.get("target") != expected["target"]
            or observed.get("passed_test_count")
            != expected["expected_passed_test_count"]
        ):
            return False
    return True


def _m5_source_derived_stress_evidence_passed(report: Mapping[str, Any]) -> bool:
    """Recognize preliminary M5 stress evidence without promoting Gate 5D."""

    fixture = _m5_report_mapping(report, "m5_source_derived_stress_adapter", "fixture")
    if fixture is None:
        return False
    watchdog = fixture.get("watchdog")
    return (
        fixture.get("arguments") == ["1", "1", "2"]
        and fixture.get("compile_defines") == ["NTHREADS=1"]
        and fixture.get("rejected_compile_modes")
        == [
            "ALLOW_LARGE",
            "MI_HEAP_WALK",
            "MI_USE_HEAPS",
            "TEST_LEAK",
            "TEST_STRESS_SUBPROCS",
            "USE_STD_MALLOC",
        ]
        and fixture.get("stdout")
        == (
            "Using 1 threads with a 1% load-per-thread and 2 iterations\n"
            "crabc adapted stress ok\n"
        )
        and fixture.get("stderr") == ""
        and isinstance(watchdog, Mapping)
        and watchdog.get("seconds") == 30
        and watchdog.get("status") == "passed"
    )


def _m5_canonical_upstream_stress_evidence_verified(report: Mapping[str, Any]) -> bool:
    """Recognize only this runner's complete, source-attested report consumer."""

    evidence = _m5_report_mapping(report, "canonical_upstream_stress")
    if evidence is None:
        return False
    return (
        evidence.get("format") == 1
        and evidence.get("schema")
        == "crabc-mimalloc-canonical-upstream-stress-consumer"
        and evidence.get("status") == "verified"
        and evidence.get("evidence_scope") == "shadow_subset"
        and evidence.get("matrix")
        == {"case_count": 12, "worker_counts": [1, 2, 4, 8]}
        and canonical_upstream_stress_exactly_matches(
            evidence.get("large_object_mode"),
            canonical_upstream_stress_expected_large_object_mode(),
        )
        and isinstance(evidence.get("current_head"), Mapping)
        and isinstance(evidence["current_head"].get("record"), Mapping)
        and isinstance(evidence["current_head"].get("source"), Mapping)
    )


def m5_gate_report(contract: Mapping[str, Any], report: Mapping[str, Any]) -> dict[str, Any]:
    """Classify the full lane from executed evidence and reviewed blockers.

    Operational failures never reach this function: they remain harness errors.
    A `blocked` result here instead means the bounded evidence passed but the
    reviewed M5 acceptance contract has not yet been met.
    """

    summary = validate_m5_gate_contract(contract, load_pin())
    full_lane = summary["full_lane"]
    base_passed = _m5_base_evidence_passed(report)
    full_lane_passed = _m5_full_lane_evidence_passed(report, full_lane)
    native_owner_exit_lifecycle_passed = _m5_native_owner_exit_lifecycle_evidence_passed(report)
    loom = _m5_report_mapping(report, "remote_free_loom_model")
    remote_free_loom_passed = loom is not None and loom.get("status") == "passed"

    observed_status = {
        "m5.base": base_passed,
        "m5.5a": full_lane_passed,
        "m5.5b": full_lane_passed and remote_free_loom_passed,
        "m5.5c": native_owner_exit_lifecycle_passed,
    }
    observed_evidence = {
        "m5.base": [
            "report:/compiler_tls_codegen",
            "report:/m4_test_adapter/fixtures/adapted_upstream_api/summary",
            "report:/remote_free_loom_model",
        ],
        "m5.5a": ["report:/runtime_ticket_zero_test_adapter/fixture"],
        "m5.5b": [
            "report:/runtime_ticket_zero_test_adapter/fixture",
            "report:/remote_free_loom_model",
        ],
        "m5.5c": ["report:/native_owner_exit_lifecycle"],
    }
    source_derived_stress_passed = _m5_source_derived_stress_evidence_passed(report)
    canonical_upstream_stress_verified = _m5_canonical_upstream_stress_evidence_verified(
        report
    )

    gate_records: list[dict[str, Any]] = []
    for source_gate in contract["gates"]:
        assert isinstance(source_gate, Mapping)
        gate_id = source_gate["id"]
        assert isinstance(gate_id, str)
        record: dict[str, Any] = {
            "acceptance": source_gate["acceptance"],
            "evidence": list(source_gate["evidence"]),
            "id": gate_id,
            "required": source_gate["required"],
        }
        if gate_id in observed_status:
            if observed_status[gate_id]:
                record["status"] = "passed"
                record["observed_evidence"] = observed_evidence[gate_id]
            else:
                record["status"] = "blocked"
                record["blocked_by"] = [
                    "The required full-lane evidence was absent or did not satisfy its checked result."
                ]
        else:
            record["status"] = "blocked"
            record["blocked_by"] = list(source_gate["blocked_by"])
            if gate_id == "m5.5d":
                observed: list[str] = []
                if source_derived_stress_passed:
                    observed.append("report:/m5_source_derived_stress_adapter/fixture")
                if canonical_upstream_stress_verified:
                    observed.append("report:/canonical_upstream_stress")
                if observed:
                    record["observed_evidence"] = observed
        gate_records.append(record)

    unmet_required = [
        record["id"]
        for record in gate_records
        if record["required"] and record["status"] != "passed"
    ]
    return {
        "contract": {
            "format": contract["format"],
            "path": relative(M5_GATE_CONTRACT),
            "schema": contract["schema"],
            "upstream": dict(contract["upstream"]),
        },
        "full_lane": dict(full_lane),
        "gates": gate_records,
        "overall_status": "passed" if not unmet_required else "unmet",
        "unmet_required": unmet_required,
    }


def m5_gate_unmet_message(gate: Mapping[str, Any]) -> str:
    """Render a concise failure that points to the durable full-gate report."""

    unmet = gate.get("unmet_required")
    gates = gate.get("gates")
    if not isinstance(unmet, list) or not unmet or not isinstance(gates, list):
        return "allocator --full did not meet the reviewed Milestone 5 gate"
    blockers = {
        entry.get("id"): entry.get("blocked_by")
        for entry in gates
        if isinstance(entry, Mapping)
    }
    details: list[str] = []
    for gate_id in unmet:
        reasons = blockers.get(gate_id)
        if isinstance(reasons, list) and reasons and isinstance(reasons[0], str):
            details.append(f"{gate_id}: {reasons[0]}")
        else:
            details.append(f"{gate_id}: required evidence did not pass")
    return "allocator --full did not meet Milestone 5: " + "; ".join(details)


def validate_adapted_test_contract(
    contract: Mapping[str, Any],
    pin: Mapping[str, str],
    adapter_header: str,
    *,
    source_selection_only: bool = False,
) -> dict[str, int]:
    """Validate the reviewed M4 patch, selection, and private ABI contract.

    The x86-64 adapter contract source-binds this review record only for its
    patch, header, symbol, and selected-check facts.  Its target-local build
    contract must not inherit the AArch64 native-library requirements stored
    here, so that narrow caller sets ``source_selection_only``.
    """

    if contract.get("format") != 1 or contract.get("schema") != "crabc-mimalloc-adapted-test-api":
        raise HarnessError("unsupported adapted allocator test contract")
    if contract.get("milestone") != "M4" or contract.get("fixture_source") != "test/test-api.c":
        raise HarnessError("adapted allocator contract must name the M4 test/test-api.c fixture")

    upstream = contract.get("upstream")
    if not isinstance(upstream, dict):
        raise HarnessError("adapted allocator contract lacks upstream identity")
    expected_upstream = {
        "archive_root": pin["archive_root"],
        "archive_sha256": pin["sha256"],
        "archive_source": pin["source"],
        "repository": pin["repository"],
        "revision": pin["revision"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "version": pin["version"],
    }
    for key, expected in expected_upstream.items():
        if upstream.get(key) != expected:
            raise HarnessError(f"adapted allocator upstream identity mismatch: {key}")
    if upstream.get("project") != "microsoft/mimalloc" or upstream.get("archive_path") != reviewed_archive_path(pin):
        raise HarnessError("adapted allocator upstream project/archive path changed")

    source_hashes = contract.get("source_hashes")
    if not isinstance(source_hashes, dict) or set(source_hashes) != {
        "test/test-api.c",
        "test/testhelper.h",
    }:
        raise HarnessError("adapted allocator source-hash set changed")
    if not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in source_hashes.values()):
        raise HarnessError("adapted allocator source hash is invalid")

    patch = contract.get("patch")
    adapted = contract.get("adapted_source")
    if not isinstance(patch, dict) or patch.get("path") != "compat/allocator/adapted/test-api-selected.patch":
        raise HarnessError("adapted allocator patch path changed")
    if not isinstance(adapted, dict) or adapted.get("path") != "test/test-api.c":
        raise HarnessError("adapted allocator output path changed")
    for label, value in (
        ("patch", patch.get("sha256")),
        ("adapted source", adapted.get("sha256")),
    ):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise HarnessError(f"adapted allocator {label} hash is invalid")

    header_contract = contract.get("adapter_header")
    if not isinstance(header_contract, dict) or header_contract.get("include_spelling") != TEST_ADAPTER_HEADER.name:
        raise HarnessError("adapted allocator header spelling changed")
    if header_contract.get("observed_checkout_path") != relative(TEST_ADAPTER_HEADER):
        raise HarnessError("adapted allocator header path changed")
    expected_symbols = contract.get("expected_adapter_symbols")
    if (
        not isinstance(expected_symbols, list)
        or not expected_symbols
        or not all(isinstance(name, str) for name in expected_symbols)
        or expected_symbols != sorted(set(expected_symbols))
    ):
        raise HarnessError("adapted allocator expected symbol list is invalid")
    if adapter_header_function_names(adapter_header) != expected_symbols:
        raise HarnessError("adapted allocator header symbol contract differs from the manifest")

    required_symbols = contract.get("required_prefixed_adapter_symbols")
    if not isinstance(required_symbols, list) or not required_symbols:
        raise HarnessError("adapted allocator required symbol mapping is absent")
    for index, item in enumerate(required_symbols):
        if not isinstance(item, dict) or not all(
            isinstance(item.get(key), str) and item.get(key)
            for key in ("upstream_spelling", "prefixed_symbol", "signature")
        ):
            raise HarnessError(f"adapted allocator required symbol mapping {index} is invalid")
        if item["prefixed_symbol"] not in expected_symbols or not item["upstream_spelling"].startswith("mi_"):
            raise HarnessError(f"adapted allocator required symbol mapping {index} is unreviewed")

    def reviewed_tests(field: str, required_fields: Sequence[str]) -> list[Mapping[str, Any]]:
        raw = contract.get(field)
        if not isinstance(raw, list) or not raw:
            raise HarnessError(f"adapted allocator {field} is absent")
        names: set[str] = set()
        normalized: list[Mapping[str, Any]] = []
        singular = "selected" if field == "selected_tests" else "omitted"
        for index, item in enumerate(raw):
            if not isinstance(item, dict) or not all(
                isinstance(item.get(key), str) and bool(item.get(key)) for key in required_fields
            ):
                raise HarnessError(f"invalid {singular} test at index {index}")
            name = item["name"]
            if name in names:
                raise HarnessError(f"adapted allocator duplicates {singular} test: {name}")
            names.add(name)
            normalized.append(item)
        return normalized

    selected = reviewed_tests("selected_tests", ("name", "source_test", "category"))
    omitted = reviewed_tests("omitted_tests", ("name", "source_test", "reason", "milestone"))
    overlap = sorted({item["name"] for item in selected}.intersection(item["name"] for item in omitted))
    if overlap:
        raise HarnessError("adapted allocator tests are both selected and omitted: " + ", ".join(overlap))

    first = contract.get("required_first_test")
    if not isinstance(first, dict) or first.get("name") != "zero_aligned_first":
        raise HarnessError("adapted allocator first-test contract changed")
    if first.get("name") not in {item["name"] for item in selected}:
        raise HarnessError("adapted allocator first test is not selected")
    if first.get("invocation") != 'CHECK("zero_aligned_first", test_zero_aligned_first());':
        raise HarnessError("adapted allocator first-test invocation changed")
    for field in (
        "assertions",
        "required_init_assertions",
        "required_summary_assertions",
        "required_shutdown_assertions",
    ):
        values = first.get(field) if field == "assertions" else contract.get(field)
        if not isinstance(values, list) or not values or not all(isinstance(value, str) and value for value in values):
            raise HarnessError(f"adapted allocator {field} is invalid")

    if not source_selection_only:
        compile_requirements = contract.get("compile_requirements")
        if not isinstance(compile_requirements, dict):
            raise HarnessError("adapted allocator compile requirements are absent")
        expected_compile = {
            "adapter_feature": "test-adapter",
            "expected_dynamic_dependencies": ["libc.musl-aarch64.so.1", "libgcc_s.so.1"],
            "language": "C11",
            "native_library_search_paths": ["/usr/lib"],
            "native_static_libs": ["-lgcc_s", "-lc"],
            "required_header": TEST_ADAPTER_HEADER.name,
        }
        for key, expected in expected_compile.items():
            if compile_requirements.get(key) != expected:
                raise HarnessError(f"adapted allocator compile requirement changed: {key}")

    verification = contract.get("verification")
    if not isinstance(verification, dict):
        raise HarnessError("adapted allocator verification record is absent")
    verification_keys = (
        "patch_applies_cleanly",
        "patch_round_trip_stable",
        "adapted_source_sha256_verified",
    )
    if not source_selection_only:
        verification_keys += ("header_compile_verified",)
    for key in verification_keys:
        if verification.get(key) is not True:
            raise HarnessError(f"adapted allocator verification is not true: {key}")
    if verification.get("unsupported_raw_mi_references_found") != []:
        raise HarnessError("adapted allocator fixture retains unsupported raw mi_* references")

    return {
        "expected_adapter_symbol_count": len(expected_symbols),
        "omitted_test_count": len(omitted),
        "selected_test_count": len(selected),
    }


def adapted_test_source_selection_payload(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the target-neutral M4 facts reused by the x86 adapter lane."""

    return {
        "adapted_source": contract.get("adapted_source"),
        "adapter_header": contract.get("adapter_header"),
        "expected_adapter_symbols": contract.get("expected_adapter_symbols"),
        "fixture_source": contract.get("fixture_source"),
        "format": contract.get("format"),
        "milestone": contract.get("milestone"),
        "omitted_tests": contract.get("omitted_tests"),
        "patch": contract.get("patch"),
        "required_first_test": contract.get("required_first_test"),
        "required_init_assertions": contract.get("required_init_assertions"),
        "required_prefixed_adapter_symbols": contract.get(
            "required_prefixed_adapter_symbols"
        ),
        "required_shutdown_assertions": contract.get("required_shutdown_assertions"),
        "required_summary_assertions": contract.get("required_summary_assertions"),
        "schema": contract.get("schema"),
        "selected_tests": contract.get("selected_tests"),
        "source_hashes": contract.get("source_hashes"),
        "upstream": contract.get("upstream"),
    }


def adapted_test_source_selection_digest(contract: Mapping[str, Any]) -> str:
    """Hash a canonical target-neutral selection payload, never its link contract."""

    encoded = json.dumps(
        adapted_test_source_selection_payload(contract),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_x86_64_test_adapter_contract(
    contract: Mapping[str, Any],
    source_contract: Mapping[str, Any],
    pin: Mapping[str, str],
    adapter_header: str,
) -> dict[str, Any]:
    """Validate the native x86-64 boundary around the reviewed M4 source set.

    The source-selection contract remains the authoritative review record for
    the patch, symbols, and selected checks.  This separate contract records
    only the native x86-64 build and evidence boundary, so it cannot inherit
    AArch64 production assumptions by accident.
    """

    expected_fields = {
        "compile_requirements",
        "evidence_boundary",
        "format",
        "profile",
        "schema",
        "scope",
        "source_selection",
        "target",
    }
    if set(contract) != expected_fields:
        raise HarnessError("native x86-64 test adapter contract fields changed")
    if contract.get("format") != 1 or contract.get("schema") != "crabc-mimalloc-x86_64-test-adapter":
        raise HarnessError("unsupported native x86-64 test adapter contract")
    if contract.get("profile") != "linux-x86_64-private-test-adapter":
        raise HarnessError("native x86-64 test adapter profile changed")
    if contract.get("scope") != (
        "Native Linux/x86-64 evidence for the private prefixed C test adapter "
        "over the bounded crabc-mimalloc engine. It is not a public mimalloc "
        "or crabc-libc allocator ABI."
    ):
        raise HarnessError("native x86-64 test adapter scope changed")

    expected_target = {
        "architecture": "x86_64",
        "endianness": "little",
        "interpreter": X86_64_INTERPRETER,
        "rust_target": X86_64_RUST_TARGET,
        "system": "linux",
    }
    if contract.get("target") != expected_target:
        raise HarnessError("native x86-64 test adapter target changed")

    source_summary = validate_adapted_test_contract(
        source_contract,
        pin,
        adapter_header,
        source_selection_only=True,
    )
    source_selection = contract.get("source_selection")
    if not isinstance(source_selection, dict):
        raise HarnessError("native x86-64 test adapter source-selection is absent")
    source_selection_digest = adapted_test_source_selection_digest(source_contract)
    if source_selection.get("base_source_selection_sha256") != source_selection_digest:
        raise HarnessError("native x86-64 test adapter source-selection digest changed")
    expected_source_selection = {
        "base_contract_path": relative(ADAPTED_TEST_CONTRACT),
        "base_source_selection_sha256": source_selection_digest,
        "base_schema": "crabc-mimalloc-adapted-test-api",
        "expected_adapter_symbol_count": source_summary["expected_adapter_symbol_count"],
        "selected_test_count": source_summary["selected_test_count"],
        "role": (
            "Reuses only the reviewed pinned-source patch and selected C checks. "
            "The AArch64 production target, dependency, and public-API claims "
            "in the base contract are not inherited."
        ),
    }
    if source_selection != expected_source_selection:
        raise HarnessError("native x86-64 test adapter source-selection changed")

    expected_compile_requirements = {
        "adapter_feature": "test-adapter",
        "compiler": "musl-gcc",
        "expected_executable_dynamic_dependencies": [],
        "expected_executable_elf": {
            "class": "ELF64",
            "endianness": "little",
            "machine": "Advanced Micro Devices X86-64",
        },
        "expected_fixture_stdout": "allocator ok\n",
        "language": "C11",
        "link_command_shape": (
            "musl-gcc <fixture-or-patched-source> <rust-staticlib> "
            "-L<rust-target-self-contained> "
            "-lunwind -lc -o <native-binary>"
        ),
        "link_order": "C fixture or selected patched source, adapter staticlib, then musl/system libraries",
        "native_library_search_paths": [],
        "native_static_libs": ["-lunwind", "-lc"],
        "required_header": TEST_ADAPTER_HEADER.name,
        "rust_cdylib_supported": False,
        "rust_target_self_contained_native_library": "libunwind.a",
        "rust_staticlib_filename": "libcrabc_mimalloc_test_adapter.a",
    }
    if contract.get("compile_requirements") != expected_compile_requirements:
        raise HarnessError("native x86-64 test adapter compile requirements changed")

    expected_boundary = {
        "canonical_native_host_provenance": {
            "execution_mode": "native",
            "host_architectures": ["x86_64", "amd64"],
        },
        "native_execution_required": True,
        "private_prefixed_c_abi_only": True,
        "public_crabc_allocator_integration": False,
        "public_mi_exports": False,
    }
    if contract.get("evidence_boundary") != expected_boundary:
        raise HarnessError("native x86-64 test adapter evidence boundary changed")

    return {
        "expected_adapter_symbol_count": source_summary["expected_adapter_symbol_count"],
        "profile": "linux-x86_64-private-test-adapter",
        "selected_test_count": source_summary["selected_test_count"],
        "target": X86_64_RUST_TARGET,
    }

def validate_adapted_stress_test_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str], adapter_header: str
) -> dict[str, int]:
    """Validate the bounded source-derived creating-thread stress adaptation.

    This contract is deliberately separate from the selected API fixture:
    it retains one fixed creating-thread execution of upstream test/test-stress.c
    without claiming its pthread, remote-transfer, heap, or subprocess paths.
    """

    if (
        contract.get("format") != 1
        or contract.get("schema") != "crabc-mimalloc-adapted-stress-test"
    ):
        raise HarnessError("unsupported adapted allocator stress contract")
    if contract.get("milestone") != "M5" or contract.get("fixture_source") != "test/test-stress.c":
        raise HarnessError("adapted allocator stress contract must name the M5 test/test-stress.c fixture")

    upstream = contract.get("upstream")
    if not isinstance(upstream, dict):
        raise HarnessError("adapted allocator stress contract lacks upstream identity")
    expected_upstream = {
        "archive_root": pin["archive_root"],
        "archive_sha256": pin["sha256"],
        "archive_source": pin["source"],
        "repository": pin["repository"],
        "revision": pin["revision"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "version": pin["version"],
    }
    for key, expected in expected_upstream.items():
        if upstream.get(key) != expected:
            raise HarnessError(f"adapted allocator stress upstream identity mismatch: {key}")
    if (
        upstream.get("project") != "microsoft/mimalloc"
        or upstream.get("archive_path") != reviewed_archive_path(pin)
    ):
        raise HarnessError("adapted allocator stress project/archive path changed")

    source_hashes = contract.get("source_hashes")
    if not isinstance(source_hashes, dict) or set(source_hashes) != {"test/test-stress.c"}:
        raise HarnessError("adapted allocator stress source-hash set changed")
    if not all(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
        for value in source_hashes.values()
    ):
        raise HarnessError("adapted allocator stress source hash is invalid")
    expected_regions = [
        "test/test-stress.c:16-110",
        "test/test-stress.c:144-345",
        "test/test-stress.c:400-564",
    ]
    if contract.get("source_regions") != expected_regions:
        raise HarnessError("adapted allocator stress source regions changed")
    expected_provenance = {
        "upstream_file_license": "MIT",
        "upstream_notice": "Copyright (c) 2018-2026 Microsoft Research, Daan Leijen",
        "adaptation_owner": "crabc",
        "rust_boundary": "crabc-mimalloc test-adapter's existing prefixed C ABI",
    }
    if contract.get("provenance") != expected_provenance:
        raise HarnessError("adapted allocator stress provenance changed")

    patch = contract.get("patch")
    adapted = contract.get("adapted_source")
    if (
        not isinstance(patch, dict)
        or patch.get("path") != "compat/allocator/adapted/test-stress-creating-thread.patch"
    ):
        raise HarnessError("adapted allocator stress patch path changed")
    if not isinstance(adapted, dict) or adapted.get("path") != "test/test-stress.c":
        raise HarnessError("adapted allocator stress output path changed")
    for label, value in (
        ("patch", patch.get("sha256")),
        ("adapted source", adapted.get("sha256")),
    ):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise HarnessError(f"adapted allocator stress {label} hash is invalid")

    header_contract = contract.get("adapter_header")
    if (
        not isinstance(header_contract, dict)
        or header_contract.get("include_spelling") != TEST_ADAPTER_HEADER.name
        or header_contract.get("observed_checkout_path") != relative(TEST_ADAPTER_HEADER)
    ):
        raise HarnessError("adapted allocator stress header contract changed")
    expected_symbols = contract.get("expected_adapter_symbols")
    if (
        not isinstance(expected_symbols, list)
        or not expected_symbols
        or not all(isinstance(name, str) for name in expected_symbols)
        or expected_symbols != sorted(set(expected_symbols))
    ):
        raise HarnessError("adapted allocator stress expected symbol list is invalid")
    if adapter_header_function_names(adapter_header) != expected_symbols:
        raise HarnessError("adapted allocator stress header symbol contract differs from the manifest")
    required_symbols = contract.get("required_prefixed_adapter_symbols")
    expected_required_symbols = [
        {
            "upstream_spelling": "mi_calloc",
            "prefixed_symbol": "crabc_test_calloc",
            "signature": "void *(size_t count, size_t size)",
        },
        {
            "upstream_spelling": "mi_free",
            "prefixed_symbol": "crabc_test_free",
            "signature": "void (void *p)",
        },
        {
            "upstream_spelling": "mi_realloc",
            "prefixed_symbol": "crabc_test_realloc",
            "signature": "void *(void *p, size_t size)",
        },
    ]
    if required_symbols != expected_required_symbols:
        raise HarnessError("adapted allocator stress prefixed symbol surface changed")

    execution = contract.get("execution")
    expected_execution = {
        "arguments": ["1", "1", "2"],
        "compile_defines": ["NTHREADS=1"],
        "creating_thread_only": True,
        "expected_stderr": "",
        "expected_stdout": (
            "Using 1 threads with a 1% load-per-thread and 2 iterations\n"
            "crabc adapted stress ok\n"
        ),
        "spawned_pthread_count": 0,
        "watchdog_seconds": 30,
    }
    if not isinstance(execution, dict):
        raise HarnessError("adapted allocator stress execution contract is absent")
    for key, expected in expected_execution.items():
        if execution.get(key) != expected:
            raise HarnessError(f"adapted allocator stress execution contract changed: {key}")
    scheduler_assertions = execution.get("scheduler_assertions")
    if (
        not isinstance(scheduler_assertions, list)
        or len(scheduler_assertions) != 3
        or not all(isinstance(assertion, str) and assertion for assertion in scheduler_assertions)
    ):
        raise HarnessError("adapted allocator stress scheduler assertions are invalid")

    excluded_modes = contract.get("excluded_upstream_modes")
    expected_mode_names = [
        "ALLOW_LARGE",
        "MI_HEAP_WALK",
        "MI_USE_HEAPS",
        "TEST_LEAK",
        "TEST_STRESS_SUBPROCS",
        "USE_STD_MALLOC",
    ]
    if (
        not isinstance(excluded_modes, list)
        or [mode.get("macro") if isinstance(mode, dict) else None for mode in excluded_modes]
        != expected_mode_names
        or not all(
            isinstance(mode, dict)
            and isinstance(mode.get("reason"), str)
            and bool(mode["reason"])
            for mode in excluded_modes
        )
    ):
        raise HarnessError("adapted allocator stress excluded-mode contract changed")

    expected_markers = [
        f'#include "{TEST_ADAPTER_HEADER.name}"',
        "#if NTHREADS != 1",
        "#if ALLOW_LARGE",
        "#if defined(USE_STD_MALLOC)",
        "#if defined(MI_USE_HEAPS)",
        "#if defined(MI_HEAP_WALK)",
        "#if defined(TEST_STRESS_SUBPROCS) && TEST_STRESS_SUBPROCS",
        "#if defined(TEST_LEAK) && TEST_LEAK",
        "static bool   main_participates = true;",
        "const size_t start = (main_participates ? 1 : 0);",
        "fun(0,arg); // run the main thread as well",
        "if (THREADS != 1 || SCALE != 1 || ITER != 2 || !main_participates || allow_large_objects)",
        "crabc_test_init()",
        "crabc_test_shutdown()",
        'printf("crabc adapted stress ok\\n");',
    ]
    if contract.get("required_source_markers") != expected_markers:
        raise HarnessError("adapted allocator stress source-marker contract changed")

    compile_requirements = contract.get("compile_requirements")
    if not isinstance(compile_requirements, dict):
        raise HarnessError("adapted allocator stress compile requirements are absent")
    expected_compile = {
        "adapter_feature": "test-adapter",
        "compile_flags": [
            "-O2",
            "-fPIE",
            "-pie",
            "-ftls-model=initial-exec",
            "-pthread",
            "-DNTHREADS=1",
        ],
        "expected_dynamic_dependencies": ["libc.musl-aarch64.so.1", "libgcc_s.so.1"],
        "language": "C11",
        "native_library_search_paths": ["/usr/lib"],
        "native_static_libs": ["-lgcc_s", "-lc"],
        "required_header": TEST_ADAPTER_HEADER.name,
    }
    for key, expected in expected_compile.items():
        if compile_requirements.get(key) != expected:
            raise HarnessError(f"adapted allocator stress compile requirement changed: {key}")
    for key in ("link_command_shape", "link_order", "notes", "rust_staticlib"):
        if not isinstance(compile_requirements.get(key), str) or not compile_requirements[key]:
            raise HarnessError(f"adapted allocator stress compile requirement is absent: {key}")
    include_directories = compile_requirements.get("include_directories")
    if include_directories != [
        "<extracted-root>/include",
        "<extracted-root>/test",
        "<repo>/compat/allocator/test-adapter",
    ]:
        raise HarnessError("adapted allocator stress include directories changed")

    verification = contract.get("verification")
    if not isinstance(verification, dict):
        raise HarnessError("adapted allocator stress verification record is absent")
    for key in (
        "patch_applies_cleanly",
        "patch_round_trip_stable",
        "adapted_source_sha256_verified",
        "header_compile_verified",
        "native_execution_verified",
        "unsupported_modes_rejected",
    ):
        if verification.get(key) is not True:
            raise HarnessError(f"adapted allocator stress verification is not true: {key}")

    return {
        "excluded_upstream_mode_count": len(excluded_modes),
        "expected_adapter_symbol_count": len(expected_symbols),
        "required_prefixed_adapter_symbol_count": len(required_symbols),
    }


def validate_native_shadow_stress_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, int]:
    """Validate the selected-libc, source-derived pthread stress contract.

    Unlike the prefixed test adapter, this route intentionally invokes the
    standard C allocation names so the selected ``native-mimalloc-shadow``
    ``libc.so`` owns the complete source workload. Its fixed scheduler is
    evidence for four source workers and fresh post-exit transfer releasers;
    it is not a general worker, pointer, heap, or subprocess admission API.
    """

    if (
        contract.get("format") != 1
        or contract.get("schema") != "crabc-mimalloc-native-shadow-stress"
        or contract.get("fixture_source") != "test/test-stress.c"
    ):
        raise HarnessError("unsupported native-shadow stress contract")

    upstream = contract.get("upstream")
    if not isinstance(upstream, dict):
        raise HarnessError("native-shadow stress contract lacks upstream identity")
    expected_upstream = {
        "archive_root": pin["archive_root"],
        "archive_sha256": pin["sha256"],
        "archive_source": pin["source"],
        "repository": pin["repository"],
        "revision": pin["revision"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "version": pin["version"],
    }
    for key, expected in expected_upstream.items():
        if upstream.get(key) != expected:
            raise HarnessError(f"native-shadow stress upstream identity mismatch: {key}")
    if (
        upstream.get("project") != "microsoft/mimalloc"
        or upstream.get("archive_path") != reviewed_archive_path(pin)
    ):
        raise HarnessError("native-shadow stress project/archive path changed")

    expected_source_hashes = {
        "test/test-stress.c": "e2bed5f2be12239b1fa696dafffda384d19140cb50a6ee2f6e096f70934d73df"
    }
    if contract.get("source_hashes") != expected_source_hashes:
        raise HarnessError("native-shadow stress source-hash set changed")
    if contract.get("source_regions") != [
        "test/test-stress.c:16-110",
        "test/test-stress.c:144-385",
        "test/test-stress.c:400-523",
    ]:
        raise HarnessError("native-shadow stress source regions changed")
    expected_provenance = {
        "upstream_file_license": "MIT",
        "upstream_notice": "Copyright (c) 2018-2026 Microsoft Research, Daan Leijen",
        "adaptation_owner": "crabc",
        "rust_boundary": "crabc-libc native-mimalloc-shadow standard C allocation ABI",
    }
    if contract.get("provenance") != expected_provenance:
        raise HarnessError("native-shadow stress provenance changed")

    patch = contract.get("patch")
    adapted = contract.get("adapted_source")
    if (
        not isinstance(patch, dict)
        or patch.get("path")
        != "compat/allocator/adapted/test-stress-native-shadow-pthreads.patch"
    ):
        raise HarnessError("native-shadow stress patch path changed")
    if not isinstance(adapted, dict) or adapted.get("path") != "test/test-stress.c":
        raise HarnessError("native-shadow stress output path changed")
    for label, value in (
        ("patch", patch.get("sha256")),
        ("adapted source", adapted.get("sha256")),
    ):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise HarnessError(f"native-shadow stress {label} hash is invalid")
    if (
        patch.get("apply_from") != "the extracted mimalloc-3.5.0 root"
        or patch.get("apply_command")
        != "patch -p1 < /path/to/crabc/compat/allocator/adapted/test-stress-native-shadow-pthreads.patch"
    ):
        raise HarnessError("native-shadow stress patch application contract changed")

    execution = contract.get("execution")
    expected_execution = {
        "arguments": ["4", "1", "2"],
        "compile_defines": ["USE_STD_MALLOC", "NTHREADS=4"],
        "expected_stderr": "",
        "expected_stdout": (
            "Using 4 threads with a 1% load-per-thread and 2 iterations\n"
            "crabc native shadow pthread stress ok\n"
        ),
        "main_participates": False,
        "post_exit_transfer_releaser": (
            "one fresh pthread runs the source free_items cleanup for every selected transfer slot"
        ),
        "process_epochs": 128,
        "source_iterations": 2,
        "source_worker_count": 4,
        "watchdog_seconds": 30,
    }
    if not isinstance(execution, dict):
        raise HarnessError("native-shadow stress execution contract is absent")
    for key, expected in expected_execution.items():
        if execution.get(key) != expected:
            raise HarnessError(f"native-shadow stress execution contract changed: {key}")
    expected_scheduler_assertions = [
        "With NTHREADS=4 and main_participates false, the source scheduler creates exactly four pthread workers for every source iteration.",
        "The retained source transfer buffer carries exact live allocation pointers across source workers and source iterations.",
        "Each selected transfer cleanup runs free_items in one fresh source-shaped pthread after the producing workers have joined, exercising the typed post-exit release route without exposing a client address or page capability.",
        "A worker that already holds one exact live-owner handoff restores it and revalidates the source input instead of waiting on a second busy handoff, so opposing source transfers cannot form a raw-TLS wait cycle.",
    ]
    if execution.get("scheduler_assertions") != expected_scheduler_assertions:
        raise HarnessError("native-shadow stress scheduler assertions changed")

    excluded_modes = contract.get("excluded_upstream_modes")
    expected_mode_names = [
        "ALLOW_LARGE",
        "MI_HEAP_WALK",
        "MI_USE_HEAPS",
        "TEST_LEAK",
        "TEST_STRESS_SUBPROCS",
    ]
    if (
        not isinstance(excluded_modes, list)
        or [mode.get("macro") if isinstance(mode, dict) else None for mode in excluded_modes]
        != expected_mode_names
        or not all(
            isinstance(mode, dict)
            and isinstance(mode.get("reason"), str)
            and bool(mode["reason"])
            for mode in excluded_modes
        )
    ):
        raise HarnessError("native-shadow stress excluded-mode contract changed")

    expected_markers = [
        "#if !defined(USE_STD_MALLOC)",
        "#if NTHREADS != 4",
        "#if ALLOW_LARGE",
        "#if defined(MI_USE_HEAPS)",
        "#if defined(MI_HEAP_WALK)",
        "#if defined(TEST_STRESS_SUBPROCS) && TEST_STRESS_SUBPROCS",
        "#if defined(TEST_LEAK) && TEST_LEAK",
        "static bool   main_participates = false;",
        "const size_t start = (main_participates ? 1 : 0);",
        "free_transferred_item_in_fresh_worker",
        "run_os_threads(subproc_null, 1, &free_transferred_item, p);",
        "if (THREADS != 4 || SCALE != 1 || ITER != 2 || main_participates || allow_large_objects)",
        'printf("crabc native shadow pthread stress ok\\n");',
    ]
    if contract.get("required_source_markers") != expected_markers:
        raise HarnessError("native-shadow stress source-marker contract changed")

    compile_requirements = contract.get("compile_requirements")
    expected_compile = {
        "allocator_feature": "native-mimalloc-shadow",
        "canonical_loader": "/lib/ld-crabc-aarch64.so.1",
        "compiler": "crabc-cc from the installed owned crabc sysroot",
        "compile_flags": [
            "-O2",
            "-DNDEBUG",
            "-fPIE",
            "-pie",
            "-ftls-model=initial-exec",
            "-pthread",
        ],
        "expected_dynamic_dependencies": ["libc.so"],
        "language": "C11",
        "link_flags": ["-Wl,--allow-shlib-undefined"],
        "link_libraries": ["-lc"],
        "owned_test_launcher": "scripts/run_owned_test_suite.py",
        "runtime_directory": "target/debug",
    }
    if not isinstance(compile_requirements, dict):
        raise HarnessError("native-shadow stress compile requirements are absent")
    for key, expected in expected_compile.items():
        if compile_requirements.get(key) != expected:
            raise HarnessError(f"native-shadow stress compile requirement changed: {key}")
    if not isinstance(compile_requirements.get("notes"), str) or not compile_requirements["notes"]:
        raise HarnessError("native-shadow stress compile notes are absent")

    verification = contract.get("verification")
    expected_verification = {
        "patch_applies_cleanly": True,
        "patch_round_trip_stable": True,
        "adapted_source_sha256_verified": True,
        "unsupported_modes_rejected": True,
        "selected_shadow_dynamic_link_verified": True,
        "native_execution_verified": True,
        "fresh_process_epochs_verified": True,
    }
    if verification != expected_verification:
        raise HarnessError("native-shadow stress verification record changed")

    return {
        "excluded_upstream_mode_count": len(excluded_modes),
        "process_epochs": execution["process_epochs"],
        "source_worker_count": execution["source_worker_count"],
    }


def apply_and_verify_adapted_test_patch(
    source: Path, contract: Mapping[str, Any], patch_tool: str
) -> dict[str, Any]:
    """Apply the reviewed patch to an ephemeral verified upstream tree."""

    source_hashes = contract["source_hashes"]
    assert isinstance(source_hashes, dict)
    for relative_source, expected_hash in source_hashes.items():
        source_path = source / relative_source
        if not source_path.is_file() or sha256_file(source_path) != expected_hash:
            raise HarnessError(f"adapted allocator source identity mismatch: {relative_source}")

    patch_contract = contract["patch"]
    assert isinstance(patch_contract, dict)
    patch_path = ROOT / str(patch_contract["path"])
    if not patch_path.is_file() or sha256_file(patch_path) != patch_contract["sha256"]:
        raise HarnessError("adapted allocator patch identity mismatch")
    apply_record = command_record(
        (patch_tool, "-p1", "-f", "-i", str(patch_path)),
        cwd=source,
    )
    require_success(apply_record, "adapted upstream API patch")

    adapted_contract = contract["adapted_source"]
    assert isinstance(adapted_contract, dict)
    adapted_path = source / str(adapted_contract["path"])
    if not adapted_path.is_file() or sha256_file(adapted_path) != adapted_contract["sha256"]:
        raise HarnessError("adapted upstream API source differs from the reviewed patch result")
    adapted_text = adapted_path.read_text(encoding="utf-8")
    include = f'#include "{TEST_ADAPTER_HEADER.name}"'
    if adapted_text.count(include) != 1:
        raise HarnessError("adapted upstream API source has an unexpected adapter include")
    selected = contract["selected_tests"]
    assert isinstance(selected, list)
    expected_names = [item["name"] for item in selected]
    observed_names = re.findall(r'\bCHECK(?:_BODY)?\("([^"]+)"', adapted_text)
    if observed_names != expected_names:
        raise HarnessError("adapted upstream API selected CHECK sequence differs from the manifest")
    first_invocation = contract["required_first_test"]["invocation"]
    init_index = adapted_text.find("crabc_test_init()")
    first_index = adapted_text.find(first_invocation)
    if init_index < 0 or first_index <= init_index:
        raise HarnessError("adapted upstream API first allocation does not follow initialization")
    if adapted_text.count("print_test_summary()") != 1 or adapted_text.count("crabc_test_shutdown()") != 1:
        raise HarnessError("adapted upstream API summary/shutdown sequence changed")
    observed_mi_calls = sorted(set(re.findall(r"\b(mi_[A-Za-z0-9_]+)\s*\(", adapted_text)))
    verification = contract["verification"]
    assert isinstance(verification, dict)
    if observed_mi_calls != verification.get("raw_mi_references_checked"):
        raise HarnessError("adapted upstream API mi_* source surface differs from the manifest")
    return {
        "adapted_source": {
            "bytes": adapted_path.stat().st_size,
            "path": str(adapted_contract["path"]),
            "sha256": sha256_file(adapted_path),
        },
        "apply_command": apply_record["command"],
        "selected_test_count": len(observed_names),
    }


def apply_and_verify_adapted_stress_test_patch(
    source: Path, contract: Mapping[str, Any], patch_tool: str
) -> dict[str, Any]:
    """Apply and inspect the narrow source-derived M5 stress fixture."""

    source_hashes = contract["source_hashes"]
    assert isinstance(source_hashes, dict)
    for relative_source, expected_hash in source_hashes.items():
        source_path = source / relative_source
        if not source_path.is_file() or sha256_file(source_path) != expected_hash:
            raise HarnessError(
                f"adapted allocator stress source identity mismatch: {relative_source}"
            )

    patch_contract = contract["patch"]
    assert isinstance(patch_contract, dict)
    patch_path = ROOT / str(patch_contract["path"])
    if not patch_path.is_file() or sha256_file(patch_path) != patch_contract["sha256"]:
        raise HarnessError("adapted allocator stress patch identity mismatch")
    apply_record = command_record(
        (patch_tool, "-p1", "-f", "-i", str(patch_path)),
        cwd=source,
    )
    require_success(apply_record, "adapted upstream stress patch")

    adapted_contract = contract["adapted_source"]
    assert isinstance(adapted_contract, dict)
    adapted_path = source / str(adapted_contract["path"])
    if not adapted_path.is_file() or sha256_file(adapted_path) != adapted_contract["sha256"]:
        raise HarnessError(
            "adapted upstream stress source differs from the reviewed patch result"
        )
    adapted_text = adapted_path.read_text(encoding="utf-8")
    include = f'#include "{TEST_ADAPTER_HEADER.name}"'
    if adapted_text.count(include) != 1:
        raise HarnessError("adapted upstream stress source has an unexpected adapter include")
    if "<mimalloc.h>" in adapted_text or "<mimalloc-stats.h>" in adapted_text:
        raise HarnessError("adapted upstream stress source retains an upstream mimalloc include")
    required_markers = contract["required_source_markers"]
    assert isinstance(required_markers, list)
    missing_markers = [marker for marker in required_markers if marker not in adapted_text]
    if missing_markers:
        raise HarnessError(
            "adapted upstream stress source omits required markers: "
            + ", ".join(missing_markers)
        )
    required_adapter_macros = [
        "#define custom_calloc(n,s)    mi_calloc(n,s)",
        "#define custom_realloc(p,s)   mi_realloc(p,s)",
        "#define custom_free(p)        mi_free(p)",
    ]
    if any(marker not in adapted_text for marker in required_adapter_macros):
        raise HarnessError("adapted upstream stress source no longer routes its default workload")
    required_rejection_markers = [
        '#error "the adapted stress fixture must use the crabc allocator adapter"',
        '#error "the adapted stress fixture excludes upstream heap APIs"',
        '#error "the adapted stress fixture excludes upstream theap traversal APIs"',
        '#error "the adapted stress fixture excludes upstream subprocess stress"',
        '#error "the adapted stress fixture excludes the upstream leak mode"',
        '#error "the adapted stress fixture requires one creating worker"',
        '#error "the adapted stress fixture excludes large-object mode"',
    ]
    if any(marker not in adapted_text for marker in required_rejection_markers):
        raise HarnessError("adapted upstream stress source no longer rejects an excluded mode")
    bounded_arguments_marker = (
        "if (THREADS != 1 || SCALE != 1 || ITER != 2 || !main_participates || "
        "allow_large_objects)"
    )
    bounded_arguments_index = adapted_text.find(bounded_arguments_marker)
    init_index = adapted_text.find("crabc_test_init()")
    shutdown_index = adapted_text.find("crabc_test_shutdown()")
    if (
        bounded_arguments_index < 0
        or init_index < 0
        or shutdown_index < 0
        or bounded_arguments_index >= init_index
        or shutdown_index <= init_index
        or adapted_text.count("crabc_test_init()") != 1
        or adapted_text.count("crabc_test_shutdown()") != 1
    ):
        raise HarnessError(
            "adapted upstream stress source does not keep bounded admission before terminal shutdown"
        )
    execution = contract["execution"]
    assert isinstance(execution, dict)
    return {
        "adapted_source": {
            "bytes": adapted_path.stat().st_size,
            "path": str(adapted_contract["path"]),
            "sha256": sha256_file(adapted_path),
        },
        "apply_command": apply_record["command"],
        "arguments": list(execution["arguments"]),
        "compile_defines": list(execution["compile_defines"]),
        "excluded_upstream_mode_count": len(contract["excluded_upstream_modes"]),
        "required_prefixed_adapter_symbol_count": len(
            contract["required_prefixed_adapter_symbols"]
        ),
    }


def apply_and_verify_native_shadow_stress_patch(
    source: Path, contract: Mapping[str, Any], patch_tool: str
) -> dict[str, Any]:
    """Apply the selected-shadow stress adaptation in an isolated source tree."""

    source_hashes = contract["source_hashes"]
    assert isinstance(source_hashes, dict)
    for relative_source, expected_hash in source_hashes.items():
        source_path = source / relative_source
        if not source_path.is_file() or sha256_file(source_path) != expected_hash:
            raise HarnessError(
                f"native-shadow stress source identity mismatch: {relative_source}"
            )

    patch_contract = contract["patch"]
    assert isinstance(patch_contract, dict)
    patch_path = ROOT / str(patch_contract["path"])
    if not patch_path.is_file() or sha256_file(patch_path) != patch_contract["sha256"]:
        raise HarnessError("native-shadow stress patch identity mismatch")
    apply_record = command_record(
        (patch_tool, "-p1", "-f", "-i", str(patch_path)),
        cwd=source,
    )
    require_success(apply_record, "native-shadow upstream stress patch")

    adapted_contract = contract["adapted_source"]
    assert isinstance(adapted_contract, dict)
    adapted_path = source / str(adapted_contract["path"])
    if not adapted_path.is_file() or sha256_file(adapted_path) != adapted_contract["sha256"]:
        raise HarnessError(
            "native-shadow stress source differs from the reviewed patch result"
        )
    adapted_text = adapted_path.read_text(encoding="utf-8")
    if "<mimalloc.h>" in adapted_text or "<mimalloc-stats.h>" in adapted_text:
        raise HarnessError("native-shadow stress source retains an upstream mimalloc include")
    required_markers = contract["required_source_markers"]
    assert isinstance(required_markers, list)
    missing_markers = [marker for marker in required_markers if marker not in adapted_text]
    if missing_markers:
        raise HarnessError(
            "native-shadow stress source omits required markers: "
            + ", ".join(missing_markers)
        )
    required_standard_macros = [
        "#define custom_calloc(n,s)    calloc(n,s)",
        "#define custom_realloc(p,s)   realloc(p,s)",
        "#define custom_free(p)        free(p)",
    ]
    if any(marker not in adapted_text for marker in required_standard_macros):
        raise HarnessError("native-shadow stress source no longer routes the workload through libc")
    if "crabc_test_" in adapted_text:
        raise HarnessError("native-shadow stress source must not route through the prefixed test adapter")
    if adapted_text.count("free_transferred_item_in_fresh_worker(p);") != 2:
        raise HarnessError("native-shadow stress source changed its fresh post-exit cleanup boundary")
    return {
        "adapted_source": {
            "bytes": adapted_path.stat().st_size,
            "path": str(adapted_contract["path"]),
            "sha256": sha256_file(adapted_path),
        },
        "apply_command": apply_record["command"],
        "arguments": list(contract["execution"]["arguments"]),
        "compile_defines": list(contract["execution"]["compile_defines"]),
        "excluded_upstream_mode_count": len(contract["excluded_upstream_modes"]),
    }


def reviewed_archive_path(pin: Mapping[str, str]) -> str:
    """Keep the reviewed manifest's cache spelling independent of local storage.

    These source contracts record the original checkout-relative archive path.
    CRABC_WORK_DIR relocates execution artifacts, not reviewed provenance; the
    actual archive is still verified against the immutable pin's SHA-256.
    """

    return f".work/allocator-cache/mimalloc-{pin['version']}.tar.gz"


def archive_path(pin: Mapping[str, str]) -> Path:
    return CACHE / f"mimalloc-{pin['version']}.tar.gz"


def tag_attestation_path(pin: Mapping[str, str]) -> Path:
    return CACHE / f"mimalloc-{pin['version']}.tag.json"


def cached_tag_attestation(pin: Mapping[str, str]) -> dict[str, Any] | None:
    path = tag_attestation_path(pin)
    if not path.is_file():
        return None
    try:
        value = read_json(path)
    except HarnessError:
        return None
    expected = {
        "format": 1,
        "repository": pin["repository"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "revision": pin["revision"],
    }
    if value != expected:
        return None
    return value


def verify_tag_identity(pin: Mapping[str, str], offline: bool) -> dict[str, Any]:
    """Cache an exact annotated-tag/peeled-commit attestation beside the archive."""

    cached = cached_tag_attestation(pin)
    if cached is not None:
        return cached
    if offline:
        raise HarnessError(
            "verified mimalloc tag identity is absent from offline cache: "
            f"{tag_attestation_path(pin)}"
        )
    git = require_tool("git")
    ref = f"refs/tags/{pin['tag']}"
    peeled = ref + "^{}"
    record = command_record((git, "ls-remote", pin["repository"], ref, peeled), cwd=ROOT)
    require_success(record, "mimalloc annotated tag identity probe")
    identities: dict[str, str] = {}
    for line in str(record["stdout"]).splitlines():
        object_id, separator, name = line.partition("\t")
        if separator and re.fullmatch(r"[0-9a-f]{40}", object_id):
            identities[name] = object_id
    if identities.get(ref) != pin["tag_object"] or identities.get(peeled) != pin["revision"]:
        raise HarnessError(
            "mimalloc v3.5.0 tag identity mismatch: "
            f"expected tag {pin['tag_object']} peeled {pin['revision']}, "
            f"observed tag {identities.get(ref)!r} peeled {identities.get(peeled)!r}"
        )
    attestation = {
        "format": 1,
        "repository": pin["repository"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "revision": pin["revision"],
    }
    write_json(tag_attestation_path(pin), attestation)
    return attestation


def fetch_archive(pin: Mapping[str, str], offline: bool) -> Path:
    """Return a locally cached archive only after validating its exact digest."""

    archive = archive_path(pin)
    expected = pin["sha256"]
    if archive.is_file() and sha256_file(archive) == expected:
        verify_tag_identity(pin, offline)
        return archive
    if archive.exists():
        archive.unlink()
    if offline:
        raise HarnessError(f"verified mimalloc archive is absent from offline cache: {archive}")
    CACHE.mkdir(parents=True, exist_ok=True)
    partial = archive.with_name(f".{archive.name}.part")
    try:
        with urllib.request.urlopen(pin["source"], timeout=60) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output)
    except (OSError, urllib.error.URLError) as error:
        partial.unlink(missing_ok=True)
        raise HarnessError(f"failed to download pinned mimalloc archive: {error}") from error
    observed = sha256_file(partial)
    if observed != expected:
        partial.unlink(missing_ok=True)
        raise HarnessError(
            "mimalloc archive SHA-256 mismatch: "
            f"expected {expected}, observed {observed}"
        )
    partial.replace(archive)
    verify_tag_identity(pin, offline=False)
    return archive


def safe_extract(archive: Path, destination: Path, archive_root: str) -> Path:
    """Extract one archive root, rejecting links, devices, and path escapes."""

    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        prefix = f"{archive_root}/"
        for member in members:
            member_path = Path(member.name)
            if (
                (member.name != archive_root and not member.name.startswith(prefix))
                or member_path.is_absolute()
                or ".." in member_path.parts
            ):
                raise HarnessError(f"mimalloc archive member escapes expected root: {member.name}")
            if member.issym() or member.islnk() or member.isdev():
                raise HarnessError(f"mimalloc archive contains unsupported link/device member: {member.name}")
        stream.extractall(destination, members, filter="data")
    source = destination / archive_root
    if not (source / "include/mimalloc.h").is_file() or not (source / "src/alloc.c").is_file():
        raise HarnessError("mimalloc archive lacks required v3.5.0 source files")
    return source


def source_file_records(source: Path, paths: Iterable[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name in sorted(paths):
        path = source / name
        if not path.is_file():
            raise HarnessError(f"pinned source is missing expected file: {name}")
        records.append({"path": name, "sha256": sha256_file(path), "bytes": path.stat().st_size})
    return records


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def without_preprocessor_directives(text: str) -> str:
    """Drop complete preprocessor directives, including continued macro bodies."""

    retained: list[str] = []
    continued = False
    for line in text.splitlines():
        if continued:
            continued = line.rstrip().endswith("\\")
            continue
        if line.lstrip().startswith("#"):
            continued = line.rstrip().endswith("\\")
            continue
        retained.append(line)
    return "\n".join(retained)


def public_external_function_names(text: str) -> set[str]:
    """Extract only `mi_decl_export` C declarations from a public header.

    The old semicolon scanner accidentally treated calls in C++ template
    bodies as functions.  In v3.5.0 all public, externally declared `mi_*`
    functions have the declaration marker, while its seven header helpers are
    explicitly `static inline`; use that source contract as the boundary.
    """

    stripped = without_preprocessor_directives(strip_comments(text))
    return {
        match.group(1)
        for match in re.finditer(
            r"\bmi_decl_export\b[^;{}]*?\b(mi_[A-Za-z0-9_]+)\s*\(", stripped
        )
    }


def public_static_inline_names(text: str) -> set[str]:
    """Extract header-only helpers that have bodies and no ELF symbol."""

    stripped = without_preprocessor_directives(strip_comments(text))
    return {
        match.group(1)
        for match in re.finditer(
            r"\bstatic\s+inline\b[^;{}]*?\b(mi_[A-Za-z0-9_]+)\s*\(", stripped
        )
    }


def public_cxx_template_names(text: str) -> set[str]:
    """Return named public C++ template conveniences, never C functions."""

    return {
        match.group(1)
        for match in re.finditer(
            r"\btemplate\s*<[^>]*>\s*struct\s+(mi_[A-Za-z0-9_]+)\b", text
        )
    }


def public_macro_names(text: str) -> set[str]:
    return {
        match.group(1)
        for match in re.finditer(r"^\s*#\s*define\s+(mi_[A-Za-z0-9_]+)\b", text, re.MULTILINE)
    }


def override_macro_names(text: str) -> set[str]:
    """Extract the opt-in source-rewrite macros, excluding its include guard."""

    return {
        match.group(1)
        for match in re.finditer(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b", text, re.MULTILINE)
        if match.group(1) != "MIMALLOC_OVERRIDE_H"
    }


def public_type_names(text: str) -> set[str]:
    stripped = strip_comments(text)
    names: set[str] = set()
    # Complete struct/enum typedefs contain member semicolons, so statement
    # splitting loses their trailing alias.  Match their braced definition as
    # a unit, then separately handle forward declarations, opaque aliases, and
    # callback function typedefs.
    for match in re.finditer(
        r"\btypedef\s+(?:struct|enum)\b.*?\}\s*(mi_[A-Za-z0-9_]+(?:_t|_fun))\s*;",
        stripped,
        re.DOTALL,
    ):
        names.add(match.group(1))
    for match in re.finditer(r"\btypedef\b[^;{}]*;", stripped, re.DOTALL):
        declaration = match.group(0)
        callback = re.search(
            r"\(\s*(?:mi_cdecl\s+)?(mi_[A-Za-z0-9_]+_fun)\s*\)\s*\(", declaration
        )
        if callback is not None:
            names.add(callback.group(1))
            continue
        aliases = re.findall(r"\b(mi_[A-Za-z0-9_]+(?:_t|_fun))\b", declaration)
        if aliases:
            names.add(aliases[-1])
    return names


def public_option_names(text: str) -> set[str]:
    """Extract exactly the `mi_option_e` enumerators, not option functions."""

    stripped = strip_comments(text)
    match = re.search(
        r"\btypedef\s+enum\s+mi_option_e\s*\{(?P<body>.*?)\}\s*mi_option_t\s*;",
        stripped,
        re.DOTALL,
    )
    if match is None:
        return set()
    names: set[str] = set()
    for entry in match.group("body").split(","):
        enumerator = re.match(r"\s*(mi_option_[A-Za-z0-9_]+)\b", entry)
        if enumerator is not None:
            names.add(enumerator.group(1))
    return names


def macro_configuration_names(source: Path) -> set[str]:
    names: set[str] = set()
    for header in sorted((source / "include").rglob("*.h")):
        text = header.read_text(encoding="utf-8", errors="replace")
        names.update(
            match.group(1)
            for match in re.finditer(r"^\s*#\s*define\s+(MI_[A-Za-z0-9_]+)\b", text, re.MULTILINE)
        )
    return names


def cmake_compile_mode_declarations(text: str) -> list[dict[str, Any]]:
    """Inventory each initial pinned root-CMake ``MI_*`` cache declaration."""

    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        option = re.match(
            r"\s*option\(\s*(MI_[A-Za-z0-9_]+)\b.*\s+(ON|OFF|\"\")\s*\)\s*$",
            line,
        )
        if option is not None:
            records.append(
                {
                    "allowed_source_tokens": ["OFF", "ON"],
                    "declaration_kind": "cmake-option",
                    "default_source_token": option.group(2).strip('"'),
                    "name": option.group(1),
                    "source": {"line": line_number, "path": "CMakeLists.txt"},
                }
            )
            continue
        cache = re.match(
            r"\s*set\(\s*(MI_[A-Za-z0-9_]+)\s+(\"[^\"]*\"|\S+)\s+"
            r"CACHE\s+STRING\b",
            line,
        )
        if cache is not None:
            records.append(
                {
                    "allowed_source_tokens": [],
                    "declaration_kind": "cmake-cache-string",
                    "default_source_token": cache.group(2).strip('"'),
                    "name": cache.group(1),
                    "source": {"line": line_number, "path": "CMakeLists.txt"},
                }
            )

    by_name = {record["name"]: record for record in records}
    if len(by_name) != len(records) or not records:
        raise HarnessError("pinned root CMake has duplicate or absent MI_* mode declarations")
    for match in re.finditer(
        r"set_property\(CACHE\s+(MI_[A-Za-z0-9_]+)\s+PROPERTY\s+STRINGS\s+([^)]*)\)",
        text,
    ):
        name = match.group(1)
        if name not in by_name:
            raise HarnessError(f"pinned root CMake gives values for undeclared mode {name}")
        tokens = [
            quoted if quoted else bare
            for quoted, bare in re.findall(r'\"([^\"]*)\"|([^\s\"]+)', match.group(2))
        ]
        if not tokens:
            raise HarnessError(f"pinned root CMake has an empty value set for mode {name}")
        by_name[name]["allowed_source_tokens"] = tokens
    for record in records:
        if not record["allowed_source_tokens"]:
            raise HarnessError(
                f"pinned root CMake cache-string mode lacks an enumerated value set: {record['name']}"
            )
    return records


def compile_mode_classification(name: str) -> dict[str, Any]:
    platform_limited = PLATFORM_LIMITED_LINUX_AARCH64_COMPILE_MODES.get(name)
    if platform_limited is not None:
        reason, sources = platform_limited
        return {
            "applicability_sources": list(sources),
            "classification": "platform-limited-mode",
            "classification_reason": reason,
            "target_applicability": "applicable",
        }
    if name in DEPRECATED_COMPILE_MODES:
        classification = "deprecated-mode"
        reason = "Deprecated upstream compatibility spelling retained by the pinned root CMake configuration."
    elif name in SOURCE_BUILD_CONTROL_MODES:
        classification = "source-build-control"
        reason = "Applicable pinned source-build control; it remains explicitly accounted for by full mode parity."
    elif name in ARTIFACT_COMPILE_MODES:
        classification = "artifact-mode"
        reason = "Applicable shared, static, or override-object artifact mode on Linux/AArch64."
    elif name.startswith("MI_DEBUG") or name in {"MI_CHECK_FULL", "MI_NO_DEBUG", "MI_SHOW_ERRORS"}:
        classification = "debug-mode"
        reason = "Applicable debug and invariant-checking mode on Linux/AArch64."
    elif name.startswith("MI_SECURE") or name == "MI_FREE_IS_CHECKED":
        classification = "secure-mode"
        reason = "Applicable security-hardening mode on Linux/AArch64."
    elif name.startswith("MI_GUARDED"):
        classification = "guarded-mode"
        reason = "Applicable guarded-allocation mode on Linux/AArch64."
    elif name.startswith("MI_TLS") or name == "MI_LOCAL_DYNAMIC_TLS":
        classification = "tls-mode"
        reason = "Applicable allocator TLS selection or compatibility spelling on Linux/AArch64."
    elif name.startswith("MI_TRACK") or name in {"MI_DEBUG_TSAN", "MI_DEBUG_UBSAN"}:
        classification = "instrumentation-mode"
        reason = "Applicable allocator instrumentation selection on Linux/AArch64."
    elif name in {"MI_OPT_ARCH", "MI_NO_OPT_ARCH", "MI_OPT_SIMD"}:
        classification = "architecture-profile"
        reason = "Applicable optional AArch64 optimization profile; it is distinct from the Armv8.0 production baseline."
    elif name in {"MI_OVERRIDE", "MI_LIBC_MUSL", "MI_USE_CXX", "MI_NO_USE_CXX"}:
        classification = "integration-mode"
        reason = "Applicable source or libc integration selection on Linux/AArch64."
    else:
        classification = "allocator-mode"
        reason = "Applicable pinned allocator compile-time mode on Linux/AArch64."
    return {
        "applicability_sources": [],
        "classification": classification,
        "classification_reason": reason,
        "target_applicability": "applicable",
    }


def compile_mode_record(declaration: Mapping[str, Any]) -> dict[str, Any]:
    classification = compile_mode_classification(str(declaration["name"]))
    applicable = classification["target_applicability"] == "applicable"
    source_values: list[dict[str, Any]] = []
    for token in declaration["allowed_source_tokens"]:
        limited_value = PLATFORM_LIMITED_LINUX_AARCH64_MODE_VALUES.get(
            (str(declaration["name"]), str(token))
        )
        if not applicable:
            value_reason = classification["classification_reason"]
            value_sources = classification["applicability_sources"]
            value_applicability = "inapplicable"
        elif limited_value is not None:
            value_reason, value_source_tuple = limited_value
            value_sources = list(value_source_tuple)
            value_applicability = "applicable"
        else:
            value_reason = "Applicable source value for this Linux/AArch64 compile-time mode."
            value_sources = []
            value_applicability = "applicable"
        source_values.append(
            {
                "applicability_sources": value_sources,
                "classification_reason": value_reason,
                "target_applicability": value_applicability,
                "token": token,
            }
        )
    return {
        **declaration,
        **classification,
        "completion_status": "blocked" if applicable else "not-required",
        "differential_verified": False,
        "implemented": False,
        "implementation_blocker": (
            "No complete Linux/AArch64 Rust mode implementation and required evidence chain is recorded."
            if applicable
            else ""
        ),
        "integration_verified": False,
        "intentional_difference": "",
        "parity_requirement": "required" if applicable else "not-required",
        "performance_qualified": False,
        "source_values": source_values,
        "stress_verified": False,
        "unit_verified": False,
    }


def api_group(name: str) -> str:
    if name.startswith("mi_theap_"):
        return "theap"
    if name.startswith("mi_heap_"):
        return "heap"
    if name.startswith("mi_arena_"):
        return "arena"
    if name.startswith("mi_subproc_"):
        return "subprocess"
    if name.startswith("mi_option_") or name.startswith("mi_options_"):
        return "options"
    if name.startswith("mi_stat") or name.startswith("mi_process_info"):
        return "statistics-process-information"
    if name.startswith("mi_register_"):
        return "callbacks"
    if name.startswith("mi_visit") or name.startswith("mi_manage"):
        return "memory-visitation-management"
    if name.startswith("mi_collect") or name.startswith("mi_thread_") or name.startswith("mi_process_"):
        return "lifecycle-collection"
    if "aligned" in name or name.startswith("mi_memalign") or name.startswith("mi_posix_memalign"):
        return "aligned-allocation"
    if name in {"mi_malloc", "mi_calloc", "mi_realloc", "mi_expand", "mi_free", "mi_strdup", "mi_strndup", "mi_realpath"}:
        return "standard-allocation"
    if name.startswith("mi_"):
        return "extended-allocation"
    return "source-convenience"


def classify_api_item(name: str, kind: str) -> dict[str, Any]:
    """Classify one pinned public-header item for this Linux/AArch64 port.

    This is intentionally a closed, source-audited policy table rather than a
    best-effort platform guess.  New header names fall into the conservative
    required/source-only defaults and then fail the release-symbol cross-check
    if they are external declarations without a reviewed symbol disposition.
    """

    classification = "required-platform-applicable"
    reason = "Pinned v3.5.0 public API applicable to the Linux/AArch64 allocator engine."
    profile = "linux-aarch64-release"
    test_adapter_applicable = kind == "external-function"

    if kind == "macro":
        if name in CXX_DECLARATION_MACROS:
            classification = "source-only-cxx-convenience"
            reason = (
                "C++-only mimalloc-new-delete.h declaration macro; it decorates "
                "global operator new overloads and has no independent ELF symbol."
            )
            profile = "linux-aarch64-cxx-source"
        else:
            classification = "source-only-macro"
            reason = "Preprocessor source convenience; it has no independent ELF symbol."
            profile = "source-only"
        test_adapter_applicable = False
    elif kind == "override-macro":
        classification = "source-only-macro"
        reason = (
            "Opt-in mimalloc-override.h source rewrite; it changes caller source "
            "and has no independent allocator ELF symbol."
        )
        profile = "linux-aarch64-override"
        test_adapter_applicable = False
    elif kind == "static-inline":
        classification = "source-only-inline"
        reason = "Pinned header `static inline` helper; it has no independent ELF symbol."
        profile = "source-only"
        test_adapter_applicable = False
    elif kind in {"cxx-template", "cxx-convenience"}:
        classification = "source-only-cxx-convenience"
        reason = "C++ source convenience, not a C function declaration or allocator ELF symbol."
        profile = "linux-aarch64-cxx-source"
        test_adapter_applicable = False
    elif kind == "type":
        reason = "Pinned public type declaration used by the Linux/AArch64 C API."
        test_adapter_applicable = False
    elif kind == "option":
        test_adapter_applicable = False
        if name in PLATFORM_SPECIFIC_EFFECT_OPTIONS:
            classification = "platform-specific-effect-option"
            reason = PLATFORM_SPECIFIC_EFFECT_OPTIONS[name]
            profile = "linux-aarch64-platform-specific-effect"
        elif name in HEADER_DEPRECATED_OPTIONS:
            classification = "deprecated"
            reason = "Explicit `mi_option_deprecated_*` enumerator retained by the pinned v3.5.0 header."
            profile = "linux-aarch64-deprecated"
        elif name in LEGACY_OPTION_ALIASES:
            classification = "deprecated"
            reason = "Legacy option alias in the pinned v3.5.0 `mi_option_e` declaration."
            profile = "linux-aarch64-legacy-option-alias"
        elif name in GUARDED_MODE_OPTIONS:
            classification = "optional-mode"
            reason = "Guarded-allocation option; relevant only in the MI_GUARDED profile."
            profile = "linux-aarch64-guarded"
        elif name == "mi_option_arena_is_numa_local":
            classification = "experimental"
            reason = "Marked experimental by the pinned v3.5.0 option declaration."
            profile = "linux-aarch64-experimental"
    elif kind == "external-function":
        if name in STALE_EXTERNAL_DECLARATIONS:
            classification = "upstream-unavailable-declaration"
            reason = NORMAL_RELEASE_SYMBOL_EXCEPTIONS[name]
            profile = "upstream-unavailable"
            test_adapter_applicable = False
        elif name in LINUX_AARCH64_LIMITED_EXTERNAL_REASONS:
            classification = "linux-einval-operation"
            reason = LINUX_AARCH64_LIMITED_EXTERNAL_REASONS[name]
            profile = "linux-aarch64-limited-operation"
        elif name in OVERRIDE_ONLY_EXTERNAL_DECLARATIONS:
            classification = "override-only"
            reason = NORMAL_RELEASE_SYMBOL_EXCEPTIONS[name]
            profile = "linux-aarch64-override"
            test_adapter_applicable = False
        elif name in EXPERIMENTAL_EXTERNAL_FUNCTIONS:
            classification = "experimental"
            reason = "Marked experimental by the pinned v3.5.0 public header."
            profile = "linux-aarch64-experimental"
        elif name in DEPRECATED_EXTERNAL_FUNCTIONS:
            classification = "deprecated"
            reason = "Marked deprecated by the pinned v3.5.0 public header."
            profile = "linux-aarch64-deprecated"
        elif name in CXX_NEW_DELETE_EXTERNAL_FUNCTIONS:
            classification = "optional-mode"
            reason = "C++ new/delete integration function; applicable when the C++ adapter mode is enabled."
            profile = "linux-aarch64-cxx-new-delete"

    return {
        "classification": classification,
        "classification_reason": reason,
        "profile": profile,
        "test_adapter_applicable": test_adapter_applicable,
    }


def item_record(name: str, kind: str, headers: Sequence[str], tests: Sequence[str]) -> dict[str, Any]:
    classification = classify_api_item(name, kind)
    target_applicability = (
        "inapplicable"
        if classification["classification"]
        in {"unsupported-linux-aarch64", "upstream-unavailable-declaration"}
        else "applicable"
    )
    applicable = target_applicability == "applicable"
    applicable_external = kind == "external-function" and classification["test_adapter_applicable"]
    return {
        "adapter_surface": "test-c-api-adapter-only" if applicable_external else "source-only",
        **classification,
        "applicability_sources": list(API_CLASSIFICATION_SOURCES.get(name, ())),
        "completion_status": "blocked" if applicable else "not-required",
        "crabc_libc_exported": False,
        "differential_verified": False,
        "exported": False,
        "group": api_group(name) if kind in {"external-function", "option", "type"} else "source-convenience",
        "headers": list(headers),
        "implemented": False,
        "implementation_blocker": (
            "No public Linux/AArch64 crabc implementation and complete evidence chain is recorded for this item."
            if applicable
            else ""
        ),
        "integration_verified": False,
        "intentional_difference": "",
        "kind": kind,
        "name": name,
        "oracle_release_exported": (
            kind == "external-function" and name not in NORMAL_RELEASE_SYMBOL_EXCEPTIONS
        ),
        "parity_requirement": "required" if applicable else "not-required",
        "performance_qualified": False,
        "stress_verified": False,
        "target_applicability": target_applicability,
        "test_references": list(tests),
        "unit_verified": False,
    }


def test_sources(source: Path) -> list[Path]:
    root = source / "test"
    paths = [path for path in root.rglob("*") if path.is_file() and path.suffix in {".c", ".cc", ".cpp", ".h"}]
    if not paths:
        raise HarnessError("pinned mimalloc source has no upstream test sources")
    return sorted(paths)


def validate_api_parity_inventory(inventory: Mapping[str, Any]) -> dict[str, int]:
    """Fail closed on API/mode omissions, contradictions, and track conflation."""

    if inventory.get("format") != 3:
        raise HarnessError("unsupported Linux/AArch64 API parity inventory format")
    items = inventory.get("items")
    modes = inventory.get("compile_time_modes")
    summary = inventory.get("summary")
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise HarnessError("API parity inventory has invalid API items")
    if not isinstance(modes, list) or not all(isinstance(mode, dict) for mode in modes):
        raise HarnessError("API parity inventory has invalid compile-time modes")
    if not isinstance(summary, dict):
        raise HarnessError("API parity inventory has no summary")

    expected_item_count = summary.get("total_item_count")
    if type(expected_item_count) is not int or expected_item_count != len(items):
        raise HarnessError("API item count differs from the inventory summary")
    expected_mode_count = summary.get("compile_time_mode_count")
    if type(expected_mode_count) is not int or expected_mode_count != len(modes):
        raise HarnessError("compile-time mode count differs from the inventory summary")

    item_keys = [(item.get("kind"), item.get("name")) for item in items]
    if any(
        not isinstance(kind, str) or not kind or not isinstance(name, str) or not name
        for kind, name in item_keys
    ) or len(item_keys) != len(set(item_keys)):
        raise HarnessError("API parity inventory has unnamed or duplicate API items")
    mode_names = [mode.get("name") for mode in modes]
    if any(not isinstance(name, str) or not name for name in mode_names) or len(mode_names) != len(set(mode_names)):
        raise HarnessError("API parity inventory has unnamed or duplicate compile-time modes")

    verification_fields = (
        "differential_verified",
        "integration_verified",
        "performance_qualified",
        "stress_verified",
        "unit_verified",
    )
    applicable_items: list[Mapping[str, Any]] = []
    blocked_items: list[Mapping[str, Any]] = []
    for item in items:
        name = item["name"]
        applicability = item.get("target_applicability")
        if applicability not in {"applicable", "inapplicable"}:
            raise HarnessError(f"API item {name} has invalid target applicability")
        if not isinstance(item.get("classification_reason"), str):
            raise HarnessError(f"API item {name} has an invalid classification rationale")
        sources = item.get("applicability_sources")
        if not isinstance(sources, list) or not all(isinstance(source, str) and source for source in sources):
            raise HarnessError(f"API item {name} has invalid applicability sources")
        for field in ("exported", "implemented", *verification_fields):
            if type(item.get(field)) is not bool:
                raise HarnessError(f"API item {name} has a non-boolean {field} status")
        if (
            item["exported"]
            or any(item[field] for field in verification_fields)
        ) and not item["implemented"]:
            raise HarnessError(f"API item {name} has contradictory implementation/evidence status")

        if applicability == "inapplicable":
            if not item["classification_reason"] or not sources:
                raise HarnessError(
                    f"inapplicable API item {name} lacks a source-backed rationale"
                )
            if item.get("classification") != "upstream-unavailable-declaration":
                raise HarnessError(
                    f"normal-release public API item {name} cannot be inapplicable merely because its behavior is platform-limited"
                )
            if item.get("parity_requirement") != "not-required" or item.get("completion_status") != "not-required":
                raise HarnessError(f"inapplicable API item {name} has a contradictory parity requirement")
            if item["implemented"] or item["exported"] or any(item[field] for field in verification_fields):
                raise HarnessError(f"inapplicable API item {name} claims implementation or evidence")
            continue

        applicable_items.append(item)
        if item.get("parity_requirement") != "required":
            raise HarnessError(f"applicable API item {name} is not required for full parity")
        completion = item.get("completion_status")
        blocker = item.get("implementation_blocker")
        if completion == "blocked":
            if not isinstance(blocker, str) or not blocker:
                raise HarnessError(f"blocked applicable API item {name} lacks an implementation blocker")
            blocked_items.append(item)
        elif completion == "complete":
            if blocker != "":
                raise HarnessError(f"complete applicable API item {name} retains a blocker")
            required = [item["implemented"], *(item[field] for field in verification_fields)]
            if item.get("kind") == "external-function":
                required.append(item["exported"])
            if not all(required):
                raise HarnessError(f"complete applicable API item {name} lacks required evidence")
        else:
            raise HarnessError(f"applicable API item {name} has invalid completion status")

    required_modes: list[Mapping[str, Any]] = []
    blocked_modes: list[Mapping[str, Any]] = []
    for mode in modes:
        name = mode["name"]
        applicability = mode.get("target_applicability")
        sources = mode.get("applicability_sources")
        if applicability not in {"applicable", "inapplicable"}:
            raise HarnessError(f"compile-time mode {name} has invalid target applicability")
        if not isinstance(mode.get("classification_reason"), str):
            raise HarnessError(f"compile-time mode {name} has an invalid classification rationale")
        if not isinstance(sources, list) or not all(isinstance(source, str) and source for source in sources):
            raise HarnessError(f"compile-time mode {name} has invalid applicability sources")
        if applicability == "inapplicable" and mode.get("declaration_kind") in {
            "cmake-cache-string",
            "cmake-option",
        }:
            if not mode["classification_reason"] or not sources:
                raise HarnessError(
                    f"inapplicable compile-time mode {name} lacks a source-backed rationale"
                )
            raise HarnessError(
                f"unconditional root-CMake mode {name} remains an applicable observable interface on Linux/AArch64"
            )
        allowed = mode.get("allowed_source_tokens")
        if not isinstance(allowed, list) or not allowed or not all(isinstance(token, str) for token in allowed):
            raise HarnessError(f"compile-time mode {name} lacks its source value inventory")
        source_values = mode.get("source_values")
        if not isinstance(source_values, list) or not all(
            isinstance(value, dict) for value in source_values
        ):
            raise HarnessError(f"compile-time mode {name} has invalid source value records")
        value_tokens = [value.get("token") for value in source_values]
        if value_tokens != allowed or len(value_tokens) != len(set(value_tokens)):
            raise HarnessError(f"compile-time mode {name} omits or duplicates a source value")
        for value in source_values:
            token = value["token"]
            value_applicability = value.get("target_applicability")
            value_sources = value.get("applicability_sources")
            if value_applicability not in {"applicable", "inapplicable"}:
                raise HarnessError(f"compile-time mode {name} value {token} has invalid target applicability")
            if not isinstance(value.get("classification_reason"), str):
                raise HarnessError(f"compile-time mode {name} value {token} has an invalid rationale")
            if not isinstance(value_sources, list) or not all(
                isinstance(value_source, str) and value_source for value_source in value_sources
            ):
                raise HarnessError(f"compile-time mode {name} value {token} has invalid applicability sources")
            if value_applicability == "inapplicable" and (
                not value["classification_reason"] or not value_sources
            ):
                raise HarnessError(
                    f"inapplicable mode value {name}={token} lacks a source-backed rationale"
                )
            if value_applicability == "inapplicable":
                raise HarnessError(
                    f"declared mode value {name}={token} remains applicable because its fallback, no-op, or rejection behavior is observable"
                )
            if applicability == "inapplicable" and value_applicability != "inapplicable":
                raise HarnessError(f"inapplicable compile-time mode {name} has an applicable source value")
        source = mode.get("source")
        if (
            not isinstance(source, dict)
            or source.get("path") != "CMakeLists.txt"
            or type(source.get("line")) is not int
            or source["line"] <= 0
        ):
            raise HarnessError(f"compile-time mode {name} lacks a source declaration anchor")
        for field in ("implemented", *verification_fields):
            if type(mode.get(field)) is not bool:
                raise HarnessError(f"compile-time mode {name} has a non-boolean {field} status")
        if any(mode[field] for field in verification_fields) and not mode["implemented"]:
            raise HarnessError(f"compile-time mode {name} has contradictory implementation/evidence status")

        if applicability == "inapplicable":
            if not mode["classification_reason"] or not sources:
                raise HarnessError(
                    f"inapplicable compile-time mode {name} lacks a source-backed rationale"
                )
            if mode.get("parity_requirement") != "not-required" or mode.get("completion_status") != "not-required":
                raise HarnessError(f"inapplicable compile-time mode {name} has a contradictory parity requirement")
            if mode["implemented"] or any(mode[field] for field in verification_fields):
                raise HarnessError(f"inapplicable compile-time mode {name} claims implementation or evidence")
            continue

        required_modes.append(mode)
        if mode.get("parity_requirement") != "required":
            raise HarnessError(f"applicable compile-time mode {name} is not required for full parity")
        completion = mode.get("completion_status")
        blocker = mode.get("implementation_blocker")
        if completion == "blocked":
            if not isinstance(blocker, str) or not blocker:
                raise HarnessError(f"blocked compile-time mode {name} lacks an implementation blocker")
            blocked_modes.append(mode)
        elif completion == "complete":
            if blocker != "" or not mode["implemented"] or not all(
                mode[field] for field in verification_fields
            ):
                raise HarnessError(f"complete compile-time mode {name} lacks required evidence")
        else:
            raise HarnessError(f"applicable compile-time mode {name} has invalid completion status")

    expected_summary = {
        "applicable_item_count": len(applicable_items),
        "blocked_applicable_item_count": len(blocked_items),
        "blocked_required_mode_count": len(blocked_modes),
        "compile_time_mode_count": len(modes),
        "configuration_macro_count": len(inventory.get("resolved_configuration_macro_names", [])),
        "cxx_convenience_count": sum(item["kind"] == "cxx-convenience" for item in items),
        "cxx_template_count": sum(item["kind"] == "cxx-template" for item in items),
        "external_function_count": sum(item["kind"] == "external-function" for item in items),
        "inapplicable_item_count": len(items) - len(applicable_items),
        "inapplicable_mode_count": len(modes) - len(required_modes),
        "macro_count": sum(item["kind"] == "macro" for item in items),
        "option_count": sum(item["kind"] == "option" for item in items),
        "override_macro_count": sum(item["kind"] == "override-macro" for item in items),
        "required_mode_count": len(required_modes),
        "source_only_count": sum(item.get("adapter_surface") == "source-only" for item in items),
        "source_only_macro_count": sum(item["kind"] in {"macro", "override-macro"} for item in items),
        "static_inline_count": sum(item["kind"] == "static-inline" for item in items),
        "total_item_count": len(items),
        "type_count": sum(item["kind"] == "type" for item in items),
    }
    if summary != expected_summary:
        raise HarnessError("API/mode parity inventory summary contradicts its item records")

    tracks = inventory.get("completion_tracks")
    if not isinstance(tracks, dict) or set(tracks) != {
        "full_linux_aarch64_v3_5_0_parity",
        "malloc_engine_readiness",
    }:
        raise HarnessError("API parity inventory lacks its two independent completion tracks")
    readiness = tracks["malloc_engine_readiness"]
    parity = tracks["full_linux_aarch64_v3_5_0_parity"]
    if not isinstance(readiness, dict) or readiness.get("inventory_driven") is not False:
        raise HarnessError("malloc-engine readiness must remain separate from the API/mode inventory")
    if readiness.get("status") not in {"blocked", "complete"}:
        raise HarnessError("malloc-engine readiness has an invalid separate-gate status")
    if readiness["status"] == "blocked" and (
        not isinstance(readiness.get("blockers"), list)
        or not readiness["blockers"]
        or not all(isinstance(blocker, str) and blocker for blocker in readiness["blockers"])
    ):
        raise HarnessError("blocked malloc-engine readiness lacks a separate-gate blocker")
    if not isinstance(parity, dict) or parity.get("inventory_driven") is not True:
        raise HarnessError("full parity must be driven only by the API/mode inventory")
    expected_parity_counts = {
        "blocked_api_item_count": len(blocked_items),
        "blocked_compile_time_mode_count": len(blocked_modes),
        "required_api_item_count": len(applicable_items),
        "required_compile_time_mode_count": len(required_modes),
    }
    if any(parity.get(key) != value for key, value in expected_parity_counts.items()):
        raise HarnessError("full parity track counts contradict the API/mode inventory")
    expected_parity_status = "blocked" if blocked_items or blocked_modes else "complete"
    if parity.get("status") != expected_parity_status:
        raise HarnessError("full parity is marked complete while required API or mode work is blocked")
    return {
        "applicable_api_item_count": len(applicable_items),
        "blocked_api_item_count": len(blocked_items),
        "blocked_compile_time_mode_count": len(blocked_modes),
        "compile_time_mode_count": len(modes),
        "required_compile_time_mode_count": len(required_modes),
    }


def build_api_inventory(source: Path, pin: Mapping[str, str]) -> dict[str, Any]:
    by_name: dict[tuple[str, str], set[str]] = {}
    all_header_text: dict[str, str] = {}
    for header in PUBLIC_HEADERS:
        path = source / header
        if not path.is_file():
            raise HarnessError(f"pinned source has no public header: {header}")
        text = path.read_text(encoding="utf-8", errors="replace")
        all_header_text[header] = text
        for name in public_external_function_names(text):
            by_name.setdefault(("external-function", name), set()).add(header)
        for name in public_static_inline_names(text):
            by_name.setdefault(("static-inline", name), set()).add(header)
        for name in public_cxx_template_names(text):
            by_name.setdefault(("cxx-template", name), set()).add(header)
        for name in public_macro_names(text):
            by_name.setdefault(("macro", name), set()).add(header)
        for name in public_type_names(text):
            by_name.setdefault(("type", name), set()).add(header)
        for name in public_option_names(text):
            by_name.setdefault(("option", name), set()).add(header)

    override_header = "include/mimalloc-override.h"
    for name in override_macro_names(all_header_text[override_header]):
        by_name.setdefault(("override-macro", name), set()).add(override_header)
    by_name.setdefault(("cxx-convenience", "global-new-delete-overrides"), set()).add(
        "include/mimalloc-new-delete.h"
    )

    test_text = {
        path.relative_to(source).as_posix(): path.read_text(encoding="utf-8", errors="replace")
        for path in test_sources(source)
    }
    items: list[dict[str, Any]] = []
    for (kind, name), headers in sorted(by_name.items(), key=lambda pair: (pair[0][1], pair[0][0])):
        references = sorted(name for name, text in test_text.items() if re.search(rf"\b{re.escape(name)}\b", text))
        items.append(item_record(name, kind, sorted(headers), references))

    compile_time_modes = [
        compile_mode_record(declaration)
        for declaration in cmake_compile_mode_declarations(
            (source / "CMakeLists.txt").read_text(encoding="utf-8", errors="replace")
        )
    ]
    config_names = sorted(macro_configuration_names(source))
    applicable_items = [
        item for item in items if item["target_applicability"] == "applicable"
    ]
    required_modes = [
        mode for mode in compile_time_modes if mode["parity_requirement"] == "required"
    ]
    blocked_items = [
        item for item in applicable_items if item["completion_status"] == "blocked"
    ]
    blocked_modes = [
        mode for mode in required_modes if mode["completion_status"] == "blocked"
    ]
    inventory = {
        "archive_root": pin["archive_root"],
        "compile_time_mode_source": source_file_records(source, ["CMakeLists.txt"])[0],
        "compile_time_modes": compile_time_modes,
        "completion_tracks": {
            "full_linux_aarch64_v3_5_0_parity": {
                "authority": "compat/allocator/api-v3.5.0.json",
                "blocked_api_item_count": len(blocked_items),
                "blocked_compile_time_mode_count": len(blocked_modes),
                "inventory_driven": True,
                "required_api_item_count": len(applicable_items),
                "required_compile_time_mode_count": len(required_modes),
                "status": "blocked" if blocked_items or blocked_modes else "complete",
            },
            "malloc_engine_readiness": {
                "authoritative_contracts": [
                    "compat/allocator/architecture-gate-v3.5.0.json",
                    "compat/allocator/m5-gate-v3.5.0.json",
                ],
                "blockers": [
                    "The nondefault allocator still depends on the separate architecture and Milestone 5 acceptance gates; API or mode inventory rows cannot close those gates by inference."
                ],
                "inventory_driven": False,
                "status": "blocked",
            },
        },
        "format": 3,
        "items": items,
        "mimalloc_version": pin["version"],
        "pinned_archive_sha256": pin["sha256"],
        "pinned_revision": pin["revision"],
        "public_headers": source_file_records(source, PUBLIC_HEADERS),
        "resolved_configuration_macro_names": config_names,
        "release_symbol_contract": {
            "expected_defined_symbol_names": sorted(
                item["name"]
                for item in items
                if item["kind"] == "external-function" and item["oracle_release_exported"]
            ),
            "header_declarations_without_normal_release_symbol": [
                {
                    "classification": item["classification"],
                    "name": item["name"],
                    "reason": item["classification_reason"],
                }
                for item in items
                if item["kind"] == "external-function" and not item["oracle_release_exported"]
            ],
        },
        "summary": {
            "applicable_item_count": len(applicable_items),
            "blocked_applicable_item_count": len(blocked_items),
            "blocked_required_mode_count": len(blocked_modes),
            "compile_time_mode_count": len(compile_time_modes),
            "configuration_macro_count": len(config_names),
            "cxx_convenience_count": sum(item["kind"] == "cxx-convenience" for item in items),
            "cxx_template_count": sum(item["kind"] == "cxx-template" for item in items),
            "external_function_count": sum(item["kind"] == "external-function" for item in items),
            "inapplicable_item_count": len(items) - len(applicable_items),
            "inapplicable_mode_count": len(compile_time_modes) - len(required_modes),
            "macro_count": sum(item["kind"] == "macro" for item in items),
            "option_count": sum(item["kind"] == "option" for item in items),
            "override_macro_count": sum(item["kind"] == "override-macro" for item in items),
            "required_mode_count": len(required_modes),
            "source_only_count": sum(item["adapter_surface"] == "source-only" for item in items),
            "source_only_macro_count": sum(item["kind"] in {"macro", "override-macro"} for item in items),
            "static_inline_count": sum(item["kind"] == "static-inline" for item in items),
            "total_item_count": len(items),
            "type_count": sum(item["kind"] == "type" for item in items),
        },
    }
    validate_api_parity_inventory(inventory)
    return inventory


def build_test_inventory(source: Path, pin: Mapping[str, str]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for path in test_sources(source):
        name = path.relative_to(source).as_posix()
        kind = "test-source" if path.suffix in {".c", ".cc", ".cpp"} else "test-support"
        if name in M4_ADAPTED_UPSTREAM_TEST_PATHS:
            status = "adapted-milestone-4"
            status_note = M4_ADAPTED_UPSTREAM_TEST_NOTE
            status_field = "execution"
        elif name in M5_ADAPTED_UPSTREAM_TEST_PATHS:
            status = "adapted-milestone-5"
            status_note = M5_ADAPTED_UPSTREAM_TEST_NOTE
            status_field = "execution"
        else:
            status = "blocked-milestone-5-plus"
            status_note = M5_PLUS_UNADAPTED_UPSTREAM_TEST_NOTE
            status_field = "blocked_by"
        items.append(
            {
                status_field: status_note,
                "kind": kind,
                "path": name,
                "sha256": sha256_file(path),
                "status": status,
            }
        )
    return {
        "format": 3,
        "mimalloc_version": pin["version"],
        "pinned_archive_sha256": pin["sha256"],
        "tests": items,
        "summary": {
            "adapted_milestone_4_file_count": sum(
                item["status"] == "adapted-milestone-4" for item in items
            ),
            "adapted_milestone_5_file_count": sum(
                item["status"] == "adapted-milestone-5" for item in items
            ),
            "blocked_milestone_5_plus_count": sum(
                item["status"] == "blocked-milestone-5-plus" for item in items
            ),
            "test_source_count": sum(item["kind"] == "test-source" for item in items),
            "test_support_file_count": sum(item["kind"] == "test-support" for item in items),
            "total_inventory_file_count": len(items),
        },
    }


def generated_contracts(source: Path, pin: Mapping[str, str]) -> dict[Path, dict[str, Any]]:
    return {API_CONTRACT: build_api_inventory(source, pin), UPSTREAM_TEST_CONTRACT: build_test_inventory(source, pin)}


def write_contracts(contracts: Mapping[Path, Mapping[str, Any]]) -> None:
    for path, payload in contracts.items():
        write_json(path, payload)


def check_contracts(contracts: Mapping[Path, Mapping[str, Any]]) -> None:
    for path, generated in contracts.items():
        if not path.is_file():
            raise HarnessError(f"generated contract is absent: {path}; run --generate-contracts")
        checked_in = read_json(path)
        if path == API_CONTRACT:
            validate_api_parity_inventory(checked_in)
        if checked_in != generated:
            raise HarnessError(
                f"generated contract is stale: {path}; run compat/allocator/run.py --generate-contracts and review the diff"
            )


def load_port_map(path: Path = PORT_MAP) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HarnessError(f"invalid port map: {path}") from error
    metadata = raw.get("metadata")
    units = raw.get("unit")
    items = raw.get("item", [])
    if not isinstance(metadata, dict) or metadata.get("format") != 1:
        raise HarnessError("port map requires [metadata] format = 1")
    if not isinstance(units, list):
        raise HarnessError("port map requires [[unit]] records")
    if not isinstance(items, list):
        raise HarnessError("port map item records must be [[item]] tables")
    observed: set[str] = set()
    for index, unit in enumerate(units):
        if not isinstance(unit, dict):
            raise HarnessError(f"port map unit {index} is not a table")
        upstream = unit.get("upstream")
        if not isinstance(upstream, str) or not upstream:
            raise HarnessError(f"port map unit {index} has no upstream path")
        if upstream in observed:
            raise HarnessError(f"port map duplicates upstream path: {upstream}")
        observed.add(upstream)
        for key in ("source_region", "rust_module", "rust_item", "intentional_difference"):
            if not isinstance(unit.get(key), str):
                raise HarnessError(f"port map unit {upstream} has invalid {key}")
        tests = unit.get("tests")
        if not isinstance(tests, list) or not all(isinstance(test, str) for test in tests):
            raise HarnessError(f"port map unit {upstream} has invalid tests")
        for flag in STATUS_FIELDS:
            if not isinstance(unit.get(flag), bool):
                raise HarnessError(f"port map unit {upstream} has non-boolean {flag}")
    required = set(REQUIRED_PORT_UNITS)
    missing = sorted(required - observed)
    unexpected = sorted(observed - required)
    if missing or unexpected:
        detail = []
        if missing:
            detail.append("missing: " + ", ".join(missing))
        if unexpected:
            detail.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError("port map source coverage changed (" + "; ".join(detail) + ")")
    observed_items: set[tuple[str, str]] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise HarnessError(f"port map item {index} is not a table")
        upstream = item.get("upstream")
        name = item.get("name")
        if not isinstance(upstream, str) or upstream not in required:
            raise HarnessError(f"port map item {index} has an unknown upstream path")
        if not isinstance(name, str) or not name:
            raise HarnessError(f"port map item {index} has no source symbol")
        key = (upstream, name)
        if key in observed_items:
            raise HarnessError(f"port map duplicates source symbol: {upstream}:{name}")
        observed_items.add(key)
        for key_name in ("source_region", "rust_module", "rust_item", "intentional_difference"):
            if not isinstance(item.get(key_name), str):
                raise HarnessError(f"port map item {upstream}:{name} has invalid {key_name}")
        tests = item.get("tests")
        if not isinstance(tests, list) or not all(isinstance(test, str) for test in tests):
            raise HarnessError(f"port map item {upstream}:{name} has invalid tests")
        for flag in STATUS_FIELDS:
            if not isinstance(item.get(flag), bool):
                raise HarnessError(f"port map item {upstream}:{name} has non-boolean {flag}")
    return raw


def port_map_counts(port_map: Mapping[str, Any]) -> dict[str, int]:
    units = port_map["unit"]
    items = port_map.get("item", [])
    assert isinstance(units, list)
    assert isinstance(items, list)
    records = [*units, *items]
    counts = {"item_count": len(items), "unit_count": len(units)}
    for field in STATUS_FIELDS:
        counts[field] = sum(bool(record[field]) for record in records)
    return counts


def port_map_true_statuses(port_map: Mapping[str, Any]) -> dict[str, list[str]]:
    statuses: dict[str, list[str]] = {}
    for unit in port_map["unit"]:
        key = f"unit:{unit['upstream']}"
        statuses[key] = [field for field in STATUS_FIELDS if unit[field]]
    for item in port_map.get("item", []):
        key = f"item:{item['upstream']}:{item['name']}"
        statuses[key] = [field for field in STATUS_FIELDS if item[field]]
    return dict(sorted(statuses.items()))


def ratchet_status_regressions(
    baseline: Mapping[str, Any], current: Mapping[str, Any]
) -> list[str]:
    baseline_statuses = baseline.get("port_map_true_statuses")
    current_statuses = current.get("port_map_true_statuses")
    if not isinstance(baseline_statuses, dict) or not isinstance(current_statuses, dict):
        return ["port_map_true_statuses:missing"]
    regressions: list[str] = []
    for record, old_fields in baseline_statuses.items():
        if not isinstance(record, str) or not isinstance(old_fields, list):
            return ["port_map_true_statuses:invalid"]
        new_fields = current_statuses.get(record, [])
        if not isinstance(new_fields, list):
            new_fields = []
        for field in old_fields:
            if field not in new_fields:
                regressions.append(f"{record}:{field}")
    return sorted(regressions)


def ratchet_measurement_regressions(
    baseline: Mapping[str, Any], current: Mapping[str, Any]
) -> list[str]:
    """Find monotonic inventory/count regressions before replacing a baseline."""

    regressions: list[str] = []
    for key in (
        "adapted_omitted_test_count",
        "adapted_selected_test_count",
        "adapted_stress_fixture_count",
        "native_shadow_stress_fixture_count",
        "api_total_item_count",
        "configuration_profile_count",
        "upstream_test_source_count",
        "upstream_test_inventory_file_count",
    ):
        old_value = baseline.get(key)
        new_value = current.get(key)
        if old_value is None and new_value is None:
            continue
        if key.startswith(("adapted_", "native_shadow_")) and old_value is None and type(new_value) is int:
            continue
        if type(old_value) is not int or type(new_value) is not int or new_value < old_value:
            regressions.append(key)

    old_counts = baseline.get("port_map_counts")
    new_counts = current.get("port_map_counts")
    if not isinstance(old_counts, dict) or not isinstance(new_counts, dict):
        regressions.append("port_map_counts")
    else:
        for key, old_value in old_counts.items():
            new_value = new_counts.get(key)
            if type(old_value) is not int or type(new_value) is not int or new_value < old_value:
                regressions.append(f"port_map_counts.{key}")
    return sorted(regressions)


def file_digest(path: Path) -> str:
    if not path.is_file():
        raise HarnessError(f"ratchet input is absent: {path}")
    return sha256_file(path)


def ratchet_payload(port_map: Mapping[str, Any]) -> dict[str, Any]:
    api = read_json(API_CONTRACT)
    tests = read_json(UPSTREAM_TEST_CONTRACT)
    adapted_tests = read_json(ADAPTED_TEST_CONTRACT)
    adapted_stress = read_json(ADAPTED_STRESS_TEST_CONTRACT)
    native_shadow_stress = read_json(NATIVE_SHADOW_STRESS_CONTRACT)
    return {
        "adapted_omitted_test_count": len(adapted_tests["omitted_tests"]),
        "adapted_selected_test_count": len(adapted_tests["selected_tests"]),
        "adapted_test_contract_sha256": file_digest(ADAPTED_TEST_CONTRACT),
        "adapted_stress_fixture_count": len(adapted_stress["source_hashes"]),
        "adapted_stress_test_contract_sha256": file_digest(ADAPTED_STRESS_TEST_CONTRACT),
        "native_shadow_stress_fixture_count": len(native_shadow_stress["source_hashes"]),
        "native_shadow_stress_contract_sha256": file_digest(NATIVE_SHADOW_STRESS_CONTRACT),
        "m1_foundations_contract_sha256": file_digest(M1_FOUNDATIONS_CONTRACT),
        "m2_memory_substrate_contract_sha256": file_digest(M2_MEMORY_SUBSTRATE_CONTRACT),
        "owner_exit_publication_contract_sha256": file_digest(
            OWNER_EXIT_PUBLICATION_CONTRACT
        ),
        "api_contract_sha256": file_digest(API_CONTRACT),
        "api_total_item_count": api["summary"]["total_item_count"],
        "configuration_profile_count": len(CONFIGURATION_PROFILES),
        "format": 1,
        "port_map_counts": port_map_counts(port_map),
        "port_map_sha256": file_digest(PORT_MAP),
        "port_map_true_statuses": port_map_true_statuses(port_map),
        "upstream_test_contract_sha256": file_digest(UPSTREAM_TEST_CONTRACT),
        "upstream_test_source_count": tests["summary"]["test_source_count"],
        "upstream_test_inventory_file_count": tests["summary"]["total_inventory_file_count"],
    }


def snapshot_ratchet(port_map: Mapping[str, Any]) -> None:
    current = ratchet_payload(port_map)
    if RATCHET.is_file():
        baseline = read_json(RATCHET)
        status_regressions = ratchet_status_regressions(baseline, current)
        if status_regressions == ["port_map_true_statuses:missing"]:
            status_regressions = []
        regressions = [
            *ratchet_measurement_regressions(baseline, current),
            *status_regressions,
        ]
        if regressions:
            raise HarnessError(
                "allocator ratchet regressed: " + ", ".join(sorted(regressions))
            )
    write_json(RATCHET, current)


def check_ratchet(port_map: Mapping[str, Any]) -> None:
    if not RATCHET.is_file():
        raise HarnessError(f"allocator ratchet is absent: {RATCHET}; run --snapshot-ratchet")
    baseline = read_json(RATCHET)
    if baseline.get("format") != 1:
        raise HarnessError("unsupported allocator ratchet format")
    current = ratchet_payload(port_map)
    regressions = [
        *ratchet_measurement_regressions(baseline, current),
        *ratchet_status_regressions(baseline, current),
    ]
    if regressions:
        raise HarnessError(
            "allocator port-map true status regressed or lacks an itemized baseline: "
            + ", ".join(regressions)
        )
    for key in (
        "adapted_test_contract_sha256",
        "adapted_stress_test_contract_sha256",
        "native_shadow_stress_contract_sha256",
        "m1_foundations_contract_sha256",
        "m2_memory_substrate_contract_sha256",
        "owner_exit_publication_contract_sha256",
        "api_contract_sha256",
        "port_map_sha256",
        "upstream_test_contract_sha256",
    ):
        if current[key] != baseline.get(key):
            raise HarnessError(f"allocator ratchet input changed: {key}; snapshot and review explicitly")


def require_native_aarch64() -> None:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise HarnessError("allocator C oracle requires the pinned native Linux/AArch64 development image")


def require_native_x86_64() -> dict[str, str]:
    """Refuse x86 evidence unless the canonical launcher attests a native host.

    A Docker guest can report x86-64 while QEMU translates it on a different
    host.  The dispatcher computes and passes these two values before the
    container starts, so require them in addition to the guest ELF/runtime
    facts.  Direct `--check` remains source-only; direct x86 execution must
    deliberately use the canonical native launcher provenance.
    """

    execution_mode = os.environ.get("CRABC_EXECUTION_MODE")
    host_architecture = os.environ.get("CRABC_HOST_ARCH")
    if execution_mode != "native" or host_architecture not in {"x86_64", "amd64"}:
        raise HarnessError(
            "native x86-64 allocator evidence requires canonical native provenance: "
            "CRABC_EXECUTION_MODE=native and CRABC_HOST_ARCH=x86_64 (or amd64); "
            "use ./compat/allocator/run-x86_64.sh allocator --quick"
        )
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise HarnessError(
            "x86-64 allocator C oracle requires the native Linux/x86-64 development image; "
            "emulation is not accepted"
        )
    return {
        "execution_mode": execution_mode,
        "host_architecture": host_architecture,
    }


def require_native_architecture(architecture: str) -> None:
    if architecture == "aarch64":
        require_native_aarch64()
    elif architecture == "x86_64":
        require_native_x86_64()
    else:
        raise HarnessError(f"unsupported allocator oracle architecture: {architecture}")


def require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise HarnessError(f"required oracle tool is unavailable: {name}")
    return resolved


def command_record(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
        raise HarnessError("oracle command timeout must be a positive integer number of seconds")
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HarnessError(f"failed to execute oracle command {' '.join(command)}: {error}") from error
    return {
        "command": list(command),
        "status": completed.returncode,
        "stderr": completed.stderr,
        "stdout": completed.stdout,
    }


def require_success(record: Mapping[str, Any], description: str) -> None:
    if record["status"] != 0:
        stderr = str(record["stderr"]).strip()
        raise HarnessError(f"{description} failed ({record['status']}): {stderr}")


def artifact_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise HarnessError(f"oracle artifact is absent: {path}")
    return {"bytes": path.stat().st_size, "path": relative(path), "sha256": sha256_file(path)}


def source_byte_record(value: bytes) -> dict[str, Any]:
    """Record Git's byte-oriented porcelain output without normalizing it."""

    return {
        "bytes": len(value),
        "hex": value.hex(),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def source_byte_payload(record: object, subject: str) -> bytes:
    """Decode and verify a source-state byte record before using its clean flag."""

    if not isinstance(record, Mapping) or set(record) != {"bytes", "hex", "sha256"}:
        raise HarnessError(f"{subject} byte record is invalid")
    try:
        payload = bytes.fromhex(str(record["hex"]))
    except (KeyError, ValueError) as error:
        raise HarnessError(f"{subject} byte record has invalid hex") from error
    if (
        type(record["bytes"]) is not int
        or record["bytes"] != len(payload)
        or record["sha256"] != hashlib.sha256(payload).hexdigest()
    ):
        raise HarnessError(f"{subject} byte record attestation drifted")
    return payload


def runtime_ticket_zero_soak_git_read_environment() -> dict[str, str]:
    """Preserve caller settings while keeping soak provenance reads index-safe."""

    environment = dict(os.environ)
    environment.update(RUNTIME_TICKET_ZERO_SOAK_GIT_READ_ENVIRONMENT)
    return environment


def validate_runtime_ticket_zero_soak_source_state(
    value: object, subject: str
) -> dict[str, Any]:
    """Validate the compact clean-Git state retained by the durable soak report."""

    if not isinstance(value, Mapping) or set(value) != {
        "kind",
        "revision",
        "worktree_clean",
        "worktree_status",
    }:
        raise HarnessError(f"{subject} source state is invalid")
    revision = value.get("revision")
    if value.get("kind") != "git" or not isinstance(revision, str) or not re.fullmatch(
        r"[0-9a-f]{40}", revision
    ):
        raise HarnessError(f"{subject} source revision is invalid")
    if type(value.get("worktree_clean")) is not bool:
        raise HarnessError(f"{subject} source cleanliness is invalid")
    status = source_byte_payload(value.get("worktree_status"), f"{subject} worktree status")
    if value["worktree_clean"] != (status == b""):
        raise HarnessError(f"{subject} source cleanliness contradicts its status")
    return dict(value)


def runtime_ticket_zero_soak_source_state() -> dict[str, Any]:
    """Capture one clean Git source state without allowing Git to refresh its index."""

    git = shutil.which("git")
    if git is None:
        raise HarnessError("runtime ticket-zero soak requires Git source attestation")
    environment = runtime_ticket_zero_soak_git_read_environment()
    revision_record = command_record(
        (git, "rev-parse", "--verify", "HEAD"), cwd=ROOT, env=environment
    )
    status_record = command_record(
        (git, "status", "--porcelain=v1", "--untracked-files=all", "-z"),
        cwd=ROOT,
        env=environment,
    )
    require_success(revision_record, "runtime ticket-zero soak Git revision")
    require_success(status_record, "runtime ticket-zero soak Git status")
    revision = revision_record.get("stdout")
    status = status_record.get("stdout")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}\n?", revision):
        raise HarnessError("runtime ticket-zero soak Git revision is invalid")
    if not isinstance(status, str):
        raise HarnessError("runtime ticket-zero soak Git status is invalid")
    state = validate_runtime_ticket_zero_soak_source_state(
        {
            "kind": "git",
            "revision": revision.strip(),
            "worktree_clean": status == "",
            "worktree_status": source_byte_record(status.encode("utf-8")),
        },
        "runtime ticket-zero soak",
    )
    if not state["worktree_clean"]:
        raise HarnessError("runtime ticket-zero soak requires a clean Git source")
    return state


def runtime_ticket_zero_soak_source_attestation(
    before: object, after: object
) -> dict[str, Any]:
    """Require the same clean Git state before and after the entire soak run."""

    source_before = validate_runtime_ticket_zero_soak_source_state(
        before, "runtime ticket-zero soak source before"
    )
    source_after = validate_runtime_ticket_zero_soak_source_state(
        after, "runtime ticket-zero soak source after"
    )
    if not source_before["worktree_clean"] or not source_after["worktree_clean"]:
        raise HarnessError("runtime ticket-zero soak requires a clean Git source")
    if source_before != source_after:
        raise HarnessError("runtime ticket-zero soak source changed during execution")
    return {
        "after": source_after,
        "before": source_before,
        "git_read_environment": dict(RUNTIME_TICKET_ZERO_SOAK_GIT_READ_ENVIRONMENT),
        "unchanged_during_execution": True,
    }


def runtime_ticket_zero_soak_regular_path(path: Path, subject: str) -> Path:
    """Reject symlink indirection in one trusted checkout-relative artifact path."""

    raw_path = path if path.is_absolute() else ROOT / path
    root = ROOT.resolve()
    try:
        relative_parts = raw_path.relative_to(root).parts
    except ValueError as error:
        raise HarnessError(
            f"runtime ticket-zero soak {subject} artifact escapes the checkout"
        ) from error
    if any(part in {".", ".."} for part in relative_parts):
        raise HarnessError(f"runtime ticket-zero soak {subject} artifact path is invalid")

    current = root
    for part in relative_parts:
        current /= part
        if current.is_symlink():
            raise HarnessError(
                f"runtime ticket-zero soak {subject} artifact is not a regular file"
            )
    if not raw_path.is_file():
        raise HarnessError(f"runtime ticket-zero soak {subject} artifact is not live")
    resolved = raw_path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise HarnessError(
            f"runtime ticket-zero soak {subject} artifact escapes the checkout"
        ) from error
    return raw_path


def runtime_ticket_zero_soak_expected_artifact_record(
    expected_path: Path, subject: str
) -> dict[str, Any]:
    """Record a trusted raw artifact path only after its full path is checked."""

    return artifact_record(runtime_ticket_zero_soak_regular_path(expected_path, subject))


def attest_runtime_ticket_zero_soak_artifact(
    record: object, subject: str, *, expected_path: Path
) -> dict[str, Any]:
    """Bind a record to one trusted raw path before recording or resolving it."""

    if not isinstance(record, Mapping) or set(record) != {"bytes", "path", "sha256"}:
        raise HarnessError(f"runtime ticket-zero soak {subject} artifact record is invalid")
    raw_path = record.get("path")
    if (
        type(record.get("bytes")) is not int
        or record["bytes"] <= 0
        or not isinstance(raw_path, str)
        or not raw_path
        or not isinstance(record.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"]))
    ):
        raise HarnessError(f"runtime ticket-zero soak {subject} artifact record is invalid")
    observed = runtime_ticket_zero_soak_expected_artifact_record(expected_path, subject)
    if observed != dict(record):
        raise HarnessError(f"runtime ticket-zero soak {subject} artifact changed")
    return observed


def runtime_ticket_zero_soak_tag_attestation(
    pin: Mapping[str, str], reported: object
) -> dict[str, Any]:
    """Require the report and live cache to name the same pinned annotated tag."""

    expected = {
        "format": 1,
        "repository": pin["repository"],
        "revision": pin["revision"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
    }
    if reported != expected:
        raise HarnessError("runtime ticket-zero soak tag attestation differs from its pin")
    path = runtime_ticket_zero_soak_regular_path(
        tag_attestation_path(pin), "tag attestation"
    )
    try:
        live = read_json(path)
    except HarnessError as error:
        raise HarnessError("runtime ticket-zero soak tag attestation is invalid") from error
    if live != expected:
        raise HarnessError("runtime ticket-zero soak tag attestation is not live or pin-matched")
    return expected


def x86_64_source_map_contract(archive: Path) -> dict[str, Any]:
    """Run the target-local source-map validator without spawning a child process."""

    spec = importlib.util.spec_from_file_location(
        "crabc_allocator_x86_64_source_map_validator",
        X86_64_SOURCE_MAP_RUNNER,
    )
    if spec is None or spec.loader is None:
        raise HarnessError("cannot load native x86-64 source-map validator")
    source_map = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(source_map)
    except Exception as error:
        raise HarnessError(f"cannot load native x86-64 source-map validator: {error}") from error

    validator = getattr(source_map, "checked_contract_result", None)
    if not callable(validator):
        raise HarnessError("native x86-64 source-map validator has no checked result callable")
    try:
        result = validator(archive)
    except Exception as error:
        raise HarnessError(f"native x86-64 source-map validation failed: {error}") from error
    if not isinstance(result, dict) or set(result) != {
        "contract",
        "overall_status",
        "profile",
        "scope",
        "source_member_count",
        "status",
        "status_counts",
        "target",
        "unit_count",
        "unfinished_unit_count",
    }:
        raise HarnessError("native x86-64 source-map validator returned an unsupported result")

    expected_contract = {
        "path": relative(X86_64_SOURCE_MAP_CONTRACT),
        "sha256": sha256_file(X86_64_SOURCE_MAP_CONTRACT),
    }
    if result["contract"] != expected_contract:
        raise HarnessError("native x86-64 source-map validator returned the wrong contract")
    expected_target = {
        "architecture": "x86_64",
        "endianness": "little",
        "rust_target": X86_64_RUST_TARGET,
        "system": "linux",
    }
    if result["target"] != expected_target:
        raise HarnessError("native x86-64 source-map validator returned the wrong target")
    if result["profile"] != "linux-x86_64-mimalloc-engine-parity":
        raise HarnessError("native x86-64 source-map validator returned the wrong profile")
    if result["overall_status"] != "incomplete" or result["status"] != "passed":
        raise HarnessError("native x86-64 source-map validator returned an invalid status")
    scope = result["scope"]
    if not isinstance(scope, str) or "does not establish" not in scope:
        raise HarnessError("native x86-64 source-map validator result has an unscoped claim")

    status_counts = result["status_counts"]
    if not isinstance(status_counts, dict) or set(status_counts) != {
        "implemented",
        "inapplicable",
        "not-started",
        "partial",
    } or any(type(count) is not int or count < 0 for count in status_counts.values()):
        raise HarnessError("native x86-64 source-map validator returned invalid status counts")
    source_member_count = result["source_member_count"]
    unit_count = result["unit_count"]
    unfinished_unit_count = result["unfinished_unit_count"]
    if (
        type(source_member_count) is not int
        or type(unit_count) is not int
        or type(unfinished_unit_count) is not int
        or source_member_count <= 0
        or unit_count != source_member_count
        or sum(status_counts.values()) != unit_count
        or unfinished_unit_count != status_counts["partial"] + status_counts["not-started"]
        or not 0 < unfinished_unit_count <= unit_count
    ):
        raise HarnessError("native x86-64 source-map validator returned inconsistent counts")
    return result


def x86_64_api_coverage_contract(archive: Path) -> dict[str, Any]:
    """Validate the x86-64 source-only public-surface coverage ledger.

    This is intentionally separate from the native C oracle and private
    adapter evidence.  It inventories source forms and mode/test inputs but
    does not select a target configuration or prove compiled symbols,
    execution, public ABI, or runtime integration.
    """

    spec = importlib.util.spec_from_file_location(
        "crabc_allocator_x86_64_api_coverage_validator",
        X86_64_API_COVERAGE_RUNNER,
    )
    if spec is None or spec.loader is None:
        raise HarnessError("cannot load x86-64 API coverage validator")
    coverage = importlib.util.module_from_spec(spec)
    try:
        # The source-only validator defines a dataclass, whose standard
        # library decorator resolves its module through sys.modules.
        sys.modules[spec.name] = coverage
        spec.loader.exec_module(coverage)
    except Exception as error:
        sys.modules.pop(spec.name, None)
        raise HarnessError(f"cannot load x86-64 API coverage validator: {error}") from error

    validator = getattr(coverage, "checked_contract_result", None)
    if not callable(validator):
        raise HarnessError("x86-64 API coverage validator has no checked result callable")
    try:
        result = validator(archive)
    except Exception as error:
        raise HarnessError(f"x86-64 API coverage validation failed: {error}") from error
    expected_fields = {
        "build_mode_declaration_count",
        "contract",
        "header_surface_count",
        "overall_status",
        "profile",
        "scope",
        "source_declared_function_count",
        "source_member_count",
        "status",
        "symbol_disposition_count",
        "target",
        "test_member_count",
    }
    if not isinstance(result, dict) or set(result) != expected_fields:
        raise HarnessError("x86-64 API coverage validator returned an unsupported result")

    expected_contract = {
        "path": relative(X86_64_API_COVERAGE_CONTRACT),
        "sha256": sha256_file(X86_64_API_COVERAGE_CONTRACT),
    }
    if result["contract"] != expected_contract:
        raise HarnessError("x86-64 API coverage validator returned the wrong contract")
    expected_target = {
        "architecture": "x86_64",
        "endianness": "little",
        "rust_target": X86_64_RUST_TARGET,
        "system": "linux",
    }
    if result["target"] != expected_target:
        raise HarnessError("x86-64 API coverage validator returned the wrong target")
    if result["profile"] != "linux-x86_64-mimalloc-source-public-surface":
        raise HarnessError("x86-64 API coverage validator returned the wrong profile")
    if result["overall_status"] != "incomplete" or result["status"] != "passed":
        raise HarnessError("x86-64 API coverage validator returned an invalid status")
    scope = result["scope"]
    if not isinstance(scope, str) or "does not establish" not in scope:
        raise HarnessError("x86-64 API coverage validator result has an unscoped claim")

    count_fields = (
        "build_mode_declaration_count",
        "header_surface_count",
        "source_declared_function_count",
        "source_member_count",
        "symbol_disposition_count",
        "test_member_count",
    )
    if any(
        type(result[field]) is not int or result[field] <= 0 for field in count_fields
    ):
        raise HarnessError("x86-64 API coverage validator returned invalid counts")
    if result["source_member_count"] <= result["test_member_count"]:
        raise HarnessError("x86-64 API coverage validator source-member count is invalid")
    return result


def x86_64_source_api_inventory(archive: Path) -> dict[str, Any]:
    """Check the target-local source declaration inventory against this archive."""

    command = [
        sys.executable,
        str(X86_64_API_INVENTORY_RUNNER),
        "--archive",
        str(archive),
    ]
    record = command_record(command, cwd=ROOT)
    require_success(record, "native x86-64 source C API inventory")
    contract = read_json(X86_64_API_CONTRACT)
    expected_target = {
        "architecture": "x86_64",
        "endianness": "little",
        "rust_target": X86_64_RUST_TARGET,
        "system": "linux",
    }
    if contract.get("target_context") != expected_target:
        raise HarnessError("native x86-64 source C API inventory target changed")
    declaration_count = contract.get("declaration_count")
    declaration_names_sha256 = contract.get("declaration_names_sha256")
    if type(declaration_count) is not int or declaration_count <= 0:
        raise HarnessError("native x86-64 source C API inventory count is invalid")
    if not isinstance(declaration_names_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", declaration_names_sha256
    ):
        raise HarnessError("native x86-64 source C API inventory digest is invalid")
    return {
        "command": command,
        "contract": artifact_record(X86_64_API_CONTRACT),
        "declaration_count": declaration_count,
        "declaration_names_sha256": declaration_names_sha256,
        "status": "passed",
    }


def parse_elf_identity(header: str, architecture: str) -> dict[str, str]:
    """Read the narrow native ELF identity needed by one oracle lane."""

    expected_machine = {
        "aarch64": "AArch64",
        "x86_64": "Advanced Micro Devices X86-64",
    }.get(architecture)
    if expected_machine is None:
        raise HarnessError(f"unsupported allocator ELF architecture: {architecture}")
    class_match = re.search(r"(?m)^\s*Class:\s*(\S+)\s*$", header)
    data_match = re.search(r"(?m)^\s*Data:\s*(.+?)\s*$", header)
    machine_match = re.search(r"(?m)^\s*Machine:\s*(.+?)\s*$", header)
    if (
        class_match is None
        or class_match.group(1) != "ELF64"
        or data_match is None
        or "little endian" not in data_match.group(1)
        or machine_match is None
        or machine_match.group(1) != expected_machine
    ):
        raise HarnessError(f"ELF artifact is not little-endian {architecture} ELF64")
    return {
        "class": "ELF64",
        "endianness": "little",
        "machine": expected_machine,
    }


def parse_macros(output: str) -> dict[str, str]:
    macros: dict[str, str] = {}
    for line in output.splitlines():
        match = re.fullmatch(r"#define\s+(MI_[A-Za-z0-9_]+)(?:\s+(.*))?", line)
        if match:
            macros[match.group(1)] = (match.group(2) or "").strip()
    return dict(sorted(macros.items()))


def parse_layout(output: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or not value.isdecimal():
            raise HarnessError(f"unparseable C layout probe output: {line!r}")
        if key in values:
            raise HarnessError(f"duplicate layout probe key: {key}")
        values[key] = int(value)
    if not values:
        raise HarnessError("C layout probe produced no values")
    return dict(sorted(values.items()))


def parse_rust_layout(output: str) -> dict[str, int]:
    """Parse the marked machine record from a noisy `cargo test --nocapture`."""

    begin = "CRABC_MI_LAYOUT_BEGIN"
    end = "CRABC_MI_LAYOUT_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise HarnessError("Rust layout probe did not emit exactly one pair of layout markers")
    start = output.index(begin) + len(begin)
    stop = output.index(end)
    if stop <= start:
        raise HarnessError("Rust layout probe emitted reversed layout markers")
    return parse_layout(output[start:stop].strip())


def parse_small_trace(output: str) -> dict[str, int]:
    """Parse one address-independent single-thread small-allocation record."""

    begin = "CRABC_MI_SMALL_TRACE_BEGIN"
    end = "CRABC_MI_SMALL_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise HarnessError("small-allocation trace did not emit exactly one pair of markers")
    start = output.index(begin) + len(begin)
    stop = output.index(end)
    if stop <= start:
        raise HarnessError("small-allocation trace emitted reversed markers")
    return parse_layout(output[start:stop].strip())


def parse_address_independent_trace(
    output: str,
    *,
    begin: str,
    end: str,
    description: str,
    allowed_address_like_scalar_keys: frozenset[str] = frozenset(),
) -> dict[str, int]:
    """Parse one marked trace and reject address-bearing machine fields.

    Trace records are intentionally portable across allocator processes and
    runs.  A future Rust probe must therefore emit only logical identifiers,
    booleans, sizes, and content fingerprints under the same marker schema;
    raw allocation addresses are neither stable evidence nor an allowed field.
    A caller may name a fixed, scalar-only lexical exception such as an
    address-space bit width; that does not permit a pointer observation.
    """

    if output.count(begin) != 1 or output.count(end) != 1:
        raise HarnessError(f"{description} did not emit exactly one pair of markers")
    start = output.index(begin) + len(begin)
    stop = output.index(end)
    if stop <= start:
        raise HarnessError(f"{description} emitted reversed markers")
    record = output[start:stop].strip()
    if re.search(r"\b0[xX][0-9A-Fa-f]+\b", record):
        raise HarnessError(f"{description} emitted a raw address")
    values = parse_layout(record)
    address_key = next(
        (
            key
            for key in values
            if key not in allowed_address_like_scalar_keys
            and re.search(r"(?:^|[._-])(?:addr(?:ess)?|ptr|pointer)(?:$|[._-])", key)
        ),
        None,
    )
    if address_key is not None:
        raise HarnessError(f"{description} emitted a raw address field: {address_key}")
    return values


def parse_fundamental_trace(output: str) -> dict[str, int]:
    """Parse the pinned-C or future-Rust fundamental-operation trace."""

    return parse_address_independent_trace(
        output,
        begin="CRABC_MI_FUNDAMENTAL_TRACE_BEGIN",
        end="CRABC_MI_FUNDAMENTAL_TRACE_END",
        description="fundamental-operation trace",
    )


def parse_m1_raw_primitive_trace(output: str) -> dict[str, int]:
    """Parse the fixed, address-free pinned-C/Rust raw M1 record."""

    return parse_address_independent_trace(
        output,
        begin="CRABC_MI_M1_RAW_TRACE_BEGIN",
        end="CRABC_MI_M1_RAW_TRACE_END",
        description="M1 raw-primitive trace",
        allowed_address_like_scalar_keys=M1_RAW_PRIMITIVE_ADDRESS_LIKE_SCALAR_KEYS,
    )


def parse_m1_compiler_tls_image_trace(output: str) -> dict[str, int]:
    """Parse the constructor-suppressed compiler-TLS root image record."""

    return parse_address_independent_trace(
        output,
        begin="CRABC_MI_M1_TLS_IMAGE_TRACE_BEGIN",
        end="CRABC_MI_M1_TLS_IMAGE_TRACE_END",
        description="M1 compiler-TLS image trace",
    )


def parse_m1_compiler_tls_transition_trace(output: str) -> dict[str, int]:
    """Parse the normal-artifact finite TLS primitive record."""

    return parse_address_independent_trace(
        output,
        begin="CRABC_MI_M1_TLS_TRANSITION_TRACE_BEGIN",
        end="CRABC_MI_M1_TLS_TRANSITION_TRACE_END",
        description="M1 compiler-TLS transition trace",
    )


def parse_m1_compiler_tls_same_tld_trace(output: str) -> dict[str, int]:
    """Parse the fixed source-internal same-TLD terminal trace."""

    return parse_address_independent_trace(
        output,
        begin="CRABC_MI_M1_TLS_SAME_TLD_TRACE_BEGIN",
        end="CRABC_MI_M1_TLS_SAME_TLD_TRACE_END",
        description="M1 compiler-TLS same-TLD terminal trace",
    )


def parse_m1_compiler_tls_trace(output: str) -> dict[str, int]:
    """Parse the full Rust compiler-TLS record emitted by one focused test."""

    return parse_address_independent_trace(
        output,
        begin="CRABC_MI_M1_TLS_TRACE_BEGIN",
        end="CRABC_MI_M1_TLS_TRACE_END",
        description="M1 compiler-TLS C/Rust trace",
    )


def parse_m2_detached_tld_static_preimage_trace(
    output: str, *, source: str
) -> dict[str, int]:
    """Parse the fixed detached `mi_tld_init` static-preimage record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_BEGIN",
        end="CRABC_MI_M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_END",
        description=f"{source} M2 detached-TLD static-preimage trace",
    )
    if set(trace) != set(M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_KEYS):
        missing = sorted(set(M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 detached-TLD static-preimage trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_detached_tld_static_preimage_trace(
    trace: Mapping[str, int], *, source: str
) -> None:
    """Require every selected detached preimage and postcondition relation."""

    if source not in {"pinned C", "Rust"}:
        raise HarnessError(f"unknown M2 detached-TLD static-preimage trace source: {source}")
    if set(trace) != set(M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_KEYS):
        raise HarnessError(
            f"{source} M2 detached-TLD static-preimage trace keys differ from the fixed contract"
        )
    for key in M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(
                f"{source} M2 detached-TLD static-preimage trace field is not an integer: {key}"
            )
        if trace[key] != 1:
            raise HarnessError(
                f"{source} M2 detached-TLD static-preimage trace contains an unmet relation: {key}"
            )


def compare_m2_detached_tld_static_preimage_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require exact parity for the selected detached helper boundary."""

    validate_m2_detached_tld_static_preimage_trace(c_trace, source="pinned C")
    validate_m2_detached_tld_static_preimage_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 detached-TLD static-preimage trace differs from pinned C: "
            + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_KEYS),
        "status": "matched",
    }


def parse_m2_normal_tld_direct_trace(output: str, *, source: str) -> dict[str, int]:
    """Parse the bounded normal-arm direct-helper record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_NORMAL_TLD_DIRECT_TRACE_BEGIN",
        end="CRABC_MI_M2_NORMAL_TLD_DIRECT_TRACE_END",
        description=f"{source} M2 normal-TLD direct-helper trace",
    )
    if set(trace) != set(M2_NORMAL_TLD_DIRECT_TRACE_KEYS):
        missing = sorted(set(M2_NORMAL_TLD_DIRECT_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_NORMAL_TLD_DIRECT_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 normal-TLD direct-helper trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_normal_tld_direct_trace(trace: Mapping[str, int], *, source: str) -> None:
    """Require every selected normal direct-helper relation."""

    if source not in {"pinned C", "Rust"}:
        raise HarnessError(f"unknown M2 normal-TLD direct-helper trace source: {source}")
    if set(trace) != set(M2_NORMAL_TLD_DIRECT_TRACE_KEYS):
        raise HarnessError(
            f"{source} M2 normal-TLD direct-helper trace keys differ from the fixed contract"
        )
    for key in M2_NORMAL_TLD_DIRECT_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(
                f"{source} M2 normal-TLD direct-helper trace field is not an integer: {key}"
            )
        if trace[key] != 1:
            raise HarnessError(
                f"{source} M2 normal-TLD direct-helper trace contains an unmet relation: {key}"
            )


def compare_m2_normal_tld_direct_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require address-free parity for the selected normal-helper boundary."""

    validate_m2_normal_tld_direct_trace(c_trace, source="pinned C")
    validate_m2_normal_tld_direct_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_NORMAL_TLD_DIRECT_TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 normal-TLD direct-helper trace differs from pinned C: "
            + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(M2_NORMAL_TLD_DIRECT_TRACE_KEYS),
        "status": "matched",
    }


def parse_m2_static_first_tld_create_trace(
    output: str, *, source: str
) -> dict[str, int]:
    """Parse the selected static-first `mi_tld_create` success-arm record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_STATIC_FIRST_TLD_CREATE_TRACE_BEGIN",
        end="CRABC_MI_M2_STATIC_FIRST_TLD_CREATE_TRACE_END",
        description=f"{source} M2 static-first-TLD create trace",
    )
    if set(trace) != set(M2_STATIC_FIRST_TLD_CREATE_TRACE_KEYS):
        missing = sorted(set(M2_STATIC_FIRST_TLD_CREATE_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_STATIC_FIRST_TLD_CREATE_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 static-first-TLD create trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_static_first_tld_create_trace(
    trace: Mapping[str, int], *, source: str
) -> None:
    """Require every selected static-first caller relation."""

    if source not in {"pinned C", "Rust"}:
        raise HarnessError(f"unknown M2 static-first-TLD create trace source: {source}")
    if set(trace) != set(M2_STATIC_FIRST_TLD_CREATE_TRACE_KEYS):
        raise HarnessError(
            f"{source} M2 static-first-TLD create trace keys differ from the fixed contract"
        )
    for key in M2_STATIC_FIRST_TLD_CREATE_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(
                f"{source} M2 static-first-TLD create trace field is not an integer: {key}"
            )
        if trace[key] != 1:
            raise HarnessError(
                f"{source} M2 static-first-TLD create trace contains an unmet relation: {key}"
            )


def compare_m2_static_first_tld_create_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require address-independent parity for the selected success arm."""

    validate_m2_static_first_tld_create_trace(c_trace, source="pinned C")
    validate_m2_static_first_tld_create_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_STATIC_FIRST_TLD_CREATE_TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 static-first-TLD create trace differs from pinned C: "
            + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(M2_STATIC_FIRST_TLD_CREATE_TRACE_KEYS),
        "status": "matched",
    }


def parse_m2_page_map_trace(output: str, *, source: str) -> dict[str, int]:
    """Parse the fixed address-free selected PageMap lifecycle record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_PAGE_MAP_TRACE_BEGIN",
        end="CRABC_MI_M2_PAGE_MAP_TRACE_END",
        description=f"{source} M2 PageMap trace",
    )
    if set(trace) != set(M2_PAGE_MAP_TRACE_KEYS):
        missing = sorted(set(M2_PAGE_MAP_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_PAGE_MAP_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 PageMap trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_page_map_trace(trace: Mapping[str, int], *, source: str) -> None:
    """Validate stable controls and relations before C/Rust comparison."""

    if set(trace) != set(M2_PAGE_MAP_TRACE_KEYS):
        raise HarnessError(f"{source} M2 PageMap trace keys differ from the fixed contract")
    for key in M2_PAGE_MAP_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(f"{source} M2 PageMap trace field is not an integer: {key}")
    expected_one = (
        "m2.page_map.control.has_overcommit_false",
        "m2.page_map.init.root_empty_before",
        "m2.page_map.init.root_published",
        "m2.page_map.init.committed_lt_reserved",
        "m2.page_map.init.submap_zero_present",
        "m2.page_map.extend.committed_increased",
        "m2.page_map.extend.first_submap_present",
        "m2.page_map.extend.second_submap_present",
        "m2.page_map.extend.submaps_distinct",
        "m2.page_map.register.first_lookup_matches",
        "m2.page_map.register.second_lookup_matches",
        "m2.page_map.unregister.first_lookup_absent",
        "m2.page_map.unregister.second_lookup_absent",
        "m2.page_map.rollback.register_failed",
        "m2.page_map.rollback.submap_present",
        "m2.page_map.rollback.entry_cleared",
        "m2.page_map.rollback.out_of_bounds_absent",
        "m2.page_map.destroy.root_absent_after",
    )
    if any(trace[key] != 1 for key in expected_one):
        raise HarnessError(f"{source} M2 PageMap trace contains an unmet relation")
    if trace["m2.page_map.control.page_size"] != 4 * 1024:
        raise HarnessError(f"{source} M2 PageMap trace is not controlled to 4KiB pages")
    if trace["m2.page_map.control.max_vabits"] != 48:
        raise HarnessError(f"{source} M2 PageMap trace is not controlled to 48 virtual-address bits")
    if trace["m2.page_map.init.reserve_count"] != 524288:
        raise HarnessError(f"{source} M2 PageMap reserve count changed from the frozen two-level geometry")
    if trace["m2.page_map.layout.header_bytes"] <= 0 or trace["m2.page_map.layout.lock_bytes"] <= 0:
        raise HarnessError(f"{source} M2 PageMap trace has an empty mapped-header representation")
    if trace["m2.page_map.init.reserved_count"] < trace["m2.page_map.init.reserve_count"]:
        raise HarnessError(f"{source} M2 PageMap reserved count is below its source reserve count")
    if trace["m2.page_map.init.committed_count"] <= 0:
        raise HarnessError(f"{source} M2 PageMap committed prefix is empty")
    if trace["m2.page_map.init.committed_count"] >= trace["m2.page_map.init.reserved_count"]:
        raise HarnessError(f"{source} M2 PageMap initial prefix is not partial")
    if trace["m2.page_map.extend.start_sub_index"] != (1 << 13) - 1:
        raise HarnessError(f"{source} M2 PageMap extension does not start at a submap boundary")
    if trace["m2.page_map.extend.slice_count"] != 2:
        raise HarnessError(f"{source} M2 PageMap extension span changed")
    if trace["m2.page_map.extend.map_index"] != trace["m2.page_map.init.committed_count"] + 1:
        raise HarnessError(f"{source} M2 PageMap extension index is not source-relative")
    if trace["m2.page_map.extend.committed_before"] != trace["m2.page_map.init.committed_count"]:
        raise HarnessError(f"{source} M2 PageMap extension baseline drifted")
    if trace["m2.page_map.extend.committed_after"] < trace["m2.page_map.extend.committed_before"]:
        raise HarnessError(f"{source} M2 PageMap committed prefix regressed")
    if (
        trace["m2.page_map.extend.committed_after"]
        - trace["m2.page_map.extend.committed_before"]
        != 7680
    ):
        raise HarnessError(f"{source} M2 PageMap extension no longer reaches the selected source commit boundary")
    root_unpublished_before = trace[M2_PAGE_MAP_ROOT_OWNERSHIP_DIFFERENCE_KEY]
    if root_unpublished_before not in {0, 1}:
        raise HarnessError(f"{source} M2 PageMap root ownership observation is not boolean")
    if source == "pinned C" and root_unpublished_before != 0:
        raise HarnessError("pinned C M2 PageMap root unexpectedly disappeared before destruction")
    if source == "Rust" and root_unpublished_before != 1:
        raise HarnessError("Rust M2 PageMap root was not unpublished before typed destruction")


def compare_m2_page_map_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Compare stable transitions while recording intentional representation differences."""

    validate_m2_page_map_trace(c_trace, source="pinned C")
    validate_m2_page_map_trace(rust_trace, source="Rust")
    exact_keys = tuple(
        key
        for key in M2_PAGE_MAP_TRACE_KEYS
        if key not in M2_PAGE_MAP_HEADER_DEPENDENT_KEYS
        and key != M2_PAGE_MAP_ROOT_OWNERSHIP_DIFFERENCE_KEY
    )
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in exact_keys
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 PageMap success trace differs from pinned C: "
            + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(exact_keys),
        "header_dependent": {
            "classification": (
                "the C header embeds musl pthread state while the no_std Rust header "
                "embeds a private futex lock; raw entry counts remain explicit evidence "
                "and are checked by per-trace source-relative invariants"
            ),
            "fields": list(M2_PAGE_MAP_HEADER_DEPENDENT_KEYS),
            "pinned_c": {
                key: c_trace[key] for key in M2_PAGE_MAP_HEADER_DEPENDENT_KEYS
            },
            "rust": {
                key: rust_trace[key] for key in M2_PAGE_MAP_HEADER_DEPENDENT_KEYS
            },
        },
        "root_ownership_difference": {
            "classification": (
                "C destroys then resets its global static root; Rust's separately owned "
                "PageMapRoot is unpublished before PageMap::destroy"
            ),
            "field": M2_PAGE_MAP_ROOT_OWNERSHIP_DIFFERENCE_KEY,
            "pinned_c": c_trace[M2_PAGE_MAP_ROOT_OWNERSHIP_DIFFERENCE_KEY],
            "rust": rust_trace[M2_PAGE_MAP_ROOT_OWNERSHIP_DIFFERENCE_KEY],
        },
        "status": "matched",
    }


def parse_m2_page_map_lazy_commit_failure_trace(
    output: str, *, source: str
) -> dict[str, int]:
    """Parse one address-free initialized-PageMap commit-failure record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_BEGIN",
        end="CRABC_MI_M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_END",
        description=f"{source} M2 PageMap lazy-commit failure trace",
    )
    if set(trace) != set(M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_KEYS):
        missing = sorted(set(M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 PageMap lazy-commit failure trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_page_map_lazy_commit_failure_trace(
    trace: Mapping[str, int], *, source: str
) -> None:
    """Validate the selected failure-before-publication and retry relations."""

    if set(trace) != set(M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_KEYS):
        raise HarnessError(f"{source} M2 PageMap lazy-commit failure keys differ from the contract")
    for key in M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(
                f"{source} M2 PageMap lazy-commit failure field is not an integer: {key}"
            )
    expected_one = (
        "m2.page_map.lazy_commit.control.has_overcommit_false",
        "m2.page_map.lazy_commit.failure.target_above_committed",
        "m2.page_map.lazy_commit.failure.returned",
        "m2.page_map.lazy_commit.failure.committed_unchanged",
        "m2.page_map.lazy_commit.failure.no_submap_result",
        "m2.page_map.lazy_commit.failure.top_owner_retained",
        "m2.page_map.lazy_commit.retry.succeeded",
        "m2.page_map.lazy_commit.retry.committed_advanced",
        "m2.page_map.lazy_commit.retry.submap_present",
        "m2.page_map.lazy_commit.cleanup.top_owner_released",
    )
    if any(trace[key] != 1 for key in expected_one):
        raise HarnessError(
            f"{source} M2 PageMap lazy-commit failure trace contains an unmet relation"
        )
    if trace["m2.page_map.lazy_commit.control.page_size"] != 4 * 1024:
        raise HarnessError(
            f"{source} M2 PageMap lazy-commit failure trace is not controlled to 4KiB pages"
        )
    if trace["m2.page_map.lazy_commit.control.max_vabits"] != 48:
        raise HarnessError(
            f"{source} M2 PageMap lazy-commit failure trace is not controlled to 48 virtual-address bits"
        )
    if trace["m2.page_map.lazy_commit.failure.commit_attempts"] != 1:
        raise HarnessError(
            f"{source} M2 PageMap lazy-commit failure did not inject exactly one commit attempt"
        )
    if trace["m2.page_map.lazy_commit.failure.submap_allocation_attempts"] != 0:
        raise HarnessError(
            f"{source} M2 PageMap lazy-commit failure entered submap allocation"
        )
    if trace["m2.page_map.lazy_commit.retry.submap_allocation_attempts"] != 1:
        raise HarnessError(
            f"{source} M2 PageMap lazy-commit retry did not allocate exactly one submap"
        )


def compare_m2_page_map_lazy_commit_failure_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Compare all selected semantic relations without normalizing representation."""

    validate_m2_page_map_lazy_commit_failure_trace(c_trace, source="pinned C")
    validate_m2_page_map_lazy_commit_failure_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 PageMap lazy-commit failure trace differs from pinned C: "
            + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_KEYS),
        "excluded_differences": {
            "classification": (
                "the trace compares only failure-before-publication and one retry relations. "
                "It deliberately excludes header-size-dependent raw counts, C's global root "
                "versus Rust's typed local Mapping owner, C boolean/diagnostic versus Rust "
                "Errno representation, and the test-only lexical-wrapper versus pre-mprotect "
                "injection mechanisms."
            ),
            "fields": [],
        },
        "status": "matched",
    }


def parse_m2_page_map_cold_init_trace(output: str, *, source: str) -> dict[str, int]:
    """Parse the fixed failed-first-initialization PageMap record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_PAGE_MAP_COLD_INIT_TRACE_BEGIN",
        end="CRABC_MI_M2_PAGE_MAP_COLD_INIT_TRACE_END",
        description=f"{source} M2 PageMap cold-init trace",
    )
    if set(trace) != set(M2_PAGE_MAP_COLD_INIT_TRACE_KEYS):
        missing = sorted(set(M2_PAGE_MAP_COLD_INIT_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_PAGE_MAP_COLD_INIT_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 PageMap cold-init trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_page_map_cold_init_trace(trace: Mapping[str, int], *, source: str) -> None:
    """Validate one side of the deliberate failed-cold-init safety boundary."""

    if source not in {"pinned C", "Rust"}:
        raise HarnessError(f"unknown M2 PageMap cold-init trace source: {source}")
    if set(trace) != set(M2_PAGE_MAP_COLD_INIT_TRACE_KEYS):
        raise HarnessError(f"{source} M2 PageMap cold-init trace keys differ from the fixed contract")
    for key in M2_PAGE_MAP_COLD_INIT_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(f"{source} M2 PageMap cold-init trace field is not an integer: {key}")
    for key in (
        "m2.page_map.cold.first_init_failed",
        "m2.page_map.cold.dynamic_root_unpublished",
    ):
        if trace[key] != 1:
            raise HarnessError(f"{source} M2 PageMap cold-init trace contains an unmet failure relation")
    if trace["m2.page_map.cold.init_body_attempt_count"] != 1:
        raise HarnessError(f"{source} M2 PageMap cold-init trace replayed its once body")

    expected = (
        {
            "m2.page_map.cold.static_empty_root": 1,
            "m2.page_map.cold.absent_root": 0,
            "m2.page_map.cold.second_call_returns_success": 1,
            "m2.page_map.cold.second_call_returns_poisoned": 0,
            "m2.page_map.cold.null_lookup_returns_null": 1,
            "m2.page_map.cold.cold_lookup_route_unavailable": 0,
        }
        if source == "pinned C"
        else {
            "m2.page_map.cold.static_empty_root": 0,
            "m2.page_map.cold.absent_root": 1,
            "m2.page_map.cold.second_call_returns_success": 0,
            "m2.page_map.cold.second_call_returns_poisoned": 1,
            "m2.page_map.cold.null_lookup_returns_null": 0,
            "m2.page_map.cold.cold_lookup_route_unavailable": 1,
        }
    )
    for key, value in expected.items():
        if trace[key] != value:
            raise HarnessError(
                f"{source} M2 PageMap cold-init trace changed its recorded safety boundary: {key}"
            )


def compare_m2_page_map_cold_init_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Compare shared cold-init failure facts without concealing the root difference."""

    validate_m2_page_map_cold_init_trace(c_trace, source="pinned C")
    validate_m2_page_map_cold_init_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_PAGE_MAP_COLD_INIT_MATCHED_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 PageMap cold-init trace differs from pinned C: " + "; ".join(mismatches)
        )
    divergence_keys = {
        "static_empty_root": "m2.page_map.cold.static_empty_root",
        "absent_root": "m2.page_map.cold.absent_root",
        "second_call_returns_success": "m2.page_map.cold.second_call_returns_success",
        "second_call_returns_poisoned": "m2.page_map.cold.second_call_returns_poisoned",
        "null_lookup_returns_null": "m2.page_map.cold.null_lookup_returns_null",
        "cold_lookup_route_unavailable": "m2.page_map.cold.cold_lookup_route_unavailable",
    }
    return {
        "matched_value_count": len(M2_PAGE_MAP_COLD_INIT_MATCHED_KEYS),
        "shared_failure_facts": {
            key: c_trace[key] for key in M2_PAGE_MAP_COLD_INIT_MATCHED_KEYS
        },
        "safety_divergence": {
            "classification": (
                "pinned C retains mi_page_map_empty for a null-safe lookup after its "
                "consumed failed once body; Rust retains no fake live root, exposes no cold "
                "lookup route in its absent-root/poisoned state, and reports the consumed "
                "attempt as a terminal typed poison"
            ),
            "pinned_c": {name: c_trace[key] for name, key in divergence_keys.items()},
            "rust": {name: rust_trace[key] for name, key in divergence_keys.items()},
        },
        "status": "modeled-safety-divergence",
    }


def parse_m2_bitmap_abandoned_claim_trace(output: str, *, source: str) -> dict[str, int]:
    """Parse the fixed source-snapshot abandoned-bitmap claim record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_BITMAP_ABANDONED_CLAIM_TRACE_BEGIN",
        end="CRABC_MI_M2_BITMAP_ABANDONED_CLAIM_TRACE_END",
        description=f"{source} M2 bitmap abandoned-claim trace",
    )
    if set(trace) != set(M2_BITMAP_ABANDONED_CLAIM_TRACE_KEYS):
        missing = sorted(set(M2_BITMAP_ABANDONED_CLAIM_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_BITMAP_ABANDONED_CLAIM_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 bitmap abandoned-claim trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_bitmap_abandoned_claim_trace(
    trace: Mapping[str, int], *, source: str
) -> None:
    """Require the selected C/Rust bitmap visitor facts before comparison."""

    if source not in {"pinned C", "Rust"}:
        raise HarnessError(f"unknown M2 bitmap abandoned-claim trace source: {source}")
    if set(trace) != set(M2_BITMAP_ABANDONED_CLAIM_TRACE_KEYS):
        raise HarnessError(f"{source} M2 bitmap abandoned-claim trace keys differ from the fixed contract")
    for key in M2_BITMAP_ABANDONED_CLAIM_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(
                f"{source} M2 bitmap abandoned-claim trace field is not an integer: {key}"
            )

    expected = {
        "m2.bitmap.control.bfield_bits": 64,
        "m2.bitmap.control.bchunk_bits": 512,
        "m2.bitmap.control.thread_sequence": 5,
        "m2.bitmap.control.selected_index": 17,
        "m2.bitmap.layout.byte_size": 192,
        "m2.bitmap.setup.chunk_count": 1,
        "m2.bitmap.setup.initial_set_transitioned": 1,
        "m2.bitmap.reject.returned_claimed": 0,
        "m2.bitmap.reject.callback_count": 1,
        "m2.bitmap.reject.callback_index": 17,
        "m2.bitmap.reject.bit_restored": 1,
        "m2.bitmap.reject.chunkmap_retained": 1,
        "m2.bitmap.accept.returned_claimed": 1,
        "m2.bitmap.accept.callback_count": 1,
        "m2.bitmap.accept.callback_index": 17,
        "m2.bitmap.accept.claimed_index": 17,
        "m2.bitmap.accept.bit_cleared": 1,
        "m2.bitmap.accept.chunkmap_retained": 1,
        "m2.bitmap.drain.returned_claimed": 0,
        "m2.bitmap.drain.callback_count": 0,
        "m2.bitmap.drain.chunkmap_cleared": 1,
    }
    for key, value in expected.items():
        if trace[key] != value:
            raise HarnessError(
                f"{source} M2 bitmap abandoned-claim trace contains an unmet relation: {key}"
            )


def compare_m2_bitmap_abandoned_claim_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require exact equality for the selected address-free bitmap transition."""

    validate_m2_bitmap_abandoned_claim_trace(c_trace, source="pinned C")
    validate_m2_bitmap_abandoned_claim_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_BITMAP_ABANDONED_CLAIM_TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 bitmap abandoned-claim trace differs from pinned C: "
            + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(M2_BITMAP_ABANDONED_CLAIM_TRACE_KEYS),
        "status": "matched",
    }


def parse_m2_bitmap_clear_range_trace(output: str, *, source: str) -> dict[str, int]:
    """Parse the fixed scalar bitmap clear-range visitor record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_BITMAP_CLEAR_RANGE_TRACE_BEGIN",
        end="CRABC_MI_M2_BITMAP_CLEAR_RANGE_TRACE_END",
        description=f"{source} M2 bitmap clear-range trace",
    )
    if set(trace) != set(M2_BITMAP_CLEAR_RANGE_TRACE_KEYS):
        missing = sorted(set(M2_BITMAP_CLEAR_RANGE_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_BITMAP_CLEAR_RANGE_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 bitmap clear-range trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_bitmap_clear_range_trace(
    trace: Mapping[str, int], *, source: str
) -> None:
    """Require the selected scalar C/Rust range-visitor facts before comparison."""

    if source not in {"pinned C", "Rust"}:
        raise HarnessError(f"unknown M2 bitmap clear-range trace source: {source}")
    if set(trace) != set(M2_BITMAP_CLEAR_RANGE_TRACE_KEYS):
        raise HarnessError(f"{source} M2 bitmap clear-range trace keys differ from the fixed contract")
    for key in M2_BITMAP_CLEAR_RANGE_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(
                f"{source} M2 bitmap clear-range trace field is not an integer: {key}"
            )

    expected = {
        "m2.bitmap_range.control.bfield_bits": 64,
        "m2.bitmap_range.control.bchunk_bits": 512,
        "m2.bitmap_range.layout.byte_size": 192,
        "m2.bitmap_range.complete.chunk_count": 1,
        "m2.bitmap_range.complete.set_transitioned": 1,
        "m2.bitmap_range.complete.returned_completed": 1,
        "m2.bitmap_range.complete.callback_count": 4,
        "m2.bitmap_range.complete.range_0_index": 1,
        "m2.bitmap_range.complete.range_0_count": 2,
        "m2.bitmap_range.complete.range_1_index": 5,
        "m2.bitmap_range.complete.range_1_count": 2,
        "m2.bitmap_range.complete.range_2_index": 62,
        "m2.bitmap_range.complete.range_2_count": 2,
        "m2.bitmap_range.complete.range_3_index": 64,
        "m2.bitmap_range.complete.range_3_count": 2,
        "m2.bitmap_range.complete.data_cleared": 1,
        "m2.bitmap_range.complete.chunkmap_retained": 1,
        "m2.bitmap_range.reject.set_transitioned": 1,
        "m2.bitmap_range.reject.returned_completed": 0,
        "m2.bitmap_range.reject.callback_count": 1,
        "m2.bitmap_range.reject.range_index": 1,
        "m2.bitmap_range.reject.range_count": 2,
        "m2.bitmap_range.reject.visited_range_cleared": 1,
        "m2.bitmap_range.reject.unvisited_same_field_restored": 1,
        "m2.bitmap_range.reject.later_field_untouched": 1,
        "m2.bitmap_range.reject.chunkmap_retained": 1,
    }
    for key, value in expected.items():
        if trace[key] != value:
            raise HarnessError(
                f"{source} M2 bitmap clear-range trace contains an unmet relation: {key}"
            )


def compare_m2_bitmap_clear_range_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require exact equality for the selected scalar bitmap visitor transition."""

    validate_m2_bitmap_clear_range_trace(c_trace, source="pinned C")
    validate_m2_bitmap_clear_range_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_BITMAP_CLEAR_RANGE_TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 bitmap clear-range trace differs from pinned C: "
            + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(M2_BITMAP_CLEAR_RANGE_TRACE_KEYS),
        "status": "matched",
    }


def parse_m2_bitmap_rangesn_trace(output: str, *, source: str) -> dict[str, int]:
    """Parse the fixed scalar bitmap rangesn-wrapper record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_BITMAP_RANGESN_TRACE_BEGIN",
        end="CRABC_MI_M2_BITMAP_RANGESN_TRACE_END",
        description=f"{source} M2 bitmap rangesn trace",
    )
    if set(trace) != set(M2_BITMAP_RANGESN_TRACE_KEYS):
        missing = sorted(set(M2_BITMAP_RANGESN_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_BITMAP_RANGESN_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 bitmap rangesn trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_bitmap_rangesn_trace(
    trace: Mapping[str, int], *, source: str
) -> None:
    """Require selected scalar rangesn facts before C/Rust comparison."""

    if source not in {"pinned C", "Rust"}:
        raise HarnessError(f"unknown M2 bitmap rangesn trace source: {source}")
    if set(trace) != set(M2_BITMAP_RANGESN_TRACE_KEYS):
        raise HarnessError(f"{source} M2 bitmap rangesn trace keys differ from the fixed contract")
    for key in M2_BITMAP_RANGESN_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(
                f"{source} M2 bitmap rangesn trace field is not an integer: {key}"
            )

    expected = {
        "m2.bitmap_rangesn.control.bfield_bits": 64,
        "m2.bitmap_rangesn.control.bchunk_bits": 512,
        "m2.bitmap_rangesn.control.aligned_rngslices": 3,
        "m2.bitmap_rangesn.control.capped_request": 65,
        "m2.bitmap_rangesn.layout.byte_size": 192,
        "m2.bitmap_rangesn.r3_complete.returned_completed": 1,
        "m2.bitmap_rangesn.r3_complete.callback_count": 3,
        "m2.bitmap_rangesn.r3_complete.range_0_index": 0,
        "m2.bitmap_rangesn.r3_complete.range_0_count": 3,
        "m2.bitmap_rangesn.r3_complete.range_1_index": 3,
        "m2.bitmap_rangesn.r3_complete.range_1_count": 3,
        "m2.bitmap_rangesn.r3_complete.range_2_index": 9,
        "m2.bitmap_rangesn.r3_complete.range_2_count": 3,
        "m2.bitmap_rangesn.r3_complete.field_0_after": 0xB0000000000000C0,
        "m2.bitmap_rangesn.r3_complete.chunkmap_field_0_after": 1,
        "m2.bitmap_rangesn.r3_reject.returned_completed": 0,
        "m2.bitmap_rangesn.r3_reject.callback_count": 1,
        "m2.bitmap_rangesn.r3_reject.range_0_index": 3,
        "m2.bitmap_rangesn.r3_reject.range_0_count": 3,
        "m2.bitmap_rangesn.r3_reject.field_0_after": 0xB000000000000EC5,
        "m2.bitmap_rangesn.r3_reject.field_1_after": 7,
        "m2.bitmap_rangesn.r3_reject.chunkmap_field_0_after": 1,
        "m2.bitmap_rangesn.delegation_zero.returned_completed": 1,
        "m2.bitmap_rangesn.delegation_zero.callback_count": 4,
        "m2.bitmap_rangesn.delegation_zero.range_0_index": 0,
        "m2.bitmap_rangesn.delegation_zero.range_0_count": 8,
        "m2.bitmap_rangesn.delegation_zero.range_1_index": 9,
        "m2.bitmap_rangesn.delegation_zero.range_1_count": 3,
        "m2.bitmap_rangesn.delegation_zero.range_2_index": 60,
        "m2.bitmap_rangesn.delegation_zero.range_2_count": 2,
        "m2.bitmap_rangesn.delegation_zero.range_3_index": 63,
        "m2.bitmap_rangesn.delegation_zero.range_3_count": 1,
        "m2.bitmap_rangesn.delegation_zero.field_0_after": 0,
        "m2.bitmap_rangesn.delegation_zero.chunkmap_field_0_after": 1,
        "m2.bitmap_rangesn.delegation_one.returned_completed": 1,
        "m2.bitmap_rangesn.delegation_one.callback_count": 4,
        "m2.bitmap_rangesn.delegation_one.range_0_index": 0,
        "m2.bitmap_rangesn.delegation_one.range_0_count": 8,
        "m2.bitmap_rangesn.delegation_one.range_1_index": 9,
        "m2.bitmap_rangesn.delegation_one.range_1_count": 3,
        "m2.bitmap_rangesn.delegation_one.range_2_index": 60,
        "m2.bitmap_rangesn.delegation_one.range_2_count": 2,
        "m2.bitmap_rangesn.delegation_one.range_3_index": 63,
        "m2.bitmap_rangesn.delegation_one.range_3_count": 1,
        "m2.bitmap_rangesn.delegation_one.field_0_after": 0,
        "m2.bitmap_rangesn.delegation_one.chunkmap_field_0_after": 1,
        "m2.bitmap_rangesn.cap_over.returned_completed": 1,
        "m2.bitmap_rangesn.cap_over.callback_count": 1,
        "m2.bitmap_rangesn.cap_over.range_0_index": 0,
        "m2.bitmap_rangesn.cap_over.range_0_count": 64,
        "m2.bitmap_rangesn.cap_over.field_0_after": 0,
        "m2.bitmap_rangesn.cap_over.chunkmap_field_0_after": 1,
    }
    for key, value in expected.items():
        if trace[key] != value:
            raise HarnessError(
                f"{source} M2 bitmap rangesn trace contains an unmet relation: {key}"
            )


def compare_m2_bitmap_rangesn_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require exact equality for the selected scalar rangesn transition."""

    validate_m2_bitmap_rangesn_trace(c_trace, source="pinned C")
    validate_m2_bitmap_rangesn_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_BITMAP_RANGESN_TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 bitmap rangesn trace differs from pinned C: " + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(M2_BITMAP_RANGESN_TRACE_KEYS),
        "status": "matched",
    }


def parse_m2_bitmap_set_trace(output: str, *, source: str) -> dict[str, int]:
    """Parse the fixed scalar read-only bitmap set-bit record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_BITMAP_SET_TRACE_BEGIN",
        end="CRABC_MI_M2_BITMAP_SET_TRACE_END",
        description=f"{source} M2 bitmap set-bit trace",
    )
    if set(trace) != set(M2_BITMAP_SET_TRACE_KEYS):
        missing = sorted(set(M2_BITMAP_SET_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_BITMAP_SET_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 bitmap set-bit trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_bitmap_set_trace(trace: Mapping[str, int], *, source: str) -> None:
    """Require selected read-only set-bit facts before C/Rust comparison."""

    if source not in {"pinned C", "Rust"}:
        raise HarnessError(f"unknown M2 bitmap set-bit trace source: {source}")
    if set(trace) != set(M2_BITMAP_SET_TRACE_KEYS):
        raise HarnessError(f"{source} M2 bitmap set-bit trace keys differ from the fixed contract")
    for key in M2_BITMAP_SET_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(
                f"{source} M2 bitmap set-bit trace field is not an integer: {key}"
            )

    expected = {
        "m2.bitmap_set.control.bfield_bits": 64,
        "m2.bitmap_set.control.bchunk_bits": 512,
        "m2.bitmap_set.control.chunk_count": 65,
        "m2.bitmap_set.layout.byte_size": 4288,
        "m2.bitmap_set.complete.seeded": 1,
        "m2.bitmap_set.complete.returned_completed": 1,
        "m2.bitmap_set.complete.callback_count": 3,
        "m2.bitmap_set.complete.visit_0_index": 1,
        "m2.bitmap_set.complete.visit_0_count": 1,
        "m2.bitmap_set.complete.visit_1_index": 65,
        "m2.bitmap_set.complete.visit_1_count": 1,
        "m2.bitmap_set.complete.visit_2_index": 32770,
        "m2.bitmap_set.complete.visit_2_count": 1,
        "m2.bitmap_set.complete.chunk_0_field_0_after": 2,
        "m2.bitmap_set.complete.chunk_0_field_1_after": 2,
        "m2.bitmap_set.complete.chunk_64_field_0_after": 4,
        "m2.bitmap_set.complete.chunkmap_field_0_after": 1,
        "m2.bitmap_set.complete.chunkmap_field_1_after": 1,
        "m2.bitmap_set.reject.seeded": 1,
        "m2.bitmap_set.reject.returned_completed": 0,
        "m2.bitmap_set.reject.callback_count": 2,
        "m2.bitmap_set.reject.visit_0_index": 1,
        "m2.bitmap_set.reject.visit_0_count": 1,
        "m2.bitmap_set.reject.visit_1_index": 65,
        "m2.bitmap_set.reject.visit_1_count": 1,
        "m2.bitmap_set.reject.chunk_0_field_0_after": 2,
        "m2.bitmap_set.reject.chunk_0_field_1_after": 2,
        "m2.bitmap_set.reject.chunk_64_field_0_after": 4,
        "m2.bitmap_set.reject.chunkmap_field_0_after": 1,
        "m2.bitmap_set.reject.chunkmap_field_1_after": 1,
    }
    for key, value in expected.items():
        if trace[key] != value:
            raise HarnessError(
                f"{source} M2 bitmap set-bit trace contains an unmet relation: {key}"
            )


def compare_m2_bitmap_set_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require exact equality for the selected read-only bitmap set-bit walk."""

    validate_m2_bitmap_set_trace(c_trace, source="pinned C")
    validate_m2_bitmap_set_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_BITMAP_SET_TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 bitmap set-bit trace differs from pinned C: " + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(M2_BITMAP_SET_TRACE_KEYS),
        "status": "matched",
    }


def parse_m2_binned_bitmap_bsr_inv_trace(output: str, *, source: str) -> dict[str, int]:
    """Parse the fixed binned inverse-BSR observer record."""

    trace = parse_address_independent_trace(
        output,
        begin="CRABC_MI_M2_BINNED_BITMAP_BSR_INV_TRACE_BEGIN",
        end="CRABC_MI_M2_BINNED_BITMAP_BSR_INV_TRACE_END",
        description=f"{source} M2 binned bitmap inverse-BSR trace",
    )
    if set(trace) != set(M2_BINNED_BITMAP_BSR_INV_TRACE_KEYS):
        missing = sorted(set(M2_BINNED_BITMAP_BSR_INV_TRACE_KEYS) - set(trace))
        unexpected = sorted(set(trace) - set(M2_BINNED_BITMAP_BSR_INV_TRACE_KEYS))
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M2 binned bitmap inverse-BSR trace does not match the fixed schema: "
            + "; ".join(problems)
        )
    return trace


def validate_m2_binned_bitmap_bsr_inv_trace(
    trace: Mapping[str, int], *, source: str
) -> None:
    """Require the selected rounded-padding and descending-scan relations."""

    if source not in {"pinned C", "Rust"}:
        raise HarnessError(f"unknown M2 binned bitmap inverse-BSR trace source: {source}")
    if set(trace) != set(M2_BINNED_BITMAP_BSR_INV_TRACE_KEYS):
        raise HarnessError(
            f"{source} M2 binned bitmap inverse-BSR trace keys differ from the fixed contract"
        )
    for key in M2_BINNED_BITMAP_BSR_INV_TRACE_KEYS:
        if type(trace[key]) is not int:
            raise HarnessError(
                f"{source} M2 binned bitmap inverse-BSR trace field is not an integer: {key}"
            )

    expected = {
        "m2.bbitmap_bsr_inv.control.bfield_bits": 64,
        "m2.bbitmap_bsr_inv.control.bchunk_bits": 512,
        "m2.bbitmap_bsr_inv.padding.logical_bit_count": 513,
        "m2.bbitmap_bsr_inv.padding.chunk_count": 2,
        "m2.bbitmap_bsr_inv.padding.max_bits": 1024,
        "m2.bbitmap_bsr_inv.padding.byte_size": 576,
        "m2.bbitmap_bsr_inv.padding.chunkmap_empty": 1,
        "m2.bbitmap_bsr_inv.padding.returned_found": 1,
        "m2.bbitmap_bsr_inv.padding.index": 1023,
        "m2.bbitmap_bsr_inv.scan.chunk_count": 2,
        "m2.bbitmap_bsr_inv.scan.byte_size": 576,
        "m2.bbitmap_bsr_inv.scan.chunkmap_empty_before": 1,
        "m2.bbitmap_bsr_inv.scan.first_returned_found": 1,
        "m2.bbitmap_bsr_inv.scan.first_index": 963,
        "m2.bbitmap_bsr_inv.scan.second_returned_found": 1,
        "m2.bbitmap_bsr_inv.scan.second_index": 585,
        "m2.bbitmap_bsr_inv.scan.third_returned_found": 1,
        "m2.bbitmap_bsr_inv.scan.third_index": 511,
        "m2.bbitmap_bsr_inv.scan.drained_returned_found": 0,
        "m2.bbitmap_bsr_inv.scan.chunkmap_empty_after": 1,
    }
    for key, value in expected.items():
        if trace[key] != value:
            raise HarnessError(
                f"{source} M2 binned bitmap inverse-BSR trace contains an unmet relation: {key}"
            )


def compare_m2_binned_bitmap_bsr_inv_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require exact equality for the selected binned inverse-BSR observer."""

    validate_m2_binned_bitmap_bsr_inv_trace(c_trace, source="pinned C")
    validate_m2_binned_bitmap_bsr_inv_trace(rust_trace, source="Rust")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in M2_BINNED_BITMAP_BSR_INV_TRACE_KEYS
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise HarnessError(
            "Rust M2 binned bitmap inverse-BSR trace differs from pinned C: "
            + "; ".join(mismatches)
        )
    return {
        "compared_value_count": len(M2_BINNED_BITMAP_BSR_INV_TRACE_KEYS),
        "status": "matched",
    }


def parse_rust_test_count(output: str) -> int:
    matches = re.findall(
        r"^test result: ok\. ([0-9]+) passed; 0 failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out;",
        output,
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise HarnessError("Rust allocator test summary is absent or ambiguous")
    return int(matches[0])


def native_owner_exit_lifecycle_command(
    execution: Mapping[str, Any], check: Mapping[str, Any]
) -> list[str]:
    """Build one focused Cargo invocation from the reviewed evidence record."""

    command = [
        "cargo",
        "test",
        "-p",
        str(execution["package"]),
        "--features",
        ",".join(str(feature) for feature in execution["features"]),
        "--locked",
    ]
    if check["kind"] == "integration-test":
        command.extend(["--test", str(check["target"])])
    else:
        command.extend(["--lib", str(check["target"])])
    command.extend(["--", f"--test-threads={execution['test_threads']}"])
    return command


def run_native_owner_exit_lifecycle(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Execute the reviewed source-shaped owner-exit lifecycle suite.

    The suite is intentionally direct-engine evidence. It proves Gate 5C's
    owner-exit traversal and typed terminal-release semantics, but it does
    not turn the separately nondefault libc shadow lane into accepted ABI or
    stress evidence.
    """

    summary = validate_native_owner_exit_lifecycle_contract(contract, pin)
    execution = summary["execution"]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(NATIVE_OWNER_EXIT_CARGO_TARGET)
    records: list[dict[str, Any]] = []
    for check in summary["checks"]:
        command = native_owner_exit_lifecycle_command(execution, check)
        result = command_record(
            command,
            cwd=ROOT,
            env=environment,
            timeout_seconds=execution["timeout_seconds"],
        )
        require_success(result, f"native owner-exit lifecycle check {check['id']}")
        output = str(result["stdout"]) + "\n" + str(result["stderr"])
        passed_test_count = parse_rust_test_count(output)
        if passed_test_count != check["expected_passed_test_count"]:
            raise HarnessError(
                "native owner-exit lifecycle check "
                f"{check['id']} passed {passed_test_count} tests; expected "
                f"{check['expected_passed_test_count']}"
            )
        records.append(
            {
                "command": command,
                "id": check["id"],
                "kind": check["kind"],
                "passed_test_count": passed_test_count,
                "target": check["target"],
            }
        )
    return {
        "check_count": summary["check_count"],
        "checks": records,
        "contract": native_owner_exit_lifecycle_contract_record(contract, pin),
        "scenario_coverage": summary["scenario_coverage"],
        "status": "passed",
    }


def parse_upstream_api_test_summary(output: str) -> dict[str, int]:
    """Parse the single terminal summary emitted by pinned `testhelper.h`."""

    matches = re.findall(
        r"(?m)^succeeded:\s*([0-9]+)\s*$\n^failed\s*:\s*([0-9]+)\s*$",
        output,
    )
    if len(matches) != 1:
        raise HarnessError("adapted upstream API test summary is absent or ambiguous")
    succeeded, failed = (int(value) for value in matches[0])
    if failed != 0:
        noun = "failure" if failed == 1 else "failures"
        raise HarnessError(f"adapted upstream API test reported {failed} {noun}")
    if succeeded == 0:
        raise HarnessError("adapted upstream API test reported no successful checks")
    return {"failed": failed, "succeeded": succeeded}


def parse_native_static_libraries(output: str) -> list[str]:
    """Retain rustc's exact ordered native link tail for the static adapter."""

    matches = re.findall(
        r"(?m)^[ \t]*(?:note:[ \t]*)?native-static-libs:[ \t]*(.*?)[ \t]*$",
        output,
    )
    if len(matches) != 1:
        raise HarnessError("Rust adapter native-static-libs record is absent or ambiguous")
    libraries = matches[0].split()
    if not libraries or any(not re.fullmatch(r"-l[A-Za-z0-9_.+-]+", item) for item in libraries):
        raise HarnessError("Rust adapter has an invalid native static library record")
    return libraries


def parse_optional_native_static_libraries(output: str) -> list[str]:
    """Parse a native link tail when a no_std staticlib needs none."""

    matches = re.findall(
        r"(?m)^[ \t]*(?:note:[ \t]*)?native-static-libs:[ \t]*(.*?)[ \t]*$",
        output,
    )
    if len(matches) != 1:
        raise HarnessError("Rust adapter native-static-libs record is absent or ambiguous")
    libraries = matches[0].split()
    if any(not re.fullmatch(r"-l[A-Za-z0-9_.+-]+", item) for item in libraries):
        raise HarnessError("Rust adapter has an invalid native static library record")
    return libraries
def rust_target_self_contained_native_library_search_path(
    rust_target: str, library: str
) -> str:
    """Resolve one rustc-shipped static library for a C staticlib consumer."""

    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", rust_target):
        raise HarnessError("Rust target for a native static library search is invalid")
    if not re.fullmatch(r"lib[A-Za-z0-9_.+-]+\.a", library):
        raise HarnessError("Rust self-contained native library name is invalid")
    rustc = require_tool("rustc")
    record = command_record((rustc, "--print", "sysroot"), cwd=ROOT)
    require_success(record, "Rust sysroot discovery for native static library link")
    lines = [line.strip() for line in str(record["stdout"]).splitlines() if line.strip()]
    if len(lines) != 1:
        raise HarnessError("Rust sysroot discovery is absent or ambiguous")
    sysroot = Path(lines[0])
    if not sysroot.is_absolute():
        raise HarnessError("Rust sysroot for native static library link is not absolute")
    search_path = sysroot / "lib" / "rustlib" / rust_target / "lib" / "self-contained"
    if not (search_path / library).is_file():
        raise HarnessError(
            "Rust target self-contained native library is absent: "
            f"{search_path / library}"
        )
    return str(search_path)


def native_static_library_search_paths(
    compile_requirements: Mapping[str, Any], *, rust_target: str
) -> list[str]:
    """Resolve declared C-link paths, including a named Rust target library."""

    declared = compile_requirements.get("native_library_search_paths")
    if (
        not isinstance(declared, list)
        or not all(isinstance(path, str) and path and Path(path).is_absolute() for path in declared)
    ):
        raise HarnessError("Rust test adapter native library search paths are invalid")
    library = compile_requirements.get("rust_target_self_contained_native_library")
    if library is None:
        return list(declared)
    if not isinstance(library, str):
        raise HarnessError("Rust target self-contained native library contract is invalid")
    return [
        *declared,
        rust_target_self_contained_native_library_search_path(rust_target, library),
    ]


def compare_configuration_layout(
    c_layout: Mapping[str, int], rust_layout: Mapping[str, int]
) -> int:
    """Require the C and Rust probes to record the same config constants."""

    c_keys = {key for key in c_layout if key.startswith("config.")}
    rust_keys = {key for key in rust_layout if key.startswith("config.")}
    missing_from_c = sorted(rust_keys - c_keys)
    missing_from_rust = sorted(c_keys - rust_keys)
    if missing_from_c or missing_from_rust:
        problems: list[str] = []
        if missing_from_c:
            problems.append("configuration records missing from C: " + ", ".join(missing_from_c))
        if missing_from_rust:
            problems.append("configuration records missing from Rust: " + ", ".join(missing_from_rust))
        raise HarnessError("C/Rust configuration record sets differ: " + "; ".join(problems))
    return len(rust_keys)


def compare_rust_layout(c_layout: Mapping[str, int], rust_layout: Mapping[str, int]) -> dict[str, Any]:
    """Require every Rust-owned layout value to equal the pinned release C oracle."""

    compare_configuration_layout(c_layout, rust_layout)
    missing = sorted(set(rust_layout).difference(c_layout))
    mismatches = [
        f"{key} (C={c_layout[key]}, Rust={rust_layout[key]})"
        for key in sorted(rust_layout)
        if key in c_layout and c_layout[key] != rust_layout[key]
    ]
    problems: list[str] = []
    if missing:
        problems.append("missing from C oracle: " + ", ".join(missing))
    if mismatches:
        problems.append("value mismatches: " + ", ".join(mismatches))
    if problems:
        raise HarnessError("Rust allocator layout differs from pinned release C: " + "; ".join(problems))
    return {"compared_value_count": len(rust_layout), "status": "matched"}


def compare_small_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require the bounded Rust lifecycle to match every pinned C trace fact."""

    missing_from_c = sorted(set(rust_trace).difference(c_trace))
    missing_from_rust = sorted(set(c_trace).difference(rust_trace))
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(set(c_trace).intersection(rust_trace))
        if c_trace[key] != rust_trace[key]
    ]
    problems: list[str] = []
    if missing_from_c:
        problems.append("missing from C oracle: " + ", ".join(missing_from_c))
    if missing_from_rust:
        problems.append("missing from Rust port: " + ", ".join(missing_from_rust))
    if mismatches:
        problems.append("value mismatches: " + ", ".join(mismatches))
    if problems:
        raise HarnessError(
            "Rust small-allocation trace differs from pinned release C: "
            + "; ".join(problems)
        )
    return {"compared_value_count": len(rust_trace), "status": "matched"}


def compare_fundamental_trace(
    c_trace: Mapping[str, int],
    rust_trace: Mapping[str, int],
    *,
    architecture: str = "aarch64",
) -> dict[str, Any]:
    """Require one architecture's Rust trace to equal its pinned C record."""

    validate_fundamental_trace_schema(c_trace, source="pinned C", architecture=architecture)
    validate_fundamental_trace_schema(rust_trace, source="Rust", architecture=architecture)

    missing_from_c = sorted(set(rust_trace).difference(c_trace))
    missing_from_rust = sorted(set(c_trace).difference(rust_trace))
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(set(c_trace).intersection(rust_trace))
        if c_trace[key] != rust_trace[key]
    ]
    problems: list[str] = []
    if missing_from_c:
        problems.append("missing from C oracle: " + ", ".join(missing_from_c))
    if missing_from_rust:
        problems.append("missing from Rust port: " + ", ".join(missing_from_rust))
    if mismatches:
        problems.append("value mismatches: " + ", ".join(mismatches))
    if problems:
        raise HarnessError(
            "Rust fundamental-operation trace differs from pinned release C: "
            + "; ".join(problems)
        )
    return {"compared_value_count": len(rust_trace), "status": "matched"}


def validate_m1_raw_primitive_trace_schema(trace: Mapping[str, int], *, source: str) -> None:
    """Refuse a narrowed or widened raw M1 record from either implementation."""

    if len(M1_RAW_PRIMITIVE_TRACE_EXPECTED_KEYS) != M1_RAW_PRIMITIVE_TRACE_EXPECTED_COUNT:
        raise HarnessError("internal M1 raw-primitive trace schema has an unexpected key count")
    observed = set(trace)
    missing = sorted(M1_RAW_PRIMITIVE_TRACE_EXPECTED_KEYS.difference(observed))
    unexpected = sorted(observed.difference(M1_RAW_PRIMITIVE_TRACE_EXPECTED_KEYS))
    if missing or unexpected:
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M1 raw-primitive trace does not match the fixed "
            f"{M1_RAW_PRIMITIVE_TRACE_EXPECTED_COUNT}-key schema: "
            + "; ".join(problems)
        )


def compare_m1_raw_primitive_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require the selected source paths to agree without comparing host noise."""

    validate_m1_raw_primitive_trace_schema(c_trace, source="pinned C")
    validate_m1_raw_primitive_trace_schema(rust_trace, source="Rust")
    missing_from_c = sorted(set(rust_trace).difference(c_trace))
    missing_from_rust = sorted(set(c_trace).difference(rust_trace))
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(set(c_trace).intersection(rust_trace))
        if c_trace[key] != rust_trace[key]
    ]
    problems: list[str] = []
    if missing_from_c:
        problems.append("missing from C oracle: " + ", ".join(missing_from_c))
    if missing_from_rust:
        problems.append("missing from Rust port: " + ", ".join(missing_from_rust))
    if mismatches:
        problems.append("value mismatches: " + ", ".join(mismatches))
    if problems:
        raise HarnessError(
            "Rust M1 raw-primitive trace differs from pinned C: " + "; ".join(problems)
        )
    return {"compared_value_count": len(rust_trace), "status": "matched"}


def validate_m1_compiler_tls_trace_schema(
    trace: Mapping[str, int], *, source: str, expected_keys: frozenset[str], expected_count: int
) -> None:
    """Refuse a narrowed or widened compiler-TLS source record."""

    if len(expected_keys) != expected_count:
        raise HarnessError("internal M1 compiler-TLS trace schema has an unexpected key count")
    observed = set(trace)
    missing = sorted(expected_keys.difference(observed))
    unexpected = sorted(observed.difference(expected_keys))
    if missing or unexpected:
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} M1 compiler-TLS trace does not match the fixed "
            f"{expected_count}-key schema: " + "; ".join(problems)
        )


def validate_m1_compiler_tls_image_trace(trace: Mapping[str, int], *, source: str) -> None:
    """Validate the isolated root-image subset before records are combined."""

    validate_m1_compiler_tls_trace_schema(
        trace,
        source=source,
        expected_keys=M1_COMPILER_TLS_IMAGE_TRACE_EXPECTED_KEYS,
        expected_count=len(M1_COMPILER_TLS_IMAGE_TRACE_EXPECTED_KEYS),
    )


def validate_m1_compiler_tls_transition_trace(
    trace: Mapping[str, int], *, source: str
) -> None:
    """Validate the normal-artifact primitive subset before records are combined."""

    validate_m1_compiler_tls_trace_schema(
        trace,
        source=source,
        expected_keys=M1_COMPILER_TLS_TRANSITION_TRACE_EXPECTED_KEYS,
        expected_count=len(M1_COMPILER_TLS_TRANSITION_TRACE_EXPECTED_KEYS),
    )


def validate_m1_compiler_tls_full_trace(trace: Mapping[str, int], *, source: str) -> None:
    """Validate the union consumed by the C/Rust differential comparator."""

    validate_m1_compiler_tls_trace_schema(
        trace,
        source=source,
        expected_keys=M1_COMPILER_TLS_TRACE_EXPECTED_KEYS,
        expected_count=M1_COMPILER_TLS_TRACE_EXPECTED_COUNT,
    )


def validate_m1_compiler_tls_same_tld_trace(trace: Mapping[str, int], *, source: str) -> None:
    """Require the fixed source-internal setup and terminal call order.

    The expected values intentionally describe only the page-free `D -> A`
    fixture: two same-TLD Theaps, their selected source-call order, and the
    observable postconditions. They do not generalize to allocator teardown
    in a normal application or to outer `mi_thread_done` work.
    """

    expected = M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_VALUES
    if len(expected) != M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_COUNT:
        raise HarnessError("internal M1 compiler-TLS same-TLD trace schema has an unexpected key count")
    observed = set(trace)
    expected_keys = M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_KEYS
    missing = sorted(expected_keys.difference(observed))
    unexpected = sorted(observed.difference(expected_keys))
    mismatches = [
        f"{key} (expected={expected[key]}, observed={trace[key]})"
        for key in sorted(expected_keys.intersection(observed))
        if trace[key] != expected[key]
    ]
    if missing or unexpected or mismatches:
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        if mismatches:
            problems.append("value mismatches: " + ", ".join(mismatches))
        raise HarnessError(
            f"{source} M1 compiler-TLS same-TLD trace does not match the fixed "
            f"{M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_COUNT}-key fixture schema: "
            + "; ".join(problems)
        )


def merge_m1_compiler_tls_trace(
    image_trace: Mapping[str, int], transition_trace: Mapping[str, int], *, source: str
) -> dict[str, int]:
    """Join the two deliberately separate C execution modes without overlap."""

    overlap = sorted(set(image_trace).intersection(transition_trace))
    if overlap:
        raise HarnessError(
            f"{source} M1 compiler-TLS image/transition records overlap: " + ", ".join(overlap)
        )
    merged = {**image_trace, **transition_trace}
    validate_m1_compiler_tls_full_trace(merged, source=source)
    return merged


def compare_m1_compiler_tls_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require the finite source-specific TLS roots/primitives to match."""

    validate_m1_compiler_tls_full_trace(c_trace, source="pinned C")
    validate_m1_compiler_tls_full_trace(rust_trace, source="Rust")
    missing_from_c = sorted(set(rust_trace).difference(c_trace))
    missing_from_rust = sorted(set(c_trace).difference(rust_trace))
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(set(c_trace).intersection(rust_trace))
        if c_trace[key] != rust_trace[key]
    ]
    problems: list[str] = []
    if missing_from_c:
        problems.append("missing from C oracle: " + ", ".join(missing_from_c))
    if missing_from_rust:
        problems.append("missing from Rust port: " + ", ".join(missing_from_rust))
    if mismatches:
        problems.append("value mismatches: " + ", ".join(mismatches))
    if problems:
        raise HarnessError(
            "Rust M1 compiler-TLS trace differs from pinned C: " + "; ".join(problems)
        )
    return {"compared_value_count": len(rust_trace), "status": "matched"}


def compare_m1_compiler_tls_same_tld_trace(
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require the selected source-internal terminal records to match exactly."""

    validate_m1_compiler_tls_same_tld_trace(c_trace, source="pinned C")
    validate_m1_compiler_tls_same_tld_trace(rust_trace, source="Rust")
    missing_from_c = sorted(set(rust_trace).difference(c_trace))
    missing_from_rust = sorted(set(c_trace).difference(rust_trace))
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(set(c_trace).intersection(rust_trace))
        if c_trace[key] != rust_trace[key]
    ]
    problems: list[str] = []
    if missing_from_c:
        problems.append("missing from C oracle: " + ", ".join(missing_from_c))
    if missing_from_rust:
        problems.append("missing from Rust port: " + ", ".join(missing_from_rust))
    if mismatches:
        problems.append("value mismatches: " + ", ".join(mismatches))
    if problems:
        raise HarnessError(
            "Rust M1 compiler-TLS same-TLD trace differs from pinned C: " + "; ".join(problems)
        )
    return {"compared_value_count": len(rust_trace), "status": "matched"}


def validate_fundamental_trace_schema(
    trace: Mapping[str, int], *, source: str, architecture: str = "aarch64"
) -> None:
    """Reject a trace whose fields drift from its architecture's fixed record."""

    expected_keys, expected_count = fundamental_trace_schema(architecture)
    if len(expected_keys) != expected_count:
        raise HarnessError(
            "internal fundamental-operation trace schema has an unexpected key count"
        )
    observed = set(trace)
    missing = sorted(expected_keys.difference(observed))
    unexpected = sorted(observed.difference(expected_keys))
    if missing or unexpected:
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        raise HarnessError(
            f"{source} fundamental-operation trace does not match the fixed "
            f"{expected_count}-key schema: "
            + "; ".join(problems)
        )


def defined_dynamic_symbols(readelf: str, artifact: Path) -> list[str]:
    record = command_record((readelf, "--wide", "--dyn-syms", str(artifact)), cwd=ROOT)
    require_success(record, "dynamic symbol inventory")
    symbols: list[str] = []
    for line in str(record["stdout"]).splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].rstrip(":").isdigit():
            continue
        name = fields[-1].split("@", 1)[0]
        binding = fields[4]
        visibility = fields[5]
        section = fields[6]
        if binding in {"GLOBAL", "WEAK"} and visibility == "DEFAULT" and section != "UND":
            symbols.append(name)
    return sorted(set(symbols))


def dynamic_symbols(readelf: str, artifact: Path) -> list[str]:
    return [name for name in defined_dynamic_symbols(readelf, artifact) if name.startswith("mi_")]


def archive_defined_symbols(nm: str, artifact: Path) -> list[str]:
    record = command_record((nm, "-g", "-U", str(artifact)), cwd=ROOT)
    require_success(record, "static archive symbol inventory")
    symbols: list[str] = []
    for line in str(record["stdout"]).splitlines():
        fields = line.split()
        if len(fields) >= 2 and not fields[-1].endswith(":"):
            symbols.append(fields[-1])
    return sorted(set(symbols))


def dynamic_dependencies(readelf: str, artifact: Path) -> list[str]:
    record = command_record((readelf, "--wide", "--dynamic", str(artifact)), cwd=ROOT)
    require_success(record, "dynamic dependency inventory")
    return sorted(set(re.findall(r"Shared library: \[([^\]]+)\]", str(record["stdout"]))))


def parse_program_interpreter(program_headers: str, expected_basename: str) -> str:
    """Require one PT_INTERP path with the contract's stable basename.

    The pinned development image installs musl below a versioned absolute
    directory, so the target contract deliberately records the loader
    basename rather than an image-private path.  The complete observed path
    remains report evidence while its basename proves the intended loader.
    """

    if not isinstance(expected_basename, str) or not expected_basename:
        raise HarnessError("executable interpreter contract is invalid")
    matches = re.findall(
        r"(?m)^\s*\[Requesting program interpreter:\s*([^\]]+)\]\s*$",
        program_headers,
    )
    if len(matches) != 1:
        raise HarnessError("executable PT_INTERP record is absent or ambiguous")
    interpreter = matches[0].strip()
    if not interpreter or Path(interpreter).name != expected_basename:
        raise HarnessError("executable PT_INTERP differs from the native target contract")
    return interpreter


def audit_native_executable(
    readelf: str,
    artifact: Path,
    *,
    architecture: str,
    expected_elf: Mapping[str, str],
    expected_interpreter: str,
    expected_dynamic_dependencies: Sequence[str],
) -> dict[str, Any]:
    """Audit a native fixture executable before treating its result as evidence."""

    if (
        not isinstance(expected_elf, Mapping)
        or set(expected_elf) != {"class", "endianness", "machine"}
        or not all(isinstance(value, str) and value for value in expected_elf.values())
    ):
        raise HarnessError("native executable ELF contract is invalid")
    if (
        isinstance(expected_dynamic_dependencies, (str, bytes))
        or not isinstance(expected_dynamic_dependencies, Sequence)
        or not all(isinstance(item, str) and item for item in expected_dynamic_dependencies)
    ):
        raise HarnessError("native executable dynamic dependency contract is invalid")

    header = command_record((readelf, "-h", str(artifact)), cwd=ROOT)
    require_success(header, "native fixture ELF header")
    elf = parse_elf_identity(str(header["stdout"]), architecture)
    if elf != dict(expected_elf):
        raise HarnessError("native fixture ELF identity differs from the manifest")

    program_headers = command_record(
        (readelf, "--wide", "--program-headers", str(artifact)), cwd=ROOT
    )
    require_success(program_headers, "native fixture PT_INTERP inventory")
    interpreter = parse_program_interpreter(
        str(program_headers["stdout"]), expected_interpreter
    )

    dependencies = dynamic_dependencies(readelf, artifact)
    if dependencies != list(expected_dynamic_dependencies):
        raise HarnessError("native fixture dynamic dependency set differs from the manifest")
    return {
        "dynamic_dependencies": dependencies,
        "elf": elf,
        "interpreter": interpreter,
    }


FORBIDDEN_ADAPTER_ALLOCATOR_EXPORTS = frozenset(
    {
        "aligned_alloc",
        "calloc",
        "cfree",
        "free",
        "malloc",
        "malloc_usable_size",
        "memalign",
        "posix_memalign",
        "pvalloc",
        "realloc",
        "reallocarray",
        "valloc",
    }
)
ADAPTER_SYMBOL_PREFIX = "crabc_test_"
RUNTIME_TICKET_ZERO_ADAPTER_SYMBOL_PREFIX = "crabc_ticket_zero_test_"


def adapter_header_function_names(header: str) -> list[str]:
    """Inventory the prefixed declarations in the private adapter header."""

    names = re.findall(
        rf"(?m)^[^#\n;]*\b({re.escape(ADAPTER_SYMBOL_PREFIX)}[A-Za-z0-9_]+)\s*\([^;{{]*\)\s*;",
        header,
    )
    return sorted(set(names))


def validate_adapter_dynamic_symbols(
    symbols: Sequence[str], expected_symbols: Sequence[str]
) -> dict[str, Any]:
    """Require one test-adapter artifact to expose exactly its prefixed C surface."""

    expected = sorted(set(expected_symbols))
    if len(expected) != len(expected_symbols) or not expected:
        raise HarnessError("adapter symbol contract must be non-empty and duplicate-free")
    invalid_expected = [
        name for name in expected if not name.startswith(ADAPTER_SYMBOL_PREFIX)
    ]
    if invalid_expected:
        raise HarnessError(
            "adapter symbol contract contains non-prefixed names: "
            + ", ".join(invalid_expected)
        )
    defined = set(symbols)
    forbidden = sorted(
        name
        for name in defined
        if name.startswith("mi_") or name in FORBIDDEN_ADAPTER_ALLOCATOR_EXPORTS
    )
    if forbidden:
        raise HarnessError("adapter has forbidden allocator exports: " + ", ".join(forbidden))
    actual = sorted(name for name in defined if name.startswith(ADAPTER_SYMBOL_PREFIX))
    missing = sorted(set(expected).difference(actual))
    unexpected = sorted(set(actual).difference(expected))
    if missing:
        raise HarnessError("missing adapter symbols: " + ", ".join(missing))
    if unexpected:
        raise HarnessError("unexpected adapter symbols: " + ", ".join(unexpected))
    return {"exported_symbol_count": len(actual), "symbols": actual}


def runtime_ticket_zero_adapter_header_function_names(header: str) -> list[str]:
    """Inventory the private ticket-zero C evidence declarations."""

    names = re.findall(
        rf"(?m)^[^#\n;]*\b({re.escape(RUNTIME_TICKET_ZERO_ADAPTER_SYMBOL_PREFIX)}[A-Za-z0-9_]+)\s*\([^;{{]*\)\s*;",
        header,
    )
    return sorted(set(names))


def validate_runtime_ticket_zero_adapter_symbols(
    symbols: Sequence[str], expected_symbols: Sequence[str]
) -> dict[str, Any]:
    """Require exactly the narrow process-lifetime evidence C ABI."""

    expected = sorted(set(expected_symbols))
    if len(expected) != len(expected_symbols) or not expected:
        raise HarnessError(
            "runtime ticket-zero adapter symbol contract must be non-empty and duplicate-free"
        )
    invalid_expected = [
        name
        for name in expected
        if not name.startswith(RUNTIME_TICKET_ZERO_ADAPTER_SYMBOL_PREFIX)
    ]
    if invalid_expected:
        raise HarnessError(
            "runtime ticket-zero adapter symbol contract contains non-prefixed names: "
            + ", ".join(invalid_expected)
        )
    defined = set(symbols)
    forbidden = sorted(
        name
        for name in defined
        if name.startswith("mi_") or name in FORBIDDEN_ADAPTER_ALLOCATOR_EXPORTS
    )
    if forbidden:
        raise HarnessError(
            "runtime ticket-zero adapter has forbidden allocator exports: "
            + ", ".join(forbidden)
        )
    actual = sorted(
        name
        for name in defined
        if name.startswith(RUNTIME_TICKET_ZERO_ADAPTER_SYMBOL_PREFIX)
    )
    missing = sorted(set(expected).difference(actual))
    unexpected = sorted(set(actual).difference(expected))
    if missing:
        raise HarnessError(
            "runtime ticket-zero adapter missing symbols: " + ", ".join(missing)
        )
    if unexpected:
        raise HarnessError(
            "runtime ticket-zero adapter has unexpected symbols: " + ", ".join(unexpected)
        )
    return {"exported_symbol_count": len(actual), "symbols": actual}


def validate_runtime_ticket_zero_adapter_contract(
    contract: Mapping[str, Any],
    adapter_header: str,
    *,
    pin: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Validate the separate C witness without widening the M4 adapter."""

    if (
        contract.get("format") != 1
        or contract.get("schema") != "crabc-mimalloc-runtime-ticket-zero-test"
    ):
        raise HarnessError("runtime ticket-zero adapter contract has an unknown schema")
    active_pin = dict(load_pin() if pin is None else pin)
    expected_upstream = {
        "project": "microsoft/mimalloc",
        "revision": active_pin["revision"],
        "tag": active_pin["tag"],
        "version": active_pin["version"],
    }
    if contract.get("upstream") != expected_upstream:
        raise HarnessError("runtime ticket-zero adapter contract upstream identity differs")
    if contract.get("adapter_package") != "crabc-mimalloc-runtime-ticket-zero-adapter":
        raise HarnessError("runtime ticket-zero adapter contract names the wrong Cargo package")
    if (
        contract.get("header")
        != "compat/allocator/runtime-ticket-zero-adapter/crabc-mimalloc-runtime-ticket-zero-test.h"
    ):
        raise HarnessError("runtime ticket-zero adapter contract names the wrong header")
    if (
        contract.get("fixture")
        != "compat/allocator/runtime-ticket-zero-adapter/runtime-ticket-zero-fixture.c"
    ):
        raise HarnessError("runtime ticket-zero adapter contract names the wrong fixture")
    expected_fixture_invocation = {
        "cycle_argument": "--worker-cycles",
        "churn_stress_seed": f"0x{RUNTIME_TICKET_ZERO_CHURN_STRESS_SEED:016x}",
        "churn_watchdog_seconds": RUNTIME_TICKET_ZERO_CHURN_WATCHDOG_SECONDS,
        "churn_worker_cycles": RUNTIME_TICKET_ZERO_CHURN_WORKER_CYCLES,
        "default_stress_seed": f"0x{RUNTIME_TICKET_ZERO_DEFAULT_STRESS_SEED:016x}",
        "default_worker_cycles": RUNTIME_TICKET_ZERO_DEFAULT_WORKER_CYCLES,
        "maximum_worker_cycles": RUNTIME_TICKET_ZERO_MAX_WORKER_CYCLES,
        "soak_stress_seed": f"0x{RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED:016x}",
        "soak_watchdog_seconds": RUNTIME_TICKET_ZERO_SOAK_WATCHDOG_SECONDS,
        "soak_worker_cycles": RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
        "stress_seed_argument": "--stress-seed",
        "worker_routes_per_cycle": RUNTIME_TICKET_ZERO_WORKER_ROUTES_PER_CYCLE,
    }
    if contract.get("fixture_invocation") != expected_fixture_invocation:
        raise HarnessError("runtime ticket-zero fixture invocation contract differs from the native lane")
    expected_symbols = contract.get("expected_adapter_symbols")
    if not isinstance(expected_symbols, list) or not all(
        isinstance(symbol, str) for symbol in expected_symbols
    ):
        raise HarnessError("runtime ticket-zero adapter contract has invalid expected symbols")
    if runtime_ticket_zero_adapter_header_function_names(adapter_header) != sorted(expected_symbols):
        raise HarnessError(
            "runtime ticket-zero adapter header declarations differ from its contract"
        )
    if contract.get("lifecycle_audit") != RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_CONTRACT:
        raise HarnessError(
            "runtime ticket-zero lifecycle audit contract differs from the native lane"
        )
    if contract.get("soak_report") != RUNTIME_TICKET_ZERO_SOAK_REPORT_CONTRACT:
        raise HarnessError(
            "runtime ticket-zero soak report contract differs from the native lane"
        )
    compile_requirements = contract.get("compile_requirements")
    if not isinstance(compile_requirements, dict):
        raise HarnessError("runtime ticket-zero adapter contract has no compile requirements")
    if compile_requirements.get("target") != PRODUCTION_RUST_TARGET:
        raise HarnessError("runtime ticket-zero adapter target differs from the native contract")
    for field in ("expected_dynamic_dependencies", "native_static_libs"):
        value = compile_requirements.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise HarnessError(
                f"runtime ticket-zero adapter contract has invalid {field}"
            )
    return {"expected_adapter_symbol_count": len(expected_symbols)}


def validate_release_symbol_contract(
    api_contract: Mapping[str, Any], symbols: Sequence[str]
) -> dict[str, int]:
    """Prove normal-release `mi_*` exports match the checked-in header audit."""

    raw_items = api_contract.get("items")
    raw_contract = api_contract.get("release_symbol_contract")
    if not isinstance(raw_items, list) or not isinstance(raw_contract, dict):
        raise HarnessError("API contract lacks a release-symbol classification")
    external_items = [
        item
        for item in raw_items
        if isinstance(item, dict) and item.get("kind") == "external-function"
    ]
    external_names = {item.get("name") for item in external_items}
    if not all(isinstance(name, str) and name for name in external_names):
        raise HarnessError("API contract has an invalid external-function name")
    expected_raw = raw_contract.get("expected_defined_symbol_names")
    exceptions_raw = raw_contract.get("header_declarations_without_normal_release_symbol")
    if not isinstance(expected_raw, list) or not all(isinstance(name, str) for name in expected_raw):
        raise HarnessError("API contract has invalid expected release symbols")
    if not isinstance(exceptions_raw, list):
        raise HarnessError("API contract has invalid release-symbol exceptions")
    exception_names: set[str] = set()
    for exception in exceptions_raw:
        if not isinstance(exception, dict):
            raise HarnessError("API contract has an invalid release-symbol exception")
        name = exception.get("name")
        if not isinstance(name, str) or not name:
            raise HarnessError("API contract has an unnamed release-symbol exception")
        exception_names.add(name)
    expected = set(expected_raw)
    if len(expected) != len(expected_raw) or len(exception_names) != len(exceptions_raw):
        raise HarnessError("API contract duplicates a release-symbol classification")
    if expected & exception_names or expected | exception_names != external_names:
        raise HarnessError(
            "API contract has unclassified external declarations in the release-symbol contract"
        )
    actual = set(symbols)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        parts: list[str] = []
        if missing:
            parts.append("missing defined symbols: " + ", ".join(missing))
        if unexpected:
            parts.append("unclassified defined symbols: " + ", ".join(unexpected))
        raise HarnessError("normal-release API/symbol contract mismatch (" + "; ".join(parts) + ")")
    return {
        "declared_external_function_count": len(external_names),
        "defined_export_count": len(actual),
    }


def profile_command(compiler: str, source: Path, artifact: Path, profile_flags: Sequence[str]) -> list[str]:
    return [
        compiler,
        "-std=c11",
        "-fPIC",
        "-fvisibility=hidden",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        *profile_flags,
        "-I",
        str(source / "include"),
        "-shared",
        "-Wl,-soname," + artifact.name,
        "-pthread",
        "-o",
        str(artifact),
        *(str(source / item) for item in ORACLE_SOURCES),
    ]


def compiler_version(compiler: str, source: Path) -> str:
    record = command_record((compiler, "--version"), cwd=source)
    require_success(record, "compiler version probe")
    return str(record["stdout"]).splitlines()[0]


def build_small_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build the pinned release allocator as a fresh logical trace process."""

    trace_source = profile_dir / "small-trace-probe.c"
    trace_binary = profile_dir / "small-trace-probe"
    trace_source.write_text(SMALL_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C small-allocation trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C small-allocation trace execution")
    return {
        "command": command,
        "record": parse_small_trace(str(run["stdout"])),
    }


def build_fundamental_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
    *,
    architecture: str = "aarch64",
) -> dict[str, Any]:
    """Build the pinned-C baseline for the Milestone 4 public API slice."""

    trace_source = profile_dir / "fundamental-trace-probe.c"
    trace_binary = profile_dir / "fundamental-trace-probe"
    trace_source.write_text(FUNDAMENTAL_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C fundamental-operation trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C fundamental-operation trace execution")
    record = parse_fundamental_trace(str(run["stdout"]))
    validate_fundamental_trace_schema(record, source="pinned C", architecture=architecture)
    return {
        "command": command,
        "record": record,
        "architecture": architecture,
    }


def build_m1_raw_primitive_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Run the finite raw M1 slice against source-private pinned C state.

    `M1_RAW_PRIMITIVE_TRACE_PROBE` includes the archive's `src/os.c` so its
    static configuration record is observed directly.  The compilation list
    replaces, rather than duplicates, that source file.  This is intentionally
    a dedicated C oracle executable, not a Rust host-model test or a probe of
    the workspace's old C integration.
    """

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m1-raw-primitive-trace-probe.c"
    trace_binary = profile_dir / "m1-raw-primitive-trace-probe"
    trace_source.write_text(M1_RAW_PRIMITIVE_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in M1_RAW_PRIMITIVE_ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M1 raw-primitive trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M1 raw-primitive trace execution")
    record = parse_m1_raw_primitive_trace(str(run["stdout"]))
    validate_m1_raw_primitive_trace_schema(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc/prim.h",
                "src/os.c",
                "src/prim/prim.c",
                "src/prim/unix/prim.c",
            ),
        ),
    }


def build_m2_detached_tld_static_preimage_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build the direct detached `mi_tld_init` static-preimage C producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-detached-tld-static-preimage-trace-probe.c"
    trace_binary = profile_dir / "m2-detached-tld-static-preimage-trace-probe"
    trace_source.write_text(M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        # This source-only preimage record must not run prim.c's ordinary
        # automatic process constructor before main reaches its local image.
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in M2_DETACHED_TLD_STATIC_PREIMAGE_ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 detached-TLD static-preimage trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 detached-TLD static-preimage trace execution")
    record = parse_m2_detached_tld_static_preimage_trace(
        str(run["stdout"]), source="pinned C"
    )
    validate_m2_detached_tld_static_preimage_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc.h",
                "include/mimalloc/atomic.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/types.h",
                "src/init.c",
                "src/prim/prim.c",
            ),
        ),
    }


def build_m2_normal_tld_direct_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build the direct normal-arm `mi_tld_init` C producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-normal-tld-direct-trace-probe.c"
    trace_binary = profile_dir / "m2-normal-tld-direct-trace-probe"
    trace_source.write_text(M2_NORMAL_TLD_DIRECT_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        # The direct source fixture must not run prim.c's automatic process
        # constructor before main reaches its local helper preimage.
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in M2_NORMAL_TLD_DIRECT_ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 normal-TLD direct-helper trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 normal-TLD direct-helper trace execution")
    record = parse_m2_normal_tld_direct_trace(str(run["stdout"]), source="pinned C")
    validate_m2_normal_tld_direct_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc.h",
                "include/mimalloc/atomic.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "include/mimalloc/prim-tls.h",
                "include/mimalloc/types.h",
                "src/init.c",
                "src/os.c",
                "src/prim/prim-tls.c",
                "src/prim/prim.c",
                "src/prim/unix/prim.c",
            ),
        ),
    }


def build_m2_static_first_tld_create_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build the direct static-first `mi_tld_create` C producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-static-first-tld-create-trace-probe.c"
    trace_binary = profile_dir / "m2-static-first-tld-create-trace-probe"
    trace_source.write_text(M2_STATIC_FIRST_TLD_CREATE_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        # Keep the actual source static main subproc/TLD untouched before the
        # one selected direct call; the fixture supplies only inert theap_meta.
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in M2_STATIC_FIRST_TLD_CREATE_ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 static-first mi_tld_create trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 static-first mi_tld_create trace execution")
    record = parse_m2_static_first_tld_create_trace(str(run["stdout"]), source="pinned C")
    validate_m2_static_first_tld_create_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc.h",
                "include/mimalloc/atomic.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "include/mimalloc/prim-tls.h",
                "include/mimalloc/types.h",
                "src/init.c",
                "src/subproc.c",
                "src/os.c",
                "src/prim/prim-tls.c",
                "src/prim/prim.c",
                "src/prim/unix/prim.c",
            ),
        ),
    }


def build_m2_bitmap_abandoned_claim_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build the selected source-private one-chunk bitmap claim producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-bitmap-abandoned-claim-trace-probe.c"
    trace_binary = profile_dir / "m2-bitmap-abandoned-claim-trace-probe"
    trace_source.write_text(M2_BITMAP_ABANDONED_CLAIM_TRACE_PROBE, encoding="utf-8")
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
        *profile_flags,
        "-ffunction-sections",
        "-fdata-sections",
        str(trace_source),
        "-Wl,--gc-sections",
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 bitmap abandoned-claim trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 bitmap abandoned-claim trace execution")
    record = parse_m2_bitmap_abandoned_claim_trace(str(run["stdout"]), source="pinned C")
    validate_m2_bitmap_abandoned_claim_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc.h",
                "include/mimalloc/atomic.h",
                "include/mimalloc/bits.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "include/mimalloc/types.h",
                "src/bitmap.h",
                "src/bitmap.c",
            ),
        ),
    }


def build_m2_bitmap_clear_range_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build the selected source-private scalar bitmap range producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-bitmap-clear-range-trace-probe.c"
    trace_binary = profile_dir / "m2-bitmap-clear-range-trace-probe"
    trace_source.write_text(M2_BITMAP_CLEAR_RANGE_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-DMI_OPT_SIMD=0",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        "-ffunction-sections",
        "-fdata-sections",
        str(trace_source),
        "-Wl,--gc-sections",
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 bitmap clear-range trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 bitmap clear-range trace execution")
    record = parse_m2_bitmap_clear_range_trace(str(run["stdout"]), source="pinned C")
    validate_m2_bitmap_clear_range_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc.h",
                "include/mimalloc/atomic.h",
                "include/mimalloc/bits.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "include/mimalloc/types.h",
                "src/bitmap.h",
                "src/bitmap.c",
            ),
        ),
    }


def build_m2_bitmap_rangesn_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build the selected source-private scalar rangesn-wrapper producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-bitmap-rangesn-trace-probe.c"
    trace_binary = profile_dir / "m2-bitmap-rangesn-trace-probe"
    trace_source.write_text(M2_BITMAP_RANGESN_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-DMI_OPT_SIMD=0",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        "-ffunction-sections",
        "-fdata-sections",
        str(trace_source),
        "-Wl,--gc-sections",
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 bitmap rangesn trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 bitmap rangesn trace execution")
    record = parse_m2_bitmap_rangesn_trace(str(run["stdout"]), source="pinned C")
    validate_m2_bitmap_rangesn_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc.h",
                "include/mimalloc/atomic.h",
                "include/mimalloc/bits.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "include/mimalloc/types.h",
                "src/bitmap.h",
                "src/bitmap.c",
            ),
        ),
    }


def build_m2_bitmap_set_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build the selected source-private read-only bitmap set-bit producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-bitmap-set-trace-probe.c"
    trace_binary = profile_dir / "m2-bitmap-set-trace-probe"
    trace_source.write_text(M2_BITMAP_SET_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-DMI_OPT_SIMD=0",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        "-ffunction-sections",
        "-fdata-sections",
        str(trace_source),
        "-Wl,--gc-sections",
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 bitmap set-bit trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 bitmap set-bit trace execution")
    record = parse_m2_bitmap_set_trace(str(run["stdout"]), source="pinned C")
    validate_m2_bitmap_set_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc.h",
                "include/mimalloc/atomic.h",
                "include/mimalloc/bits.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "include/mimalloc/types.h",
                "src/bitmap.h",
                "src/bitmap.c",
            ),
        ),
    }


def build_m2_binned_bitmap_bsr_inv_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build the selected source-private binned inverse-BSR producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-binned-bitmap-bsr-inv-trace-probe.c"
    trace_binary = profile_dir / "m2-binned-bitmap-bsr-inv-trace-probe"
    trace_source.write_text(M2_BINNED_BITMAP_BSR_INV_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-DMI_OPT_SIMD=0",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        "-ffunction-sections",
        "-fdata-sections",
        str(trace_source),
        "-Wl,--gc-sections",
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 binned bitmap inverse-BSR trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 binned bitmap inverse-BSR trace execution")
    record = parse_m2_binned_bitmap_bsr_inv_trace(str(run["stdout"]), source="pinned C")
    validate_m2_binned_bitmap_bsr_inv_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc.h",
                "include/mimalloc/atomic.h",
                "include/mimalloc/bits.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "include/mimalloc/types.h",
                "src/bitmap.h",
                "src/bitmap.c",
            ),
        ),
    }


def build_m2_page_map_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build and execute the selected pinned-C two-level PageMap producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-page-map-trace-probe.c"
    trace_binary = profile_dir / "m2-page-map-trace-probe"
    trace_source.write_text(M2_PAGE_MAP_TRACE_PROBE, encoding="utf-8")
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
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in M2_PAGE_MAP_ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 PageMap trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 PageMap trace execution")
    record = parse_m2_page_map_trace(str(run["stdout"]), source="pinned C")
    validate_m2_page_map_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "src/init.c",
                "src/os.c",
                "src/page-map.c",
            ),
        ),
    }


def build_m2_page_map_lazy_commit_failure_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build and execute the selected pinned-C PageMap commit-failure producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-page-map-lazy-commit-failure-trace-probe.c"
    trace_binary = profile_dir / "m2-page-map-lazy-commit-failure-trace-probe"
    trace_source.write_text(M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_PROBE, encoding="utf-8")
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
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in M2_PAGE_MAP_ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 PageMap lazy-commit failure trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 PageMap lazy-commit failure trace execution")
    record = parse_m2_page_map_lazy_commit_failure_trace(
        str(run["stdout"]), source="pinned C"
    )
    validate_m2_page_map_lazy_commit_failure_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "src/init.c",
                "src/os.c",
                "src/page-map.c",
            ),
        ),
    }


def build_m2_page_map_cold_init_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build one fresh pinned-C failed-first PageMap initialization producer."""

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m2-page-map-cold-init-trace-probe.c"
    trace_binary = profile_dir / "m2-page-map-cold-init-trace-probe"
    trace_source.write_text(M2_PAGE_MAP_COLD_INIT_TRACE_PROBE, encoding="utf-8")
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
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in M2_PAGE_MAP_ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M2 PageMap cold-init trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M2 PageMap cold-init trace execution")
    record = parse_m2_page_map_cold_init_trace(str(run["stdout"]), source="pinned C")
    validate_m2_page_map_cold_init_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc/internal.h",
                "include/mimalloc/prim.h",
                "src/init.c",
                "src/os.c",
                "src/page-map.c",
            ),
        ),
    }


def build_m1_compiler_tls_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Run the finite compiler-TLS C records in their two source modes.

    The pre-process image and normal regular-backing/cache primitives cannot
    share a process: the former must suppress automatic attach, while the
    latter must retain the ordinary pinned C artifact configuration. Their
    non-overlapping address-free records are joined only after each mode has
    passed its own fixed schema.
    """

    profile_dir.mkdir(parents=True, exist_ok=True)

    def build_one(
        *,
        name: str,
        probe: str,
        defines: Sequence[str],
        parser: Callable[[str], dict[str, int]],
        validator: Callable[[Mapping[str, int]], None],
    ) -> dict[str, Any]:
        trace_source = profile_dir / f"m1-compiler-tls-{name}-trace-probe.c"
        trace_binary = profile_dir / f"m1-compiler-tls-{name}-trace-probe"
        trace_source.write_text(probe, encoding="utf-8")
        command = [
            compiler,
            "-std=c11",
            "-fPIC",
            "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB",
            "-DMI_SHARED_LIB_EXPORT",
            "-DMI_LIBC_MUSL=1",
            *defines,
            "-I",
            str(source / "include"),
            "-I",
            str(source / "src"),
            *profile_flags,
            str(trace_source),
            *(str(source / item) for item in M1_COMPILER_TLS_ORACLE_SOURCES),
            "-pthread",
            "-o",
            str(trace_binary),
        ]
        build = command_record(command, cwd=source)
        require_success(build, f"pinned C M1 compiler-TLS {name} trace build")
        run = command_record((str(trace_binary),), cwd=source)
        require_success(run, f"pinned C M1 compiler-TLS {name} trace execution")
        record = parser(str(run["stdout"]))
        validator(record)
        return {
            "command": command,
            "defines": list(defines),
            "record": record,
        }

    image = build_one(
        name="image",
        probe=M1_COMPILER_TLS_IMAGE_TRACE_PROBE,
        defines=M1_BOOTSTRAP_STATIC_IMAGE_PROBE_DEFINES,
        parser=parse_m1_compiler_tls_image_trace,
        validator=lambda record: validate_m1_compiler_tls_image_trace(record, source="pinned C"),
    )
    transition = build_one(
        name="transition",
        probe=M1_COMPILER_TLS_TRANSITION_TRACE_PROBE,
        defines=(),
        parser=parse_m1_compiler_tls_transition_trace,
        validator=lambda record: validate_m1_compiler_tls_transition_trace(
            record, source="pinned C"
        ),
    )
    return {
        "image": image,
        "record": merge_m1_compiler_tls_trace(
            image["record"], transition["record"], source="pinned C"
        ),
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc/prim-tls.h",
                "include/mimalloc/internal.h",
                "src/threadlocal.c",
                "src/prim/prim-tls.c",
                "src/theap.c",
                "src/init.c",
                "src/prim/prim.c",
            ),
        ),
        "transition": transition,
    }


def build_m1_compiler_tls_same_tld_trace(
    compiler: str,
    source: Path,
    profile_dir: Path,
    profile_flags: Sequence[str],
) -> dict[str, Any]:
    """Build one source-internal page-free same-TLD C trace.

    This is intentionally kept separate from `build_m1_compiler_tls_trace`:
    its C producer alone makes no C/Rust comparison. A static
    auxiliary Heap is initialized through the ordinary regular-key setup and
    `_mi_heap_theap_get_or_init`, without public `mi_heap_new`, so the main
    static default D and Malloc-backed cached A start page-free in one TLD.
    The dedicated probe includes `src/init.c` and directly invokes its exact
    file-static `mi_thread_theaps_done` body; the ordinary source list omits
    only `init.c` to preserve one-definition C linkage.
    """

    profile_dir.mkdir(parents=True, exist_ok=True)
    trace_source = profile_dir / "m1-compiler-tls-same-tld-trace-probe.c"
    trace_binary = profile_dir / "m1-compiler-tls-same-tld-trace-probe"
    trace_source.write_text(M1_COMPILER_TLS_SAME_TLD_TRACE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *profile_flags,
        str(trace_source),
        *(str(source / item) for item in M1_COMPILER_TLS_SAME_TLD_TRACE_ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(trace_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M1 compiler-TLS same-TLD trace build")
    run = command_record((str(trace_binary),), cwd=source)
    require_success(run, "pinned C M1 compiler-TLS same-TLD trace execution")
    record = parse_m1_compiler_tls_same_tld_trace(str(run["stdout"]))
    validate_m1_compiler_tls_same_tld_trace(record, source="pinned C")
    return {
        "command": command,
        "record": record,
        "scope": (
            "source-internal page-free C fixture: static auxiliary Heap regular-key setup plus "
            "one main static default Theap D and one Malloc-backed cached Theap A in one TLD; "
            "direct included init.c:mi_thread_theaps_done(D.tld) body; _Exit avoids teardown of "
            "the synthetic static auxiliary Heap; no Rust comparison or general lifecycle claim"
        ),
        "source_files": source_file_records(
            source,
            (
                "include/mimalloc/internal.h",
                "include/mimalloc/prim-tls.h",
                "src/init.c",
                "src/theap.c",
                "src/heap.c",
                "src/threadlocal.c",
                "src/prim/prim-tls.c",
                "src/prim/prim.c",
                "src/prim/unix/prim.c",
            ),
        ),
    }


def run_m1_compiler_tls_terminal_prototype(*, offline: bool) -> dict[str, Any]:
    """Build and run the isolated pinned-C half of the terminal trace.

    This intentionally has no report path: it is an explicit development
    view of the C half only. `--m1` consumes the same C producer with the
    dedicated Rust trace and remains the status-bearing evidence path.
    """

    require_native_aarch64()
    compiler = require_tool("musl-gcc")
    pin = load_pin()
    archive = fetch_archive(pin, offline)
    with temporary_directory(prefix="crabc-mimalloc-m1-compiler-tls-same-tld-source-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        c_oracle = build_m1_compiler_tls_same_tld_trace(
            compiler,
            source,
            M1_COMPILER_TLS_SAME_TLD_TRACE_ARTIFACT_ROOT,
            CONFIGURATION_PROFILES["release"],
        )
    return {
        "c_oracle": c_oracle,
        "scope": (
            "explicit source-only C half; it does not by itself produce an M1 report "
            "or establish M2+ or public allocator lifecycle completion"
        ),
        "status": "passed",
        "target": {"architecture": platform.machine(), "system": platform.system()},
    }


def pending_fundamental_trace_comparison() -> dict[str, str]:
    """Describe the same-run comparison before the Rust library probe runs."""

    return {
        "reason": (
            "The pinned C record is built before the Rust library probe; "
            "run_milestone0 replaces this marker with the exact comparison "
            "before it writes a report."
        ),
        "status": "pending",
    }


def build_m1_static_image_probe(
    compiler: str,
    source: Path,
    profile_dir: Path,
    flags: Sequence[str],
) -> dict[str, Any]:
    """Read only the M1 pre-process-initialization static image.

    This is intentionally not a `build_profile` layout variant. Its one
    constructor-suppression define is limited to the generated reader, so the
    normal profile artifact, generic layout reader, macro probe, and runtime
    traces retain the pinned ordinary automatic-attach configuration.
    """

    probe_source = profile_dir / "m1-static-image-probe.c"
    probe_binary = profile_dir / "m1-static-image-probe"
    probe_source.write_text(STATIC_IMAGE_PROBE, encoding="utf-8")
    command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        *M1_BOOTSTRAP_STATIC_IMAGE_PROBE_DEFINES,
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *flags,
        str(probe_source),
        *(str(source / item) for item in ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(probe_binary),
    ]
    build = command_record(command, cwd=source)
    require_success(build, "pinned C M1 static-image reader build")
    run = command_record((str(probe_binary),), cwd=source)
    require_success(run, "pinned C M1 static-image reader execution")
    layout = parse_layout(str(run["stdout"]))
    actual_keys = set(layout)
    expected_keys = set(M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEYS)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        unexpected = sorted(actual_keys - expected_keys)
        problems: list[str] = []
        if missing:
            problems.append("missing " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected " + ", ".join(unexpected))
        raise HarnessError(
            "pinned C M1 static-image reader does not emit the frozen vector: "
            + "; ".join(problems)
        )
    return {
        "command": command,
        "defines": list(M1_BOOTSTRAP_STATIC_IMAGE_PROBE_DEFINES),
        "layout": layout,
    }


def build_profile(
    compiler: str,
    readelf: str,
    source: Path,
    name: str,
    flags: Sequence[str],
    *,
    artifact_root: Path = ORACLE_ARTIFACT_ROOT,
    architecture: str = "aarch64",
    include_m1_static_image_probe: bool = False,
) -> dict[str, Any]:
    profile_dir = artifact_root / name
    profile_dir.mkdir(parents=True, exist_ok=True)
    artifact = profile_dir / "libmimalloc.so"
    command = profile_command(compiler, source, artifact, flags)
    build = command_record(command, cwd=source)
    require_success(build, f"pinned C oracle {name} build")
    probe_source = profile_dir / "layout-probe.c"
    probe_binary = profile_dir / "layout-probe"
    probe_source.write_text(LAYOUT_PROBE, encoding="utf-8")
    probe_command = [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *flags,
        str(probe_source),
        *(str(source / item) for item in ORACLE_SOURCES),
        "-pthread",
        "-o",
        str(probe_binary),
    ]
    probe_build = command_record(probe_command, cwd=source)
    require_success(probe_build, f"pinned C layout probe {name} build")
    probe_run = command_record((str(probe_binary),), cwd=source)
    require_success(probe_run, f"pinned C layout probe {name} execution")
    layout = parse_layout(str(probe_run["stdout"]))
    reader_only_keys_in_generic_layout = sorted(
        set(layout) & M1_BOOTSTRAP_STATIC_IMAGE_READER_ONLY_LAYOUT_KEY_SET
    )
    if reader_only_keys_in_generic_layout:
        raise HarnessError(
            "generic C layout reader unexpectedly contains M1 static-image-only keys: "
            + ", ".join(reader_only_keys_in_generic_layout)
        )
    macro_probe = command_record(
        [compiler, "-std=c11", "-dM", "-E", "-I", str(source / "include"), *flags, "-"],
        cwd=source,
        input_text="#include <mimalloc/types.h>\n",
    )
    require_success(macro_probe, f"pinned C preprocessor probe {name}")
    header = command_record((readelf, "-h", str(artifact)), cwd=source)
    require_success(header, f"pinned C ELF header probe {name}")
    parse_elf_identity(str(header["stdout"]), architecture)
    result = {
        "artifact": artifact_record(artifact),
        "build": {"command": command, "stderr": build["stderr"]},
        "configuration_macros": parse_macros(str(macro_probe["stdout"])),
        "flags": list(flags),
        "layout": layout,
        "profile": name,
        "symbols": dynamic_symbols(readelf, artifact),
    }
    if include_m1_static_image_probe:
        result["m1_static_image_probe"] = build_m1_static_image_probe(
            compiler, source, profile_dir, flags
        )
    if name == "release":
        result["single_thread_small_trace"] = build_small_trace(
            compiler, source, profile_dir, flags
        )
        result["fundamental_trace"] = {
            "c_oracle": build_fundamental_trace(
                compiler, source, profile_dir, flags, architecture=architecture
            ),
            "rust_comparison": pending_fundamental_trace_comparison(),
        }
    return result


def validate_exact_normal_dependency_graph(
    metadata: Mapping[str, Any],
    *,
    target: str,
    expected_dependency_versions: Mapping[str, str],
    expected_dependency_edges: Mapping[str, tuple[str, ...]],
) -> dict[str, Any]:
    """Judge one explicit target's normal `crabc-mimalloc` dependency graph.

    This parser is shared only to avoid giving the AArch64 and x86-64
    evidence lanes subtly different graph traversal rules. Each caller still
    supplies its own target, versions, and edges: a target-specific graph is
    not inherited merely because its metadata is parsed by the same code.
    Cargo lockfiles retain target-conditional packages, so lockfile presence is
    not evidence that a dependency is linked.
    """

    if set(expected_dependency_versions) != set(expected_dependency_edges):
        raise HarnessError("allocator dependency contract has mismatched packages and edges")

    raw_packages = metadata.get("packages")
    raw_resolve = metadata.get("resolve")
    if not isinstance(raw_packages, list) or not isinstance(raw_resolve, dict):
        raise HarnessError("Cargo metadata lacks packages or a resolved graph")
    raw_nodes = raw_resolve.get("nodes")
    if not isinstance(raw_nodes, list):
        raise HarnessError("Cargo metadata lacks resolved dependency nodes")

    packages: dict[str, Mapping[str, Any]] = {}
    for package in raw_packages:
        if not isinstance(package, dict):
            raise HarnessError("Cargo metadata contains an invalid package")
        package_id = package.get("id")
        if not isinstance(package_id, str) or not package_id or package_id in packages:
            raise HarnessError("Cargo metadata contains an invalid or duplicate package id")
        packages[package_id] = package

    nodes: dict[str, Mapping[str, Any]] = {}
    for node in raw_nodes:
        if not isinstance(node, dict):
            raise HarnessError("Cargo metadata contains an invalid dependency node")
        package_id = node.get("id")
        if not isinstance(package_id, str) or not package_id or package_id in nodes:
            raise HarnessError("Cargo metadata contains an invalid or duplicate dependency node id")
        nodes[package_id] = node

    roots = [
        package_id
        for package_id, package in packages.items()
        if package.get("name") == "crabc-mimalloc"
        and package.get("version") == expected_dependency_versions["crabc-mimalloc"]
        and package.get("source") is None
    ]
    if len(roots) != 1:
        raise HarnessError(
            "Cargo metadata must contain exactly one workspace "
            f"crabc-mimalloc {expected_dependency_versions['crabc-mimalloc']} root"
        )

    selected_ids: set[str] = set()
    selected_edges: dict[str, tuple[str, ...]] = {}
    pending = [roots[0]]
    while pending:
        package_id = pending.pop()
        if package_id in selected_ids:
            continue
        package = packages.get(package_id)
        node = nodes.get(package_id)
        if package is None or node is None:
            raise HarnessError(f"Cargo metadata has no package/node pair for selected id {package_id}")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise HarnessError(f"Cargo metadata has an unnamed selected package: {package_id}")
        raw_dependencies = node.get("deps")
        if not isinstance(raw_dependencies, list):
            raise HarnessError(f"Cargo metadata has invalid dependencies for {name} {version}")
        normal_dependency_ids: list[str] = []
        for dependency in raw_dependencies:
            if not isinstance(dependency, dict):
                raise HarnessError(f"Cargo metadata has an invalid dependency for {name} {version}")
            dependency_id = dependency.get("pkg")
            dependency_kinds = dependency.get("dep_kinds")
            if not isinstance(dependency_id, str) or not isinstance(dependency_kinds, list):
                raise HarnessError(f"Cargo metadata has an invalid dependency edge for {name} {version}")
            normal = False
            for dependency_kind in dependency_kinds:
                if not isinstance(dependency_kind, dict) or "kind" not in dependency_kind:
                    raise HarnessError(f"Cargo metadata has an invalid dependency kind for {name} {version}")
                if dependency_kind["kind"] is None:
                    normal = True
            if normal:
                if dependency_id not in packages:
                    raise HarnessError(
                        f"Cargo metadata names an unknown selected dependency {dependency_id}"
                    )
                normal_dependency_ids.append(dependency_id)
        dependency_names: list[str] = []
        for dependency_id in normal_dependency_ids:
            dependency_name = packages[dependency_id].get("name")
            if not isinstance(dependency_name, str):
                raise HarnessError(f"Cargo metadata has an unnamed dependency {dependency_id}")
            dependency_names.append(dependency_name)
        if len(dependency_names) != len(set(dependency_names)):
            raise HarnessError(f"Cargo metadata duplicates a normal dependency edge for {name} {version}")
        selected_ids.add(package_id)
        selected_edges[name] = tuple(sorted(dependency_names))
        pending.extend(normal_dependency_ids)

    selected_versions = {
        (str(packages[package_id].get("name")), str(packages[package_id].get("version")))
        for package_id in selected_ids
    }
    expected_versions = set(expected_dependency_versions.items())
    unexpected = sorted(selected_versions - expected_versions)
    missing = sorted(expected_versions - selected_versions)
    if unexpected:
        rendered = ", ".join(f"{name} {version}" for name, version in unexpected)
        label = "package" if len(unexpected) == 1 else "packages"
        raise HarnessError(f"unexpected selected {label}: {rendered}")
    if missing:
        rendered = ", ".join(f"{name} {version}" for name, version in missing)
        label = "package" if len(missing) == 1 else "packages"
        raise HarnessError(f"missing selected {label}: {rendered}")

    build_scripts: list[str] = []
    proc_macros: list[str] = []
    report_packages: list[dict[str, str]] = []
    for package_id in selected_ids:
        package = packages[package_id]
        name = str(package["name"])
        version = str(package["version"])
        source = package.get("source")
        expected_source = None if name in {"crabc-mimalloc", "crabc-core"} else CRATES_IO_SOURCE
        if source != expected_source:
            raise HarnessError(
                f"selected package has an unexpected source: {name} {version} ({source!r})"
            )
        raw_targets = package.get("targets")
        if not isinstance(raw_targets, list):
            raise HarnessError(f"Cargo metadata has invalid targets for {name} {version}")
        for package_target in raw_targets:
            if not isinstance(package_target, dict) or not isinstance(package_target.get("kind"), list):
                raise HarnessError(f"Cargo metadata has an invalid target for {name} {version}")
            kinds = package_target["kind"]
            if "custom-build" in kinds:
                build_scripts.append(f"{name} {version}")
            if "proc-macro" in kinds:
                proc_macros.append(f"{name} {version}")
        if name != "crabc-mimalloc":
            report_packages.append(
                {
                    "name": name,
                    "source": "workspace" if source is None else "crates.io",
                    "version": version,
                }
            )
    if build_scripts:
        rendered = ", ".join(sorted(build_scripts))
        label = "script" if len(build_scripts) == 1 else "scripts"
        raise HarnessError(f"selected build {label}: {rendered}")
    if proc_macros:
        rendered = ", ".join(sorted(proc_macros))
        label = "macro" if len(proc_macros) == 1 else "macros"
        raise HarnessError(f"selected proc {label}: {rendered}")

    expected_edges = {
        name: tuple(sorted(dependencies))
        for name, dependencies in expected_dependency_edges.items()
    }
    if selected_edges != expected_edges:
        differences = [
            f"{name}: expected {expected_edges.get(name, ())}, selected {selected_edges.get(name, ())}"
            for name in sorted(set(expected_edges) | set(selected_edges))
            if expected_edges.get(name) != selected_edges.get(name)
        ]
        raise HarnessError("selected dependency edge mismatch (" + "; ".join(differences) + ")")

    report_packages.sort(key=lambda package: (package["name"], package["version"]))
    return {
        "build_script_count": 0,
        "external_package_count": sum(package["source"] == "crates.io" for package in report_packages),
        "packages": report_packages,
        "proc_macro_count": 0,
        "target": target,
    }


def validate_production_dependency_graph(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Judge the exact normal dependency graph selected for production AArch64."""

    return validate_exact_normal_dependency_graph(
        metadata,
        target=PRODUCTION_RUST_TARGET,
        expected_dependency_versions=EXPECTED_PRODUCTION_DEPENDENCY_VERSIONS,
        expected_dependency_edges=EXPECTED_PRODUCTION_DEPENDENCY_EDGES,
    )


def validate_x86_64_engine_dependency_graph(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Judge the normal unfeatured engine graph selected for native x86-64.

    `cpufeatures` is required here for the selected RustCrypto x86 path; the
    absence of a selected `libc` package is enforced by the same exact graph.
    This is allocator-engine evidence only, not the AArch64 production graph
    and not a public x86 allocator integration claim.
    """

    return validate_exact_normal_dependency_graph(
        metadata,
        target=X86_64_RUST_TARGET,
        expected_dependency_versions=EXPECTED_X86_64_ENGINE_DEPENDENCY_VERSIONS,
        expected_dependency_edges=EXPECTED_X86_64_ENGINE_DEPENDENCY_EDGES,
    )


def production_dependency_graph() -> dict[str, Any]:
    command = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--filter-platform",
        PRODUCTION_RUST_TARGET,
        "--locked",
    ]
    record = command_record(command, cwd=ROOT)
    require_success(record, "Rust allocator production dependency graph")
    try:
        metadata = json.loads(str(record["stdout"]))
    except json.JSONDecodeError as error:
        raise HarnessError(f"Cargo metadata did not return valid JSON: {error}") from error
    if not isinstance(metadata, dict):
        raise HarnessError("Cargo metadata did not return a JSON object")
    report = validate_production_dependency_graph(metadata)
    report["command"] = command
    return report


def x86_64_engine_dependency_graph() -> dict[str, Any]:
    """Collect the native x86-64 engine's exact normal dependency graph."""

    # The canonical Docker image may begin with an empty bind-mounted Cargo
    # cache. `--locked` pins this resolution without falsely requiring that
    # the cache was already populated; a first native run may download the
    # lockfile-selected crates.
    command = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--filter-platform",
        X86_64_RUST_TARGET,
        "--no-default-features",
        "--locked",
    ]
    record = command_record(command, cwd=ROOT)
    require_success(record, "Rust allocator x86-64 engine dependency graph")
    try:
        metadata = json.loads(str(record["stdout"]))
    except json.JSONDecodeError as error:
        raise HarnessError(f"Cargo metadata did not return valid JSON: {error}") from error
    if not isinstance(metadata, dict):
        raise HarnessError("Cargo metadata did not return a JSON object")
    report = validate_x86_64_engine_dependency_graph(metadata)
    report["command"] = command
    report["resolution"] = dict(X86_64_LOCKFILE_RESOLUTION)
    return report


def x86_64_normal_engine_rlib_from_cargo_output(output: str) -> Path:
    """Select the one unfeatured release rlib emitted for the x86 engine."""

    candidates: list[Path] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("reason") != "compiler-artifact":
            continue
        target = event.get("target")
        if not isinstance(target, dict) or target.get("name") != "crabc_mimalloc":
            continue
        if target.get("kind") != ["lib"] or target.get("crate_types") != ["lib"]:
            raise HarnessError("x86-64 engine artifact is not the normal Rust library")
        profile = event.get("profile")
        if not isinstance(profile, dict) or profile.get("test") is not False:
            raise HarnessError("x86-64 engine artifact unexpectedly selected a test profile")
        features = event.get("features")
        if features != []:
            raise HarnessError("x86-64 engine artifact unexpectedly selected crate features")
        filenames = event.get("filenames")
        if not isinstance(filenames, list):
            raise HarnessError("x86-64 engine artifact lacks output filenames")
        rlibs = [Path(filename) for filename in filenames if isinstance(filename, str) and filename.endswith(".rlib")]
        if len(rlibs) != 1:
            raise HarnessError("x86-64 engine artifact must report exactly one rlib")
        candidates.extend(rlibs)
    if len(candidates) != 1:
        raise HarnessError("cargo did not report exactly one unfeatured x86-64 engine rlib")
    return candidates[0]


def x86_64_normal_engine_artifact_command(cargo: str) -> list[str]:
    """Return the exact unfeatured, lockfile-verified x86 release-rustc command."""

    return [
        cargo,
        "rustc",
        "--locked",
        "--package",
        "crabc-mimalloc",
        "--lib",
        "--release",
        "--no-default-features",
        "--target",
        X86_64_RUST_TARGET,
        "--message-format=json",
    ]


def extract_single_rlib_codegen_member(ar: str, archive: Path, destination: Path) -> str:
    """Copy the sole codegen-unit member from a controlled one-unit rlib."""

    inventory = command_record((ar, "t", str(archive)), cwd=ROOT)
    require_success(inventory, "x86-64 engine rlib inventory")
    objects = [line for line in str(inventory["stdout"]).splitlines() if line.endswith(".o")]
    if len(objects) != 1:
        raise HarnessError(
            "x86-64 engine rlib must contain exactly one codegen-unit member, "
            f"found {objects}"
        )
    member = objects[0]
    if Path(member).name != member:
        raise HarnessError("x86-64 engine rlib codegen member is not a bare filename")
    try:
        completed = subprocess.run(
            (ar, "p", str(archive), member),
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HarnessError(f"failed to extract x86-64 engine rlib codegen member: {error}") from error
    if completed.returncode != 0:
        raise HarnessError(
            "failed to extract x86-64 engine rlib codegen member: "
            + completed.stderr.decode(errors="replace").strip()
        )
    destination.write_bytes(completed.stdout)
    return member


def x86_64_normal_engine_codegen_member_format(file_output: str) -> str:
    """Require the normal fat-LTO release rlib's recorded codegen format.

    The workspace release profile intentionally uses fat LTO.  Rust therefore
    stores LLVM bitcode in this normal library rlib instead of a final linked
    ELF object.  Treat that distinction as evidence, not as a reason to run a
    non-normal `-Clto=off` build or to overclaim an ELF artifact.
    """

    if "LLVM IR bitcode" not in file_output:
        raise HarnessError(
            "x86-64 normal engine rlib codegen member is not the expected "
            "fat-LTO LLVM bitcode: "
            + file_output
        )
    return "llvm-ir-bitcode"


def x86_64_normal_engine_artifact() -> dict[str, Any]:
    """Build and inspect the normal native x86-64 `#![no_std]` engine rlib.

    A no_std library has no standalone panic handler, so a staticlib would
    fail before it could prove this boundary. The rlib is therefore the exact
    normal-library artifact being audited here. The workspace release profile
    uses fat LTO, so its codegen member is LLVM bitcode rather than a final
    linked ELF object. This is not a final linked ABI, a public allocator
    artifact, or an integration claim.
    """

    require_native_x86_64()
    cargo = require_tool("cargo")
    ar = require_tool("ar")
    file_tool = require_tool("file")
    crate_root = ROOT / "crabc-mimalloc/src/lib.rs"
    if not re.search(r"(?m)^#!\[no_std\]\s*$", crate_root.read_text(encoding="utf-8")):
        raise HarnessError("crabc-mimalloc crate root no longer declares #![no_std]")

    with temporary_directory(prefix="crabc-mimalloc-engine-x86_64-") as temporary:
        temporary_root = Path(temporary)
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(temporary_root / "target")
        environment["CARGO_INCREMENTAL"] = "0"
        command = x86_64_normal_engine_artifact_command(cargo)
        build = command_record(command, cwd=ROOT, env=environment)
        require_success(build, "Rust allocator x86-64 normal engine rlib")
        rlib = x86_64_normal_engine_rlib_from_cargo_output(
            str(build["stdout"]) + "\n" + str(build["stderr"])
        )
        if not rlib.is_file():
            raise HarnessError("cargo-reported x86-64 engine rlib is absent")
        release_directory = environment["CARGO_TARGET_DIR"]
        expected_rlib_directory = Path(release_directory) / X86_64_RUST_TARGET / "release"
        try:
            rlib.relative_to(expected_rlib_directory)
        except ValueError as error:
            raise HarnessError(
                "cargo-reported x86-64 engine rlib is outside its isolated target release directory"
            ) from error
        codegen_member_path = temporary_root / "crabc_mimalloc_normal_engine.codegen"
        archive_member = extract_single_rlib_codegen_member(ar, rlib, codegen_member_path)
        file_output = command_record((file_tool, str(codegen_member_path)), cwd=ROOT)
        require_success(file_output, "x86-64 engine rlib codegen member inspection")
        normalized_file = str(file_output["stdout"]).replace(
            str(codegen_member_path), "<normal-engine-codegen-member>"
        ).strip()
        codegen_member_format = x86_64_normal_engine_codegen_member_format(normalized_file)
        return {
            "artifact": {
                "archive_member": archive_member,
                "codegen_member_format": codegen_member_format,
                "file": normalized_file,
                "codegen_member_sha256": sha256_file(codegen_member_path),
                "rlib_sha256": sha256_file(rlib),
            },
            "cargo_command": command,
            "crate_root": {
                "no_std": True,
                "path": relative(crate_root),
                "sha256": sha256_file(crate_root),
            },
            "dependency_resolution": dict(X86_64_LOCKFILE_RESOLUTION),
            "features": [],
            "profile": "release",
            "scope": (
                "unfeatured normal crabc-mimalloc fat-LTO rlib only; its LLVM bitcode "
                "codegen member is not a final linked ELF, staticlib, cdylib, public allocator "
                "ABI, libc integration, or backend-promotion claim"
            ),
            "target": X86_64_RUST_TARGET,
            "target_directory": "fresh temporary CARGO_TARGET_DIR",
        }


def fundamental_trace_architecture_for_rust_target(rust_target: str | None) -> str:
    """Map an admitted direct-engine target to its fixed trace contract."""

    if rust_target is None or rust_target == PRODUCTION_RUST_TARGET:
        return "aarch64"
    if rust_target == X86_64_RUST_TARGET:
        return "x86_64"
    raise HarnessError(
        "direct Rust fundamental trace has no schema for target: "
        f"{rust_target}"
    )


def generic_layout_without_m1_static_reader_fields(
    layout: Mapping[str, int],
) -> dict[str, int]:
    """Keep the ordinary C/Rust layout comparison outside the new reader.

    The legacy eight const-image memid fields remain ordinary layout evidence;
    the newly audited relational fields are compared only against the separate
    pre-process-initialization C reader.
    """

    return {
        key: value
        for key, value in layout.items()
        if key not in M1_BOOTSTRAP_STATIC_IMAGE_READER_ONLY_LAYOUT_KEY_SET
    }


def rust_layout_probe(
    c_release_layout: Mapping[str, int],
    c_release_small_trace: Mapping[str, int],
    c_release_fundamental_trace: Mapping[str, int],
    *,
    rust_target: str | None = None,
) -> dict[str, Any]:
    """Compare the direct Rust engine against one native C release profile.

    The historical AArch64 invocation deliberately relies on the native image's
    default target.  A selected explicit target is only for the separately
    native x86-64 parity profile; it keeps that evidence from inheriting an
    AArch64 test artifact or report by accident.
    """

    architecture = fundamental_trace_architecture_for_rust_target(rust_target)
    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--lib",
        "--locked",
    ]
    if rust_target is not None:
        if rust_target == X86_64_RUST_TARGET:
            # The x86 evidence lane must not inherit a feature-selected
            # adapter/test artifact from the shared target volume. Its test
            # harness remains behavioral evidence, while the separate normal
            # rlib audit owns the no_std artifact claim below. The common
            # command above already locks the workspace resolution.
            command.append("--no-default-features")
        command.extend(("--target", rust_target))
    command.extend((
        "--",
        "--nocapture",
    ))
    if rust_target == X86_64_RUST_TARGET:
        with temporary_directory(prefix="crabc-mimalloc-direct-x86_64-") as temporary:
            environment = os.environ.copy()
            environment["CARGO_TARGET_DIR"] = str(Path(temporary) / "target")
            environment["CARGO_INCREMENTAL"] = "0"
            record = command_record(command, cwd=ROOT, env=environment)
    else:
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(RUST_LAYOUT_CARGO_TARGET)
        record = command_record(command, cwd=ROOT, env=environment)
    require_success(record, "Rust allocator layout probe")
    output = str(record["stdout"]) + "\n" + str(record["stderr"])
    rust_layout = parse_rust_layout(output)
    generic_rust_layout = generic_layout_without_m1_static_reader_fields(rust_layout)
    rust_small_trace = parse_small_trace(output)
    rust_fundamental_trace = parse_fundamental_trace(output)
    result = {
        "command": command,
        "comparison": compare_rust_layout(c_release_layout, generic_rust_layout),
        "layout": rust_layout,
        "passed_test_count": parse_rust_test_count(output),
        "single_thread_small_trace": {
            "comparison": compare_small_trace(c_release_small_trace, rust_small_trace),
            "record": rust_small_trace,
        },
        "single_thread_fundamental_trace": {
            "comparison": compare_fundamental_trace(
                c_release_fundamental_trace,
                rust_fundamental_trace,
                architecture=architecture,
            ),
            "record": rust_fundamental_trace,
        },
    }
    if rust_target is not None:
        result["target"] = rust_target
    if rust_target == X86_64_RUST_TARGET:
        result["dependency_resolution"] = dict(X86_64_LOCKFILE_RESOLUTION)
        result["target_directory"] = "fresh temporary CARGO_TARGET_DIR"
    return result


def loom_remote_free_model() -> dict[str, Any]:
    """Run the bounded scheduler over the production remote-head CAS loops.

    This test-only model uses Loom's `std` scheduler and never accesses an
    allocator compiler-TLS root. Its atomic-ordering evidence must not inherit
    the production AArch64 initial-exec TLS model: on the pinned nightly that
    combination produces an invalid test link, while `compiler_tls_codegen`
    separately proves the production requirement.
    """

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--lib",
        "--features",
        "loom",
        "--locked",
        "remote_free::loom_tests",
        "--",
        "--test-threads=1",
    ]
    environment = os.environ.copy()
    environment["CARGO_ENCODED_RUSTFLAGS"] = ""
    environment["CARGO_TARGET_DIR"] = str(LOOM_CARGO_TARGET)
    record = command_record(command, cwd=ROOT, env=environment)
    require_success(record, "Rust allocator remote-free Loom model")
    output = str(record["stdout"]) + "\n" + str(record["stderr"])
    return {
        "command": command,
        "cargo_encoded_rustflags": [],
        "passed_test_count": parse_rust_test_count(output),
        "status": "passed",
    }


def compiler_tls_codegen(*, architecture: str = "aarch64") -> dict[str, Any]:
    """Prove the selected native profile's private compiler-TLS model."""

    if architecture == "aarch64":
        runner = TLS_CODEGEN_RUNNER
        report_path = TLS_CODEGEN_REPORT
    elif architecture == "x86_64":
        runner = X86_64_TLS_CODEGEN_RUNNER
        report_path = X86_64_TLS_CODEGEN_REPORT
    else:
        raise HarnessError(f"unsupported allocator TLS architecture: {architecture}")

    command = [sys.executable, str(runner)]
    record = command_record(command, cwd=ROOT)
    require_success(record, "Rust allocator compiler-TLS codegen")
    report = read_json(report_path)
    if report.get("status") != "pass":
        raise HarnessError("allocator compiler-TLS report did not record a pass")
    result = {
        "command": command,
        "report": report,
        "status": "passed",
    }
    if architecture != "aarch64":
        result["architecture"] = architecture
    return result


def integration_provenance() -> dict[str, str]:
    return {
        "crate": "libmimalloc-sys",
        "crate_version": "0.1.49",
        "bundled_mimalloc_version": "3.3.2",
        "role": "current crabc C integration only; never an allocator oracle",
    }


def build_test_adapter(
    readelf: str,
    nm: str,
    contract: Mapping[str, Any],
    *,
    rust_target: str = PRODUCTION_RUST_TARGET,
    architecture: str = "aarch64",
    artifact_root: Path | None = None,
    expected_symbols: Sequence[str] | None = None,
) -> tuple[Path, list[str], dict[str, Any]]:
    """Build and audit the test-only prefixed Rust staticlib and optional cdylib."""

    if artifact_root is None:
        artifact_root = ARTIFACT_ROOT / "test-adapter"
    cargo_target = artifact_root / "cargo-target"
    artifact_root.mkdir(parents=True, exist_ok=True)
    clean_command = [
        "cargo",
        "clean",
        "--locked",
        "--package",
        "crabc-mimalloc-test-adapter",
        "--target",
        rust_target,
        "--release",
        "--target-dir",
        str(cargo_target),
    ]
    clean_record = command_record(clean_command, cwd=ROOT)
    require_success(clean_record, "Rust test adapter clean build boundary")

    test_command = [
        "cargo",
        "test",
        "--locked",
        "--package",
        "crabc-mimalloc-test-adapter",
        "--features",
        "test-adapter",
        "--target",
        rust_target,
        "--release",
        "--target-dir",
        str(cargo_target),
        "--lib",
        "--",
        "--test-threads=1",
    ]
    test_record = command_record(test_command, cwd=ROOT)
    require_success(test_record, "Rust test adapter unit suite")
    test_output = str(test_record["stdout"]) + "\n" + str(test_record["stderr"])

    rustc_command = [
        "cargo",
        "rustc",
        "--locked",
        "--package",
        "crabc-mimalloc-test-adapter",
        "--features",
        "test-adapter",
        "--target",
        rust_target,
        "--release",
        "--target-dir",
        str(cargo_target),
        "--",
        "--print=native-static-libs",
    ]
    rustc_record = command_record(rustc_command, cwd=ROOT)
    require_success(rustc_record, "Rust test adapter staticlib/cdylib build")
    native_libraries = parse_native_static_libraries(
        str(rustc_record["stdout"]) + "\n" + str(rustc_record["stderr"])
    )
    compile_requirements = contract.get("compile_requirements")
    if not isinstance(compile_requirements, dict):
        raise HarnessError("Rust test adapter lacks compile requirements")
    native_search_paths = native_static_library_search_paths(
        compile_requirements, rust_target=rust_target
    )
    if native_libraries != compile_requirements["native_static_libs"]:
        raise HarnessError("Rust test adapter native static library order differs from the manifest")

    release_root = cargo_target / rust_target / "release"
    static_filename = compile_requirements.get(
        "rust_staticlib_filename", "libcrabc_mimalloc_test_adapter.a"
    )
    cdylib_supported = compile_requirements.get("rust_cdylib_supported", True)
    if not isinstance(cdylib_supported, bool):
        raise HarnessError("Rust test adapter cdylib-support contract is invalid")
    if static_filename != "libcrabc_mimalloc_test_adapter.a":
        raise HarnessError("Rust test adapter staticlib filename differs from the manifest")
    if not cdylib_supported and any(
        key in compile_requirements
        for key in (
            "expected_cdylib_elf",
            "expected_dynamic_dependencies",
            "rust_cdylib_filename",
        )
    ):
        raise HarnessError("static-only Rust test adapter declares a cdylib contract")
    static_library = release_root / static_filename
    if expected_symbols is None:
        expected_symbols = contract.get("expected_adapter_symbols")
    if (
        not isinstance(expected_symbols, Sequence)
        or isinstance(expected_symbols, (str, bytes))
        or not expected_symbols
        or not all(isinstance(symbol, str) and symbol for symbol in expected_symbols)
    ):
        raise HarnessError("Rust test adapter expected symbols are absent or invalid")
    archive_symbols = validate_adapter_dynamic_symbols(
        archive_defined_symbols(nm, static_library), expected_symbols
    )

    report = {
        "archive": artifact_record(static_library),
        "archive_symbols": archive_symbols,
        "cdylib_supported": cdylib_supported,
        "clean_command": clean_command,
        "native_library_search_paths": native_search_paths,
        "native_static_libraries": native_libraries,
        "rustc_command": rustc_command,
        "unit_test_command": test_command,
        "unit_test_count": parse_rust_test_count(test_output),
    }
    if cdylib_supported:
        shared_filename = compile_requirements.get(
            "rust_cdylib_filename", "libcrabc_mimalloc_test_adapter.so"
        )
        if shared_filename != "libcrabc_mimalloc_test_adapter.so":
            raise HarnessError("Rust test adapter cdylib filename differs from the manifest")
        shared_library = release_root / shared_filename
        shared_symbols = validate_adapter_dynamic_symbols(
            defined_dynamic_symbols(readelf, shared_library), expected_symbols
        )
        needed = dynamic_dependencies(readelf, shared_library)
        expected_dynamic_dependencies = compile_requirements.get("expected_dynamic_dependencies")
        if not isinstance(expected_dynamic_dependencies, list) or not all(
            isinstance(dependency, str) and dependency for dependency in expected_dynamic_dependencies
        ):
            raise HarnessError("Rust test adapter cdylib dependency contract is invalid")
        if needed != expected_dynamic_dependencies:
            raise HarnessError("Rust test adapter dynamic dependency set differs from the manifest")

        expected_cdylib_elf = compile_requirements.get("expected_cdylib_elf")
        if expected_cdylib_elf is not None:
            if not isinstance(expected_cdylib_elf, dict):
                raise HarnessError("Rust test adapter cdylib ELF contract is invalid")
            header = command_record((readelf, "-h", str(shared_library)), cwd=ROOT)
            require_success(header, "Rust test adapter cdylib ELF header")
            cdylib_elf = parse_elf_identity(str(header["stdout"]), architecture)
            if cdylib_elf != expected_cdylib_elf:
                raise HarnessError("Rust test adapter cdylib ELF identity differs from the manifest")
            report["cdylib_elf"] = cdylib_elf
        report["dynamic_dependencies"] = needed
        report["shared_library"] = artifact_record(shared_library)
        report["shared_symbols"] = shared_symbols
    return static_library, native_libraries, report


def runtime_ticket_zero_adapter_artifact_paths() -> dict[str, Path]:
    """Name the only build outputs accepted by the durable soak producer."""

    artifact_root = ARTIFACT_ROOT / "runtime-ticket-zero-adapter"
    release_root = artifact_root / "cargo-target" / PRODUCTION_RUST_TARGET / "release"
    return {
        "archive": release_root / "libcrabc_mimalloc_runtime_ticket_zero_adapter.a",
        "fixture": artifact_root / "runtime-ticket-zero-fixture",
        "shared_library": release_root
        / "libcrabc_mimalloc_runtime_ticket_zero_adapter.so",
    }


def build_runtime_ticket_zero_adapter(
    readelf: str,
    nm: str,
    contract: Mapping[str, Any],
) -> tuple[Path, list[str], dict[str, Any]]:
    """Build and audit the separate no_std runtime page-owner test ABI."""

    artifact_paths = runtime_ticket_zero_adapter_artifact_paths()
    artifact_root = artifact_paths["fixture"].parent
    cargo_target = artifact_root / "cargo-target"
    artifact_root.mkdir(parents=True, exist_ok=True)
    package = str(contract["adapter_package"])
    clean_command = [
        "cargo",
        "clean",
        "--locked",
        "--package",
        package,
        "--target",
        PRODUCTION_RUST_TARGET,
        "--release",
        "--target-dir",
        str(cargo_target),
    ]
    clean_record = command_record(clean_command, cwd=ROOT)
    require_success(clean_record, "runtime ticket-zero adapter clean build boundary")
    rustc_command = [
        "cargo",
        "rustc",
        "--locked",
        "--package",
        package,
        "--target",
        PRODUCTION_RUST_TARGET,
        "--release",
        "--target-dir",
        str(cargo_target),
        "--",
        "--print=native-static-libs",
    ]
    rustc_record = command_record(rustc_command, cwd=ROOT)
    require_success(rustc_record, "runtime ticket-zero adapter staticlib/cdylib build")
    native_libraries = parse_optional_native_static_libraries(
        str(rustc_record["stdout"]) + "\n" + str(rustc_record["stderr"])
    )
    compile_requirements = contract["compile_requirements"]
    assert isinstance(compile_requirements, dict)
    expected_native_libraries = compile_requirements["native_static_libs"]
    assert isinstance(expected_native_libraries, list)
    if native_libraries != expected_native_libraries:
        raise HarnessError(
            "runtime ticket-zero adapter native static library order differs from the contract"
        )

    static_library = artifact_paths["archive"]
    shared_library = artifact_paths["shared_library"]
    expected_symbols = contract["expected_adapter_symbols"]
    assert isinstance(expected_symbols, list)
    shared_symbols = validate_runtime_ticket_zero_adapter_symbols(
        defined_dynamic_symbols(readelf, shared_library), expected_symbols
    )
    archive_symbols = validate_runtime_ticket_zero_adapter_symbols(
        archive_defined_symbols(nm, static_library), expected_symbols
    )
    needed = dynamic_dependencies(readelf, shared_library)
    expected_dependencies = compile_requirements["expected_dynamic_dependencies"]
    assert isinstance(expected_dependencies, list)
    if needed != expected_dependencies:
        raise HarnessError(
            "runtime ticket-zero adapter dynamic dependency set differs from the contract"
        )
    return static_library, native_libraries, {
        "archive": artifact_record(static_library),
        "archive_symbols": archive_symbols,
        "clean_command": clean_command,
        "dynamic_dependencies": needed,
        "native_static_libraries": native_libraries,
        "rustc_command": rustc_command,
        "shared_library": artifact_record(shared_library),
        "shared_symbols": shared_symbols,
    }


def run_test_adapter_fixtures(
    compiler: str,
    source: Path,
    static_library: Path,
    native_libraries: Sequence[str],
    source_contract: Mapping[str, Any],
    *,
    artifact_root: Path | None = None,
    target_compile_requirements: Mapping[str, Any] | None = None,
    rust_target: str = PRODUCTION_RUST_TARGET,
    expected_fixture_stdout: str = "allocator ok\n",
    readelf: str | None = None,
    native_executable_expectations: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build, audit, and run the fixture plus selected upstream API checks.

    The historical AArch64 adapter caller omits the optional executable
    expectations.  The target-local x86-64 adapter supplies them so a fixture
    result cannot stand as native evidence unless its ELF identity, PT_INTERP,
    and DT_NEEDED records all match the checked-in target contract.
    """

    if artifact_root is None:
        artifact_root = ARTIFACT_ROOT / "test-adapter"
    if target_compile_requirements is None:
        target_compile_requirements = source_contract.get("compile_requirements")
    compile_requirements = target_compile_requirements
    assert isinstance(compile_requirements, dict)
    native_search_paths = native_static_library_search_paths(
        compile_requirements, rust_target=rust_target
    )
    native_search_flags = [f"-L{path}" for path in native_search_paths]
    fixture_binary = artifact_root / "allocator-fixture-rust"
    fixture_command = [
        compiler,
        "-std=c11",
        "-O2",
        "-fPIE",
        "-pie",
        "-ftls-model=initial-exec",
        "-pthread",
        "-I",
        str(TEST_ADAPTER_ROOT),
        str(TEST_ADAPTER_FIXTURE),
        str(static_library),
        *native_search_flags,
        *native_libraries,
        "-o",
        str(fixture_binary),
    ]
    fixture_build = command_record(fixture_command, cwd=ROOT)
    require_success(fixture_build, "existing allocator fixture against Rust adapter")
    fixture_executable_evidence: dict[str, Any] | None = None
    adapted_executable_evidence: dict[str, Any] | None = None
    if native_executable_expectations is not None:
        if readelf is None:
            raise HarnessError("native fixture executable audit lacks readelf")
        expected_fields = {
            "architecture",
            "dynamic_dependencies",
            "elf",
            "interpreter",
        }
        if (
            not isinstance(native_executable_expectations, Mapping)
            or set(native_executable_expectations) != expected_fields
        ):
            raise HarnessError("native fixture executable audit contract fields changed")
        architecture = native_executable_expectations["architecture"]
        expected_elf = native_executable_expectations["elf"]
        expected_interpreter = native_executable_expectations["interpreter"]
        expected_dependencies = native_executable_expectations["dynamic_dependencies"]
        if not isinstance(architecture, str):
            raise HarnessError("native fixture executable audit architecture is invalid")
        fixture_executable_evidence = audit_native_executable(
            readelf,
            fixture_binary,
            architecture=architecture,
            expected_elf=expected_elf,
            expected_interpreter=expected_interpreter,
            expected_dynamic_dependencies=expected_dependencies,
        )
    fixture_run = command_record((str(fixture_binary),), cwd=ROOT)
    if fixture_run["status"] != 0 or fixture_run["stdout"] != expected_fixture_stdout:
        raise HarnessError(
            "existing allocator fixture failed against Rust adapter: "
            f"status={fixture_run['status']} stdout={fixture_run['stdout']!r} "
            f"stderr={fixture_run['stderr']!r}"
        )

    adapted_binary = artifact_root / "upstream-test-api-selected-rust"
    adapted_source = source / str(source_contract["adapted_source"]["path"])
    adapted_command = [
        compiler,
        "-std=c11",
        "-O2",
        "-fPIE",
        "-pie",
        "-ftls-model=initial-exec",
        "-pthread",
        "-I",
        str(source / "include"),
        "-I",
        str(source / "test"),
        "-I",
        str(TEST_ADAPTER_ROOT),
        str(adapted_source),
        str(static_library),
        *native_search_flags,
        *native_libraries,
        "-o",
        str(adapted_binary),
    ]
    adapted_build = command_record(adapted_command, cwd=source)
    require_success(adapted_build, "adapted upstream API fixture against Rust adapter")
    if native_executable_expectations is not None:
        assert readelf is not None
        adapted_executable_evidence = audit_native_executable(
            readelf,
            adapted_binary,
            architecture=architecture,
            expected_elf=expected_elf,
            expected_interpreter=expected_interpreter,
            expected_dynamic_dependencies=expected_dependencies,
        )
    adapted_run = command_record((str(adapted_binary),), cwd=source)
    require_success(adapted_run, "adapted upstream API fixture")
    summary = parse_upstream_api_test_summary(
        str(adapted_run["stdout"]) + "\n" + str(adapted_run["stderr"])
    )
    selected = source_contract["selected_tests"]
    assert isinstance(selected, list)
    if summary["succeeded"] != len(selected):
        raise HarnessError(
            "adapted upstream API summary count differs from the reviewed selection"
        )

    result = {
        "adapted_upstream_api": {
            "artifact": artifact_record(adapted_binary),
            "build_command": adapted_command,
            "run_command": [str(adapted_binary)],
            "summary": summary,
        },
        "existing_allocator_fixture": {
            "artifact": artifact_record(fixture_binary),
            "build_command": fixture_command,
            "run_command": [str(fixture_binary)],
            "stdout": str(fixture_run["stdout"]),
        },
    }
    if fixture_executable_evidence is not None:
        assert adapted_executable_evidence is not None
        result["existing_allocator_fixture"]["native_executable"] = fixture_executable_evidence
        result["adapted_upstream_api"]["native_executable"] = adapted_executable_evidence
    return result


def run_adapted_stress_fixture(
    compiler: str,
    source: Path,
    static_library: Path,
    native_libraries: Sequence[str],
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    """Run the one reviewed source-derived upstream stress route.

    This is intentionally not folded into the M4 fixture result: its fixed
    creating-thread scheduler is preliminary M5 evidence and must stay visibly
    distinct from a claimed multi-thread upstream stress acceptance.
    """

    artifact_root = ARTIFACT_ROOT / "test-adapter"
    compile_requirements = contract["compile_requirements"]
    execution = contract["execution"]
    adapted_source_contract = contract["adapted_source"]
    assert isinstance(compile_requirements, dict)
    assert isinstance(execution, dict)
    assert isinstance(adapted_source_contract, dict)
    compile_flags = compile_requirements["compile_flags"]
    native_search_paths = compile_requirements["native_library_search_paths"]
    assert isinstance(compile_flags, list)
    assert isinstance(native_search_paths, list)
    native_search_flags = [f"-L{path}" for path in native_search_paths]
    fixture_binary = artifact_root / "upstream-test-stress-creating-thread-rust"
    adapted_source = source / str(adapted_source_contract["path"])
    fixture_command = [
        compiler,
        "-std=c11",
        *compile_flags,
        "-I",
        str(source / "include"),
        "-I",
        str(source / "test"),
        "-I",
        str(TEST_ADAPTER_ROOT),
        str(adapted_source),
        str(static_library),
        *native_search_flags,
        *native_libraries,
        "-o",
        str(fixture_binary),
    ]
    fixture_build = command_record(fixture_command, cwd=source)
    require_success(fixture_build, "adapted upstream stress fixture against Rust adapter")
    arguments = execution["arguments"]
    watchdog_seconds = execution["watchdog_seconds"]
    assert isinstance(arguments, list)
    assert isinstance(watchdog_seconds, int)
    fixture_run_command = [str(fixture_binary), *arguments]
    fixture_run = command_record(
        fixture_run_command,
        cwd=source,
        timeout_seconds=watchdog_seconds,
    )
    if (
        fixture_run["status"] != 0
        or fixture_run["stdout"] != execution["expected_stdout"]
        or fixture_run["stderr"] != execution["expected_stderr"]
    ):
        raise HarnessError(
            "adapted upstream stress fixture failed: "
            f"status={fixture_run['status']} stdout={fixture_run['stdout']!r} "
            f"stderr={fixture_run['stderr']!r}"
        )
    excluded_modes = contract["excluded_upstream_modes"]
    assert isinstance(excluded_modes, list)
    rejected_compile_modes: list[str] = []
    for mode in excluded_modes:
        assert isinstance(mode, dict)
        macro = mode["macro"]
        assert isinstance(macro, str)
        rejection_command = [
            compiler,
            "-std=c11",
            *compile_flags,
            f"-D{macro}=1",
            "-fsyntax-only",
            "-I",
            str(source / "include"),
            "-I",
            str(source / "test"),
            "-I",
            str(TEST_ADAPTER_ROOT),
            str(adapted_source),
        ]
        rejection = command_record(rejection_command, cwd=source)
        if (
            rejection["status"] == 0
            or "the adapted stress fixture" not in str(rejection["stderr"])
        ):
            raise HarnessError(
                "adapted upstream stress mode was not rejected by its reviewed source guard: "
                f"{macro}; status={rejection['status']} stderr={rejection['stderr']!r}"
            )
        rejected_compile_modes.append(macro)
    return {
        "artifact": artifact_record(fixture_binary),
        "arguments": list(arguments),
        "build_command": fixture_command,
        "compile_defines": list(execution["compile_defines"]),
        "rejected_compile_modes": rejected_compile_modes,
        "run_command": fixture_run_command,
        "stderr": str(fixture_run["stderr"]),
        "stdout": str(fixture_run["stdout"]),
        "watchdog": {
            "seconds": watchdog_seconds,
            "status": "passed",
        },
    }


def run_native_shadow_stress_fixture(
    source: Path, contract: Mapping[str, Any]
) -> dict[str, Any]:
    """Build and execute the source workload through the selected debug libc.

    The owning shell lane must enter through ``run_owned_test_suite.py`` first.
    That launcher stages exactly the canonical interpreter and libc aliases;
    this function then narrows the fixture process to the selected debug
    ``libc.so`` with no inherited preload or library-search override.
    """

    compile_requirements = contract["compile_requirements"]
    execution = contract["execution"]
    adapted_source_contract = contract["adapted_source"]
    assert isinstance(compile_requirements, dict)
    assert isinstance(execution, dict)
    assert isinstance(adapted_source_contract, dict)

    raw_sysroot = os.environ.get("CRABC_TEST_SYSROOT")
    if not raw_sysroot:
        raise HarnessError(
            "native-shadow stress requires CRABC_TEST_SYSROOT from scripts/run_owned_test_suite.py"
        )
    sysroot = Path(raw_sysroot).expanduser().resolve()
    manifest = sysroot / "share/crabc/manifest.json"
    compiler = sysroot / "bin/crabc-cc"
    if not manifest.is_file() or not compiler.is_file():
        raise HarnessError("native-shadow stress requires a complete owned crabc sysroot")
    runtime_directory = ROOT / str(compile_requirements["runtime_directory"])
    debug_libc = runtime_directory / "libc.so"
    debug_loader = runtime_directory / "libldso.so"
    if not debug_libc.is_file() or not debug_loader.is_file():
        raise HarnessError(
            "native-shadow stress requires target/debug/libc.so and target/debug/libldso.so"
        )
    canonical_loader = Path(str(compile_requirements["canonical_loader"]))
    if not canonical_loader.is_file() or canonical_loader.is_symlink():
        raise HarnessError(
            "native-shadow stress must run under scripts/run_owned_test_suite.py's canonical-loader staging"
        )

    artifact_root = ARTIFACT_ROOT / "native-shadow-stress"
    artifact_root.mkdir(parents=True, exist_ok=True)
    fixture_binary = artifact_root / "upstream-test-stress-native-shadow-pthreads"
    adapted_source = source / str(adapted_source_contract["path"])
    compile_flags = compile_requirements["compile_flags"]
    link_flags = compile_requirements["link_flags"]
    link_libraries = compile_requirements["link_libraries"]
    compile_defines = execution["compile_defines"]
    assert isinstance(compile_flags, list)
    assert isinstance(link_flags, list)
    assert isinstance(link_libraries, list)
    assert isinstance(compile_defines, list)
    fixture_command = [
        str(compiler),
        "-std=c11",
        *compile_flags,
        *(f"-D{define}" for define in compile_defines),
        "-L",
        str(runtime_directory),
        str(adapted_source),
        *link_flags,
        *link_libraries,
        "-o",
        str(fixture_binary),
    ]
    fixture_build = command_record(fixture_command, cwd=source)
    require_success(fixture_build, "native-shadow upstream pthread stress fixture")

    readelf = require_tool("readelf")
    dependencies = dynamic_dependencies(readelf, fixture_binary)
    expected_dependencies = compile_requirements["expected_dynamic_dependencies"]
    assert isinstance(expected_dependencies, list)
    if dependencies != expected_dependencies:
        raise HarnessError(
            "native-shadow stress fixture dynamic dependency set differs from the contract"
        )

    excluded_modes = contract["excluded_upstream_modes"]
    assert isinstance(excluded_modes, list)
    rejected_compile_modes: list[str] = []
    for mode in excluded_modes:
        assert isinstance(mode, dict)
        macro = mode["macro"]
        assert isinstance(macro, str)
        rejection_object = artifact_root / f"rejected-{macro.lower()}.o"
        rejection_command = [
            str(compiler),
            "-std=c11",
            *compile_flags,
            *(f"-D{define}" for define in compile_defines),
            f"-D{macro}=1",
            "-c",
            str(adapted_source),
            "-o",
            str(rejection_object),
        ]
        rejection = command_record(rejection_command, cwd=source)
        if (
            rejection["status"] == 0
            or "the native-shadow stress fixture" not in str(rejection["stderr"])
        ):
            raise HarnessError(
                "native-shadow stress mode was not rejected by its reviewed source guard: "
                f"{macro}; status={rejection['status']} stderr={rejection['stderr']!r}"
            )
        rejected_compile_modes.append(macro)

    arguments = execution["arguments"]
    watchdog_seconds = execution["watchdog_seconds"]
    process_epochs = execution["process_epochs"]
    assert isinstance(arguments, list)
    assert isinstance(watchdog_seconds, int)
    assert isinstance(process_epochs, int)
    fixture_run_command = [str(fixture_binary), *arguments]
    fixture_environment = dict(os.environ)
    for key in ("LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"):
        fixture_environment.pop(key, None)
    fixture_environment["LD_LIBRARY_PATH"] = str(runtime_directory)
    for epoch in range(process_epochs):
        fixture_run = command_record(
            fixture_run_command,
            cwd=source,
            env=fixture_environment,
            timeout_seconds=watchdog_seconds,
        )
        if (
            fixture_run["status"] != 0
            or fixture_run["stdout"] != execution["expected_stdout"]
            or fixture_run["stderr"] != execution["expected_stderr"]
        ):
            raise HarnessError(
                "native-shadow stress fixture failed at fresh process epoch "
                f"{epoch + 1}/{process_epochs}: status={fixture_run['status']} "
                f"stdout={fixture_run['stdout']!r} stderr={fixture_run['stderr']!r}"
            )

    return {
        "artifact": artifact_record(fixture_binary),
        "arguments": list(arguments),
        "build_command": fixture_command,
        "compile_defines": list(compile_defines),
        "dynamic_dependencies": dependencies,
        "rejected_compile_modes": rejected_compile_modes,
        "run_command": fixture_run_command,
        "selected_runtime_library": artifact_record(debug_libc),
        "stderr": execution["expected_stderr"],
        "stdout": execution["expected_stdout"],
        "successful_process_epochs": process_epochs,
        "watchdog": {
            "seconds": watchdog_seconds,
            "status": "passed",
        },
    }


def run_native_shadow_stress(*, offline: bool) -> dict[str, Any]:
    """Run the isolated four-pthread source stress evidence lane."""

    require_native_aarch64()
    pin = load_pin()
    archive = fetch_archive(pin, offline)
    contract = read_json(NATIVE_SHADOW_STRESS_CONTRACT)
    summary = validate_native_shadow_stress_contract(contract, pin)
    with temporary_directory(prefix="crabc-native-shadow-stress-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        patch = apply_and_verify_native_shadow_stress_patch(
            source,
            contract,
            require_tool("patch"),
        )
        fixture = run_native_shadow_stress_fixture(source, contract)
    report = {
        "contract": {
            "format": contract["format"],
            "path": relative(NATIVE_SHADOW_STRESS_CONTRACT),
            "schema": contract["schema"],
            "sha256": file_digest(NATIVE_SHADOW_STRESS_CONTRACT),
            "upstream": dict(contract["upstream"]),
        },
        "fixture": fixture,
        "format": 1,
        "patch": patch,
        "summary": summary,
        "target": {"architecture": platform.machine(), "system": platform.system()},
    }
    write_json(NATIVE_SHADOW_STRESS_REPORT, report)
    return report


def runtime_ticket_zero_stress_schedule(
    *,
    worker_cycles: int,
    stress_seed: int = RUNTIME_TICKET_ZERO_DEFAULT_STRESS_SEED,
) -> dict[str, int | str]:
    """Validate and describe one bounded, reproducible C lifecycle schedule."""

    if (
        not isinstance(worker_cycles, int)
        or isinstance(worker_cycles, bool)
        or not 1 <= worker_cycles <= RUNTIME_TICKET_ZERO_MAX_WORKER_CYCLES
    ):
        raise HarnessError(
            "runtime ticket-zero worker cycles must be an integer in "
            f"1..{RUNTIME_TICKET_ZERO_MAX_WORKER_CYCLES}"
        )
    if (
        not isinstance(stress_seed, int)
        or isinstance(stress_seed, bool)
        or not 0 <= stress_seed <= RUNTIME_TICKET_ZERO_MAX_STRESS_SEED
    ):
        raise HarnessError(
            "runtime ticket-zero stress seed must be an unsigned 64-bit integer"
        )
    return {
        "seed": f"0x{stress_seed:016x}",
        "worker_route_invocation_count": (
            worker_cycles * RUNTIME_TICKET_ZERO_WORKER_ROUTES_PER_CYCLE
        ),
        "worker_routes_per_cycle": RUNTIME_TICKET_ZERO_WORKER_ROUTES_PER_CYCLE,
    }


def runtime_ticket_zero_fixture_command(
    fixture_binary: Path,
    *,
    worker_cycles: int,
    stress_seed: int = RUNTIME_TICKET_ZERO_DEFAULT_STRESS_SEED,
) -> list[str]:
    """Build one reproducible invocation of the private C lifecycle witness."""

    schedule = runtime_ticket_zero_stress_schedule(
        worker_cycles=worker_cycles,
        stress_seed=stress_seed,
    )
    return [
        str(fixture_binary),
        "--worker-cycles",
        str(worker_cycles),
        "--stress-seed",
        str(schedule["seed"]),
    ]


def parse_runtime_ticket_zero_lifecycle_audit(stdout: str) -> dict[str, int]:
    """Parse the fixture's one scalar-only lifecycle stability record."""

    lines = stdout.splitlines()
    if len(lines) != 2 or lines[-1] != RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_SUCCESS_LINE:
        raise HarnessError("runtime ticket-zero fixture emitted an invalid lifecycle audit record")
    audit_line = lines[0]
    if not audit_line.startswith(RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_PREFIX):
        raise HarnessError("runtime ticket-zero fixture omitted its lifecycle audit record")
    fields: dict[str, int] = {}
    for token in audit_line.removeprefix(RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_PREFIX).split():
        name, separator, value = token.partition("=")
        if (
            separator != "="
            or not name
            or name in fields
            or not re.fullmatch(r"[0-9]+", value)
        ):
            raise HarnessError("runtime ticket-zero fixture has a malformed lifecycle audit field")
        fields[name] = int(value)
    if tuple(fields) != RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_FIELDS:
        raise HarnessError("runtime ticket-zero fixture lifecycle audit fields differ from the contract")
    return fields


def run_runtime_ticket_zero_adapter_fixture(
    compiler: str,
    static_library: Path,
    native_libraries: Sequence[str],
    *,
    worker_cycles: int = RUNTIME_TICKET_ZERO_DEFAULT_WORKER_CYCLES,
    watchdog_seconds: int = RUNTIME_TICKET_ZERO_CHURN_WATCHDOG_SECONDS,
    stress_seed: int = RUNTIME_TICKET_ZERO_DEFAULT_STRESS_SEED,
) -> dict[str, Any]:
    """Run one fresh process through the bounded, seeded ticket-zero C witness."""

    fixture_binary = runtime_ticket_zero_adapter_artifact_paths()["fixture"]
    fixture_command = [
        compiler,
        "-std=c11",
        "-O2",
        "-fPIE",
        "-pie",
        "-ftls-model=initial-exec",
        "-pthread",
        "-I",
        str(RUNTIME_TICKET_ZERO_ADAPTER_ROOT),
        str(RUNTIME_TICKET_ZERO_ADAPTER_FIXTURE),
        str(static_library),
        *native_libraries,
        "-o",
        str(fixture_binary),
    ]
    stress_schedule = runtime_ticket_zero_stress_schedule(
        worker_cycles=worker_cycles,
        stress_seed=stress_seed,
    )
    fixture_run_command = runtime_ticket_zero_fixture_command(
        fixture_binary,
        worker_cycles=worker_cycles,
        stress_seed=stress_seed,
    )
    fixture_build = command_record(fixture_command, cwd=ROOT)
    require_success(fixture_build, "runtime ticket-zero C fixture build")
    if (
        not isinstance(watchdog_seconds, int)
        or isinstance(watchdog_seconds, bool)
        or watchdog_seconds <= 0
    ):
        raise HarnessError("runtime ticket-zero fixture watchdog must be a positive integer")
    fixture_run = command_record(
        fixture_run_command,
        cwd=ROOT,
        timeout_seconds=watchdog_seconds,
    )
    if fixture_run["status"] != 0:
        raise HarnessError(
            "runtime ticket-zero C fixture failed: "
            f"status={fixture_run['status']} stdout={fixture_run['stdout']!r} "
            f"stderr={fixture_run['stderr']!r}"
        )
    try:
        lifecycle_audit = parse_runtime_ticket_zero_lifecycle_audit(
            str(fixture_run["stdout"])
        )
    except HarnessError as error:
        raise HarnessError(
            "runtime ticket-zero C fixture failed: "
            f"status={fixture_run['status']} stdout={fixture_run['stdout']!r} "
            f"stderr={fixture_run['stderr']!r}; {error}"
        ) from error
    if lifecycle_audit["worker_cycles"] != worker_cycles:
        raise HarnessError("runtime ticket-zero lifecycle audit names the wrong worker cycle count")
    required_quiescent_values = {
        "process_active": 1,
        "page_owner_ready": 1,
        "page_map_registered_entries": 0,
        "arena_registry_entries": 1,
        "live_tlds": 1,
        "metadata_live_capabilities": 0,
        "shared_later_theaps": 0,
        "abandoned_regular_pages": 0,
        "os_abandoned_pages_empty": 1,
    }
    if any(lifecycle_audit[name] != value for name, value in required_quiescent_values.items()):
        raise HarnessError("runtime ticket-zero lifecycle audit is not quiescent")
    return {
        "artifact": artifact_record(fixture_binary),
        "build_command": fixture_command,
        "run_command": fixture_run_command,
        "stdout": str(fixture_run["stdout"]),
        "lifecycle_stability": {
            "audit_snapshot_count": worker_cycles + 1,
            "post_warm_cycle_count": worker_cycles - 1,
            "status": "passed",
            "warm_baseline": lifecycle_audit,
        },
        "watchdog": {
            "seconds": watchdog_seconds,
            "status": "passed",
        },
        "worker_cycles": worker_cycles,
        "stress_schedule": stress_schedule,
    }


def runtime_ticket_zero_soak_contract_record(
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a durable soak observation to the checked-in witness contract."""

    return {
        "format": contract["format"],
        "record": runtime_ticket_zero_soak_expected_artifact_record(
            RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT, "contract"
        ),
        "schema": contract["schema"],
        "soak_report": dict(contract["soak_report"]),
        "upstream": dict(contract["upstream"]),
    }


def runtime_ticket_zero_soak_fixture_evidence(
    milestone_report: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Extract only the completed 1,024-cycle private witness from its full run."""

    oracle = milestone_report.get("oracle")
    if not isinstance(oracle, Mapping):
        raise HarnessError("runtime ticket-zero soak milestone report lacks its pinned oracle")
    expected_oracle_fields = {
        "archive",
        "archive_root",
        "revision",
        "sha256",
        "source",
        "tag_object",
        "tag_verified",
        "version",
    }
    if set(oracle) != expected_oracle_fields:
        raise HarnessError("runtime ticket-zero soak oracle record changed")
    for field in ("archive_root", "revision", "sha256", "source", "tag_object", "version"):
        if oracle.get(field) != pin[field]:
            raise HarnessError("runtime ticket-zero soak oracle no longer matches its pin")
    archive = attest_runtime_ticket_zero_soak_artifact(
        oracle.get("archive"), "archive", expected_path=archive_path(pin)
    )
    if archive["sha256"] != pin["sha256"]:
        raise HarnessError("runtime ticket-zero soak archive differs from its pin")
    tag_verified = runtime_ticket_zero_soak_tag_attestation(
        pin, oracle.get("tag_verified")
    )

    c_oracle = milestone_report.get("c_oracle")
    if not isinstance(c_oracle, Mapping) or set(c_oracle) != {
        "build_strategy",
        "compiler",
        "profiles",
        "source_files",
    }:
        # The completed `run_milestone0` report has the complete C-oracle
        # profile inventory. Keep the stable report smaller by retaining only
        # its stable identity fields, but fail closed if that producer shape
        # is absent or stale.
        raise HarnessError("runtime ticket-zero soak C oracle record changed")
    if (
        not isinstance(c_oracle.get("build_strategy"), str)
        or not c_oracle["build_strategy"]
        or not isinstance(c_oracle.get("compiler"), str)
        or not c_oracle["compiler"]
        or not isinstance(c_oracle.get("source_files"), list)
        or not isinstance(c_oracle.get("profiles"), Mapping)
    ):
        raise HarnessError("runtime ticket-zero soak C oracle record is invalid")

    target = milestone_report.get("target")
    if target != {"architecture": "aarch64", "system": "Linux"}:
        raise HarnessError("runtime ticket-zero soak target is not native Linux/AArch64")

    adapter = milestone_report.get("runtime_ticket_zero_test_adapter")
    if not isinstance(adapter, Mapping) or set(adapter) != {"build", "fixture"}:
        raise HarnessError("runtime ticket-zero soak adapter record changed")
    build = adapter.get("build")
    fixture = adapter.get("fixture")
    if not isinstance(build, Mapping) or not isinstance(fixture, Mapping):
        raise HarnessError("runtime ticket-zero soak adapter record is invalid")
    artifact_paths = runtime_ticket_zero_adapter_artifact_paths()
    adapter_archive = attest_runtime_ticket_zero_soak_artifact(
        build.get("archive"), "adapter archive", expected_path=artifact_paths["archive"]
    )
    adapter_shared_library = attest_runtime_ticket_zero_soak_artifact(
        build.get("shared_library"),
        "adapter shared library",
        expected_path=artifact_paths["shared_library"],
    )

    fixture_artifact = attest_runtime_ticket_zero_soak_artifact(
        fixture.get("artifact"), "fixture", expected_path=artifact_paths["fixture"]
    )
    fixture_build_command = fixture.get("build_command")
    fixture_run_command = fixture.get("run_command")
    stdout = fixture.get("stdout")
    if (
        not isinstance(fixture_build_command, list)
        or not fixture_build_command
        or not all(isinstance(argument, str) and argument for argument in fixture_build_command)
        or not isinstance(fixture_run_command, list)
        or not fixture_run_command
        or not all(isinstance(argument, str) and argument for argument in fixture_run_command)
        or not isinstance(stdout, str)
    ):
        raise HarnessError("runtime ticket-zero soak fixture command record is invalid")
    fixture_path = artifact_paths["fixture"]
    fixture_executable = runtime_ticket_zero_soak_regular_path(
        Path(fixture_run_command[0]), "fixture executable"
    )
    if fixture_executable != fixture_path:
        raise HarnessError(
            "runtime ticket-zero soak fixture executable differs from its attested artifact"
        )
    output_positions = [
        index for index, argument in enumerate(fixture_build_command) if argument == "-o"
    ]
    if (
        len(output_positions) != 1
        or output_positions[0] + 1 >= len(fixture_build_command)
    ):
        raise HarnessError(
            "runtime ticket-zero soak fixture build output differs from its attested artifact"
        )
    fixture_build_output = runtime_ticket_zero_soak_regular_path(
        Path(fixture_build_command[output_positions[0] + 1]), "fixture build output"
    )
    if fixture_build_output != fixture_path:
        raise HarnessError(
            "runtime ticket-zero soak fixture build output differs from its attested artifact"
        )
    fixture_source = runtime_ticket_zero_soak_regular_path(
        RUNTIME_TICKET_ZERO_ADAPTER_FIXTURE, "fixture source"
    )
    if fixture_build_command.count(str(fixture_source)) != 1:
        raise HarnessError(
            "runtime ticket-zero soak fixture build input differs from its checked-in source"
        )
    if fixture_build_command.count(str(artifact_paths["archive"])) != 1:
        raise HarnessError(
            "runtime ticket-zero soak fixture build input differs from its attested adapter archive"
        )
    expected_run_command = runtime_ticket_zero_fixture_command(
        fixture_path,
        worker_cycles=RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
        stress_seed=RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
    )
    if fixture_run_command != expected_run_command:
        raise HarnessError("runtime ticket-zero soak fixture command differs from the contract")

    expected_schedule = runtime_ticket_zero_stress_schedule(
        worker_cycles=RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
        stress_seed=RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
    )
    schedule = fixture.get("stress_schedule")
    if (
        fixture.get("worker_cycles") != RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES
        or schedule != expected_schedule
        or fixture.get("watchdog")
        != {"seconds": RUNTIME_TICKET_ZERO_SOAK_WATCHDOG_SECONDS, "status": "passed"}
    ):
        raise HarnessError("runtime ticket-zero soak schedule differs from the contract")

    lifecycle = fixture.get("lifecycle_stability")
    if not isinstance(lifecycle, Mapping) or set(lifecycle) != {
        "audit_snapshot_count",
        "post_warm_cycle_count",
        "status",
        "warm_baseline",
    }:
        raise HarnessError("runtime ticket-zero soak lifecycle audit record changed")
    warm_baseline = lifecycle.get("warm_baseline")
    if not isinstance(warm_baseline, Mapping) or set(warm_baseline) != set(
        RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_FIELDS
    ):
        raise HarnessError("runtime ticket-zero soak lifecycle audit fields differ")
    if any(
        type(warm_baseline[name]) is not int or warm_baseline[name] < 0
        for name in RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_FIELDS
    ):
        raise HarnessError("runtime ticket-zero soak lifecycle audit values are invalid")
    expected_quiescent_values = {
        "process_active": 1,
        "page_owner_ready": 1,
        "page_map_registered_entries": 0,
        "arena_registry_entries": 1,
        "live_tlds": 1,
        "metadata_live_capabilities": 0,
        "shared_later_theaps": 0,
        "abandoned_regular_pages": 0,
        "os_abandoned_pages_empty": 1,
    }
    if (
        warm_baseline["worker_cycles"] != RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES
        or any(
            warm_baseline[name] != value
            for name, value in expected_quiescent_values.items()
        )
        or lifecycle.get("audit_snapshot_count")
        != RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES + 1
        or lifecycle.get("post_warm_cycle_count")
        != RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES - 1
        or lifecycle.get("status") != "passed"
    ):
        raise HarnessError("runtime ticket-zero soak lifecycle audit is not quiescent")
    if parse_runtime_ticket_zero_lifecycle_audit(stdout) != dict(warm_baseline):
        raise HarnessError("runtime ticket-zero soak fixture stdout differs from its audit")

    return {
        "build_artifacts": {
            "adapter_archive": adapter_archive,
            "adapter_shared_library": adapter_shared_library,
        },
        "fixture": {
            "artifact": fixture_artifact,
            "build_command": list(fixture_build_command),
            "run_command": list(fixture_run_command),
            "stdout": stdout,
        },
        "oracle": {
            "build_strategy": c_oracle["build_strategy"],
            "compiler": c_oracle["compiler"],
            "source_files": list(c_oracle["source_files"]),
        },
        "pin": {
            "archive": archive,
            "archive_root": oracle["archive_root"],
            "revision": oracle["revision"],
            "sha256": oracle["sha256"],
            "source": oracle["source"],
            "tag_object": oracle["tag_object"],
            "tag_verified": tag_verified,
            "version": oracle["version"],
        },
        "schedule": {
            "stress_seed": expected_schedule["seed"],
            "watchdog_seconds": RUNTIME_TICKET_ZERO_SOAK_WATCHDOG_SECONDS,
            "worker_cycles": RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
            "worker_route_invocation_count": expected_schedule[
                "worker_route_invocation_count"
            ],
            "worker_routes_per_cycle": expected_schedule["worker_routes_per_cycle"],
        },
        "audit": dict(lifecycle),
        "target": {
            "architecture": target["architecture"],
            "rust_target": PRODUCTION_RUST_TARGET,
            "system": target["system"],
        },
    }


def run_runtime_ticket_zero_soak(*, offline: bool, architecture: str) -> dict[str, Any]:
    """Run and atomically publish the one source-attested private 1,024-cycle soak."""

    if architecture != "aarch64":
        raise HarnessError("runtime ticket-zero soak is available only for Linux/AArch64")
    # The pin, witness contract, and checked-in fixture/header are all source
    # inputs. Capture cleanliness before any of them so their semantic fields
    # and recorded digests cannot describe a source state observed too late.
    source_before = runtime_ticket_zero_soak_source_state()
    pin = load_pin()
    contract = read_json(RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT)
    validate_runtime_ticket_zero_adapter_contract(
        contract, RUNTIME_TICKET_ZERO_ADAPTER_HEADER.read_text(encoding="utf-8")
    )
    milestone_report = run_milestone0(
        offline=offline,
        generate_contracts=False,
        check_only=False,
        include_test_adapter=True,
        include_adapted_stress=False,
        include_native_owner_exit_lifecycle=False,
        runtime_ticket_zero_worker_cycles=RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
        runtime_ticket_zero_watchdog_seconds=RUNTIME_TICKET_ZERO_SOAK_WATCHDOG_SECONDS,
        runtime_ticket_zero_stress_seed=RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
        architecture=architecture,
        write_report=False,
    )
    contract_record = runtime_ticket_zero_soak_contract_record(contract)
    evidence = runtime_ticket_zero_soak_fixture_evidence(milestone_report, pin)
    report = {
        "format": RUNTIME_TICKET_ZERO_SOAK_REPORT_FORMAT,
        "schema": RUNTIME_TICKET_ZERO_SOAK_REPORT_SCHEMA,
        "mode": "soak",
        "status": "passed",
        "evidence_scope": RUNTIME_TICKET_ZERO_SOAK_EVIDENCE_SCOPE,
        "nonclaims": list(RUNTIME_TICKET_ZERO_SOAK_NONCLAIMS),
        "contract": contract_record,
        "source": None,
        **evidence,
    }
    # Keep this capture as the last substantive operation before publication:
    # a source edit during build, audit, or artifact attestation invalidates
    # the run and leaves a previously published stable report untouched.
    source_after = runtime_ticket_zero_soak_source_state()
    report["source"] = runtime_ticket_zero_soak_source_attestation(
        source_before, source_after
    )
    write_json(RUNTIME_TICKET_ZERO_SOAK_REPORT, report)
    return report


def runtime_ticket_zero_soak_consumer_exactly_matches(
    observed: object, expected: object
) -> bool:
    """Compare report data without accepting JSON type coercion."""

    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(observed, dict)
        return set(observed) == set(expected) and all(
            runtime_ticket_zero_soak_consumer_exactly_matches(
                observed[key], expected[key]
            )
            for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(observed, list)
        return len(observed) == len(expected) and all(
            runtime_ticket_zero_soak_consumer_exactly_matches(left, right)
            for left, right in zip(observed, expected)
        )
    return observed == expected


def runtime_ticket_zero_soak_consumer_raw_path(path: Path) -> Path:
    """Make one lexical absolute path without resolving its components."""

    return Path(os.path.abspath(os.fspath(path)))


def runtime_ticket_zero_soak_consumer_relative_path(root: Path, path: Path) -> str:
    """Render one fixed raw checkout-relative path after containment checks."""

    raw_root = runtime_ticket_zero_soak_consumer_raw_path(root)
    raw_path = runtime_ticket_zero_soak_consumer_raw_path(path)
    try:
        return raw_path.relative_to(raw_root).as_posix()
    except ValueError as error:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer artifact escapes the checkout"
        ) from error


def runtime_ticket_zero_soak_consumer_regular_path(
    root: Path, path: Path, subject: str
) -> Path:
    """Require one fixed path and every checkout-local parent to be non-symlinked."""

    raw_root = runtime_ticket_zero_soak_consumer_raw_path(root)
    raw_path = runtime_ticket_zero_soak_consumer_raw_path(path)
    if raw_root.is_symlink() or not raw_root.is_dir():
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer checkout root is not a real directory"
        )
    try:
        relative_parts = raw_path.relative_to(raw_root).parts
    except ValueError as error:
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} escapes the checkout"
        ) from error
    if not relative_parts or any(part in {"", ".", ".."} for part in relative_parts):
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} has an invalid fixed path"
        )
    current = raw_root
    for part in relative_parts:
        current /= part
        if current.is_symlink():
            raise RuntimeTicketZeroSoakRejected(
                f"runtime ticket-zero soak consumer {subject} is not a regular file"
            )
    if not raw_path.is_file():
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} is unavailable or not a regular file"
        )
    return raw_path


def runtime_ticket_zero_soak_consumer_observed_file(
    root: Path, path: Path, subject: str
) -> tuple[bytes, dict[str, Any]]:
    """Read one stable fixed file and retain the exact record that was read."""

    raw_path = runtime_ticket_zero_soak_consumer_regular_path(root, path, subject)
    try:
        before = raw_path.stat()
        payload = raw_path.read_bytes()
        after = raw_path.stat()
    except OSError as error:
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer cannot read {subject}"
        ) from error
    if (
        before.st_size != len(payload)
        or after.st_size != len(payload)
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
        or before.st_dev != after.st_dev
    ):
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} changed while being read"
        )
    return payload, {
        "bytes": len(payload),
        "path": runtime_ticket_zero_soak_consumer_relative_path(root, raw_path),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def runtime_ticket_zero_soak_consumer_read_json(
    root: Path, path: Path, subject: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode one fixed JSON input from the bytes whose record is retained."""

    payload, record = runtime_ticket_zero_soak_consumer_observed_file(root, path, subject)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} is not valid JSON"
        ) from error
    if not isinstance(value, dict):
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} is not a JSON object"
        )
    return value, record


def runtime_ticket_zero_soak_consumer_live_pin(root: Path) -> dict[str, str]:
    """Read the pinned oracle through its fixed non-symlinked source path."""

    pin_path = runtime_ticket_zero_soak_consumer_raw_path(root) / "compat/upstreams.toml"
    payload, _ = runtime_ticket_zero_soak_consumer_observed_file(
        root, pin_path, "upstream pin"
    )
    try:
        raw = tomllib.loads(payload.decode("utf-8"))
        return normalize_mimalloc_pin(raw)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, HarnessError) as error:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer upstream pin is invalid"
        ) from error


def runtime_ticket_zero_soak_consumer_byte_payload(
    record: object, subject: str
) -> bytes:
    """Decode the exact source-status byte record without trusting its flag."""

    if not isinstance(record, dict) or set(record) != {"bytes", "hex", "sha256"}:
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} byte record is invalid"
        )
    if (
        type(record.get("bytes")) is not int
        or record["bytes"] < 0
        or not isinstance(record.get("hex"), str)
        or not isinstance(record.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
    ):
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} byte record is invalid"
        )
    try:
        payload = bytes.fromhex(record["hex"])
    except ValueError as error:
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} byte record has invalid hex"
        ) from error
    if (
        len(payload) != record["bytes"]
        or hashlib.sha256(payload).hexdigest() != record["sha256"]
    ):
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} byte record drifted"
        )
    return payload


def runtime_ticket_zero_soak_consumer_clean_source_state(
    value: object, subject: str
) -> dict[str, Any]:
    """Validate one clean-Git source state retained by the stable report."""

    if not isinstance(value, dict) or set(value) != {
        "kind",
        "revision",
        "worktree_clean",
        "worktree_status",
    }:
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} source state is invalid"
        )
    if (
        value.get("kind") != "git"
        or not isinstance(value.get("revision"), str)
        or re.fullmatch(r"[0-9a-f]{40}", value["revision"]) is None
        or type(value.get("worktree_clean")) is not bool
    ):
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} source state is invalid"
        )
    status = runtime_ticket_zero_soak_consumer_byte_payload(
        value.get("worktree_status"), f"{subject} worktree status"
    )
    if value["worktree_clean"] is not True or status != b"":
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} requires a clean Git source"
        )
    return dict(value)


def runtime_ticket_zero_soak_consumer_current_git_source_state(root: Path) -> dict[str, Any]:
    """Read the live source state without allowing Git to refresh its index."""

    git = shutil.which("git")
    if git is None:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer requires Git source attestation"
        )
    environment = dict(os.environ)
    environment.update(RUNTIME_TICKET_ZERO_SOAK_GIT_READ_ENVIRONMENT)
    try:
        revision = subprocess.run(
            [git, "rev-parse", "--verify", "HEAD"],
            cwd=root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        status = subprocess.run(
            [git, "status", "--porcelain=v1", "--untracked-files=all", "-z"],
            cwd=root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer cannot read its Git source state"
        ) from error
    if revision.returncode != 0 or status.returncode != 0:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer requires an available Git source tree"
        )
    try:
        revision_text = revision.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer has an invalid Git revision"
        ) from error
    state = {
        "kind": "git",
        "revision": revision_text,
        "worktree_clean": status.stdout == b"",
        "worktree_status": source_byte_record(status.stdout),
    }
    return runtime_ticket_zero_soak_consumer_clean_source_state(
        state, "current execution"
    )


def runtime_ticket_zero_soak_consumer_artifact_paths(
    work_root: Path,
) -> dict[str, Path]:
    """Name every live raw artifact accepted by the durable soak consumer."""

    artifact_root = (
        work_root / "target/compat/allocator/runtime-ticket-zero-adapter"
    )
    release_root = artifact_root / "cargo-target" / PRODUCTION_RUST_TARGET / "release"
    return {
        "archive": work_root / "allocator-cache/mimalloc-3.5.0.tar.gz",
        "tag_attestation": work_root / "allocator-cache/mimalloc-3.5.0.tag.json",
        "adapter_archive": release_root
        / "libcrabc_mimalloc_runtime_ticket_zero_adapter.a",
        "adapter_shared_library": release_root
        / "libcrabc_mimalloc_runtime_ticket_zero_adapter.so",
        "fixture": artifact_root / "runtime-ticket-zero-fixture",
    }


def runtime_ticket_zero_soak_consumer_attest_artifact(
    root: Path,
    record: object,
    subject: str,
    *,
    expected_path: Path,
) -> dict[str, Any]:
    """Bind one report file record to its only accepted current raw pathname."""

    if not isinstance(record, dict) or set(record) != {"bytes", "path", "sha256"}:
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} artifact record is invalid"
        )
    expected_relative = runtime_ticket_zero_soak_consumer_relative_path(
        root, expected_path
    )
    if (
        type(record.get("bytes")) is not int
        or record["bytes"] <= 0
        or record.get("path") != expected_relative
        or not isinstance(record.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
    ):
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} artifact has a noncanonical record"
        )
    _, observed = runtime_ticket_zero_soak_consumer_observed_file(
        root, expected_path, subject
    )
    if not runtime_ticket_zero_soak_consumer_exactly_matches(record, observed):
        raise RuntimeTicketZeroSoakRejected(
            f"runtime ticket-zero soak consumer {subject} artifact changed"
        )
    return observed


def runtime_ticket_zero_soak_consumer_pinned_source_records(
    root: Path,
    archive_path: Path,
    pin: Mapping[str, str],
    archive_record: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Re-read every producer C-oracle member from the live pinned archive.

    The soak producer carries the compact `source_file_records` inventory from
    `milestone0_report`.  Those member records are meaningful only when this
    later reader independently verifies the same ordered `ORACLE_SOURCES`
    bytes against the still-live archive that already matched the immutable
    pin.  Reading directly from the archive avoids accepting a relabelled
    extracted tree or a producer-shaped list of arbitrary strings.
    """

    _, before = runtime_ticket_zero_soak_consumer_observed_file(
        root, archive_path, "pinned archive"
    )
    if (
        not runtime_ticket_zero_soak_consumer_exactly_matches(before, archive_record)
        or before["sha256"] != pin["sha256"]
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer pinned archive changed before source-member validation"
        )
    records: list[dict[str, Any]] = []
    try:
        with tarfile.open(archive_path, mode="r:gz") as stream:
            for name in sorted(ORACLE_SOURCES):
                member_path = f"{pin['archive_root']}/{name}"
                members = [
                    member
                    for member in stream.getmembers()
                    if member.name == member_path
                ]
                if len(members) != 1 or not members[0].isfile():
                    raise RuntimeTicketZeroSoakRejected(
                        "runtime ticket-zero soak consumer pinned archive lacks a required C-oracle source member"
                    )
                extracted = stream.extractfile(members[0])
                if extracted is None:
                    raise RuntimeTicketZeroSoakRejected(
                        "runtime ticket-zero soak consumer cannot read a C-oracle source member"
                    )
                with extracted:
                    payload = extracted.read()
                records.append(
                    {
                        "bytes": len(payload),
                        "path": name,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
    except (OSError, tarfile.TarError) as error:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer cannot read the pinned upstream archive"
        ) from error
    _, after = runtime_ticket_zero_soak_consumer_observed_file(
        root, archive_path, "pinned archive"
    )
    if not runtime_ticket_zero_soak_consumer_exactly_matches(before, after):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer pinned archive changed during source-member validation"
        )
    return records


def runtime_ticket_zero_soak_consumer_fixture_build_command(
    root: Path, artifact_paths: Mapping[str, Path]
) -> list[str]:
    """Reconstruct the one pinned-container fixture build command exactly."""

    compiler = shutil.which("musl-gcc")
    if compiler is None:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer requires the pinned musl-gcc path"
        )
    adapter_root = runtime_ticket_zero_soak_consumer_raw_path(root) / (
        "compat/allocator/runtime-ticket-zero-adapter"
    )
    fixture_source = adapter_root / "runtime-ticket-zero-fixture.c"
    return [
        compiler,
        "-std=c11",
        "-O2",
        "-fPIE",
        "-pie",
        "-ftls-model=initial-exec",
        "-pthread",
        "-I",
        str(adapter_root),
        str(fixture_source),
        str(artifact_paths["adapter_archive"]),
        "-o",
        str(artifact_paths["fixture"]),
    ]


def runtime_ticket_zero_soak_consumer_validate_report(
    report: Mapping[str, Any],
    *,
    root: Path,
    work_root: Path,
    contract: Mapping[str, Any],
    contract_record: Mapping[str, Any],
    pin: Mapping[str, str],
) -> dict[str, Any]:
    """Reject stale, redirected, or broadened private-soak evidence."""

    expected_keys = {
        "audit",
        "build_artifacts",
        "contract",
        "evidence_scope",
        "fixture",
        "format",
        "mode",
        "nonclaims",
        "oracle",
        "pin",
        "schedule",
        "schema",
        "source",
        "status",
        "target",
    }
    if not isinstance(report, dict) or set(report) != expected_keys:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer report schema drifted"
        )
    if (
        report.get("format") != RUNTIME_TICKET_ZERO_SOAK_REPORT_FORMAT
        or report.get("schema") != RUNTIME_TICKET_ZERO_SOAK_REPORT_SCHEMA
        or report.get("mode") != "soak"
        or report.get("status") != "passed"
        or report.get("evidence_scope") != RUNTIME_TICKET_ZERO_SOAK_EVIDENCE_SCOPE
        or report.get("nonclaims") != RUNTIME_TICKET_ZERO_SOAK_NONCLAIMS
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer report identity or nonclaims drifted"
        )

    expected_contract = {
        "format": contract["format"],
        "record": dict(contract_record),
        "schema": contract["schema"],
        "soak_report": dict(contract["soak_report"]),
        "upstream": dict(contract["upstream"]),
    }
    if not runtime_ticket_zero_soak_consumer_exactly_matches(
        report.get("contract"), expected_contract
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer contract binding drifted"
        )

    source = report.get("source")
    if not isinstance(source, dict) or set(source) != {
        "after",
        "before",
        "git_read_environment",
        "unchanged_during_execution",
    }:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer source attestation schema drifted"
        )
    before = runtime_ticket_zero_soak_consumer_clean_source_state(
        source.get("before"), "report before"
    )
    after = runtime_ticket_zero_soak_consumer_clean_source_state(
        source.get("after"), "report after"
    )
    if (
        source.get("git_read_environment")
        != RUNTIME_TICKET_ZERO_SOAK_GIT_READ_ENVIRONMENT
        or source.get("unchanged_during_execution") is not True
        or not runtime_ticket_zero_soak_consumer_exactly_matches(before, after)
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer source attestation drifted"
        )

    artifact_paths = runtime_ticket_zero_soak_consumer_artifact_paths(work_root)
    report_pin = report.get("pin")
    if not isinstance(report_pin, dict):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer pin record is invalid"
        )
    archive = runtime_ticket_zero_soak_consumer_attest_artifact(
        root,
        report_pin.get("archive"),
        "pinned archive",
        expected_path=artifact_paths["archive"],
    )
    expected_tag = {
        "format": 1,
        "repository": pin["repository"],
        "revision": pin["revision"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
    }
    tag, tag_record = runtime_ticket_zero_soak_consumer_read_json(
        root, artifact_paths["tag_attestation"], "tag attestation"
    )
    expected_pin = {
        "archive": archive,
        "archive_root": pin["archive_root"],
        "revision": pin["revision"],
        "sha256": pin["sha256"],
        "source": pin["source"],
        "tag_object": pin["tag_object"],
        "tag_verified": expected_tag,
        "version": pin["version"],
    }
    if (
        archive["sha256"] != pin["sha256"]
        or not runtime_ticket_zero_soak_consumer_exactly_matches(report_pin, expected_pin)
        or not runtime_ticket_zero_soak_consumer_exactly_matches(tag, expected_tag)
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer pin, archive, or tag binding drifted"
        )

    oracle = report.get("oracle")
    if (
        not isinstance(oracle, dict)
        or set(oracle) != {"build_strategy", "compiler", "source_files"}
        or not isinstance(oracle.get("build_strategy"), str)
        or not oracle["build_strategy"]
        or not isinstance(oracle.get("compiler"), str)
        or not oracle["compiler"]
        or not isinstance(oracle.get("source_files"), list)
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer C oracle identity drifted"
        )
    source_files = runtime_ticket_zero_soak_consumer_pinned_source_records(
        root,
        artifact_paths["archive"],
        pin,
        archive,
    )
    if not runtime_ticket_zero_soak_consumer_exactly_matches(
        oracle["source_files"], source_files
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer C oracle source-member binding drifted"
        )
    expected_target = {
        "architecture": "aarch64",
        "rust_target": PRODUCTION_RUST_TARGET,
        "system": "Linux",
    }
    if not runtime_ticket_zero_soak_consumer_exactly_matches(
        report.get("target"), expected_target
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer target is not native Linux/AArch64"
        )

    build_artifacts = report.get("build_artifacts")
    if not isinstance(build_artifacts, dict) or set(build_artifacts) != {
        "adapter_archive",
        "adapter_shared_library",
    }:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer adapter artifact inventory drifted"
        )
    adapter_archive = runtime_ticket_zero_soak_consumer_attest_artifact(
        root,
        build_artifacts.get("adapter_archive"),
        "adapter archive",
        expected_path=artifact_paths["adapter_archive"],
    )
    adapter_shared_library = runtime_ticket_zero_soak_consumer_attest_artifact(
        root,
        build_artifacts.get("adapter_shared_library"),
        "adapter shared library",
        expected_path=artifact_paths["adapter_shared_library"],
    )

    fixture = report.get("fixture")
    if not isinstance(fixture, dict) or set(fixture) != {
        "artifact",
        "build_command",
        "run_command",
        "stdout",
    }:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer fixture record schema drifted"
        )
    fixture_artifact = runtime_ticket_zero_soak_consumer_attest_artifact(
        root,
        fixture.get("artifact"),
        "fixture",
        expected_path=artifact_paths["fixture"],
    )
    fixture_source = runtime_ticket_zero_soak_consumer_raw_path(root) / (
        "compat/allocator/runtime-ticket-zero-adapter/runtime-ticket-zero-fixture.c"
    )
    runtime_ticket_zero_soak_consumer_regular_path(
        root, fixture_source, "fixture source"
    )
    expected_build_command = runtime_ticket_zero_soak_consumer_fixture_build_command(
        root, artifact_paths
    )
    expected_run_command = runtime_ticket_zero_fixture_command(
        artifact_paths["fixture"],
        worker_cycles=RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
        stress_seed=RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
    )
    if (
        not runtime_ticket_zero_soak_consumer_exactly_matches(
            fixture.get("build_command"), expected_build_command
        )
        or not runtime_ticket_zero_soak_consumer_exactly_matches(
            fixture.get("run_command"), expected_run_command
        )
        or not isinstance(fixture.get("stdout"), str)
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer fixture build or run command drifted"
        )

    expected_schedule = runtime_ticket_zero_stress_schedule(
        worker_cycles=RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
        stress_seed=RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
    )
    expected_schedule_record = {
        "stress_seed": expected_schedule["seed"],
        "watchdog_seconds": RUNTIME_TICKET_ZERO_SOAK_WATCHDOG_SECONDS,
        "worker_cycles": RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
        "worker_route_invocation_count": expected_schedule[
            "worker_route_invocation_count"
        ],
        "worker_routes_per_cycle": expected_schedule["worker_routes_per_cycle"],
    }
    if not runtime_ticket_zero_soak_consumer_exactly_matches(
        report.get("schedule"), expected_schedule_record
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer schedule drifted"
        )
    audit = report.get("audit")
    if not isinstance(audit, dict) or set(audit) != {
        "audit_snapshot_count",
        "post_warm_cycle_count",
        "status",
        "warm_baseline",
    }:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer lifecycle audit schema drifted"
        )
    warm_baseline = audit.get("warm_baseline")
    if (
        not isinstance(warm_baseline, dict)
        or set(warm_baseline) != set(RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_FIELDS)
        or any(
            type(warm_baseline[field]) is not int or warm_baseline[field] < 0
            for field in RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_FIELDS
        )
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer lifecycle audit fields drifted"
        )
    expected_quiescent_values = {
        "process_active": 1,
        "page_owner_ready": 1,
        "page_map_registered_entries": 0,
        "arena_registry_entries": 1,
        "live_tlds": 1,
        "metadata_live_capabilities": 0,
        "shared_later_theaps": 0,
        "abandoned_regular_pages": 0,
        "os_abandoned_pages_empty": 1,
    }
    try:
        stdout_audit = parse_runtime_ticket_zero_lifecycle_audit(fixture["stdout"])
    except HarnessError as error:
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer fixture stdout audit drifted"
        ) from error
    if (
        warm_baseline["worker_cycles"] != RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES
        or any(
            warm_baseline[field] != value
            for field, value in expected_quiescent_values.items()
        )
        or audit.get("audit_snapshot_count")
        != RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES + 1
        or audit.get("post_warm_cycle_count")
        != RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES - 1
        or audit.get("status") != "passed"
        or not runtime_ticket_zero_soak_consumer_exactly_matches(
            stdout_audit, warm_baseline
        )
    ):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer lifecycle audit is not quiescent"
        )

    live_source = runtime_ticket_zero_soak_consumer_current_git_source_state(root)
    if not runtime_ticket_zero_soak_consumer_exactly_matches(live_source, after):
        raise RuntimeTicketZeroSoakRejected(
            "runtime ticket-zero soak consumer current Git HEAD no longer matches the report"
        )
    return {
        "artifacts": {
            "adapter_archive": adapter_archive,
            "adapter_shared_library": adapter_shared_library,
            "archive": archive,
            "fixture": fixture_artifact,
            "tag_attestation": tag_record,
        },
        "audit": dict(audit),
        "evidence_scope": report["evidence_scope"],
        "nonclaims": list(report["nonclaims"]),
        "pin": {
            "revision": pin["revision"],
            "tag": pin["tag"],
            "version": pin["version"],
        },
        "schedule": dict(report["schedule"]),
        "source": dict(source),
        "target": dict(expected_target),
    }


def consume_runtime_ticket_zero_soak_evidence(
    *,
    contract_path: Path = RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT,
    report_path: Path = RUNTIME_TICKET_ZERO_SOAK_REPORT,
    root: Path = ROOT,
    work_root: Path = WORK_ROOT,
    pin: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Classify the one durable private soak report without running its fixture.

    This is intentionally a top-level provenance reader.  It neither invokes
    the opt-in soak producer nor supplies evidence to the M5 gate contract.
    """

    raw_root = runtime_ticket_zero_soak_consumer_raw_path(root)
    raw_work_root = runtime_ticket_zero_soak_consumer_raw_path(work_root)
    expected_work_root = raw_root / ".work"
    expected_contract_path = raw_root / "compat/allocator/runtime-ticket-zero-test-v3.5.0.json"
    expected_report_path = expected_work_root / RUNTIME_TICKET_ZERO_SOAK_REPORT_RELATIVE_PATH
    base: dict[str, Any] = {
        "format": 1,
        "schema": "crabc-mimalloc-runtime-ticket-zero-soak-consumer",
        "status": "rejected",
        "reason": None,
        "report_path": runtime_ticket_zero_soak_consumer_relative_path(
            raw_root, expected_report_path
        ),
        "report": None,
        "contract": None,
        "source": None,
        "target": None,
        "schedule": None,
        "audit": None,
        "evidence_scope": None,
        "nonclaims": None,
        "artifacts": None,
    }
    if (
        raw_work_root != expected_work_root
        or runtime_ticket_zero_soak_consumer_raw_path(contract_path)
        != expected_contract_path
        or runtime_ticket_zero_soak_consumer_raw_path(report_path) != expected_report_path
    ):
        base["reason"] = (
            "runtime ticket-zero soak consumer accepts only its fixed raw contract and report paths"
        )
        return base
    if (
        raw_root.is_symlink()
        or not raw_root.is_dir()
        or expected_work_root.is_symlink()
    ):
        base["reason"] = (
            "runtime ticket-zero soak consumer fixed checkout or work root is redirected"
        )
        return base
    if not os.path.lexists(expected_report_path):
        base["status"] = "unavailable"
        base["reason"] = "runtime ticket-zero soak report is unavailable"
        return base
    try:
        actual_pin = (
            runtime_ticket_zero_soak_consumer_live_pin(raw_root)
            if pin is None
            else normalize_mimalloc_pin({"mimalloc": dict(pin)})
        )
        contract, contract_record = runtime_ticket_zero_soak_consumer_read_json(
            raw_root, expected_contract_path, "contract"
        )
        header_path = raw_root / (
            "compat/allocator/runtime-ticket-zero-adapter/"
            "crabc-mimalloc-runtime-ticket-zero-test.h"
        )
        header_payload, _ = runtime_ticket_zero_soak_consumer_observed_file(
            raw_root, header_path, "adapter header"
        )
        try:
            header = header_payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeTicketZeroSoakRejected(
                "runtime ticket-zero soak consumer adapter header is not UTF-8"
            ) from error
        try:
            validate_runtime_ticket_zero_adapter_contract(
                contract, header, pin=actual_pin
            )
        except HarnessError as error:
            raise RuntimeTicketZeroSoakRejected(
                "runtime ticket-zero soak consumer contract is invalid"
            ) from error
        report, report_record = runtime_ticket_zero_soak_consumer_read_json(
            raw_root, expected_report_path, "report"
        )
        verified = runtime_ticket_zero_soak_consumer_validate_report(
            report,
            root=raw_root,
            work_root=raw_work_root,
            contract=contract,
            contract_record=contract_record,
            pin=actual_pin,
        )
    except (RuntimeTicketZeroSoakRejected, HarnessError, OSError, TypeError) as error:
        base["reason"] = str(error)
        return base
    base.update(
        {
            "status": "verified",
            "reason": None,
            "report": report_record,
            "contract": {
                "format": contract["format"],
                "record": contract_record,
                "schema": contract["schema"],
            },
            **verified,
        }
    )
    return base


def milestone0_report(
    pin: Mapping[str, str],
    archive: Path,
    source: Path,
    profiles: Mapping[str, Any],
    *,
    architecture: str = "aarch64",
    target_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    report = {
        "c_oracle": {
            "build_strategy": "direct compilation of the pinned CMake mi_sources list; the pinned development image intentionally does not contain CMake",
            "compiler": compiler_version("musl-gcc", source),
            "profiles": profiles,
            "source_files": source_file_records(source, ORACLE_SOURCES),
        },
        "current_integration_provenance": integration_provenance(),
        "format": 1,
        "oracle": {
            "archive": artifact_record(archive),
            "archive_root": pin["archive_root"],
            "revision": pin["revision"],
            "sha256": pin["sha256"],
            "source": pin["source"],
            "tag_object": pin["tag_object"],
            "tag_verified": cached_tag_attestation(pin),
            "version": pin["version"],
        },
        "target": {"architecture": platform.machine(), "system": platform.system()},
    }
    if architecture != "aarch64":
        if target_metadata is None:
            raise HarnessError("non-AArch64 allocator report lacks target metadata")
        report["target"] = dict(target_metadata) | {
            "system": platform.system(),
            "native_machine": platform.machine(),
        }
    return report


def run_x86_64_oracle(
    *,
    pin: Mapping[str, str],
    archive: Path,
    source: Path,
    source_api_inventory: Mapping[str, Any],
    source_api_coverage: Mapping[str, Any],
    source_map: Mapping[str, Any],
    adapter_source_contract: Mapping[str, Any],
    adapter_source_summary: Mapping[str, Any],
    adapter_contract: Mapping[str, Any],
    adapter_summary: Mapping[str, Any],
    adapter_patch: Mapping[str, Any],
) -> dict[str, Any]:
    """Run native x86-64 C-oracle and private test-adapter evidence.

    The AArch64 API/adapter contracts remain the production contract.  This
    lane deliberately proves source identity, C layouts/traces, ELF machine
    identity, the target-local normal-engine dependency/rlib boundary, native
    direct-Rust configuration/layout/trace parity, compiler TLS code
    generation, the target-local private test adapter, and the x86-64 musl
    target assumptions while leaving public allocator integration unclaimed.
    """

    native_execution_provenance = require_native_x86_64()
    engine_dependency_graph = x86_64_engine_dependency_graph()
    normal_engine_artifact = x86_64_normal_engine_artifact()
    compiler = require_tool("musl-gcc")
    readelf = require_tool("readelf")
    nm = require_tool("nm")
    profiles = {
        name: build_profile(
            compiler,
            readelf,
            source,
            name,
            flags,
            artifact_root=X86_64_ORACLE_ARTIFACT_ROOT / "oracle",
            architecture="x86_64",
        )
        for name, flags in CONFIGURATION_PROFILES.items()
    }
    rust_direct_engine = rust_layout_probe(
        profiles["release"]["layout"],
        profiles["release"]["single_thread_small_trace"]["record"],
        profiles["release"]["fundamental_trace"]["c_oracle"]["record"],
        rust_target=X86_64_RUST_TARGET,
    )
    profiles["release"]["fundamental_trace"]["rust_comparison"] = rust_direct_engine[
        "single_thread_fundamental_trace"
    ]["comparison"]
    report = milestone0_report(
        pin,
        archive,
        source,
        profiles,
        architecture="x86_64",
        target_metadata=X86_64_TARGET_METADATA,
    )
    report["architecture_profile"] = "x86_64-native-c-oracle"
    report["native_execution_provenance"] = native_execution_provenance
    report["x86_64_source_api_inventory"] = dict(source_api_inventory)
    report["x86_64_api_coverage"] = dict(source_api_coverage)
    report["x86_64_source_map"] = dict(source_map)
    report["x86_64_engine_dependency_graph"] = engine_dependency_graph
    report["x86_64_normal_engine_artifact"] = normal_engine_artifact
    # The unit suite exercises the direct no_std engine against this native C
    # oracle. It is distinct from the target-local private adapter below and
    # is not evidence for public allocator integration.
    report["rust_direct_engine"] = rust_direct_engine
    report["compiler_tls_codegen"] = compiler_tls_codegen(architecture="x86_64")
    adapter_compile_requirements = adapter_contract["compile_requirements"]
    assert isinstance(adapter_compile_requirements, dict)
    adapter_target = adapter_contract["target"]
    assert isinstance(adapter_target, dict)
    native_executable_expectations = {
        "architecture": adapter_target["architecture"],
        "dynamic_dependencies": adapter_compile_requirements[
            "expected_executable_dynamic_dependencies"
        ],
        "elf": adapter_compile_requirements["expected_executable_elf"],
        "interpreter": adapter_target["interpreter"],
    }
    expected_adapter_symbols = adapter_source_contract["expected_adapter_symbols"]
    assert isinstance(expected_adapter_symbols, list)
    adapter_artifact_root = X86_64_ORACLE_ARTIFACT_ROOT / "test-adapter"
    static_library, native_libraries, adapter_build = build_test_adapter(
        readelf,
        nm,
        adapter_contract,
        rust_target=X86_64_RUST_TARGET,
        architecture="x86_64",
        artifact_root=adapter_artifact_root,
        expected_symbols=expected_adapter_symbols,
    )
    report["x86_64_private_test_adapter"] = {
        "build": adapter_build,
        "contract": artifact_record(X86_64_TEST_ADAPTER_CONTRACT),
        "contract_summary": dict(adapter_summary),
        "evidence_boundary": adapter_contract["evidence_boundary"],
        "fixtures": run_test_adapter_fixtures(
            compiler,
            source,
            static_library,
            native_libraries,
            adapter_source_contract,
            artifact_root=adapter_artifact_root,
            target_compile_requirements=adapter_compile_requirements,
            rust_target=X86_64_RUST_TARGET,
            expected_fixture_stdout=str(
                adapter_compile_requirements["expected_fixture_stdout"]
            ),
            readelf=readelf,
            native_executable_expectations=native_executable_expectations,
        ),
        "source_selection": {
            "base_contract_path": relative(ADAPTED_TEST_CONTRACT),
            "base_contract_summary": dict(adapter_source_summary),
            "base_source_selection_sha256": adapted_test_source_selection_digest(
                adapter_source_contract
            ),
            "patch": adapter_patch,
        },
    }
    report["unsupported_lanes"] = {
        "public_allocator_integration": (
            "not run: the private prefixed adapter exports no mi_* symbols and "
            "does not establish public crabc allocator integration or default promotion"
        ),
    }
    output = X86_64_ORACLE_REPORT_ROOT / "latest.json"
    write_json(output, report)
    return report


def run_milestone0(
    *,
    offline: bool,
    generate_contracts: bool,
    check_only: bool,
    include_test_adapter: bool = False,
    include_adapted_stress: bool = False,
    architecture: str = "aarch64",
    include_native_owner_exit_lifecycle: bool = False,
    runtime_ticket_zero_worker_cycles: int = RUNTIME_TICKET_ZERO_DEFAULT_WORKER_CYCLES,
    runtime_ticket_zero_watchdog_seconds: int = RUNTIME_TICKET_ZERO_CHURN_WATCHDOG_SECONDS,
    runtime_ticket_zero_stress_seed: int = RUNTIME_TICKET_ZERO_DEFAULT_STRESS_SEED,
    write_report: bool = True,
) -> dict[str, Any]:
    if architecture not in {"aarch64", "x86_64"}:
        raise HarnessError(f"unsupported allocator oracle architecture: {architecture}")
    if architecture == "x86_64" and not check_only:
        # Refuse an accidental foreign/emulated invocation before downloading
        # or compiling anything for the native-only profile.
        require_native_x86_64()
    if include_adapted_stress and not include_test_adapter:
        raise HarnessError("adapted upstream stress requires the prefixed test adapter")
    if architecture == "x86_64" and include_adapted_stress:
        raise HarnessError("adapted upstream stress is available only in the AArch64 allocator profile")
    pin = load_pin()
    archive = fetch_archive(pin, offline)
    x86_64_source_map: Mapping[str, Any] | None = None
    x86_64_api_coverage: Mapping[str, Any] | None = None
    if architecture == "x86_64":
        x86_64_source_map = x86_64_source_map_contract(archive)
        x86_64_api_coverage = x86_64_api_coverage_contract(archive)
    with temporary_directory(prefix="crabc-mimalloc-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        if architecture == "x86_64":
            if generate_contracts:
                raise HarnessError(
                    "native x86-64 uses its checked-in source API inventory; "
                    "AArch64 contract generation is not part of this profile"
                )
            assert x86_64_source_map is not None
            assert x86_64_api_coverage is not None
            source_api_inventory = x86_64_source_api_inventory(archive)
            adapted_contract = read_json(ADAPTED_TEST_CONTRACT)
            adapted_summary = validate_adapted_test_contract(
                adapted_contract,
                pin,
                TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
                source_selection_only=True,
            )
            x86_64_adapter_contract = read_json(X86_64_TEST_ADAPTER_CONTRACT)
            x86_64_adapter_summary = validate_x86_64_test_adapter_contract(
                x86_64_adapter_contract,
                adapted_contract,
                pin,
                TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )
            adapted_patch = apply_and_verify_adapted_test_patch(
                source,
                adapted_contract,
                require_tool("patch"),
            )
            if check_only:
                return {
                    "architecture_profile": "x86_64-source-contract-check",
                    "x86_64_source_api_inventory": source_api_inventory,
                    "x86_64_api_coverage": dict(x86_64_api_coverage),
                    "x86_64_source_map": dict(x86_64_source_map),
                    "x86_64_private_test_adapter": {
                        "contract": artifact_record(X86_64_TEST_ADAPTER_CONTRACT),
                        "contract_summary": x86_64_adapter_summary,
                        "source_selection": {
                            "base_contract_path": relative(ADAPTED_TEST_CONTRACT),
                            "base_contract_summary": adapted_summary,
                            "base_source_selection_sha256": adapted_test_source_selection_digest(
                                adapted_contract
                            ),
                            "patch": adapted_patch,
                        },
                    },
                    "status": "checked",
                }
            return run_x86_64_oracle(
                pin=pin,
                archive=archive,
                source=source,
                source_api_inventory=source_api_inventory,
                source_api_coverage=x86_64_api_coverage,
                source_map=x86_64_source_map,
                adapter_source_contract=adapted_contract,
                adapter_source_summary=adapted_summary,
                adapter_contract=x86_64_adapter_contract,
                adapter_summary=x86_64_adapter_summary,
                adapter_patch=adapted_patch,
            )
        contracts = generated_contracts(source, pin)
        if generate_contracts:
            write_contracts(contracts)
        else:
            check_contracts(contracts)
        owner_exit_publication_contract = read_json(OWNER_EXIT_PUBLICATION_CONTRACT)
        owner_exit_publication_summary = validate_owner_exit_publication_contract(
            owner_exit_publication_contract,
            pin,
            source,
        )
        port_map = load_port_map()
        check_ratchet(port_map)
        adapted_contract = read_json(ADAPTED_TEST_CONTRACT)
        adapted_summary = validate_adapted_test_contract(
            adapted_contract,
            pin,
            TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
        )
        adapted_patch = apply_and_verify_adapted_test_patch(
            source,
            adapted_contract,
            require_tool("patch"),
        )
        adapted_stress_contract = read_json(ADAPTED_STRESS_TEST_CONTRACT)
        adapted_stress_summary = validate_adapted_stress_test_contract(
            adapted_stress_contract,
            pin,
            TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
        )
        adapted_stress_patch = apply_and_verify_adapted_stress_test_patch(
            source,
            adapted_stress_contract,
            require_tool("patch"),
        )
        native_shadow_stress_contract = read_json(NATIVE_SHADOW_STRESS_CONTRACT)
        native_shadow_stress_summary = validate_native_shadow_stress_contract(
            native_shadow_stress_contract,
            pin,
        )
        native_shadow_stress_source = safe_extract(
            archive,
            Path(temporary) / "native-shadow-stress",
            pin["archive_root"],
        )
        native_shadow_stress_patch = apply_and_verify_native_shadow_stress_patch(
            native_shadow_stress_source,
            native_shadow_stress_contract,
            require_tool("patch"),
        )
        runtime_ticket_zero_contract = read_json(RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT)
        runtime_ticket_zero_summary = validate_runtime_ticket_zero_adapter_contract(
            runtime_ticket_zero_contract,
            RUNTIME_TICKET_ZERO_ADAPTER_HEADER.read_text(encoding="utf-8"),
        )
        native_owner_exit_lifecycle_contract = read_json(
            NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT
        )
        native_owner_exit_lifecycle_summary = validate_native_owner_exit_lifecycle_contract(
            native_owner_exit_lifecycle_contract,
            pin,
        )
        m5_gate_contract = read_json(M5_GATE_CONTRACT)
        m5_gate_summary = validate_m5_gate_contract(m5_gate_contract, pin)
        port_map = load_port_map()
        check_ratchet(port_map)
        if check_only:
            return {
                "adapted_test_contract": adapted_summary,
                "adapted_test_patch": adapted_patch,
                "adapted_stress_test_contract": adapted_stress_summary,
                "adapted_stress_test_patch": adapted_stress_patch,
                "native_shadow_stress_contract": native_shadow_stress_summary,
                "native_shadow_stress_patch": native_shadow_stress_patch,
                "m5_gate_contract": m5_gate_summary,
                "native_owner_exit_lifecycle_contract": native_owner_exit_lifecycle_summary,
                "owner_exit_publication_contract": owner_exit_publication_summary,
                "runtime_ticket_zero_test_contract": runtime_ticket_zero_summary,
                "contracts": {relative(path): payload["summary"] for path, payload in contracts.items()},
                "port_map": port_map_counts(port_map),
                "status": "checked",
            }
        require_native_architecture(architecture)
        compiler = require_tool("musl-gcc")
        readelf = require_tool("readelf")
        profiles = {
            name: build_profile(
                compiler,
                readelf,
                source,
                name,
                flags,
                include_m1_static_image_probe=(
                    architecture == "aarch64" and name == "release"
                ),
            )
            for name, flags in CONFIGURATION_PROFILES.items()
        }
        release_symbol_contract = validate_release_symbol_contract(
            contracts[API_CONTRACT], profiles["release"]["symbols"]
        )
        dependency_graph = production_dependency_graph()
        rust_layout = rust_layout_probe(
            profiles["release"]["layout"],
            profiles["release"]["single_thread_small_trace"]["record"],
            profiles["release"]["fundamental_trace"]["c_oracle"]["record"],
        )
        profiles["release"]["fundamental_trace"]["rust_comparison"] = rust_layout[
            "single_thread_fundamental_trace"
        ]["comparison"]
        report = milestone0_report(pin, archive, source, profiles)
        report["contracts"] = {relative(path): payload["summary"] for path, payload in contracts.items()}
        report["owner_exit_publication_contract"] = owner_exit_publication_summary
        report["port_map"] = port_map_counts(port_map)
        report["compiler_tls_codegen"] = compiler_tls_codegen()
        report["production_dependency_graph"] = dependency_graph
        report["remote_free_loom_model"] = loom_remote_free_model()
        report["release_symbol_contract"] = release_symbol_contract
        report["rust_release_layout"] = rust_layout
        report["adapted_test_contract"] = adapted_summary
        report["adapted_test_patch"] = adapted_patch
        report["adapted_stress_test_contract"] = adapted_stress_summary
        report["adapted_stress_test_patch"] = adapted_stress_patch
        report["native_shadow_stress_contract"] = native_shadow_stress_summary
        report["native_shadow_stress_patch"] = native_shadow_stress_patch
        report["m5_gate_contract"] = m5_gate_summary
        report["native_owner_exit_lifecycle_contract"] = native_owner_exit_lifecycle_summary
        report["runtime_ticket_zero_test_contract"] = runtime_ticket_zero_summary
        if include_native_owner_exit_lifecycle:
            report["native_owner_exit_lifecycle"] = run_native_owner_exit_lifecycle(
                native_owner_exit_lifecycle_contract,
                pin,
            )
        if include_test_adapter:
            nm = require_tool("nm")
            static_library, native_libraries, adapter_build = build_test_adapter(
                readelf,
                nm,
                adapted_contract,
            )
            report["m4_test_adapter"] = {
                "build": adapter_build,
                "fixtures": run_test_adapter_fixtures(
                    compiler,
                    source,
                    static_library,
                    native_libraries,
                    adapted_contract,
                ),
            }
            if include_adapted_stress:
                report["m5_source_derived_stress_adapter"] = {
                    "fixture": run_adapted_stress_fixture(
                        compiler,
                        source,
                        static_library,
                        native_libraries,
                        adapted_stress_contract,
                    ),
                }
            runtime_static_library, runtime_native_libraries, runtime_adapter_build = (
                build_runtime_ticket_zero_adapter(readelf, nm, runtime_ticket_zero_contract)
            )
            report["runtime_ticket_zero_test_adapter"] = {
                "build": runtime_adapter_build,
                "fixture": run_runtime_ticket_zero_adapter_fixture(
                    compiler,
                    runtime_static_library,
                    runtime_native_libraries,
                    worker_cycles=runtime_ticket_zero_worker_cycles,
                    watchdog_seconds=runtime_ticket_zero_watchdog_seconds,
                    stress_seed=runtime_ticket_zero_stress_seed,
                ),
            }
        if write_report:
            write_json(REPORT_ROOT / "latest.json", report)
        return report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="run the Milestone 0 C oracle and deterministic contract gate")
    mode.add_argument(
        "--m1",
        action="store_true",
        help="run the current-commit finite M1 foundations evidence gate",
    )
    mode.add_argument(
        "--m2",
        action="store_true",
        help="run the current-commit partial M2 memory-substrate evidence gate",
    )
    mode.add_argument(
        "--m1-tls-terminal-prototype",
        action="store_true",
        help="run the standalone pinned-C half of the same-TLD M1 terminal trace",
    )
    mode.add_argument("--full", action="store_true", help="run the audited Milestone 5 full-lane report")
    mode.add_argument(
        "--churn",
        action="store_true",
        help="run the bounded ticket-zero pthread churn evidence lane",
    )
    mode.add_argument(
        "--soak",
        action="store_true",
        help="run the larger ticket-zero pthread lifecycle soak lane",
    )
    mode.add_argument(
        "--native-shadow-stress",
        action="store_true",
        help="run the selected-libc four-pthread upstream stress evidence lane",
    )
    perf = parser.add_mutually_exclusive_group()
    perf.add_argument("--perf-smoke", action="store_true", help="attempt the later allocator performance smoke gate")
    perf.add_argument("--perf-full", action="store_true", help="attempt the later allocator performance full gate")
    parser.add_argument("--offline", action="store_true", help="require the verified source archive to already be cached")
    parser.add_argument("--generate-contracts", action="store_true", help="write deterministic checked-in API and upstream-test contracts")
    parser.add_argument("--snapshot-ratchet", action="store_true", help="write the reviewed allocator ratchet after contracts are current")
    parser.add_argument("--check", action="store_true", help="check contracts, source map, and ratchets without compiling C")
    architecture = parser.add_mutually_exclusive_group()
    architecture.add_argument(
        "--architecture",
        "--arch",
        choices=("aarch64", "x86_64"),
        help="native oracle architecture (default: aarch64)",
    )
    architecture.add_argument(
        "--x86-64",
        "--x86_64",
        dest="architecture",
        action="store_const",
        const="x86_64",
        help="explicit native Linux/x86-64 C-oracle profile",
    )
    # The private x86-64 evidence runner exports this allocator-specific
    # selector. Keep direct invocation's historical AArch64 default, while
    # preventing the AArch64 public dispatcher from becoming an x86 surface.
    parser.set_defaults(
        architecture=(
            "x86_64"
            if os.environ.get("CRABC_ALLOCATOR_EVIDENCE_ARCH") == "x86_64"
            else "aarch64"
        )
    )
    arguments = parser.parse_args()
    if not any((arguments.quick, arguments.m1, arguments.m2, arguments.m1_tls_terminal_prototype, arguments.full, arguments.churn, arguments.soak, arguments.native_shadow_stress, arguments.perf_smoke, arguments.perf_full, arguments.generate_contracts, arguments.snapshot_ratchet, arguments.check)):
        parser.error("choose --quick, --m1, --m2, --m1-tls-terminal-prototype, --full, --churn, --soak, --native-shadow-stress, --perf-smoke, --perf-full, --generate-contracts, --snapshot-ratchet, or --check")
    if arguments.generate_contracts or arguments.snapshot_ratchet:
        if arguments.quick or arguments.m1 or arguments.m2 or arguments.m1_tls_terminal_prototype or arguments.full or arguments.churn or arguments.soak or arguments.native_shadow_stress or arguments.perf_smoke or arguments.perf_full:
            parser.error("contract generation/snapshot cannot be combined with a gate mode")
    if arguments.architecture == "x86_64" and (
        arguments.m2
        or arguments.m1_tls_terminal_prototype
        or arguments.full
        or arguments.perf_smoke
        or arguments.perf_full
        or arguments.generate_contracts
        or arguments.snapshot_ratchet
    ):
        parser.error("the native x86-64 profile supports only --quick, --m1, or --check")
    return arguments


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.generate_contracts:
            pin = load_pin()
            archive = fetch_archive(pin, arguments.offline)
            with temporary_directory(prefix="crabc-mimalloc-") as temporary:
                source = safe_extract(archive, Path(temporary), pin["archive_root"])
                contracts = generated_contracts(source, pin)
                validate_owner_exit_publication_contract(
                    read_json(OWNER_EXIT_PUBLICATION_CONTRACT),
                    pin,
                    source,
                )
                write_contracts(contracts)
                print("\n".join(str(path) for path in contracts))
            return 0
        if arguments.snapshot_ratchet:
            port_map = load_port_map()
            snapshot_ratchet(port_map)
            print(RATCHET)
            return 0
        if arguments.native_shadow_stress:
            run_native_shadow_stress(offline=arguments.offline)
            print(NATIVE_SHADOW_STRESS_REPORT)
            return 0
        if arguments.check:
            result = run_milestone0(
                offline=arguments.offline,
                generate_contracts=False,
                check_only=True,
                architecture=arguments.architecture,
            )
            if arguments.architecture == "aarch64":
                m2_contract = read_json(M2_MEMORY_SUBSTRATE_CONTRACT)
                result["m2_memory_substrate_contract"] = (
                    validate_m2_memory_substrate_contract(m2_contract, load_pin())
                )
            else:
                m1_contract = read_json(M1_X86_64_FOUNDATIONS_CONTRACT)
                result["x86_64_m1_foundations_contract"] = (
                    validate_x86_64_m1_foundations_contract(m1_contract, load_pin())
                )
            print(json.dumps(result, sort_keys=True))
            return 0
        if arguments.m1:
            if arguments.architecture == "x86_64":
                report = run_x86_64_m1_foundations(offline=arguments.offline)
                report_path = M1_X86_64_FOUNDATIONS_REPORT
            else:
                report = run_m1_foundations(offline=arguments.offline)
                report_path = M1_FOUNDATIONS_REPORT
            print(report_path)
            if report["milestone"]["status"] != "complete":
                raise MilestoneUnavailable(
                    m1_foundations_unmet_message(report, report_path=report_path)
                )
            return 0
        if arguments.m2:
            report = run_m2_memory_substrate(offline=arguments.offline)
            print(M2_MEMORY_SUBSTRATE_REPORT)
            if report["milestone"]["status"] != "complete":
                raise MilestoneUnavailable(m2_memory_substrate_unmet_message(report))
            return 0
        if arguments.m1_tls_terminal_prototype:
            print(json.dumps(run_m1_compiler_tls_terminal_prototype(offline=arguments.offline), sort_keys=True))
            return 0
        if arguments.soak:
            run_runtime_ticket_zero_soak(
                offline=arguments.offline,
                architecture=arguments.architecture,
            )
            print(RUNTIME_TICKET_ZERO_SOAK_REPORT)
            return 0
        report = run_milestone0(
            offline=arguments.offline,
            generate_contracts=False,
            check_only=False,
            include_test_adapter=arguments.full or arguments.churn,
            include_adapted_stress=arguments.full,
            include_native_owner_exit_lifecycle=arguments.full,
            runtime_ticket_zero_worker_cycles=(
                RUNTIME_TICKET_ZERO_CHURN_WORKER_CYCLES
                if arguments.full or arguments.churn
                else RUNTIME_TICKET_ZERO_DEFAULT_WORKER_CYCLES
            ),
            runtime_ticket_zero_watchdog_seconds=(
                RUNTIME_TICKET_ZERO_CHURN_WATCHDOG_SECONDS
            ),
            runtime_ticket_zero_stress_seed=(
                RUNTIME_TICKET_ZERO_CHURN_STRESS_SEED
                if arguments.full or arguments.churn
                else RUNTIME_TICKET_ZERO_DEFAULT_STRESS_SEED
            ),
            architecture=arguments.architecture,
        )
        if arguments.full:
            # Consume the separately produced canonical matrix once.  Its
            # unavailable/rejected result is durable evidence too; it never
            # triggers a nested upstream-stress build or process.
            report["canonical_upstream_stress"] = (
                consume_canonical_upstream_stress_evidence()
            )
            # This separate private-soak reader is intentionally only a
            # top-level provenance result.  Its checked-in nonclaims keep it
            # out of the M5 acceptance model and prevent a full run from
            # spawning the optional 1,024-cycle fixture again.
            report["runtime_ticket_zero_soak"] = (
                consume_runtime_ticket_zero_soak_evidence()
            )
            gate = m5_gate_report(read_json(M5_GATE_CONTRACT), report)
            report["m5_gate"] = gate
            write_json(REPORT_ROOT / "latest.json", report)
            if gate["overall_status"] == "passed":
                print(REPORT_ROOT / "latest.json")
                return 0
            raise MilestoneUnavailable(
                m5_gate_unmet_message(gate)
            )
        if arguments.perf_smoke or arguments.perf_full:
            raise MilestoneUnavailable(
                "allocator performance is unavailable: Milestone 9 requires comparable C and Rust opaque allocator boundaries plus Milestone 8 integrated crabc backends; the current private one-thread engine is not a benchmark boundary."
            )
        output = (
            X86_64_ORACLE_REPORT_ROOT / "latest.json"
            if arguments.architecture == "x86_64"
            else REPORT_ROOT / "latest.json"
        )
        print(output)
        return 0
    except MilestoneUnavailable as error:
        print(f"UNMET MILESTONE: {error}", file=sys.stderr)
        return 3
    except (HarnessError, OSError, tarfile.TarError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
