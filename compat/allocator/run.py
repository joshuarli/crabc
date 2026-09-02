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
from typing import Any, Iterable, Mapping, Sequence


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
    "compiler-tls-codegen",
    "production-dependency-graph",
)
M1_FOUNDATIONS_COMPONENT_STATUSES = frozenset({"partial", "complete"})
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
  U("sizeof.mi_memid_t", sizeof(mi_memid_t));
  U("alignof.mi_memid_t", _Alignof(mi_memid_t));
  U("offsetof.mi_memid_t.mem", offsetof(mi_memid_t, mem));
  U("offsetof.mi_memid_t.memkind", offsetof(mi_memid_t, memkind));
  U("offsetof.mi_memid_t.is_pinned", offsetof(mi_memid_t, is_pinned));
  U("offsetof.mi_memid_t.initially_committed", offsetof(mi_memid_t, initially_committed));
  U("offsetof.mi_memid_t.initially_zero", offsetof(mi_memid_t, initially_zero));
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
  U("sizeof.mi_page_t", sizeof(mi_page_t));
  U("alignof.mi_page_t", _Alignof(mi_page_t));
  U("offsetof.mi_page_t.xthread_free", offsetof(mi_page_t, xthread_free));
  U("offsetof.mi_page_t.theap", offsetof(mi_page_t, theap));
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
  // In particular, the two 24-byte records take internal.h's generic
  // non-power-of-two division paths.
  U("m1.scalar.is_power_of_two.zero", _mi_is_power_of_two(0));
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
  U("config.ARENA_SLICE_SHIFT", (13 + MI_SIZE_SHIFT));
  U("config.BCHUNK_BITS_SHIFT", (6 + MI_SIZE_SHIFT));
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
    if len(target_parts) != 3 or target_parts[1] != "tests":
        raise HarnessError(
            f"M1 foundations check {check_id} has an unsupported source test filter: {target}"
        )
    module, _, test = target_parts
    source = ROOT / "crabc-mimalloc" / "src" / f"{module}.rs"
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


def m1_foundations_contract_record(
    contract: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Render the checked contract identity retained in each M1 report."""

    return {
        "format": contract["format"],
        "path": relative(M1_FOUNDATIONS_CONTRACT),
        "schema": contract["schema"],
        "sha256": file_digest(M1_FOUNDATIONS_CONTRACT),
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
    features = execution["features"]
    if features:
        command.extend(("--features", ",".join(str(feature) for feature in features)))
    command.extend(("--locked", "--lib", str(check["target"])))
    command.extend(("--", f"--test-threads={execution['test_threads']}"))
    return command


def run_m1_foundations_checks(summary: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Run every focused M1 check in a gate-private Cargo target directory."""

    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(M1_FOUNDATIONS_CARGO_TARGET)
    execution = summary["execution"]
    records: list[dict[str, Any]] = []
    for component in summary["components"]:
        for check in component["checks"]:
            command = m1_foundations_check_command(execution, check)
            result = command_record(
                command,
                cwd=ROOT,
                env=environment,
                timeout_seconds=execution["timeout_seconds"],
            )
            require_success(result, f"M1 foundations check {check['id']}")
            output = str(result["stdout"]) + "\n" + str(result["stderr"])
            passed_test_count = parse_rust_test_count(output)
            if passed_test_count != check["expected_passed_test_count"]:
                raise HarnessError(
                    f"M1 foundations check {check['id']} passed {passed_test_count} tests; "
                    f"expected {check['expected_passed_test_count']}"
                )
            records.append(
                {
                    "component": component["id"],
                    "command": command,
                    "evidence_scope": "focused-source-test",
                    "id": check["id"],
                    "passed_test_count": passed_test_count,
                    "target": check["target"],
                }
            )
    return records


def m1_foundations_layout_evidence(
    components: Sequence[Mapping[str, Any]],
    c_layout: Mapping[str, int],
    rust_layout: Mapping[str, int],
) -> dict[str, dict[str, Any]]:
    """Classify only the layout keys declared by the M1 component contract."""

    evidence: dict[str, dict[str, Any]] = {}
    for component in components:
        keys = component["layout_keys"]
        if not keys:
            evidence[component["id"]] = {
                "keys": [],
                "status": "not-applicable",
            }
            continue
        missing_from_c = sorted(key for key in keys if key not in c_layout)
        if missing_from_c:
            raise HarnessError(
                "M1 foundations required C release layout keys are absent for "
                f"{component['id']}: {', '.join(missing_from_c)}"
            )
        missing_from_rust = sorted(key for key in keys if key not in rust_layout)
        mismatches = [
            f"{key} (C={c_layout[key]}, Rust={rust_layout[key]})"
            for key in keys
            if key in rust_layout and c_layout[key] != rust_layout[key]
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
    focused_checks: Sequence[Mapping[str, Any]],
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
    layout_evidence = m1_foundations_layout_evidence(
        summary["components"], c_layout, rust_layout
    )

    compiler_tls = shared_oracle.get("compiler_tls_codegen")
    dependency_graph = shared_oracle.get("production_dependency_graph")
    if not isinstance(compiler_tls, Mapping) or compiler_tls.get("status") != "passed":
        raise HarnessError("M1 foundations compiler-TLS codegen evidence did not pass")
    if not isinstance(dependency_graph, Mapping):
        raise HarnessError("M1 foundations production dependency evidence is absent")

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
        complete = (
            component["completion_status"] == "complete"
            and not component["remaining_conditions"]
            and layout["status"] in {"matched", "not-applicable"}
        )
        if not complete:
            incomplete_components.append(component_id)
        report_component = {
            "completion_status": component["completion_status"],
            "executed_checks": checks,
            "id": component_id,
            "layout_evidence": layout,
            "remaining_conditions": list(component["remaining_conditions"]),
            "source_map_records": list(component["source_map_records"]),
            "status": "complete" if complete else "partial",
        }
        if component_id == "linux-raw-primitives":
            report_component["prim_h_declaration_inventory"] = list(
                component["prim_h_declaration_inventory"]
            )
        components.append(report_component)

    milestone_complete = (
        summary["milestone"]["status"] == "complete" and not incomplete_components
    )
    release_layout_artifact = release.get("artifact")
    if not isinstance(release_layout_artifact, Mapping):
        raise HarnessError("M1 foundations shared release profile lacks its artifact record")
    return {
        "components": components,
        "contract": m1_foundations_contract_record(contract, pin),
        "exclusions": list(summary["exclusions"]),
        "format": 1,
        "milestone": {
            "completion_rule": summary["milestone"]["completion_rule"],
            "id": "m1",
            "nonclaims": list(summary["milestone"]["nonclaims"]),
            "status": "complete" if milestone_complete else "partial",
            "unmet_component_ids": incomplete_components,
        },
        "schema": "crabc-mimalloc-m1-foundations-report",
        "shared_evidence": {
            "compiler_tls_codegen": {
                "status": compiler_tls["status"],
            },
            "production_dependency_graph": {
                "status": "recorded",
            },
            "release_c_rust_layout": {
                "c_layout_key_count": len(c_layout),
                "c_release_artifact": dict(release_layout_artifact),
                "rust_layout_key_count": len(rust_layout),
                "rust_subset_comparison": rust_release_layout.get("comparison"),
                "scope": (
                    "M1 consumes only the component-declared layout keys; the shared "
                    "oracle's broader M0/M3/M4 traces are supporting producers, not M1 closure."
                ),
            },
        },
        "source": dict(source_attestation),
        "target": dict(summary["target"]),
    }


def run_m1_foundations(*, offline: bool) -> dict[str, Any]:
    """Execute and record the finite M1 gate, including a clean-commit binding."""

    source_before = m1_foundations_source_state()
    pin = load_pin()
    contract = read_json(M1_FOUNDATIONS_CONTRACT)
    port_map = load_port_map()
    summary = validate_m1_foundations_contract(contract, pin, port_map)
    shared_oracle = run_milestone0(
        offline=offline,
        generate_contracts=False,
        check_only=False,
        architecture="aarch64",
        write_report=False,
    )
    focused_checks = run_m1_foundations_checks(summary)
    source_after = m1_foundations_source_state()
    report = m1_foundations_report(
        contract=contract,
        pin=pin,
        summary=summary,
        source_attestation=m1_foundations_source_attestation(source_before, source_after),
        shared_oracle=shared_oracle,
        focused_checks=focused_checks,
    )
    write_json(M1_FOUNDATIONS_REPORT, report)
    return report


def m1_foundations_unmet_message(report: Mapping[str, Any]) -> str:
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
        + f"; review {relative(M1_FOUNDATIONS_REPORT)}"
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
    if upstream.get("project") != "microsoft/mimalloc" or upstream.get("archive_path") != relative(archive_path(pin)):
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
        or upstream.get("archive_path") != relative(archive_path(pin))
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
        or upstream.get("archive_path") != relative(archive_path(pin))
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
    output: str, *, begin: str, end: str, description: str
) -> dict[str, int]:
    """Parse one marked trace and reject address-bearing machine fields.

    Trace records are intentionally portable across allocator processes and
    runs.  A future Rust probe must therefore emit only logical identifiers,
    booleans, sizes, and content fingerprints under the same marker schema;
    raw allocation addresses are neither stable evidence nor an allowed field.
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
            if re.search(r"(?:^|[._-])(?:addr(?:ess)?|ptr|pointer)(?:$|[._-])", key)
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


def build_profile(
    compiler: str,
    readelf: str,
    source: Path,
    name: str,
    flags: Sequence[str],
    *,
    artifact_root: Path = ORACLE_ARTIFACT_ROOT,
    architecture: str = "aarch64",
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
        "layout": parse_layout(str(probe_run["stdout"])),
        "profile": name,
        "symbols": dynamic_symbols(readelf, artifact),
    }
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
    rust_small_trace = parse_small_trace(output)
    rust_fundamental_trace = parse_fundamental_trace(output)
    result = {
        "command": command,
        "comparison": compare_rust_layout(c_release_layout, rust_layout),
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
            name: build_profile(compiler, readelf, source, name, flags)
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
    if not any((arguments.quick, arguments.m1, arguments.full, arguments.churn, arguments.soak, arguments.native_shadow_stress, arguments.perf_smoke, arguments.perf_full, arguments.generate_contracts, arguments.snapshot_ratchet, arguments.check)):
        parser.error("choose --quick, --m1, --full, --churn, --soak, --native-shadow-stress, --perf-smoke, --perf-full, --generate-contracts, --snapshot-ratchet, or --check")
    if arguments.generate_contracts or arguments.snapshot_ratchet:
        if arguments.quick or arguments.m1 or arguments.full or arguments.churn or arguments.soak or arguments.native_shadow_stress or arguments.perf_smoke or arguments.perf_full:
            parser.error("contract generation/snapshot cannot be combined with a gate mode")
    if arguments.architecture == "x86_64" and (
        arguments.m1
        or arguments.full
        or arguments.perf_smoke
        or arguments.perf_full
        or arguments.generate_contracts
        or arguments.snapshot_ratchet
    ):
        parser.error("the native x86-64 profile supports only --quick or --check")
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
            print(json.dumps(result, sort_keys=True))
            return 0
        if arguments.m1:
            report = run_m1_foundations(offline=arguments.offline)
            print(M1_FOUNDATIONS_REPORT)
            if report["milestone"]["status"] != "complete":
                raise MilestoneUnavailable(m1_foundations_unmet_message(report))
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
