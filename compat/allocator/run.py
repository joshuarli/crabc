#!/usr/bin/env python3
"""Build and inventory the pinned mimalloc v3.5.0 C oracle.

This Milestone 0 runner deliberately has no third-party Python dependencies
and never regards the workspace's `libmimalloc-sys` copy as an oracle.  Its
only allocator source input is the SHA-256-verified upstream archive named in
`compat/upstreams.toml`.  It records the existing v3.3.2 integration solely
as migration provenance.

The runner is a source/provenance and C-oracle instrument.  It does not claim
that a Rust allocator operation, adapter symbol, differential trace, or
performance comparison exists before its owning implementation milestone.
"""

from __future__ import annotations

import argparse
import hashlib
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
ALLOCATOR_ROOT = Path(__file__).resolve().parent
UPSTREAMS = ROOT / "compat/upstreams.toml"
CACHE = ALLOCATOR_ROOT / ".cache"
REPORT_ROOT = ROOT / "compat/reports/allocator"
API_CONTRACT = ALLOCATOR_ROOT / "api-v3.5.0.json"
UPSTREAM_TEST_CONTRACT = ALLOCATOR_ROOT / "upstream-tests-v3.5.0.json"
ADAPTED_TEST_CONTRACT = ALLOCATOR_ROOT / "adapted-tests-v3.5.0.json"
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
TLS_CODEGEN_RUNNER = ALLOCATOR_ROOT / "tls-codegen/run.py"
TLS_CODEGEN_REPORT = ROOT / "compat/reports/allocator/tls-codegen.json"
X86_64_TLS_CODEGEN_RUNNER = ALLOCATOR_ROOT / "tls-codegen/run-x86_64.py"
X86_64_TLS_CODEGEN_REPORT = ROOT / "compat/reports/allocator/tls-codegen-x86_64.json"
PORT_MAP = ALLOCATOR_ROOT / "port-map.toml"
RATCHET = ALLOCATOR_ROOT / "ratchet-v3.5.0.json"

PRODUCTION_RUST_TARGET = "aarch64-unknown-linux-musl"
X86_64_RUST_TARGET = "x86_64-unknown-linux-musl"
X86_64_INTERPRETER = "ld-musl-x86_64.so.1"
X86_64_ORACLE_REPORT_ROOT = REPORT_ROOT / "x86_64"

# The checked-in allocator contracts and Rust adapter are intentionally still
# AArch64 contracts.  This explicit native x86-64 profile therefore stops at
# the pinned C oracle: it records the target assumptions needed to compile and
# inspect that oracle without pretending that an AArch64 adapter is portable.
X86_64_TARGET_METADATA: Mapping[str, Any] = {
    "architecture": "x86_64",
    "target": X86_64_RUST_TARGET,
    "interpreter": X86_64_INTERPRETER,
    "expected_dynamic_dependencies": [
        "libc.musl-x86_64.so.1",
        "libgcc_s.so.1",
    ],
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

# This source can compile its wide-environment helper on Linux, but crabc's
# Linux/AArch64 C ABI deliberately has no wide-character environment surface.
# It remains in the symbol cross-check so that the C oracle's actual export is
# never hidden by its crabc applicability classification.
UNSUPPORTED_LINUX_AARCH64_EXTERNAL_REASONS: Mapping[str, str] = {
    "mi_collect_reduce": NORMAL_RELEASE_SYMBOL_EXCEPTIONS["mi_collect_reduce"],
    "mi_stats_merge": NORMAL_RELEASE_SYMBOL_EXCEPTIONS["mi_stats_merge"],
    "mi_wdupenv_s": (
        "Windows wide-character environment API; crabc's Linux/AArch64 ABI "
        "does not provide a wide-character environment surface. The pinned C "
        "oracle does define the symbol, and the release-symbol contract records it."
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

UNSUPPORTED_LINUX_AARCH64_OPTIONS: Mapping[str, str] = {
    "mi_option_os_tag": "macOS-only OS logging tag option in the pinned v3.5.0 header.",
    "mi_option_retry_on_oom": "Windows-only out-of-memory retry option in the pinned v3.5.0 header.",
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
  U("sizeof.mi_random_ctx_t", sizeof(mi_random_ctx_t));
  U("alignof.mi_random_ctx_t", _Alignof(mi_random_ctx_t));
  U("offsetof.mi_random_ctx_t.input", offsetof(mi_random_ctx_t, input));
  U("offsetof.mi_random_ctx_t.output", offsetof(mi_random_ctx_t, output));
  U("offsetof.mi_random_ctx_t.output_available", offsetof(mi_random_ctx_t, output_available));
  U("offsetof.mi_random_ctx_t.weak", offsetof(mi_random_ctx_t, weak));
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

  const size_t aligned_size = 97;
  const size_t aligned_alignment = 256;
  uint8_t* const aligned = (uint8_t*)mi_malloc_aligned(aligned_size, aligned_alignment);
  if (aligned == NULL) return 16;
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
  if (offset_aligned == NULL) return 17;
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
    return 18;
  }

  puts("CRABC_MI_FUNDAMENTAL_TRACE_END");
  return 0;
}
"""


class HarnessError(RuntimeError):
    """A reproducibility, source, or oracle-build contract failure."""


class MilestoneUnavailable(HarnessError):
    """A requested later milestone has no implementation yet."""


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
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessError(f"invalid JSON contract: {path}") from error
    if not isinstance(value, dict):
        raise HarnessError(f"JSON contract is not an object: {path}")
    return value


def load_pin(path: Path = UPSTREAMS) -> dict[str, str]:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HarnessError(f"invalid upstream pin file: {path}") from error
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


def validate_adapted_test_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str], adapter_header: str
) -> dict[str, int]:
    """Validate the reviewed M4 patch, selection, and private ABI contract."""

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
    if not isinstance(patch, dict) or patch.get("path") != "compat/allocator/adapted/test-api-m4.patch":
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
    for key in ("patch_applies_cleanly", "patch_round_trip_stable", "adapted_source_sha256_verified", "header_compile_verified"):
        if verification.get(key) is not True:
            raise HarnessError(f"adapted allocator verification is not true: {key}")
    if verification.get("unsupported_raw_mi_references_found") != []:
        raise HarnessError("adapted allocator fixture retains unsupported raw mi_* references")

    return {
        "expected_adapter_symbol_count": len(expected_symbols),
        "omitted_test_count": len(omitted),
        "selected_test_count": len(selected),
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
        if name in UNSUPPORTED_LINUX_AARCH64_OPTIONS:
            classification = "unsupported-linux-aarch64"
            reason = UNSUPPORTED_LINUX_AARCH64_OPTIONS[name]
            profile = "not-applicable-linux-aarch64"
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
        if name in UNSUPPORTED_LINUX_AARCH64_EXTERNAL_REASONS:
            classification = "unsupported-linux-aarch64"
            reason = UNSUPPORTED_LINUX_AARCH64_EXTERNAL_REASONS[name]
            profile = "not-applicable-linux-aarch64"
            test_adapter_applicable = False
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
    applicable_external = kind == "external-function" and classification["test_adapter_applicable"]
    return {
        "adapter_surface": "test-c-api-adapter-only" if applicable_external else "source-only",
        **classification,
        "crabc_libc_exported": False,
        "differential_verified": False,
        "exported": False,
        "group": api_group(name) if kind in {"external-function", "option", "type"} else "source-convenience",
        "headers": list(headers),
        "implemented": False,
        "intentional_difference": "",
        "kind": kind,
        "name": name,
        "oracle_release_exported": (
            kind == "external-function" and name not in NORMAL_RELEASE_SYMBOL_EXCEPTIONS
        ),
        "performance_qualified": False,
        "stress_verified": False,
        "test_references": list(tests),
        "unit_verified": False,
    }


def test_sources(source: Path) -> list[Path]:
    root = source / "test"
    paths = [path for path in root.rglob("*") if path.is_file() and path.suffix in {".c", ".cc", ".cpp", ".h"}]
    if not paths:
        raise HarnessError("pinned mimalloc source has no upstream test sources")
    return sorted(paths)


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

    config_names = sorted(macro_configuration_names(source))
    return {
        "archive_root": pin["archive_root"],
        "format": 2,
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
            "configuration_macro_count": len(config_names),
            "cxx_convenience_count": sum(item["kind"] == "cxx-convenience" for item in items),
            "cxx_template_count": sum(item["kind"] == "cxx-template" for item in items),
            "external_function_count": sum(item["kind"] == "external-function" for item in items),
            "macro_count": sum(item["kind"] == "macro" for item in items),
            "option_count": sum(item["kind"] == "option" for item in items),
            "override_macro_count": sum(item["kind"] == "override-macro" for item in items),
            "source_only_count": sum(item["adapter_surface"] == "source-only" for item in items),
            "source_only_macro_count": sum(item["kind"] in {"macro", "override-macro"} for item in items),
            "static_inline_count": sum(item["kind"] == "static-inline" for item in items),
            "total_item_count": len(items),
            "type_count": sum(item["kind"] == "type" for item in items),
        },
    }


def build_test_inventory(source: Path, pin: Mapping[str, str]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for path in test_sources(source):
        name = path.relative_to(source).as_posix()
        kind = "test-source" if path.suffix in {".c", ".cc", ".cpp"} else "test-support"
        items.append(
            {
                "blocked_by": "Milestone 4: the prefixed Rust test C API adapter is not implemented.",
                "kind": kind,
                "path": name,
                "sha256": sha256_file(path),
                "status": "blocked-milestone-4",
            }
        )
    return {
        "format": 1,
        "mimalloc_version": pin["version"],
        "pinned_archive_sha256": pin["sha256"],
        "tests": items,
        "summary": {
            "blocked_milestone_4_count": sum(item["kind"] == "test-source" for item in items),
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
        "api_total_item_count",
        "configuration_profile_count",
        "upstream_test_source_count",
        "upstream_test_inventory_file_count",
    ):
        old_value = baseline.get(key)
        new_value = current.get(key)
        if old_value is None and new_value is None:
            continue
        if key.startswith("adapted_") and old_value is None and type(new_value) is int:
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
    return {
        "adapted_omitted_test_count": len(adapted_tests["omitted_tests"]),
        "adapted_selected_test_count": len(adapted_tests["selected_tests"]),
        "adapted_test_contract_sha256": file_digest(ADAPTED_TEST_CONTRACT),
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
        "api_contract_sha256",
        "port_map_sha256",
        "upstream_test_contract_sha256",
    ):
        if current[key] != baseline.get(key):
            raise HarnessError(f"allocator ratchet input changed: {key}; snapshot and review explicitly")


def require_native_aarch64() -> None:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise HarnessError("allocator C oracle requires the pinned native Linux/AArch64 development image")


def require_native_x86_64() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise HarnessError(
            "x86-64 allocator C oracle requires the native Linux/x86-64 development image; "
            "emulation is not accepted"
        )


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
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=300,
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
    c_trace: Mapping[str, int], rust_trace: Mapping[str, int]
) -> dict[str, Any]:
    """Require a future Rust fundamental trace to equal the pinned C record."""

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
    require_success(record, "adapter dynamic dependency inventory")
    return sorted(set(re.findall(r"Shared library: \[([^\]]+)\]", str(record["stdout"]))))


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
    """Require the test-only cdylib to expose exactly its prefixed C surface."""

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
    contract: Mapping[str, Any], adapter_header: str
) -> dict[str, Any]:
    """Validate the separate C witness without widening the M4 adapter."""

    if (
        contract.get("format") != 1
        or contract.get("schema") != "crabc-mimalloc-runtime-ticket-zero-test"
    ):
        raise HarnessError("runtime ticket-zero adapter contract has an unknown schema")
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
    expected_symbols = contract.get("expected_adapter_symbols")
    if not isinstance(expected_symbols, list) or not all(
        isinstance(symbol, str) for symbol in expected_symbols
    ):
        raise HarnessError("runtime ticket-zero adapter contract has invalid expected symbols")
    if runtime_ticket_zero_adapter_header_function_names(adapter_header) != sorted(expected_symbols):
        raise HarnessError(
            "runtime ticket-zero adapter header declarations differ from its contract"
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
    return {
        "command": command,
        "record": parse_fundamental_trace(str(run["stdout"])),
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
    report_root: Path = REPORT_ROOT,
    architecture: str = "aarch64",
) -> dict[str, Any]:
    profile_dir = report_root / "oracle" / name
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
    header_text = str(header["stdout"])
    machine_marker = {
        "aarch64": "AArch64",
        "x86_64": "Advanced Micro Devices X86-64",
    }.get(architecture)
    if machine_marker is None:
        raise HarnessError(f"unsupported allocator oracle architecture: {architecture}")
    if machine_marker not in header_text or "little endian" not in header_text:
        raise HarnessError(
            f"C oracle artifact is not little-endian {architecture}: {artifact}"
        )
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
            "c_oracle": build_fundamental_trace(compiler, source, profile_dir, flags),
            "rust_comparison": pending_fundamental_trace_comparison(),
        }
    return result


def validate_production_dependency_graph(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Judge the exact normal dependency graph selected for production AArch64.

    Cargo lockfiles retain target-conditional packages, so lockfile presence is
    not evidence that a dependency is linked. The caller must obtain `metadata`
    with `--filter-platform` for `PRODUCTION_RUST_TARGET`; this function then
    traverses only normal dependency edges reachable from `crabc-mimalloc`.
    """

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
        and package.get("version") == EXPECTED_PRODUCTION_DEPENDENCY_VERSIONS["crabc-mimalloc"]
        and package.get("source") is None
    ]
    if len(roots) != 1:
        raise HarnessError("Cargo metadata must contain exactly one workspace crabc-mimalloc 0.3.0 root")

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
    expected_versions = set(EXPECTED_PRODUCTION_DEPENDENCY_VERSIONS.items())
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
        for target in raw_targets:
            if not isinstance(target, dict) or not isinstance(target.get("kind"), list):
                raise HarnessError(f"Cargo metadata has an invalid target for {name} {version}")
            kinds = target["kind"]
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
        for name, dependencies in EXPECTED_PRODUCTION_DEPENDENCY_EDGES.items()
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
        "target": PRODUCTION_RUST_TARGET,
    }


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

    command = [
        "cargo",
        "test",
        "-p",
        "crabc-mimalloc",
        "--lib",
    ]
    if rust_target is not None:
        command.extend(("--target", rust_target))
    command.extend((
        "--",
        "--nocapture",
    ))
    record = command_record(command, cwd=ROOT)
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
                c_release_fundamental_trace, rust_fundamental_trace
            ),
            "record": rust_fundamental_trace,
        },
    }
    if rust_target is not None:
        result["target"] = rust_target
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
) -> tuple[Path, list[str], dict[str, Any]]:
    """Build and audit the test-only prefixed Rust staticlib/cdylib pair."""

    artifact_root = REPORT_ROOT / "test-adapter"
    cargo_target = artifact_root / "cargo-target"
    artifact_root.mkdir(parents=True, exist_ok=True)
    clean_command = [
        "cargo",
        "clean",
        "--package",
        "crabc-mimalloc-test-adapter",
        "--target",
        PRODUCTION_RUST_TARGET,
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
        PRODUCTION_RUST_TARGET,
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
        PRODUCTION_RUST_TARGET,
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
    compile_requirements = contract["compile_requirements"]
    assert isinstance(compile_requirements, dict)
    native_search_paths = compile_requirements["native_library_search_paths"]
    assert isinstance(native_search_paths, list)
    if native_libraries != compile_requirements["native_static_libs"]:
        raise HarnessError("Rust test adapter native static library order differs from the manifest")

    release_root = cargo_target / PRODUCTION_RUST_TARGET / "release"
    static_library = release_root / "libcrabc_mimalloc_test_adapter.a"
    shared_library = release_root / "libcrabc_mimalloc_test_adapter.so"
    expected_symbols = contract["expected_adapter_symbols"]
    assert isinstance(expected_symbols, list)
    shared_symbols = validate_adapter_dynamic_symbols(
        defined_dynamic_symbols(readelf, shared_library), expected_symbols
    )
    archive_symbols = validate_adapter_dynamic_symbols(
        archive_defined_symbols(nm, static_library), expected_symbols
    )
    needed = dynamic_dependencies(readelf, shared_library)
    if needed != compile_requirements["expected_dynamic_dependencies"]:
        raise HarnessError("Rust test adapter dynamic dependency set differs from the manifest")

    return static_library, native_libraries, {
        "archive": artifact_record(static_library),
        "archive_symbols": archive_symbols,
        "clean_command": clean_command,
        "dynamic_dependencies": needed,
        "native_library_search_paths": native_search_paths,
        "native_static_libraries": native_libraries,
        "rustc_command": rustc_command,
        "shared_library": artifact_record(shared_library),
        "shared_symbols": shared_symbols,
        "unit_test_command": test_command,
        "unit_test_count": parse_rust_test_count(test_output),
    }


def build_runtime_ticket_zero_adapter(
    readelf: str,
    nm: str,
    contract: Mapping[str, Any],
) -> tuple[Path, list[str], dict[str, Any]]:
    """Build and audit the separate no_std runtime page-owner test ABI."""

    artifact_root = REPORT_ROOT / "runtime-ticket-zero-adapter"
    cargo_target = artifact_root / "cargo-target"
    artifact_root.mkdir(parents=True, exist_ok=True)
    package = str(contract["adapter_package"])
    clean_command = [
        "cargo",
        "clean",
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

    release_root = cargo_target / PRODUCTION_RUST_TARGET / "release"
    static_library = release_root / "libcrabc_mimalloc_runtime_ticket_zero_adapter.a"
    shared_library = release_root / "libcrabc_mimalloc_runtime_ticket_zero_adapter.so"
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
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    """Run the existing allocator fixture and selected upstream API checks."""

    artifact_root = REPORT_ROOT / "test-adapter"
    compile_requirements = contract["compile_requirements"]
    assert isinstance(compile_requirements, dict)
    native_search_paths = compile_requirements["native_library_search_paths"]
    assert isinstance(native_search_paths, list)
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
    fixture_run = command_record((str(fixture_binary),), cwd=ROOT)
    if fixture_run["status"] != 0 or fixture_run["stdout"] != "allocator ok\n":
        raise HarnessError(
            "existing allocator fixture failed against Rust adapter: "
            f"status={fixture_run['status']} stdout={fixture_run['stdout']!r} "
            f"stderr={fixture_run['stderr']!r}"
        )

    adapted_binary = artifact_root / "upstream-test-api-m4-rust"
    adapted_source = source / str(contract["adapted_source"]["path"])
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
    adapted_run = command_record((str(adapted_binary),), cwd=source)
    require_success(adapted_run, "adapted upstream API fixture")
    summary = parse_upstream_api_test_summary(
        str(adapted_run["stdout"]) + "\n" + str(adapted_run["stderr"])
    )
    selected = contract["selected_tests"]
    assert isinstance(selected, list)
    if summary["succeeded"] != len(selected):
        raise HarnessError(
            "adapted upstream API summary count differs from the reviewed selection"
        )

    return {
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


def run_runtime_ticket_zero_adapter_fixture(
    compiler: str,
    static_library: Path,
    native_libraries: Sequence[str],
) -> dict[str, Any]:
    """Run one fresh process through the permanent ticket-zero C witness."""

    artifact_root = REPORT_ROOT / "runtime-ticket-zero-adapter"
    fixture_binary = artifact_root / "runtime-ticket-zero-fixture"
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
    fixture_build = command_record(fixture_command, cwd=ROOT)
    require_success(fixture_build, "runtime ticket-zero C fixture build")
    fixture_run = command_record((str(fixture_binary),), cwd=ROOT)
    if (
        fixture_run["status"] != 0
        or fixture_run["stdout"] != "runtime ticket-zero allocator ok\n"
    ):
        raise HarnessError(
            "runtime ticket-zero C fixture failed: "
            f"status={fixture_run['status']} stdout={fixture_run['stdout']!r} "
            f"stderr={fixture_run['stderr']!r}"
        )
    return {
        "artifact": artifact_record(fixture_binary),
        "build_command": fixture_command,
        "run_command": [str(fixture_binary)],
        "stdout": str(fixture_run["stdout"]),
    }


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
    contracts: Mapping[Path, Mapping[str, Any]],
    port_map: Mapping[str, Any],
) -> dict[str, Any]:
    """Run only the native x86-64 pinned C-oracle lane.

    The AArch64 API/adapter contracts remain the production contract.  This
    lane deliberately proves source identity, C layouts/traces, ELF machine
    identity, native direct-Rust configuration/layout/trace parity, compiler
    TLS code generation, and the x86-64 musl target assumptions while leaving
    the target-dependent Rust adapter and dependency graph unclaimed.
    """

    require_native_x86_64()
    compiler = require_tool("musl-gcc")
    readelf = require_tool("readelf")
    profiles = {
        name: build_profile(
            compiler,
            readelf,
            source,
            name,
            flags,
            report_root=X86_64_ORACLE_REPORT_ROOT,
            architecture="x86_64",
        )
        for name, flags in CONFIGURATION_PROFILES.items()
    }
    release_symbol_contract = validate_release_symbol_contract(
        contracts[API_CONTRACT], profiles["release"]["symbols"]
    )
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
    report["contracts"] = {
        relative(path): payload["summary"] for path, payload in contracts.items()
    }
    report["port_map"] = port_map_counts(port_map)
    report["release_symbol_contract"] = release_symbol_contract
    # The unit suite exercises the direct no_std engine against this native C
    # oracle. It is intentionally not evidence for the AArch64-only C adapter
    # or for public allocator integration.
    report["rust_direct_engine"] = rust_direct_engine
    report["compiler_tls_codegen"] = compiler_tls_codegen(architecture="x86_64")
    report["unsupported_lanes"] = {
        "rust_adapter": (
            "not run: the checked-in adapter contract is target-specific to "
            "AArch64 and this profile owns only native x86-64 C-oracle evidence"
        ),
        "production_dependency_graph": (
            "not run: the production graph contract is target-specific to "
            f"{PRODUCTION_RUST_TARGET}"
        ),
        "public_allocator_integration": (
            "not run: public crabc allocator integration and default promotion "
            "remain Linux/AArch64-only"
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
    architecture: str = "aarch64",
) -> dict[str, Any]:
    if architecture not in {"aarch64", "x86_64"}:
        raise HarnessError(f"unsupported allocator oracle architecture: {architecture}")
    if architecture == "x86_64" and not check_only:
        # Refuse an accidental foreign/emulated invocation before downloading
        # or compiling anything for the native-only profile.
        require_native_x86_64()
    pin = load_pin()
    archive = fetch_archive(pin, offline)
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-") as temporary:
        source = safe_extract(archive, Path(temporary), pin["archive_root"])
        contracts = generated_contracts(source, pin)
        if generate_contracts:
            write_contracts(contracts)
        else:
            check_contracts(contracts)
        port_map = load_port_map()
        check_ratchet(port_map)
        if architecture == "x86_64":
            if check_only:
                return {
                    "architecture_profile": "x86_64-native-c-oracle",
                    "contracts": {
                        relative(path): payload["summary"]
                        for path, payload in contracts.items()
                    },
                    "port_map": port_map_counts(port_map),
                    "status": "checked",
                }
            return run_x86_64_oracle(
                pin=pin,
                archive=archive,
                source=source,
                contracts=contracts,
                port_map=port_map,
            )
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
        runtime_ticket_zero_contract = read_json(RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT)
        runtime_ticket_zero_summary = validate_runtime_ticket_zero_adapter_contract(
            runtime_ticket_zero_contract,
            RUNTIME_TICKET_ZERO_ADAPTER_HEADER.read_text(encoding="utf-8"),
        )
        if check_only:
            return {
                "adapted_test_contract": adapted_summary,
                "adapted_test_patch": adapted_patch,
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
        report["port_map"] = port_map_counts(port_map)
        report["compiler_tls_codegen"] = compiler_tls_codegen()
        report["production_dependency_graph"] = dependency_graph
        report["remote_free_loom_model"] = loom_remote_free_model()
        report["release_symbol_contract"] = release_symbol_contract
        report["rust_release_layout"] = rust_layout
        report["adapted_test_contract"] = adapted_summary
        report["adapted_test_patch"] = adapted_patch
        report["runtime_ticket_zero_test_contract"] = runtime_ticket_zero_summary
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
            runtime_static_library, runtime_native_libraries, runtime_adapter_build = (
                build_runtime_ticket_zero_adapter(readelf, nm, runtime_ticket_zero_contract)
            )
            report["runtime_ticket_zero_test_adapter"] = {
                "build": runtime_adapter_build,
                "fixture": run_runtime_ticket_zero_adapter_fixture(
                    compiler,
                    runtime_static_library,
                    runtime_native_libraries,
                ),
            }
        write_json(REPORT_ROOT / "latest.json", report)
        return report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="run the Milestone 0 C oracle and deterministic contract gate")
    mode.add_argument("--full", action="store_true", help="attempt the later full allocator gate")
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
    # The architecture-specific Docker wrappers export CRABC_DEV_ARCH.  Keep
    # direct invocation's historical AArch64 default, while allowing
    # `scripts/dev-amd64.sh allocator --quick` to select the explicit x86-64
    # lane without reusing an AArch64 report or target assumption.
    parser.set_defaults(
        architecture=(
            "x86_64" if os.environ.get("CRABC_DEV_ARCH") == "x86_64" else "aarch64"
        )
    )
    arguments = parser.parse_args()
    if not any((arguments.quick, arguments.full, arguments.perf_smoke, arguments.perf_full, arguments.generate_contracts, arguments.snapshot_ratchet, arguments.check)):
        parser.error("choose --quick, --full, --perf-smoke, --perf-full, --generate-contracts, --snapshot-ratchet, or --check")
    if arguments.generate_contracts or arguments.snapshot_ratchet:
        if arguments.quick or arguments.full or arguments.perf_smoke or arguments.perf_full:
            parser.error("contract generation/snapshot cannot be combined with a gate mode")
    if arguments.architecture == "x86_64" and (
        arguments.full or arguments.perf_smoke or arguments.perf_full
    ):
        parser.error("the native x86-64 profile supports only --quick or --check")
    return arguments


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.generate_contracts:
            pin = load_pin()
            archive = fetch_archive(pin, arguments.offline)
            with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-") as temporary:
                source = safe_extract(archive, Path(temporary), pin["archive_root"])
                contracts = generated_contracts(source, pin)
                write_contracts(contracts)
                print("\n".join(str(path) for path in contracts))
            return 0
        if arguments.snapshot_ratchet:
            port_map = load_port_map()
            snapshot_ratchet(port_map)
            print(RATCHET)
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
        run_milestone0(
            offline=arguments.offline,
            generate_contracts=False,
            check_only=False,
            include_test_adapter=arguments.full,
            architecture=arguments.architecture,
        )
        if arguments.full:
            raise MilestoneUnavailable(
                "allocator --full remains unavailable after the passing Milestone 4 adapter lane: Milestone 5 must complete integrated remote free, lifecycle-safe abandonment/adoption and release, thread/TLS lifecycle, remaining Loom protocols, and pthread stress before later backend, fork, and corpus lanes can run."
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
