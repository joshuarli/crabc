#!/usr/bin/env python3
"""Differentially prove bounded small direct-cache on-demand extensions.

This private native-x86-64 lane compiles the pinned mimalloc 3.5.0 C oracle
and compares its address-independent reserved-small direct-cache trace with
the crate-private Rust test
``main_heap_page::tests::ordinary_reserved_small_direct_on_demand_extensions_follow_source_prefix_boundaries``.
Both probes allocate 1024-byte small objects from one explicitly reserved
arena. They observe the fixed initial 8-object/four-OS-page prefix, the
no-commit extension reached by allocation nine, and the poststate of the
source-anchored direct page-area commit-before-extension branch at allocation
seventeen. The exact direct-cache range, queue, PageMap, arena-bit, and final
normal-release witnesses are recorded without exposing any address or
allocator identity. The trace is not temporal instrumentation; the pinned
source anchors establish the branch's mutation order.

The C probe alone uses ``mi_option_page_commit_on_demand`` to choose its
pinned-source branch. Rust uses a crate-private ``cfg(test)`` seam only. This
does not claim C fault-injection parity, Rust production option processing,
fresh fallback, public ``mi_*`` behavior, public x86 runtime support, libc or
backend integration, or AArch64 evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-direct-on-demand-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/direct-on-demand.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/main_heap_page.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = (
    "main_heap_page::tests::ordinary_reserved_small_direct_on_demand_extensions_follow_source_prefix_boundaries"
)
TRACE_BEGIN = "CRABC_MI_ON_DEMAND_DIRECT_TRACE_BEGIN"
TRACE_END = "CRABC_MI_ON_DEMAND_DIRECT_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded direct-cache differential could not establish its claim."""


EXPECTED_TARGET = {
    "architecture": "x86_64",
    "endianness": "little",
    "rust_target": TARGET,
    "system": "linux",
}
EXPECTED_UPSTREAM = {
    "archive_root": "mimalloc-3.5.0",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "version": "3.5.0",
}
EXPECTED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
EXPECTED_PROFILE = "linux-x86_64-private-reserved-small-direct-on-demand-prefix-boundaries"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "native_linux_x86_64_required": True,
    "oracle_option_setup_only": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "reserved_small_direct_on_demand_extensions_only": True,
    "failed_commit_recovery_claimed": False,
    "production_page_on_demand_policy_claimed": False,
    "fresh_fallback_claimed": False,
}
EXPECTED_COMPILE_DEFINITIONS = (
    "-DMI_SHARED_LIB",
    "-DMI_SHARED_LIB_EXPORT",
    "-DMI_LIBC_MUSL=1",
)
EXPECTED_C_ELF = {
    "class": "ELF64",
    "endianness": "little",
    "machine": "Advanced Micro Devices X86-64",
}
EXPECTED_SOURCE_ANCHORS = (
    ("src/alloc.c", 29, 58, "ebecab0a27c74739c146a986504e36e8361dbac617a78071cc97ef8d3e67602a"),
    ("src/alloc.c", 132, 159, "7e0bfe74a463bbe348abe76b053d33a413c8b808222f64f77b921a51a6f13b78"),
    ("src/alloc.c", 204, 214, "1cc8fd1bdc079b0fc4fc4d3ac4f9fbbdc81cb73dbd700b2958e7012100973723"),
    ("include/mimalloc/internal.h", 650, 655, "6388823e5d1e066d764c6d2f506a1f852325be603eac748877f5411dec492fcc"),
    ("src/page-queue.c", 204, 244, "4216ce3f998d0a8c3891e0c89e1feaa34aff407d10e14135e68334ce833d6e6b"),
    ("src/page.c", 630, 706, "c2fdd18ad991b45c8bf8f8a6441f66c1c2dbfe1f5f81e60688e8e66fd32865f3"),
    ("src/page.c", 709, 758, "b2cfe8e2b1154751399e9c71b8782883e4f19f5bfe73bd36766a9c368deb72f1"),
    ("src/page.c", 765, 875, "3c8a1de257b88eb5c17b54da1cca31337fc9555aaca6a1cf167f3f0f4aaa7598"),
    ("src/page.c", 879, 917, "b9a8d102ea3285c4f0283e7379d621f36dde91728a5daa3306e764e979a949b6"),
    ("src/arena.c", 951, 1069, "b1c4e4f4c2f7d18243066233baa3070a563c51b0d55a212aeea990f8a1289fcf"),
    ("src/arena.c", 1138, 1154, "4777f29be08991a04391029e1cd4daabcc00f2e53e9e6f36f20ad69093a142ed"),
)

# All values are fixed, address-independent observations from one native
# x86-64 release profile. The geometry includes the initial partial prefix,
# its ordinary no-commit extension, and the first required direct commit.
EXPECTED_TRACE_VALUES = {
    "trace.on_demand_direct.arena_backed": 1,
    "trace.on_demand_direct.reserved_mapping": 1,
    "trace.on_demand_direct.small_direct_page": 1,
    "trace.on_demand_direct.initial_prefix_four_os_pages": 1,
    "trace.on_demand_direct.initial_capacity_eight": 1,
    "trace.on_demand_direct.initial_direct_range_registered": 1,
    "trace.on_demand_direct.initial_queue_registered": 1,
    "trace.on_demand_direct.initial_page_map_registered": 1,
    "trace.on_demand_direct.initial_arena_bit_set": 1,
    "trace.on_demand_direct.first_eight_direct_head": 1,
    "trace.on_demand_direct.first_eight_same_page": 1,
    "trace.on_demand_direct.eighth_full_prefix": 1,
    "trace.on_demand_direct.ninth_same_page": 1,
    "trace.on_demand_direct.ninth_zero_commit": 1,
    "trace.on_demand_direct.ninth_capacity_sixteen": 1,
    "trace.on_demand_direct.ninth_used_nine": 1,
    "trace.on_demand_direct.second_direct_head": 1,
    "trace.on_demand_direct.sixteenth_full_prefix": 1,
    "trace.on_demand_direct.seventeenth_same_page": 1,
    "trace.on_demand_direct.seventeenth_commit_before_extension": 1,
    "trace.on_demand_direct.seventeenth_capacity_twenty_four": 1,
    "trace.on_demand_direct.seventeenth_used_seventeen": 1,
    "trace.on_demand_direct.direct_range_after_commit": 1,
    "trace.on_demand_direct.queue_registered_after_commit": 1,
    "trace.on_demand_direct.page_map_registered_after_commit": 1,
    "trace.on_demand_direct.arena_bit_set_after_commit": 1,
    "trace.on_demand_direct.payload_preserved": 1,
    "trace.on_demand_direct.final_page_released": 1,
    "trace.on_demand_direct.initial_capacity": 8,
    "trace.on_demand_direct.initial_used": 1,
    "trace.on_demand_direct.initial_slice_pcommitted": 4,
    "trace.on_demand_direct.eighth_capacity": 8,
    "trace.on_demand_direct.eighth_used": 8,
    "trace.on_demand_direct.eighth_slice_pcommitted": 4,
    "trace.on_demand_direct.ninth_capacity": 16,
    "trace.on_demand_direct.ninth_used": 9,
    "trace.on_demand_direct.ninth_slice_pcommitted": 4,
    "trace.on_demand_direct.sixteenth_capacity": 16,
    "trace.on_demand_direct.sixteenth_used": 16,
    "trace.on_demand_direct.sixteenth_slice_pcommitted": 4,
    "trace.on_demand_direct.seventeenth_capacity": 24,
    "trace.on_demand_direct.seventeenth_used": 17,
    "trace.on_demand_direct.seventeenth_slice_pcommitted": 8,
    "trace.on_demand_direct.valid": 1,
}

# The fixture intentionally uses the public small entry only to select the
# frozen direct-cache path. Every structural observation is private oracle
# evidence from `mimalloc/internal.h`. The C option is set only after saving
# its value and is restored on every exit; Rust has no corresponding option
# API or policy.
C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "bitmap.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private direct-on-demand fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private direct-on-demand fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0
#error this private direct-on-demand fixture requires the native x86-64 two-level PageMap branch
#endif

_Static_assert(sizeof(void*) == 8, "this private fixture requires 64-bit pointers");
_Static_assert(sizeof(size_t) == 8, "this private fixture requires 64-bit size_t");

static bool direct_cache_image_matches_page(
    const mi_theap_t* theap,
    const mi_page_queue_t* queue,
    const mi_page_t* page
) {
  const size_t size = queue->block_size;
  if (size > MI_SMALL_SIZE_MAX) return false;
  const size_t index = _mi_wsize_from_size(size);
  if (index >= MI_PAGES_DIRECT) return false;

  size_t start = 0;
  if (index > 1) {
    const size_t bin = _mi_bin(size);
    const mi_page_queue_t* previous = queue - 1;
    while (bin == _mi_bin(previous->block_size) && previous > &theap->pages[0]) {
      previous--;
    }
    start = 1 + _mi_wsize_from_size(previous->block_size);
    if (start > index) start = index;
  }
  for (size_t slot = 0; slot < MI_PAGES_DIRECT; slot++) {
    const mi_page_t* expected = (slot >= start && slot <= index)
        ? page
        : _mi_page_empty_get();
    if (theap->pages_free_direct[slot] != expected) return false;
  }
  return true;
}

int main(void) {
  const size_t request = MI_SMALL_SIZE_MAX;
  void* blocks[17] = { NULL };
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_queue_t* queue = NULL;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  size_t slice = 0;
  long old_page_commit_on_demand = 0;
  bool option_changed = false;
  bool valid = false;
  int stage = 0;

  int arena_backed = 0;
  int reserved_mapping = 0;
  int small_direct_page = 0;
  int initial_prefix_four_os_pages = 0;
  int initial_capacity_eight = 0;
  int initial_direct_range_registered = 0;
  int initial_queue_registered = 0;
  int initial_page_map_registered = 0;
  int initial_arena_bit_set = 0;
  int first_eight_direct_head = 0;
  int first_eight_same_page = 0;
  int eighth_full_prefix = 0;
  int ninth_same_page = 0;
  int ninth_zero_commit = 0;
  int ninth_capacity_sixteen = 0;
  int ninth_used_nine = 0;
  int second_direct_head = 0;
  int sixteenth_full_prefix = 0;
  int seventeenth_same_page = 0;
  int seventeenth_commit_before_extension = 0;
  int seventeenth_capacity_twenty_four = 0;
  int seventeenth_used_seventeen = 0;
  int direct_range_after_commit = 0;
  int queue_registered_after_commit = 0;
  int page_map_registered_after_commit = 0;
  int arena_bit_set_after_commit = 0;
  int payload_preserved = 0;
  int final_page_released = 0;

  size_t initial_capacity = 0;
  size_t initial_used = 0;
  size_t initial_slice_pcommitted = 0;
  size_t eighth_capacity = 0;
  size_t eighth_used = 0;
  size_t eighth_slice_pcommitted = 0;
  size_t ninth_capacity = 0;
  size_t ninth_used = 0;
  size_t ninth_slice_pcommitted = 0;
  size_t sixteenth_capacity = 0;
  size_t sixteenth_used = 0;
  size_t sixteenth_slice_pcommitted = 0;
  size_t seventeenth_capacity = 0;
  size_t seventeenth_used = 0;
  size_t seventeenth_slice_pcommitted = 0;

  old_page_commit_on_demand = mi_option_get(mi_option_page_commit_on_demand);
  mi_option_set(mi_option_page_commit_on_demand, 1);
  option_changed = true;
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), false, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto cleanup;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto cleanup;

  blocks[0] = mi_heap_malloc_small(heap, request);
  if (blocks[0] == NULL) goto cleanup;
  page = _mi_ptr_page(blocks[0]);
  theap = mi_heap_theap(heap);
  if (page == NULL || theap == NULL) goto cleanup;
  if (page->memid.memkind != MI_MEM_ARENA) goto cleanup;
  queue = mi_page_queue(theap, page->block_size);
  arena = page->memid.mem.arena.arena;
  if (queue == NULL || arena == NULL) goto cleanup;
  arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  slice = page->memid.mem.arena.slice_index;
  if (arena_pages == NULL) goto cleanup;

  arena_backed = page->memid.memkind == MI_MEM_ARENA;
  reserved_mapping = !page->memid.initially_committed;
  small_direct_page = page->block_size == request && page->block_size <= MI_SMALL_SIZE_MAX
      && page->memid.mem.arena.slice_count == 1;
  initial_capacity = page->capacity;
  initial_used = page->used;
  initial_slice_pcommitted = page->slice_pcommitted;
  initial_prefix_four_os_pages = initial_slice_pcommitted == 4;
  initial_capacity_eight = initial_capacity == 8;
  initial_direct_range_registered = direct_cache_image_matches_page(theap, queue, page);
  initial_queue_registered = queue->count == 1 && queue->first == page;
  initial_page_map_registered = _mi_ptr_page(blocks[0]) == page;
  initial_arena_bit_set = mi_bitmap_is_set(arena_pages->pages, slice);
  if (!arena_backed || !reserved_mapping || !small_direct_page
      || !initial_prefix_four_os_pages || !initial_capacity_eight
      || !initial_direct_range_registered || !initial_queue_registered
      || !initial_page_map_registered || !initial_arena_bit_set) goto cleanup;
  ((unsigned char*)blocks[0])[0] = 0xA5;
  stage = 1;

  first_eight_direct_head = 1;
  first_eight_same_page = 1;
  for (size_t index = 1; index < 8; index++) {
    first_eight_direct_head = first_eight_direct_head
        && theap->pages_free_direct[_mi_wsize_from_size(request)] == page
        && page->free != NULL;
    blocks[index] = mi_heap_malloc_small(heap, request);
    if (blocks[index] == NULL) goto cleanup;
    first_eight_same_page = first_eight_same_page && _mi_ptr_page(blocks[index]) == page;
  }
  eighth_capacity = page->capacity;
  eighth_used = page->used;
  eighth_slice_pcommitted = page->slice_pcommitted;
  eighth_full_prefix = eighth_capacity == 8 && eighth_used == 8
      && eighth_slice_pcommitted == 4 && page->free == NULL;
  if (!first_eight_direct_head || !first_eight_same_page || !eighth_full_prefix) goto cleanup;
  stage = 2;

  blocks[8] = mi_heap_malloc_small(heap, request);
  if (blocks[8] == NULL) goto cleanup;
  ninth_capacity = page->capacity;
  ninth_used = page->used;
  ninth_slice_pcommitted = page->slice_pcommitted;
  ninth_same_page = _mi_ptr_page(blocks[8]) == page;
  ninth_zero_commit = ninth_slice_pcommitted == eighth_slice_pcommitted;
  ninth_capacity_sixteen = ninth_capacity == 16;
  ninth_used_nine = ninth_used == 9;
  second_direct_head = 1;
  if (!ninth_same_page || !ninth_zero_commit || !ninth_capacity_sixteen
      || !ninth_used_nine || !second_direct_head) goto cleanup;
  stage = 3;

  for (size_t index = 9; index < 16; index++) {
    second_direct_head = second_direct_head
        && theap->pages_free_direct[_mi_wsize_from_size(request)] == page
        && page->free != NULL;
    blocks[index] = mi_heap_malloc_small(heap, request);
    if (blocks[index] == NULL || _mi_ptr_page(blocks[index]) != page) goto cleanup;
  }
  sixteenth_capacity = page->capacity;
  sixteenth_used = page->used;
  sixteenth_slice_pcommitted = page->slice_pcommitted;
  sixteenth_full_prefix = sixteenth_capacity == 16 && sixteenth_used == 16
      && sixteenth_slice_pcommitted == 4 && page->free == NULL;
  if (!sixteenth_full_prefix) goto cleanup;
  stage = 4;

  blocks[16] = mi_heap_malloc_small(heap, request);
  if (blocks[16] == NULL) goto cleanup;
  seventeenth_capacity = page->capacity;
  seventeenth_used = page->used;
  seventeenth_slice_pcommitted = page->slice_pcommitted;
  seventeenth_same_page = _mi_ptr_page(blocks[16]) == page;
  // This is an address-independent poststate witness. The pinned
  // `mi_page_extend_free` source anchor establishes commit-before-capacity
  // publication; this fixture does not pretend to observe intermediate time.
  seventeenth_commit_before_extension = seventeenth_slice_pcommitted == 8
      && seventeenth_slice_pcommitted > sixteenth_slice_pcommitted;
  seventeenth_capacity_twenty_four = seventeenth_capacity == 24;
  seventeenth_used_seventeen = seventeenth_used == 17;
  direct_range_after_commit = direct_cache_image_matches_page(theap, queue, page);
  queue_registered_after_commit = queue->count == 1 && queue->first == page;
  page_map_registered_after_commit = _mi_ptr_page(blocks[0]) == page;
  arena_bit_set_after_commit = mi_bitmap_is_set(arena_pages->pages, slice);
  payload_preserved = ((unsigned char*)blocks[0])[0] == 0xA5;
  if (!seventeenth_same_page || !seventeenth_commit_before_extension
      || !seventeenth_capacity_twenty_four || !seventeenth_used_seventeen
      || !direct_range_after_commit || !queue_registered_after_commit
      || !page_map_registered_after_commit || !arena_bit_set_after_commit
      || !payload_preserved) goto cleanup;
  stage = 5;

  for (size_t index = 0; index < 17; index++) {
    mi_free(blocks[index]);
    blocks[index] = NULL;
  }
  // The source local-free path may retain an all-free page. The matching
  // Rust fixture invokes its forced normal collector before observing release.
  mi_heap_collect(heap, true);
  final_page_released = !mi_bitmap_is_set(arena_pages->pages, slice);
  valid = arena_backed && reserved_mapping && small_direct_page
      && initial_prefix_four_os_pages && initial_capacity_eight
      && initial_direct_range_registered && initial_queue_registered
      && initial_page_map_registered && initial_arena_bit_set
      && first_eight_direct_head && first_eight_same_page && eighth_full_prefix
      && ninth_same_page && ninth_zero_commit && ninth_capacity_sixteen
      && ninth_used_nine && second_direct_head && sixteenth_full_prefix
      && seventeenth_same_page && seventeenth_commit_before_extension
      && seventeenth_capacity_twenty_four && seventeenth_used_seventeen
      && direct_range_after_commit && queue_registered_after_commit
      && page_map_registered_after_commit && arena_bit_set_after_commit
      && payload_preserved && final_page_released;
  stage = 6;

  printf("CRABC_MI_ON_DEMAND_DIRECT_TRACE_BEGIN\n");
  printf("trace.on_demand_direct.arena_backed=%d\n", arena_backed);
  printf("trace.on_demand_direct.reserved_mapping=%d\n", reserved_mapping);
  printf("trace.on_demand_direct.small_direct_page=%d\n", small_direct_page);
  printf("trace.on_demand_direct.initial_prefix_four_os_pages=%d\n", initial_prefix_four_os_pages);
  printf("trace.on_demand_direct.initial_capacity_eight=%d\n", initial_capacity_eight);
  printf("trace.on_demand_direct.initial_direct_range_registered=%d\n", initial_direct_range_registered);
  printf("trace.on_demand_direct.initial_queue_registered=%d\n", initial_queue_registered);
  printf("trace.on_demand_direct.initial_page_map_registered=%d\n", initial_page_map_registered);
  printf("trace.on_demand_direct.initial_arena_bit_set=%d\n", initial_arena_bit_set);
  printf("trace.on_demand_direct.first_eight_direct_head=%d\n", first_eight_direct_head);
  printf("trace.on_demand_direct.first_eight_same_page=%d\n", first_eight_same_page);
  printf("trace.on_demand_direct.eighth_full_prefix=%d\n", eighth_full_prefix);
  printf("trace.on_demand_direct.ninth_same_page=%d\n", ninth_same_page);
  printf("trace.on_demand_direct.ninth_zero_commit=%d\n", ninth_zero_commit);
  printf("trace.on_demand_direct.ninth_capacity_sixteen=%d\n", ninth_capacity_sixteen);
  printf("trace.on_demand_direct.ninth_used_nine=%d\n", ninth_used_nine);
  printf("trace.on_demand_direct.second_direct_head=%d\n", second_direct_head);
  printf("trace.on_demand_direct.sixteenth_full_prefix=%d\n", sixteenth_full_prefix);
  printf("trace.on_demand_direct.seventeenth_same_page=%d\n", seventeenth_same_page);
  printf("trace.on_demand_direct.seventeenth_commit_before_extension=%d\n", seventeenth_commit_before_extension);
  printf("trace.on_demand_direct.seventeenth_capacity_twenty_four=%d\n", seventeenth_capacity_twenty_four);
  printf("trace.on_demand_direct.seventeenth_used_seventeen=%d\n", seventeenth_used_seventeen);
  printf("trace.on_demand_direct.direct_range_after_commit=%d\n", direct_range_after_commit);
  printf("trace.on_demand_direct.queue_registered_after_commit=%d\n", queue_registered_after_commit);
  printf("trace.on_demand_direct.page_map_registered_after_commit=%d\n", page_map_registered_after_commit);
  printf("trace.on_demand_direct.arena_bit_set_after_commit=%d\n", arena_bit_set_after_commit);
  printf("trace.on_demand_direct.payload_preserved=%d\n", payload_preserved);
  printf("trace.on_demand_direct.final_page_released=%d\n", final_page_released);
  printf("trace.on_demand_direct.initial_capacity=%zu\n", initial_capacity);
  printf("trace.on_demand_direct.initial_used=%zu\n", initial_used);
  printf("trace.on_demand_direct.initial_slice_pcommitted=%zu\n", initial_slice_pcommitted);
  printf("trace.on_demand_direct.eighth_capacity=%zu\n", eighth_capacity);
  printf("trace.on_demand_direct.eighth_used=%zu\n", eighth_used);
  printf("trace.on_demand_direct.eighth_slice_pcommitted=%zu\n", eighth_slice_pcommitted);
  printf("trace.on_demand_direct.ninth_capacity=%zu\n", ninth_capacity);
  printf("trace.on_demand_direct.ninth_used=%zu\n", ninth_used);
  printf("trace.on_demand_direct.ninth_slice_pcommitted=%zu\n", ninth_slice_pcommitted);
  printf("trace.on_demand_direct.sixteenth_capacity=%zu\n", sixteenth_capacity);
  printf("trace.on_demand_direct.sixteenth_used=%zu\n", sixteenth_used);
  printf("trace.on_demand_direct.sixteenth_slice_pcommitted=%zu\n", sixteenth_slice_pcommitted);
  printf("trace.on_demand_direct.seventeenth_capacity=%zu\n", seventeenth_capacity);
  printf("trace.on_demand_direct.seventeenth_used=%zu\n", seventeenth_used);
  printf("trace.on_demand_direct.seventeenth_slice_pcommitted=%zu\n", seventeenth_slice_pcommitted);
  printf("trace.on_demand_direct.valid=%d\n", valid);
  printf("CRABC_MI_ON_DEMAND_DIRECT_TRACE_END\n");

cleanup:
  if (!valid) {
    fprintf(stderr, "private direct-on-demand fixture failed at stage %d\n", stage);
  }
  for (size_t index = 0; index < 17; index++) {
    if (blocks[index] != NULL) mi_free(blocks[index]);
  }
  if (heap != NULL) mi_heap_destroy(heap);
  if (option_changed) mi_option_set(mi_option_page_commit_on_demand, old_page_commit_on_demand);
  return valid ? 0 : 2;
}
'''


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"required evidence input is missing: {relative(path)}")
    return sha256_bytes(path.read_bytes())


def exactly_matches(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(observed, dict)
        return set(observed) == set(expected) and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(observed, list)
        return len(observed) == len(expected) and all(
            exactly_matches(left, right) for left, right in zip(observed, expected)
        )
    return observed == expected


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise EvidenceError("direct-on-demand source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def _schema_template() -> dict[str, Any]:
    return {
        "format": 1,
        "schema": "crabc-mimalloc-x86_64-direct-on-demand-evidence",
        "profile": EXPECTED_PROFILE,
        "target": copy.deepcopy(EXPECTED_TARGET),
        "upstream": copy.deepcopy(EXPECTED_UPSTREAM),
        "scope": copy.deepcopy(EXPECTED_SCOPE),
        "compile_definitions": list(EXPECTED_COMPILE_DEFINITIONS),
        "release_flags": list(run.CONFIGURATION_PROFILES["release"]),
        "release_source_set": list(run.ORACLE_SOURCES),
        "source_anchors": [
            {"member": member, "start_line": start, "end_line": end, "sha256": digest}
            for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
        ],
        "c_probe_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "rust_test": {
            "path": relative(RUST_TEST_SOURCE),
            "target_arch": "x86_64",
            "test_filter": RUST_TEST_FILTER,
        },
        "trace": {
            "begin": TRACE_BEGIN,
            "end": TRACE_END,
            "expected_values": dict(EXPECTED_TRACE_VALUES),
        },
    }


def load_schema(path: Path | None = None) -> dict[str, Any]:
    """Load and fail-closed validate the checked-in direct-cache contract."""

    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 direct-on-demand evidence schema") from error
    if not isinstance(schema, dict):
        raise EvidenceError("x86-64 direct-on-demand evidence schema is not an object")
    expected_fields = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "rust_test", "schema", "scope", "source_anchors", "target",
        "trace", "upstream",
    }
    if set(schema) != expected_fields:
        raise EvidenceError("x86-64 direct-on-demand schema fields drifted")
    if type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("unsupported x86-64 direct-on-demand evidence schema")
    if schema["schema"] != "crabc-mimalloc-x86_64-direct-on-demand-evidence":
        raise EvidenceError("unsupported x86-64 direct-on-demand evidence schema")
    if schema["profile"] != EXPECTED_PROFILE or not exactly_matches(schema["target"], EXPECTED_TARGET):
        raise EvidenceError("direct-on-demand target or profile drifted")
    if not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("direct-on-demand upstream pin drifted")
    if not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("direct-on-demand private boundary drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("direct-on-demand compile definitions drifted")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("direct-on-demand release flags drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("direct-on-demand C source set differs from the pinned oracle")
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("direct-on-demand C probe source hash drifted")
    template = _schema_template()
    if not exactly_matches(schema["rust_test"], template["rust_test"]):
        raise EvidenceError("direct-on-demand Rust test selection drifted")
    if not exactly_matches(schema["trace"], template["trace"]):
        raise EvidenceError("direct-on-demand fixed trace schema drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("direct-on-demand source anchors drifted")
    observed: list[tuple[str, int, int, str]] = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("direct-on-demand source anchor has an invalid shape")
        member = anchor.get("member")
        start = anchor.get("start_line")
        end = anchor.get("end_line")
        digest = anchor.get("sha256")
        if (
            not isinstance(member, str)
            or type(start) is not int
            or type(end) is not int
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise EvidenceError("direct-on-demand source anchor has invalid values")
        observed.append((member, start, end, digest))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("direct-on-demand source anchor contract drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate the pinned direct-on-demand upstream identity") from error
    if (
        not exactly_matches(
            {"archive_root": pin["archive_root"], "revision": pin["revision"], "version": pin["version"]},
            EXPECTED_UPSTREAM,
        )
        or pin["sha256"] != EXPECTED_ARCHIVE_SHA256
    ):
        raise EvidenceError("direct-on-demand upstream archive pin drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    anchors = schema["source_anchors"]
    assert isinstance(anchors, list)
    for anchor in anchors:
        assert isinstance(anchor, dict)
        path = source / str(anchor["member"])
        if not path.is_file():
            raise EvidenceError(f"pinned source lacks direct-on-demand anchor member: {anchor['member']}")
        observed = sha256_bytes(source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"])))
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned direct-on-demand source anchor drifted: {anchor['member']}")
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(output, begin=TRACE_BEGIN, end=TRACE_END, description=description)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    non_integer = sorted(key for key, value in trace.items() if type(value) is not int)
    mismatches = [
        f"{key} (expected {EXPECTED_TRACE_VALUES[key]}, observed {trace[key]})"
        for key in sorted(set(trace) & set(EXPECTED_TRACE_VALUES))
        if type(trace[key]) is int and trace[key] != EXPECTED_TRACE_VALUES[key]
    ]
    if missing or unexpected or non_integer or mismatches:
        details: list[str] = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        if non_integer:
            details.append("non-integer values: " + ", ".join(non_integer))
        if mismatches:
            details.append("value mismatches: " + ", ".join(mismatches))
        raise EvidenceError(f"{description} differs from the fixed direct-on-demand trace: " + "; ".join(details))


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C direct-on-demand trace")
    validate_trace(rust_trace, description="Rust direct-on-demand trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise EvidenceError("Rust direct-on-demand trace differs from pinned C: " + ", ".join(mismatches))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized: list[str] = []
    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            normalized.append(NORMALIZED_PINNED_SOURCE + part[len(source_text):])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text):])
        else:
            normalized.append(part)
    return normalized


def c_trace_command(
    compiler: str,
    source: Path,
    probe_source: Path,
    probe_binary: Path,
    schema: Mapping[str, Any],
) -> list[str]:
    return [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        *schema["compile_definitions"],
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *schema["release_flags"],
        str(probe_source),
        *(str(source / member) for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        str(probe_binary),
    ]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(EXPECTED_COMPILE_DEFINITIONS) or definitions != list(schema["compile_definitions"]):
        raise EvidenceError("direct-on-demand C command compile definitions drifted")
    if flags != list(schema["release_flags"]):
        raise EvidenceError("direct-on-demand C command release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("direct-on-demand C command lacks the fixed pthread/TLS mode")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(part, str) for part in command)
        or Path(command[0]).name != "musl-gcc"
    ):
        raise EvidenceError("direct-on-demand report C command is malformed")
    expected = [
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        *schema["compile_definitions"],
        "-I",
        f"{NORMALIZED_PINNED_SOURCE}/include",
        "-I",
        f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"],
        f"{NORMALIZED_EVIDENCE_ROOT}/direct-on-demand.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/direct-on-demand-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("direct-on-demand report C command drifted")


def rust_trace_command(cargo: str, target_dir: Path) -> list[str]:
    return [
        cargo,
        "test",
        "--locked",
        "--target",
        TARGET,
        "--target-dir",
        str(target_dir),
        "-p",
        "crabc-mimalloc",
        "--lib",
        "--no-default-features",
        RUST_TEST_FILTER,
        "--",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]


def validate_normalized_rust_command(command: object) -> None:
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(part, str) for part in command)
        or Path(command[0]).name != "cargo"
    ):
        raise EvidenceError("direct-on-demand report Rust command is malformed")
    expected = [
        "test",
        "--locked",
        "--target",
        TARGET,
        "--target-dir",
        f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        "-p",
        "crabc-mimalloc",
        "--lib",
        "--no-default-features",
        RUST_TEST_FILTER,
        "--",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]
    if command[1:] != expected:
        raise EvidenceError("direct-on-demand report Rust command drifted")


def build_c_trace(
    compiler: str,
    readelf: str,
    source: Path,
    temporary: Path,
    schema: Mapping[str, Any],
) -> dict[str, Any]:
    probe_source = temporary / "direct-on-demand.c"
    probe_binary = temporary / "direct-on-demand-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C direct-on-demand fixture build")
        header = run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        run.require_success(header, "pinned C direct-on-demand fixture ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(probe_binary),), cwd=source)
        run.require_success(execution, "pinned C direct-on-demand fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C direct-on-demand trace")
    validate_trace(trace, description="pinned C direct-on-demand trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/direct-on-demand-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, environment=environment)
        run.require_success(execution, "Rust direct-on-demand fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust direct-on-demand fixture passed {passed} tests, expected one")
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust direct-on-demand trace",
    )
    validate_trace(trace, description="Rust direct-on-demand trace")
    return {
        "cargo_command": normalize_command(command, temporary, None),
        "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
        "passed_test_count": passed,
        "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)},
        "target_dir": {
            "isolated": True,
            "retained": False,
            "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        },
        "trace": trace,
    }


def report_from_results(
    *,
    schema: Mapping[str, Any],
    provenance: Mapping[str, str],
    archive_sha256: str,
    anchors: Sequence[Mapping[str, Any]],
    c_probe: Mapping[str, Any],
    rust_probe: Mapping[str, Any],
) -> dict[str, Any]:
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("direct-on-demand report inputs lack trace records")
    report: dict[str, Any] = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": "mimalloc-x86_64-reserved-small-direct-on-demand-differential-evidence",
        "profile": schema["profile"],
        "provenance": dict(provenance),
        "rust_probe": dict(rust_probe),
        "scope": schema["scope"],
        "source": {
            "archive_sha256": archive_sha256,
            "anchors": [dict(anchor) for anchor in anchors],
            "release_flags": list(schema["release_flags"]),
            "release_source_set": list(schema["release_source_set"]),
        },
        "status": "passed",
        "target": schema["target"],
        "trace": schema["trace"],
        "upstream": schema["upstream"],
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    required = {
        "c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe",
        "scope", "source", "status", "target", "trace", "upstream",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("direct-on-demand report schema drifted")
    if (
        report["format"] != 1
        or report["status"] != "passed"
        or report["kind"] != "mimalloc-x86_64-reserved-small-direct-on-demand-differential-evidence"
    ):
        raise EvidenceError("direct-on-demand report format/status/kind drifted")
    if (
        report["profile"] != EXPECTED_PROFILE
        or not exactly_matches(report["target"], EXPECTED_TARGET)
        or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM)
    ):
        raise EvidenceError("direct-on-demand report target/profile/source boundary drifted")
    if not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("direct-on-demand report source or private boundary drifted")
    if not exactly_matches(report["trace"], _schema_template()["trace"]):
        raise EvidenceError("direct-on-demand report trace contract drifted")
    if report["provenance"] not in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    ):
        raise EvidenceError("direct-on-demand report lacks native x86-64 provenance")
    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {
        "archive_sha256", "anchors", "release_flags", "release_source_set"
    }:
        raise EvidenceError("direct-on-demand report source record is malformed")
    if (
        source["archive_sha256"] != run.load_pin()["sha256"]
        or not exactly_matches(source["anchors"], schema["source_anchors"])
        or not exactly_matches(source["release_flags"], schema["release_flags"])
        or not exactly_matches(source["release_source_set"], schema["release_source_set"])
    ):
        raise EvidenceError("direct-on-demand report source identity drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {
        "build_command", "elf", "run_command", "source_sha256", "trace"
    }:
        raise EvidenceError("direct-on-demand report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {
        "cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"
    }:
        raise EvidenceError("direct-on-demand report Rust probe record drifted")
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF):
        raise EvidenceError("direct-on-demand report C ELF identity drifted")
    if (
        c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/direct-on-demand-c"]
        or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8"))
    ):
        raise EvidenceError("direct-on-demand report C probe identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if (
        type(rust_probe["passed_test_count"]) is not int
        or rust_probe["passed_test_count"] != 1
        or not exactly_matches(
            rust_probe["target_dir"],
            {
                "isolated": True,
                "retained": False,
                "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
            },
        )
    ):
        raise EvidenceError("direct-on-demand report Rust selection/target directory drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(
        rust_probe["lockfile"],
        {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
    ) or not exactly_matches(
        rust_probe["source"],
        {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)},
    ):
        raise EvidenceError("direct-on-demand report Rust source identity drifted")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise EvidenceError("direct-on-demand report comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-direct-on-demand-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
            compiler = run.require_tool("musl-gcc")
            readelf = run.require_tool("readelf")
            cargo = run.require_tool("cargo")
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source)
        c_probe = build_c_trace(compiler, readelf, source, temporary, schema)
        rust_probe = build_rust_trace(cargo, temporary)
        report = report_from_results(
            schema=schema,
            provenance=provenance,
            archive_sha256=sha256_file(archive),
            anchors=anchors,
            c_probe=c_probe,
            rust_probe=rust_probe,
        )
    if sha256_file(LOCKFILE) != before_lockfile:
        raise EvidenceError("Cargo.lock changed despite the required --locked Rust trace command")
    run.write_json(report_path, report)
    return report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 direct-on-demand differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 direct-on-demand differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
