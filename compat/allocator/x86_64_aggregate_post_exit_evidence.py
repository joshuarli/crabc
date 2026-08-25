#!/usr/bin/env python3
"""Differential evidence for two aggregate post-exit medium-page releases.

This native Linux/x86-64 private-engine lane compares a pinned mimalloc C
worker that abandons two distinct, live nonfull medium pages at real
``mi_thread_done()`` with the bounded Rust aggregate route.  The consumer
joins the worker, frees the second page's only client first, then frees the
first page's only client.  It deliberately proves neither a public x86 API
nor general teardown, routing, or concurrency behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-aggregate-post-exit-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/aggregate-post-exit.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/main_heap_page.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "main_heap_page::tests::x86_64_aggregate_post_exit_trace_matches_pinned_c_protocol"
TRACE_BEGIN = "CRABC_MI_AGGREGATE_POST_EXIT_TRACE_BEGIN"
TRACE_END = "CRABC_MI_AGGREGATE_POST_EXIT_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded aggregate post-exit differential could not establish its claim."""


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
EXPECTED_PROFILE = "linux-x86_64-private-aggregate-post-exit"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "producer_theap_teardown_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
    "two_live_nonfull_medium_pages_in_distinct_bins_only": True,
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
# This is the active two-level x86-64 PageMap source branch, not the retired
# flat-map anchor.  The remaining anchors bind the exact free, teardown,
# allocation/free entry points, mapped-abandonment, private-heap lifetime,
# arena bitmap, and stable slice-release operations read by the C trace.
EXPECTED_SOURCE_ANCHORS = (
    ("src/free.c", 364, 515, "073739d4f87219076fb8f087093b775d3a61ed8bf84c0588765bed0e6d619d68"),
    ("src/page.c", 414, 518, "7816ab31e29ea080a6e54da8bb851b5b8f6b7c27e987a00149a5f83256f5f5de"),
    ("src/theap.c", 89, 152, "5281d80ac6e2103f30d680e38dff6b5117ae5b7f921e2e28f4082161dec71a06"),
    ("src/init.c", 378, 417, "c31e558c1bf6c292aecab8e4a4fe3ef8c2616d2f10d9ac6549fe987ad72cac62"),
    ("src/init.c", 448, 480, "81710fd90ab37ebaf517e33c88e82c8a847eafad277c376eb18c196d9d86838d"),
    ("src/arena.c", 1216, 1297, "5f42cce2e334fe6146608499cfd545049832daaf683cab8d707d044623404437"),
    ("src/arena.c", 1304, 1355, "d7328658d88aa8c24dabcd1a093e5857b6bc699b03677eb4e8ab3c7d160c6dbb"),
    ("src/arena.c", 1383, 1423, "9c7568705a74690b5c291dce159b31869f817e613c96870e67e96cd1f7d8d22e"),
    ("src/arena.c", 1433, 1479, "631f8f26d44bdd530c61980d7f2cb94196051f350c58d2532ad3ff9bd2a95da2"),
    ("src/page-map.c", 484, 515, "33e2c50551c2ebc989adb01835fc6dc4e9ace9f4817ff8160ce8b33ca22a6aad"),
    ("include/mimalloc/internal.h", 753, 767, "bdbdaa6d7cc27818bd997d2b6d149e8be8424940d5ad6c57960fe7aa338da186"),
    ("src/arena.c", 207, 222, "aebd0a1e5aea4a2635853c0330b8eabd1d029891745889fa4007adb3261d53fb"),
    ("src/arena.c", 677, 696, "4c9eddf754a5717b7ed72f11fd7c1b10977afdb3bdb78ef72801e41e8a13d0c0"),
    ("include/mimalloc/types.h", 315, 350, "46e218a5dd1c5456b3e73458c2a8179d6b910d2aa615ef8574d2d9142bd804d2"),
    ("src/bitmap.h", 177, 186, "cf4b43b2a4f327a54e7827e6daa7fe27f517459e2e6c61eb467b2b049e35d4ef"),
    ("src/bitmap.h", 308, 317, "9c25d2dbef5f5a78db4f585724a714f057799339c27cf709a795aeed39e3b20f"),
    ("src/heap.c", 128, 155, "772e19faf0e26a3a12ecbd390f48610207f52d0600662dd6b1aa44eca1c63864"),
    ("src/free.c", 221, 256, "11e0aa2d13e7eba9f7bebb5b5395304041e4c5b492d2b4d09e43ba3bedb942fe"),
    ("src/alloc.c", 252, 262, "7f782391729bac2e29ed2c8f120b25970bdf4b5837010f101dd776b959fa15ad"),
)
EXPECTED_TRACE_VALUES = {name: 1 for name in (
    "trace.aggregate_post_exit.arena_backed",
    "trace.aggregate_post_exit.both_medium",
    "trace.aggregate_post_exit.distinct_pages",
    "trace.aggregate_post_exit.distinct_bins",
    "trace.aggregate_post_exit.first_used_one_before_exit",
    "trace.aggregate_post_exit.second_used_one_before_exit",
    "trace.aggregate_post_exit.producer_teardown_completed_before_consumer_free",
    "trace.aggregate_post_exit.first_page_map_registered_after_teardown",
    "trace.aggregate_post_exit.second_page_map_registered_after_teardown",
    "trace.aggregate_post_exit.first_arena_page_bitmap_set_after_teardown",
    "trace.aggregate_post_exit.second_arena_page_bitmap_set_after_teardown",
    "trace.aggregate_post_exit.first_mapped_abandoned_after_teardown",
    "trace.aggregate_post_exit.second_mapped_abandoned_after_teardown",
    "trace.aggregate_post_exit.second_page_map_unregistered_after_first_free",
    "trace.aggregate_post_exit.second_arena_page_bitmap_clear_after_first_free",
    "trace.aggregate_post_exit.second_arena_slice_released_after_first_free",
    "trace.aggregate_post_exit.first_page_map_registered_after_second_free",
    "trace.aggregate_post_exit.first_arena_page_bitmap_set_after_second_free",
    "trace.aggregate_post_exit.first_mapped_abandoned_after_second_free",
    "trace.aggregate_post_exit.first_used_one_after_second_free",
    "trace.aggregate_post_exit.first_page_map_unregistered_after_final_free",
    "trace.aggregate_post_exit.first_arena_page_bitmap_clear_after_final_free",
    "trace.aggregate_post_exit.first_arena_slice_released_after_final_free",
    "trace.aggregate_post_exit.route_empty_after_final_free",
    "trace.aggregate_post_exit.valid",
)}


C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0
#error this fixture requires the native x86-64 two-level PageMap branch
#endif

typedef struct fixture_s {
  mi_arena_id_t arena_id;
  mi_heap_t* heap;
  mi_page_t* first_page;
  mi_page_t* second_page;
  void* first;
  void* second;
  mi_arena_t* arena;
  mi_arena_pages_t* arena_pages;
  size_t first_slice;
  size_t second_slice;
  size_t first_slices;
  size_t second_slices;
  size_t first_bin;
  size_t second_bin;
  uintptr_t first_address;
  uintptr_t second_address;
  bool setup;
  bool producer_done;
  bool arena_backed;
  bool both_medium;
  bool distinct_pages;
  bool distinct_bins;
  bool first_used_one;
  bool second_used_one;
} fixture_t;

static void* producer_main(void* arg) {
  fixture_t* const f = (fixture_t*)arg;
  mi_heap_t* heap = mi_heap_new_in_arena(f->arena_id);
  void* first = NULL;
  void* second = NULL;
  mi_page_t* first_page = NULL;
  mi_page_t* second_page = NULL;

  if (heap == NULL) goto fail;
  first = mi_heap_malloc(heap, MI_SMALL_MAX_OBJ_SIZE + 1);
  second = mi_heap_malloc(heap, MI_MEDIUM_MAX_OBJ_SIZE / 2);
  if (first == NULL || second == NULL) goto fail;
  first_page = _mi_ptr_page(first);
  second_page = _mi_ptr_page(second);
  if (first_page == NULL || second_page == NULL || first_page == second_page
      || first_page->memid.memkind != MI_MEM_ARENA
      || second_page->memid.memkind != MI_MEM_ARENA
      || first_page->block_size <= MI_SMALL_MAX_OBJ_SIZE
      || first_page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || second_page->block_size <= MI_SMALL_MAX_OBJ_SIZE
      || second_page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || _mi_bin(first_page->block_size) == _mi_bin(second_page->block_size)
      || mi_page_is_full(first_page) || mi_page_is_full(second_page)
      || first_page->used != 1 || second_page->used != 1) goto fail;

  f->arena_backed = (first_page->memid.memkind == MI_MEM_ARENA
                     && second_page->memid.memkind == MI_MEM_ARENA);
  f->both_medium = (first_page->block_size > MI_SMALL_MAX_OBJ_SIZE
                    && first_page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE
                    && second_page->block_size > MI_SMALL_MAX_OBJ_SIZE
                    && second_page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE);
  f->distinct_pages = (first_page != second_page);
  f->distinct_bins = (_mi_bin(first_page->block_size) != _mi_bin(second_page->block_size));
  f->first_used_one = (first_page->used == 1);
  f->second_used_one = (second_page->used == 1);
  f->arena = mi_memid_arena(first_page->memid);
  f->first_slice = first_page->memid.mem.arena.slice_index;
  f->second_slice = second_page->memid.mem.arena.slice_index;
  f->first_slices = first_page->memid.mem.arena.slice_count;
  f->second_slices = second_page->memid.mem.arena.slice_count;
  f->first_bin = _mi_bin(first_page->block_size);
  f->second_bin = _mi_bin(second_page->block_size);
  f->first_address = (uintptr_t)first;
  f->second_address = (uintptr_t)second;
  if (f->arena == NULL || mi_memid_arena(second_page->memid) != f->arena
      || f->arena->arena_idx >= MI_MAX_ARENAS
      || f->first_slices == 0 || f->second_slices == 0
      || f->first_bin >= MI_ARENA_BIN_COUNT || f->second_bin >= MI_ARENA_BIN_COUNT) goto fail;
  // `mi_page_arena_pages` is private to arena.c.  Read the same stable table
  // while both page metadata objects remain PageMap-published.
  f->arena_pages = mi_atomic_load_ptr_acquire(
      mi_arena_pages_t, &heap->arena_pages[f->arena->arena_idx]);
  if (f->arena_pages == NULL || !f->arena_backed || !f->both_medium
      || !f->distinct_pages || !f->distinct_bins || !f->first_used_one
      || !f->second_used_one) goto fail;

  // Publish every client/metadata handle only after all fallible setup work.
  // The real source teardown owns the Theap after this point.
  f->heap = heap;
  f->first_page = first_page;
  f->second_page = second_page;
  f->first = first;
  f->second = second;
  mi_thread_done();
  f->producer_done = true;
  f->setup = true;
  return NULL;

fail:
  if (first != NULL) mi_free(first);
  if (second != NULL) mi_free(second);
  if (heap != NULL) mi_heap_destroy(heap);
  return NULL;
}

int main(void) {
  fixture_t f = {0};
  mi_arena_id_t arena_id = _mi_arena_id_none();
  pthread_t worker;
  bool started = false;
  int valid = 0;
  int arena_backed = 0, both_medium = 0, distinct_pages = 0, distinct_bins = 0;
  int first_used_one_before_exit = 0, second_used_one_before_exit = 0;
  int producer_teardown_completed_before_consumer_free = 0;
  int first_page_map_registered_after_teardown = 0, second_page_map_registered_after_teardown = 0;
  int first_arena_page_bitmap_set_after_teardown = 0, second_arena_page_bitmap_set_after_teardown = 0;
  int first_mapped_abandoned_after_teardown = 0, second_mapped_abandoned_after_teardown = 0;
  int second_page_map_unregistered_after_first_free = 0;
  int second_arena_page_bitmap_clear_after_first_free = 0;
  int second_arena_slice_released_after_first_free = 0;
  int first_page_map_registered_after_second_free = 0;
  int first_arena_page_bitmap_set_after_second_free = 0;
  int first_mapped_abandoned_after_second_free = 0;
  int first_used_one_after_second_free = 0;
  int first_page_map_unregistered_after_final_free = 0;
  int first_arena_page_bitmap_clear_after_final_free = 0;
  int first_arena_slice_released_after_final_free = 0;
  int route_empty_after_final_free = 0;

  mi_thread_init();
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto done;
  f.arena_id = arena_id;
  if (pthread_create(&worker, NULL, producer_main, &f) != 0) goto done;
  started = true;
  if (pthread_join(worker, NULL) != 0) goto done;
  started = false;
  if (!f.setup || !f.producer_done || f.heap == NULL || f.arena == NULL
      || f.arena_pages == NULL || f.first == NULL || f.second == NULL) goto done;

  arena_backed = f.arena_backed;
  both_medium = f.both_medium;
  distinct_pages = f.distinct_pages;
  distinct_bins = f.distinct_bins;
  first_used_one_before_exit = f.first_used_one;
  second_used_one_before_exit = f.second_used_one;
  producer_teardown_completed_before_consumer_free = (f.producer_done && !started);
  first_page_map_registered_after_teardown = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.first_address) == f.first_page);
  second_page_map_registered_after_teardown = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.second_address) == f.second_page);
  // Never inspect a stored page pointer until the PageMap proves it is still
  // live.  A broken teardown may release either page before the consumer.
  if (!first_page_map_registered_after_teardown || !second_page_map_registered_after_teardown) {
    f.first = NULL;
    f.second = NULL;
    goto done;
  }
  first_arena_page_bitmap_set_after_teardown = mi_bitmap_is_setN(
      f.arena_pages->pages, f.first_slice, 1);
  second_arena_page_bitmap_set_after_teardown = mi_bitmap_is_setN(
      f.arena_pages->pages, f.second_slice, 1);
  first_mapped_abandoned_after_teardown = mi_page_is_abandoned_mapped(f.first_page);
  second_mapped_abandoned_after_teardown = mi_page_is_abandoned_mapped(f.second_page);
  if (!arena_backed || !both_medium || !distinct_pages || !distinct_bins
      || !first_used_one_before_exit || !second_used_one_before_exit
      || !producer_teardown_completed_before_consumer_free
      || !first_arena_page_bitmap_set_after_teardown
      || !second_arena_page_bitmap_set_after_teardown
      || !first_mapped_abandoned_after_teardown
      || !second_mapped_abandoned_after_teardown) goto done;

  // The required aggregate order is the second distinct-bin page first.
  mi_free(f.second);
  f.second = NULL;
  // The second page metadata may now be retired.  Use only its saved client
  // address plus the reserved arena structures after this free.
  second_page_map_unregistered_after_first_free = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.second_address) == NULL);
  second_arena_page_bitmap_clear_after_first_free = mi_bitmap_is_clearN(
      f.arena_pages->pages, f.second_slice, 1);
  second_arena_slice_released_after_first_free = mi_bbitmap_is_setN(
      f.arena->slices_free, f.second_slice, f.second_slices);
  first_page_map_registered_after_second_free = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.first_address) == f.first_page);
  if (!first_page_map_registered_after_second_free) {
    f.first = NULL;
    goto done;
  }
  first_arena_page_bitmap_set_after_second_free = mi_bitmap_is_setN(
      f.arena_pages->pages, f.first_slice, 1);
  first_mapped_abandoned_after_second_free = mi_page_is_abandoned_mapped(f.first_page);
  first_used_one_after_second_free = (f.first_page->used == 1);
  if (!second_page_map_unregistered_after_first_free
      || !second_arena_page_bitmap_clear_after_first_free
      || !second_arena_slice_released_after_first_free
      || !first_arena_page_bitmap_set_after_second_free
      || !first_mapped_abandoned_after_second_free
      || !first_used_one_after_second_free) goto done;

  mi_free(f.first);
  f.first = NULL;
  // The final page may now be retired too; do not read `first_page` again.
  first_page_map_unregistered_after_final_free = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.first_address) == NULL);
  first_arena_page_bitmap_clear_after_final_free = mi_bitmap_is_clearN(
      f.arena_pages->pages, f.first_slice, 1);
  first_arena_slice_released_after_final_free = mi_bbitmap_is_setN(
      f.arena->slices_free, f.first_slice, f.first_slices);
  route_empty_after_final_free = (
      mi_atomic_load_relaxed(&f.heap->abandoned_count[f.first_bin]) == 0
      && mi_atomic_load_relaxed(&f.heap->abandoned_count[f.second_bin]) == 0);
  valid = arena_backed && both_medium && distinct_pages && distinct_bins
      && first_used_one_before_exit && second_used_one_before_exit
      && producer_teardown_completed_before_consumer_free
      && first_page_map_registered_after_teardown
      && second_page_map_registered_after_teardown
      && first_arena_page_bitmap_set_after_teardown
      && second_arena_page_bitmap_set_after_teardown
      && first_mapped_abandoned_after_teardown
      && second_mapped_abandoned_after_teardown
      && second_page_map_unregistered_after_first_free
      && second_arena_page_bitmap_clear_after_first_free
      && second_arena_slice_released_after_first_free
      && first_page_map_registered_after_second_free
      && first_arena_page_bitmap_set_after_second_free
      && first_mapped_abandoned_after_second_free
      && first_used_one_after_second_free
      && first_page_map_unregistered_after_final_free
      && first_arena_page_bitmap_clear_after_final_free
      && first_arena_slice_released_after_final_free
      && route_empty_after_final_free;
done:
  if (started) pthread_join(worker, NULL);
  if (f.first != NULL) mi_free(f.first);
  if (f.second != NULL) mi_free(f.second);
  if (f.heap != NULL) mi_heap_destroy(f.heap);
  if (valid) {
    printf("CRABC_MI_AGGREGATE_POST_EXIT_TRACE_BEGIN\n");
    printf("trace.aggregate_post_exit.arena_backed=%d\n", arena_backed);
    printf("trace.aggregate_post_exit.both_medium=%d\n", both_medium);
    printf("trace.aggregate_post_exit.distinct_pages=%d\n", distinct_pages);
    printf("trace.aggregate_post_exit.distinct_bins=%d\n", distinct_bins);
    printf("trace.aggregate_post_exit.first_used_one_before_exit=%d\n", first_used_one_before_exit);
    printf("trace.aggregate_post_exit.second_used_one_before_exit=%d\n", second_used_one_before_exit);
    printf("trace.aggregate_post_exit.producer_teardown_completed_before_consumer_free=%d\n", producer_teardown_completed_before_consumer_free);
    printf("trace.aggregate_post_exit.first_page_map_registered_after_teardown=%d\n", first_page_map_registered_after_teardown);
    printf("trace.aggregate_post_exit.second_page_map_registered_after_teardown=%d\n", second_page_map_registered_after_teardown);
    printf("trace.aggregate_post_exit.first_arena_page_bitmap_set_after_teardown=%d\n", first_arena_page_bitmap_set_after_teardown);
    printf("trace.aggregate_post_exit.second_arena_page_bitmap_set_after_teardown=%d\n", second_arena_page_bitmap_set_after_teardown);
    printf("trace.aggregate_post_exit.first_mapped_abandoned_after_teardown=%d\n", first_mapped_abandoned_after_teardown);
    printf("trace.aggregate_post_exit.second_mapped_abandoned_after_teardown=%d\n", second_mapped_abandoned_after_teardown);
    printf("trace.aggregate_post_exit.second_page_map_unregistered_after_first_free=%d\n", second_page_map_unregistered_after_first_free);
    printf("trace.aggregate_post_exit.second_arena_page_bitmap_clear_after_first_free=%d\n", second_arena_page_bitmap_clear_after_first_free);
    printf("trace.aggregate_post_exit.second_arena_slice_released_after_first_free=%d\n", second_arena_slice_released_after_first_free);
    printf("trace.aggregate_post_exit.first_page_map_registered_after_second_free=%d\n", first_page_map_registered_after_second_free);
    printf("trace.aggregate_post_exit.first_arena_page_bitmap_set_after_second_free=%d\n", first_arena_page_bitmap_set_after_second_free);
    printf("trace.aggregate_post_exit.first_mapped_abandoned_after_second_free=%d\n", first_mapped_abandoned_after_second_free);
    printf("trace.aggregate_post_exit.first_used_one_after_second_free=%d\n", first_used_one_after_second_free);
    printf("trace.aggregate_post_exit.first_page_map_unregistered_after_final_free=%d\n", first_page_map_unregistered_after_final_free);
    printf("trace.aggregate_post_exit.first_arena_page_bitmap_clear_after_final_free=%d\n", first_arena_page_bitmap_clear_after_final_free);
    printf("trace.aggregate_post_exit.first_arena_slice_released_after_final_free=%d\n", first_arena_slice_released_after_final_free);
    printf("trace.aggregate_post_exit.route_empty_after_final_free=%d\n", route_empty_after_final_free);
    printf("trace.aggregate_post_exit.valid=%d\n", valid);
    printf("CRABC_MI_AGGREGATE_POST_EXIT_TRACE_END\n");
  }
  return valid ? 0 : 2;
}
'''


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"missing evidence input: {path}")
    return sha256_bytes(path.read_bytes())


def exactly_matches(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(observed) == set(expected) and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(
            exactly_matches(actual, wanted) for actual, wanted in zip(observed, expected)
        )
    return observed == expected


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def source_range(contents: bytes, start: int, end: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start < 1 or end < start or end > len(lines):
        raise EvidenceError("source anchor outside pinned member")
    return b"".join(lines[start - 1 : end])


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def load_schema(path: Path | None = None) -> dict[str, Any]:
    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read aggregate-post-exit schema") from error
    required = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "rust_test", "schema", "scope", "source_anchors",
        "target", "trace", "upstream",
    }
    if not isinstance(schema, dict) or set(schema) != required:
        raise EvidenceError("aggregate-post-exit schema fields drifted")
    if type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("aggregate-post-exit schema format drifted")
    if schema["schema"] != "crabc-mimalloc-x86_64-aggregate-post-exit-evidence":
        raise EvidenceError("aggregate-post-exit schema identity drifted")
    if schema["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("aggregate-post-exit profile drifted")
    if not exactly_matches(schema["target"], EXPECTED_TARGET):
        raise EvidenceError("aggregate-post-exit target drifted")
    if not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("aggregate-post-exit upstream drifted")
    if not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("aggregate-post-exit scope drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate pinned aggregate-post-exit upstream") from error
    if (pin["sha256"] != EXPECTED_ARCHIVE_SHA256
            or pin["archive_root"] != EXPECTED_UPSTREAM["archive_root"]
            or pin["revision"] != EXPECTED_UPSTREAM["revision"]
            or pin["version"] != EXPECTED_UPSTREAM["version"]):
        raise EvidenceError("aggregate-post-exit upstream pin drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("aggregate-post-exit C source set drifted")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("aggregate-post-exit release flags drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("aggregate-post-exit compile definitions drifted")
    if not exactly_matches(schema["rust_test"], {
        "path": relative(RUST_TEST_SOURCE),
        "target_arch": "x86_64",
        "test_filter": RUST_TEST_FILTER,
    }):
        raise EvidenceError("aggregate-post-exit Rust test selection drifted")
    if not exactly_matches(schema["trace"], {
        "begin": TRACE_BEGIN,
        "end": TRACE_END,
        "expected_values": EXPECTED_TRACE_VALUES,
    }):
        raise EvidenceError("aggregate-post-exit trace contract drifted")
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("aggregate-post-exit C probe hash drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("aggregate-post-exit source anchors drifted")
    observed = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {
            "end_line", "member", "sha256", "start_line",
        }:
            raise EvidenceError("aggregate-post-exit source anchor shape drifted")
        if (type(anchor["member"]) is not str or type(anchor["start_line"]) is not int
                or type(anchor["end_line"]) is not int or type(anchor["sha256"]) is not str):
            raise EvidenceError("aggregate-post-exit source anchor type drifted")
        observed.append((anchor["member"], anchor["start_line"], anchor["end_line"], anchor["sha256"]))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("aggregate-post-exit source anchors drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated = []
    for anchor in schema["source_anchors"]:
        member = source / str(anchor["member"])
        if (not member.is_file()
                or sha256_bytes(source_range(member.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"])))
                != anchor["sha256"]):
            raise EvidenceError(f"aggregate-post-exit source anchor drifted: {anchor['member']}")
        validated.append(dict(anchor))
    return validated


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    non_integer = sorted(key for key, value in trace.items() if type(value) is not int)
    wrong = sorted(
        key for key in EXPECTED_TRACE_VALUES
        if type(trace.get(key)) is int and trace[key] != 1
    )
    if missing or unexpected or non_integer or wrong:
        raise EvidenceError(f"{description} violates the fixed 25-field trace contract")


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        trace = run.parse_address_independent_trace(
            output, begin=TRACE_BEGIN, end=TRACE_END, description=description,
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    validate_trace(trace, description=description)
    return trace


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized = []
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


def c_command(compiler: str, source: Path, probe: Path, binary: Path, schema: Mapping[str, Any]) -> list[str]:
    return [
        compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"),
        *schema["release_flags"], str(probe),
        *(str(source / member) for member in schema["release_source_set"]),
        "-pthread", "-o", str(binary),
    ]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    if [item for item in command if item in EXPECTED_COMPILE_DEFINITIONS] != list(schema["compile_definitions"]):
        raise EvidenceError("aggregate-post-exit C compile definitions drifted")
    if [item for item in command if item in run.CONFIGURATION_PROFILES["release"]] != list(schema["release_flags"]):
        raise EvidenceError("aggregate-post-exit C release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("aggregate-post-exit C command lacks pthread/TLS requirements")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/aggregate-post-exit.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/aggregate-post-exit-c",
    ]
    if (not isinstance(command, list) or not command
            or Path(command[0]).name != "musl-gcc" or command[1:] != expected):
        raise EvidenceError("aggregate-post-exit normalized C command drifted")


def rust_command(cargo: str, target_dir: Path) -> list[str]:
    return [
        cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir),
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER,
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]


def validate_normalized_rust_command(command: object) -> None:
    expected = [
        "test", "--locked", "--target", TARGET,
        "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER,
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]
    if (not isinstance(command, list) or not command
            or Path(command[0]).name != "cargo" or command[1:] != expected):
        raise EvidenceError("aggregate-post-exit normalized Rust command drifted")


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    probe = temporary / "aggregate-post-exit.c"
    binary = temporary / "aggregate-post-exit-c"
    probe.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_command(compiler, source, probe, binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(
            run.command_record(command, cwd=source),
            "aggregate-post-exit C build",
        )
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "aggregate-post-exit C ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source)
        run.require_success(execution, "aggregate-post-exit C execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C aggregate-post-exit trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/aggregate-post-exit-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    target_dir = temporary / "rust-target"
    command = rust_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, environment=environment)
        run.require_success(execution, "Rust aggregate-post-exit fixture")
        passed = run.parse_rust_test_count(
            str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust aggregate-post-exit fixture passed {passed} tests")
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust aggregate-post-exit trace",
    )
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


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C aggregate-post-exit trace")
    validate_trace(rust_trace, description="Rust aggregate-post-exit trace")
    mismatch = [key for key in EXPECTED_TRACE_VALUES if c_trace[key] != rust_trace[key]]
    if mismatch:
        raise EvidenceError("C/Rust aggregate-post-exit mismatch: " + ", ".join(mismatch))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def report_from_results(
    schema: Mapping[str, Any],
    provenance: Mapping[str, str],
    archive_sha256: str,
    anchors: Sequence[Mapping[str, Any]],
    c_probe: Mapping[str, Any],
    rust_probe: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_probe["trace"], rust_probe["trace"]),
        "format": 1,
        "kind": "mimalloc-x86_64-aggregate-post-exit-differential-evidence",
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


def validate_report(report: Mapping[str, Any]) -> None:
    required = {
        "c_probe", "comparison", "format", "kind", "profile", "provenance",
        "rust_probe", "scope", "source", "status", "target", "trace", "upstream",
    }
    if (not isinstance(report, dict) or set(report) != required
            or report["format"] != 1 or report["status"] != "passed"):
        raise EvidenceError("aggregate-post-exit report shape/status drifted")
    if (report["kind"] != "mimalloc-x86_64-aggregate-post-exit-differential-evidence"
            or report["profile"] != EXPECTED_PROFILE):
        raise EvidenceError("aggregate-post-exit report identity drifted")
    if (not exactly_matches(report["target"], EXPECTED_TARGET)
            or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM)
            or not exactly_matches(report["scope"], EXPECTED_SCOPE)):
        raise EvidenceError("aggregate-post-exit report boundary drifted")
    if report["provenance"] not in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    ):
        raise EvidenceError("aggregate-post-exit report lacks native provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("aggregate-post-exit report trace drifted")
    source = report["source"]
    if (not isinstance(source, dict)
            or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}
            or source["archive_sha256"] != run.load_pin()["sha256"]
            or not exactly_matches(source["anchors"], schema["source_anchors"])
            or not exactly_matches(source["release_flags"], schema["release_flags"])
            or not exactly_matches(source["release_source_set"], schema["release_source_set"])):
        raise EvidenceError("aggregate-post-exit source provenance drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if (not isinstance(c_probe, dict)
            or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}
            or not isinstance(rust_probe, dict)
            or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}):
        raise EvidenceError("aggregate-post-exit probe shape drifted")
    if (not exactly_matches(c_probe["elf"], EXPECTED_C_ELF)
            or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/aggregate-post-exit-c"]
            or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8"))):
        raise EvidenceError("aggregate-post-exit C probe drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if (rust_probe["passed_test_count"] != 1
            or not exactly_matches(rust_probe["target_dir"], {
                "isolated": True,
                "retained": False,
                "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
            })):
        raise EvidenceError("aggregate-post-exit Rust result drifted")
    if (not exactly_matches(rust_probe["lockfile"], {
                "path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE),
            })
            or not exactly_matches(rust_probe["source"], {
                "path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE),
            })):
        raise EvidenceError("aggregate-post-exit Rust provenance drifted")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise EvidenceError("aggregate-post-exit comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lock = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-aggregate-post-exit-") as name:
        temporary = Path(name)
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
            schema, provenance, sha256_file(archive), anchors, c_probe, rust_probe,
        )
    if sha256_file(LOCKFILE) != before_lock:
        raise EvidenceError("Cargo.lock changed")
    validate_report(report)
    run.write_json(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 aggregate-post-exit differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 aggregate-post-exit differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
