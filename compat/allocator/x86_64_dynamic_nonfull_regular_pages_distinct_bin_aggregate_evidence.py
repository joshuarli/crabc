#!/usr/bin/env python3
"""Differentially prove a dynamic two-page nonfull regular aggregate.

This private native Linux/x86-64 mimalloc v3.5.0 evidence lane creates two
one-client medium arena pages in distinct regular bins on a worker's dynamic
``mi_heap_new_in_arena`` heap.  The worker takes the real ``mi_thread_done``
path with the source-shaped ``page_full_retain=2`` image, and the consumer
joins it before it frees the second page and then the first page.  The trace
is deliberately limited to the PageMap, arena, dynamic-bitmap/count, and
terminal-release facts of that exact two-member route.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
_spec = importlib.util.spec_from_file_location("regular_small_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
RUNNER = _base.run

SCHEMA_PATH = ROOT / "compat/allocator/x86_64-dynamic-nonfull-regular-pages-distinct-bin-aggregate-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/dynamic-nonfull-regular-pages-distinct-bin-aggregate.json"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/dynamic_theap.rs"
TARGET = _base.TARGET
LOCKFILE = _base.LOCKFILE
NORMALIZED_EVIDENCE_ROOT = _base.NORMALIZED_EVIDENCE_ROOT
NORMALIZED_PINNED_SOURCE = _base.NORMALIZED_PINNED_SOURCE
EXPECTED_TARGET = _base.EXPECTED_TARGET
EXPECTED_UPSTREAM = _base.EXPECTED_UPSTREAM
EXPECTED_ARCHIVE_SHA256 = _base.EXPECTED_ARCHIVE_SHA256
EXPECTED_COMPILE_DEFINITIONS = _base.EXPECTED_COMPILE_DEFINITIONS
EXPECTED_C_ELF = _base.EXPECTED_C_ELF
EvidenceError = _base.EvidenceError
sha256_bytes = _base.sha256_bytes
sha256_file = _base.sha256_file
relative = _base.relative

EXPECTED_PROFILE = "linux-x86_64-private-dynamic-nonfull-regular-pages-distinct-bin-aggregate"
RUST_TEST_FILTER = (
    "dynamic_theap::tests::"
    "x86_64_dynamic_nonfull_regular_pages_distinct_bin_aggregate_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_DYNAMIC_NONFULL_REGULAR_PAGES_DISTINCT_BIN_AGGREGATE_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DYNAMIC_NONFULL_REGULAR_PAGES_DISTINCT_BIN_AGGREGATE_TRACE_END"
STEM = "dynamic-nonfull-regular-pages-distinct-bin-aggregate"
KIND = "mimalloc-x86_64-dynamic-nonfull-regular-pages-distinct-bin-aggregate-differential-evidence"

EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "c_oracle_dynamic_heap_new_in_arena_only": True,
    "c_oracle_full_retain_two_only": True,
    "c_oracle_real_thread_exit_and_join_required": True,
    "c_oracle_second_then_first_sequential_frees_only": True,
    "c_oracle_two_one_client_medium_arena_pages_in_distinct_bins_only": True,
    "dynamic_nonfull_regular_pages_distinct_bin_aggregate_only": True,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_remote_free_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
    "rust_real_thread_or_join_claimed": False,
    "rust_typed_owner_exit_then_sequential_client_frees_only": True,
}
EXPECTED_TLS = {
    "compiler_model": "initial-exec",
    "mimalloc_model": "MI_TLS_MODEL_LOCAL",
    "thread_pointer_path": "x86_64-fs-tls-slot-fallback",
}

# These anchors bind the source option image, dynamic Theap teardown, regular
# queue removal, mapped abandonment, failed-reclaim free tail, page-map, arena
# bitmap/count, and Linux x86-64 TLS mechanism that the fixture observes.
EXPECTED_SOURCE_ANCHORS = (
    ("src/theap.c", 23, 48, "4df1e18388900637745d7867bb5a4b6e1bac86679b550bb8ff77ac6ff9a68679"),
    ("src/theap.c", 97, 114, "9c66a394ded8185fc4af733ddcf4fd2f60db3922fc8c547400bc612def40f2d5"),
    ("src/theap.c", 123, 152, "c7811179e91e8cd66dc0587e824265cff4db6ce660ba0639309d909dd0df519c"),
    ("src/theap.c", 228, 232, "16c0e73a20b9a94bf994c4e83836c976f5683e3c6e8b18935782a934405adba0"),
    ("src/page-queue.c", 204, 244, "4216ce3f998d0a8c3891e0c89e1feaa34aff407d10e14135e68334ce833d6e6b"),
    ("src/page.c", 214, 243, "35148cff687e602b8de307ca1abad524655f48bf4410b2c64a7e44af8909203b"),
    ("src/page.c", 291, 303, "d363079d5e484919082b5602cc3757a3e3a357e68594fc040d902232c7458bbf"),
    ("src/page.c", 771, 798, "4e2872a2891831c5b9982dcfc21e22471655a0cf4037e01dc072f7ba094ca477"),
    ("src/page.c", 1072, 1081, "c0e6b4f003a664d9a0e78a4b7036b760ad37ba0f91755fc534facfdd05f779d4"),
    ("src/arena.c", 631, 651, "f413bc26c42c40483f59f3b79042a836113403fa1ed9501d9d7baf4a130b5ee0"),
    ("src/arena.c", 1304, 1409, "6a6d08e7cb4a45803619ce1c9d7efab31808068a756a727a4d3fd3d48d30413f"),
    ("src/free.c", 365, 515, "4f31b0716f4b8086797a84d1bfc6ca21531d1316ca37bbea18e218937fc941c1"),
    ("src/free.c", 479, 515, "538f3923096192771e3a516447f42778a74ea93f1084605b4ac24fd3b28eb501"),
    ("src/init.c", 378, 417, "c31e558c1bf6c292aecab8e4a4fe3ef8c2616d2f10d9ac6549fe987ad72cac62"),
    ("src/init.c", 448, 477, "289083292b594ae6e467808000a94f3ddaacdacb0372abee002f4db779137b0c"),
    ("src/page-map.c", 460, 465, "16d731af7789d5a35e755fe6b652b09b97992bfd39a31336778965e9751ac427"),
    ("src/page-map.c", 484, 514, "c4453ebc7aa0e6c6dbb59189b789d0d5ddf970499e2926d952558f4a1ae229a5"),
    ("include/mimalloc/internal.h", 38, 75, "5fcb7fc4ded7caedd3fbc10cb257af1f6679cff979e075b94781556997f81505"),
    ("include/mimalloc/internal.h", 918, 929, "82eaca070fdc3c9091c26d385304168b89d8ed57338f36de071d3a18b48badb5"),
    ("include/mimalloc/prim-tls.h", 41, 50, "acfbfaa3f692a04fa9fc1833a7c65238b5c9c4f7dc37047ee1e52c144ad6de8d"),
    ("include/mimalloc/prim-tls.h", 61, 73, "1eff24a0bb7271ad024368ee5f46d52b2e31d370f1941689ac842a643b4b802e"),
    ("include/mimalloc/prim-tls.h", 116, 127, "5fa059e7f8ed17d475334c06df04e3a802ff360ce57db59d8d706c02d114d479"),
    ("include/mimalloc/prim-tls.h", 247, 265, "47bbedcc76ad64ef4884e4b2ebaa8a38267f2f5ec3c8233a579e09474c06c6e6"),
    ("include/mimalloc/prim-tls.h", 412, 423, "1f82dc8f2ada933d948e8dd7ab86fec34b0d47a281b5e9333fee5f1f23088337"),
    ("src/prim/prim-tls.c", 25, 39, "0d63cba91b60be481a3d36fb3b63aade81bc32719f651712a60692e73bc6b3d6"),
    ("src/prim/prim-tls.c", 209, 251, "dcc472f7b145faa5140f2944857c1b7ca7285fdef45bd5e6ba62d266455d4b4c"),
)


def _page_values(page: int) -> dict[str, int]:
    prefix = f"trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.page{page}"
    return {
        f"{prefix}.page_map_all_slices_registered_after_thread_done": 1,
        f"{prefix}.arena_page_bitmap_set_after_thread_done": 1,
        f"{prefix}.mapped_abandoned_after_thread_done": 1,
        f"{prefix}.dynamic_abandoned_bitmap_set_after_thread_done": 1,
        f"{prefix}.dynamic_abandoned_count_one_after_thread_done": 1,
        f"{prefix}.used_one_after_thread_done": 1,
    }


EXPECTED_TRACE_VALUES = {
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.full_retain_two": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.arena_backed": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.both_medium": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.distinct_pages": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.distinct_bins": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.one_client_each_before_thread_done": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.ordinary_queue_one_each_before_thread_done": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.direct_cache_empty_before_thread_done": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.no_remote_free_before_thread_done": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.producer_thread_done_completed": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.producer_joined_before_consumer_frees": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.both_ordinary_queues_detached_after_thread_done": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.second_page_map_all_slices_unregistered_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.second_arena_page_bitmap_clear_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.second_arena_slice_released_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.second_dynamic_abandoned_bitmap_clear_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.second_dynamic_abandoned_count_zero_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_page_map_all_slices_registered_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_arena_page_bitmap_set_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_mapped_abandoned_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_dynamic_abandoned_bitmap_set_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_dynamic_abandoned_count_one_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_used_one_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_ordinary_queue_detached_after_second_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_page_map_all_slices_unregistered_after_final_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_arena_page_bitmap_clear_after_final_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_arena_slice_released_after_final_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_dynamic_abandoned_bitmap_clear_after_final_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.first_dynamic_abandoned_count_zero_after_final_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.route_empty_after_final_free": 1,
    "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.valid": 1,
}
EXPECTED_TRACE_VALUES.update(_page_values(0))
EXPECTED_TRACE_VALUES.update(_page_values(1))


C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0 || MI_PADDING != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native two-level map and unencoded release freelist
#endif
#if !defined(MI_TLS_MODEL_LOCAL) || MI_TLS_MODEL_LOCAL != 1 || defined(MI_TLS_MODEL_PTHREADS) || defined(MI_TLS_MODEL_FIXED) || defined(MI_TLS_MODEL_WIN32)
#error this fixture requires pinned Linux local compiler TLS
#endif
#if defined(MI_USE_BUILTIN_THREAD_POINTER) || defined(MI_PRIM_THREAD_POINTER) || defined(MI_NO_THREAD_POINTER) || !defined(MI_HAS_TLS_SLOT) || MI_HAS_TLS_SLOT != 1 || MI_INTPTR_SIZE != 8
#error this fixture requires the pinned x86_64 FS TLS-slot fallback
#endif

#define PAGE_COUNT 2

typedef struct fixture_s {
  mi_arena_id_t arena_id;
  mi_heap_t* heap;
  mi_page_t* pages[PAGE_COUNT];
  void* blocks[PAGE_COUNT];
  mi_arena_t* arena;
  size_t bins[PAGE_COUNT];
  size_t slice_indices[PAGE_COUNT];
  size_t slice_counts[PAGE_COUNT];
  uintptr_t slice_starts[PAGE_COUNT];
  uintptr_t addresses[PAGE_COUNT];
  bool full_retain_two;
  bool arena_backed;
  bool both_medium;
  bool distinct_pages;
  bool distinct_bins;
  bool one_client_each;
  bool ordinary_queue_one_each;
  bool direct_cache_empty;
  bool no_remote_free;
  bool setup_valid;
  bool producer_done;
} fixture_t;

static bool direct_empty(const mi_theap_t* theap) {
  if (theap == NULL) return false;
  for (size_t index = 0; index < MI_PAGES_DIRECT; index++) {
    if (theap->pages_free_direct[index] != _mi_page_empty_get()) return false;
  }
  return true;
}

static bool page_map_span_has_members(uintptr_t start, size_t count) {
  if (start == 0 || count == 0) return false;
  for (size_t index = 0; index < count; index++) {
    if (_mi_safe_ptr_page((const void*)(start + index * MI_ARENA_SLICE_SIZE)) == NULL) return false;
  }
  return true;
}

static bool page_map_span_is_clear(uintptr_t start, size_t count) {
  if (start == 0 || count == 0) return false;
  for (size_t index = 0; index < count; index++) {
    if (_mi_safe_ptr_page((const void*)(start + index * MI_ARENA_SLICE_SIZE)) != NULL) return false;
  }
  return true;
}

static bool page_is_detached(const mi_page_t* page) {
  return page != NULL && page->next == NULL && page->prev == NULL && !mi_page_is_owned(page);
}

static void* producer_main(void* argument) {
  fixture_t* const fixture = (fixture_t*)argument;
  const size_t first_request = MI_SMALL_MAX_OBJ_SIZE + sizeof(void*);
  const size_t second_request = first_request * 2;
  mi_heap_t* heap = mi_heap_new_in_arena(fixture->arena_id);
  mi_theap_t* theap = NULL;
  mi_page_t* first_page = NULL;
  mi_page_t* second_page = NULL;
  void* first = NULL;
  void* second = NULL;

  if (heap == NULL) goto failed;
  theap = _mi_heap_theap(heap);
  first = mi_heap_malloc(heap, first_request);
  second = mi_heap_malloc(heap, second_request);
  if (first == NULL || second == NULL || theap == NULL) goto failed;
  first_page = _mi_ptr_page(first);
  second_page = _mi_ptr_page(second);
  if (first_page == NULL || second_page == NULL) goto failed;

  fixture->full_retain_two = (mi_option_get(mi_option_page_full_retain) == 2
      && theap->allow_page_abandon);
  fixture->arena_backed = (first_page->memid.memkind == MI_MEM_ARENA
      && second_page->memid.memkind == MI_MEM_ARENA);
  fixture->both_medium = (first_page->block_size > MI_SMALL_MAX_OBJ_SIZE
      && first_page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE
      && second_page->block_size > MI_SMALL_MAX_OBJ_SIZE
      && second_page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE);
  fixture->distinct_pages = (first_page != second_page);
  fixture->one_client_each = (first_page->used == 1 && second_page->used == 1);
  fixture->bins[0] = _mi_bin(first_page->block_size);
  fixture->bins[1] = _mi_bin(second_page->block_size);
  fixture->distinct_bins = (fixture->bins[0] != fixture->bins[1]);
  fixture->ordinary_queue_one_each = (fixture->distinct_bins
      && fixture->bins[0] < MI_ARENA_BIN_COUNT && fixture->bins[1] < MI_ARENA_BIN_COUNT
      && fixture->bins[0] != MI_BIN_FULL && fixture->bins[1] != MI_BIN_FULL
      && theap->pages[fixture->bins[0]].count == 1
      && theap->pages[fixture->bins[1]].count == 1
      && theap->pages[fixture->bins[0]].first == first_page
      && theap->pages[fixture->bins[1]].first == second_page
      && !mi_page_is_full(first_page) && !mi_page_is_full(second_page));
  fixture->direct_cache_empty = direct_empty(theap);
  fixture->no_remote_free = (mi_page_thread_free(first_page) == NULL
      && mi_page_thread_free(second_page) == NULL);
  fixture->arena = mi_memid_arena(first_page->memid);
  fixture->pages[0] = first_page;
  fixture->pages[1] = second_page;
  fixture->blocks[0] = first;
  fixture->blocks[1] = second;
  fixture->addresses[0] = (uintptr_t)first;
  fixture->addresses[1] = (uintptr_t)second;
  for (size_t index = 0; index < PAGE_COUNT; index++) {
    mi_page_t* page = fixture->pages[index];
    uint8_t* const slice_start = mi_page_slice_start(page);
    fixture->slice_indices[index] = page->memid.mem.arena.slice_index;
    fixture->slice_counts[index] = page->memid.mem.arena.slice_count;
    fixture->slice_starts[index] = (uintptr_t)slice_start;
  }
  if (fixture->arena == NULL || mi_memid_arena(second_page->memid) != fixture->arena
      || fixture->arena->arena_idx >= MI_MAX_ARENAS
      || fixture->slice_counts[0] != 8 || fixture->slice_counts[1] != 8
      || fixture->slice_starts[0] == 0 || fixture->slice_starts[1] == 0
      || !fixture->full_retain_two || !fixture->arena_backed || !fixture->both_medium
      || !fixture->distinct_pages || !fixture->distinct_bins || !fixture->one_client_each
      || !fixture->ordinary_queue_one_each || !fixture->direct_cache_empty
      || !fixture->no_remote_free) goto failed;

  fixture->heap = heap;
  fixture->setup_valid = true;
  mi_thread_done();
  fixture->producer_done = true;
  return NULL;

failed:
  if (first != NULL) mi_free(first);
  if (second != NULL) mi_free(second);
  if (heap != NULL) mi_heap_destroy(heap);
  fixture->heap = NULL;
  fixture->blocks[0] = NULL;
  fixture->blocks[1] = NULL;
  fixture->setup_valid = false;
  return NULL;
}

int main(void) {
  fixture_t fixture = { .arena_id = _mi_arena_id_none() };
  pthread_t producer;
  bool producer_started = false;
  bool options_changed = false;
  bool valid = false;
  long old_reclaim_on_free = 0;
  long old_full_retain = 0;
  mi_arena_pages_t* arena_pages = NULL;
  mi_page_t* pages[PAGE_COUNT] = { NULL, NULL };

  int producer_thread_done_completed = 0;
  int producer_joined_before_consumer_frees = 0;
  int both_ordinary_queues_detached_after_thread_done = 0;
  int page_map_registered[PAGE_COUNT] = { 0, 0 };
  int arena_page_set[PAGE_COUNT] = { 0, 0 };
  int mapped_abandoned[PAGE_COUNT] = { 0, 0 };
  int dynamic_bitmap_set[PAGE_COUNT] = { 0, 0 };
  int dynamic_count_one[PAGE_COUNT] = { 0, 0 };
  int used_one[PAGE_COUNT] = { 0, 0 };
  int second_page_map_clear = 0;
  int second_arena_page_clear = 0;
  int second_slice_released = 0;
  int second_dynamic_bitmap_clear = 0;
  int second_dynamic_count_zero = 0;
  int first_page_map_registered_after_second = 0;
  int first_arena_page_set_after_second = 0;
  int first_mapped_abandoned_after_second = 0;
  int first_dynamic_bitmap_set_after_second = 0;
  int first_dynamic_count_one_after_second = 0;
  int first_used_one_after_second = 0;
  int first_ordinary_queue_detached_after_second = 0;
  int first_page_map_clear_after_final = 0;
  int first_arena_page_clear_after_final = 0;
  int first_slice_released_after_final = 0;
  int first_dynamic_bitmap_clear_after_final = 0;
  int first_dynamic_count_zero_after_final = 0;
  int route_empty_after_final = 0;

  mi_thread_init();
  old_reclaim_on_free = mi_option_get(mi_option_page_reclaim_on_free);
  old_full_retain = mi_option_get(mi_option_page_full_retain);
  mi_option_set(mi_option_page_reclaim_on_free, 0);
  mi_option_set(mi_option_page_full_retain, 2);
  options_changed = true;
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &fixture.arena_id) != 0
      || fixture.arena_id == _mi_arena_id_none()) goto output;
  if (pthread_create(&producer, NULL, producer_main, &fixture) != 0) goto output;
  producer_started = true;
  if (pthread_join(producer, NULL) != 0) goto output;
  producer_started = false;
  if (!fixture.setup_valid || fixture.heap == NULL || fixture.arena == NULL
      || fixture.blocks[0] == NULL || fixture.blocks[1] == NULL
      || !fixture.producer_done) goto output;

  producer_thread_done_completed = fixture.producer_done;
  producer_joined_before_consumer_frees = producer_thread_done_completed && !producer_started;
  arena_pages = mi_atomic_load_ptr_acquire(
      mi_arena_pages_t, &fixture.heap->arena_pages[fixture.arena->arena_idx]);
  if (arena_pages == NULL || !producer_joined_before_consumer_frees) goto output;
  for (size_t index = 0; index < PAGE_COUNT; index++) {
    pages[index] = _mi_safe_ptr_page((const void*)fixture.addresses[index]);
    if (pages[index] == NULL || pages[index] != fixture.pages[index]
        || pages[index]->memid.memkind != MI_MEM_ARENA
        || pages[index]->memid.mem.arena.slice_index != fixture.slice_indices[index]
        || pages[index]->memid.mem.arena.slice_count != fixture.slice_counts[index]) goto output;
    page_map_registered[index] = page_map_span_has_members(
        fixture.slice_starts[index], fixture.slice_counts[index]);
    arena_page_set[index] = mi_bitmap_is_setN(
        arena_pages->pages, fixture.slice_indices[index], 1);
    mapped_abandoned[index] = mi_page_is_abandoned_mapped(pages[index])
        && mi_page_is_abandoned(pages[index]);
    dynamic_bitmap_set[index] = arena_pages->pages_abandoned[fixture.bins[index]] != NULL
        && mi_bitmap_is_setN(
            arena_pages->pages_abandoned[fixture.bins[index]], fixture.slice_indices[index], 1);
    dynamic_count_one[index] = mi_atomic_load_relaxed(
        &fixture.heap->abandoned_count[fixture.bins[index]]) == 1;
    used_one[index] = pages[index]->used == 1;
  }
  both_ordinary_queues_detached_after_thread_done = page_is_detached(pages[0])
      && page_is_detached(pages[1]);
  if (!fixture.full_retain_two || !fixture.arena_backed || !fixture.both_medium
      || !fixture.distinct_pages || !fixture.distinct_bins || !fixture.one_client_each
      || !fixture.ordinary_queue_one_each || !fixture.direct_cache_empty
      || !fixture.no_remote_free || !producer_thread_done_completed
      || !producer_joined_before_consumer_frees || !both_ordinary_queues_detached_after_thread_done
      || !page_map_registered[0] || !page_map_registered[1]
      || !arena_page_set[0] || !arena_page_set[1]
      || !mapped_abandoned[0] || !mapped_abandoned[1]
      || !dynamic_bitmap_set[0] || !dynamic_bitmap_set[1]
      || !dynamic_count_one[0] || !dynamic_count_one[1]
      || !used_one[0] || !used_one[1]) goto output;

  // The required consumer order is second, then first.  All observations
  // after each free use saved addresses and persistent arena structures only.
  mi_free(fixture.blocks[1]);
  fixture.blocks[1] = NULL;
  second_page_map_clear = page_map_span_is_clear(
      fixture.slice_starts[1], fixture.slice_counts[1]);
  second_arena_page_clear = mi_bitmap_is_clearN(
      arena_pages->pages, fixture.slice_indices[1], 1);
  second_slice_released = mi_bbitmap_is_setN(
      fixture.arena->slices_free, fixture.slice_indices[1], fixture.slice_counts[1]);
  second_dynamic_bitmap_clear = arena_pages->pages_abandoned[fixture.bins[1]] == NULL
      || mi_bitmap_is_clearN(
          arena_pages->pages_abandoned[fixture.bins[1]], fixture.slice_indices[1], 1);
  second_dynamic_count_zero = mi_atomic_load_relaxed(
      &fixture.heap->abandoned_count[fixture.bins[1]]) == 0;
  pages[0] = _mi_safe_ptr_page((const void*)fixture.addresses[0]);
  if (pages[0] == NULL) goto output;
  first_page_map_registered_after_second = page_map_span_has_members(
      fixture.slice_starts[0], fixture.slice_counts[0]);
  first_arena_page_set_after_second = mi_bitmap_is_setN(
      arena_pages->pages, fixture.slice_indices[0], 1);
  first_mapped_abandoned_after_second = mi_page_is_abandoned_mapped(pages[0])
      && mi_page_is_abandoned(pages[0]);
  first_dynamic_bitmap_set_after_second = arena_pages->pages_abandoned[fixture.bins[0]] != NULL
      && mi_bitmap_is_setN(
          arena_pages->pages_abandoned[fixture.bins[0]], fixture.slice_indices[0], 1);
  first_dynamic_count_one_after_second = mi_atomic_load_relaxed(
      &fixture.heap->abandoned_count[fixture.bins[0]]) == 1;
  first_used_one_after_second = pages[0]->used == 1;
  first_ordinary_queue_detached_after_second = page_is_detached(pages[0]);
  if (!second_page_map_clear || !second_arena_page_clear || !second_slice_released
      || !second_dynamic_bitmap_clear || !second_dynamic_count_zero
      || !first_page_map_registered_after_second || !first_arena_page_set_after_second
      || !first_mapped_abandoned_after_second || !first_dynamic_bitmap_set_after_second
      || !first_dynamic_count_one_after_second || !first_used_one_after_second
      || !first_ordinary_queue_detached_after_second) goto output;

  mi_free(fixture.blocks[0]);
  fixture.blocks[0] = NULL;
  first_page_map_clear_after_final = page_map_span_is_clear(
      fixture.slice_starts[0], fixture.slice_counts[0]);
  first_arena_page_clear_after_final = mi_bitmap_is_clearN(
      arena_pages->pages, fixture.slice_indices[0], 1);
  first_slice_released_after_final = mi_bbitmap_is_setN(
      fixture.arena->slices_free, fixture.slice_indices[0], fixture.slice_counts[0]);
  first_dynamic_bitmap_clear_after_final = arena_pages->pages_abandoned[fixture.bins[0]] == NULL
      || mi_bitmap_is_clearN(
          arena_pages->pages_abandoned[fixture.bins[0]], fixture.slice_indices[0], 1);
  first_dynamic_count_zero_after_final = mi_atomic_load_relaxed(
      &fixture.heap->abandoned_count[fixture.bins[0]]) == 0;
  route_empty_after_final = first_dynamic_count_zero_after_final
      && second_dynamic_count_zero;
  valid = first_page_map_clear_after_final && first_arena_page_clear_after_final
      && first_slice_released_after_final && first_dynamic_bitmap_clear_after_final
      && first_dynamic_count_zero_after_final && route_empty_after_final;

output:
  printf("CRABC_MI_DYNAMIC_NONFULL_REGULAR_PAGES_DISTINCT_BIN_AGGREGATE_TRACE_BEGIN\n");
#define OUT_BOOL(name, value) printf("trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.%s=%d\n", name, (value) ? 1 : 0)
  OUT_BOOL("full_retain_two", fixture.full_retain_two);
  OUT_BOOL("arena_backed", fixture.arena_backed);
  OUT_BOOL("both_medium", fixture.both_medium);
  OUT_BOOL("distinct_pages", fixture.distinct_pages);
  OUT_BOOL("distinct_bins", fixture.distinct_bins);
  OUT_BOOL("one_client_each_before_thread_done", fixture.one_client_each);
  OUT_BOOL("ordinary_queue_one_each_before_thread_done", fixture.ordinary_queue_one_each);
  OUT_BOOL("direct_cache_empty_before_thread_done", fixture.direct_cache_empty);
  OUT_BOOL("no_remote_free_before_thread_done", fixture.no_remote_free);
  OUT_BOOL("producer_thread_done_completed", producer_thread_done_completed);
  OUT_BOOL("producer_joined_before_consumer_frees", producer_joined_before_consumer_frees);
  OUT_BOOL("both_ordinary_queues_detached_after_thread_done", both_ordinary_queues_detached_after_thread_done);
  for (size_t index = 0; index < PAGE_COUNT; index++) {
    printf("trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.page%zu.page_map_all_slices_registered_after_thread_done=%d\n", index, page_map_registered[index] ? 1 : 0);
    printf("trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.page%zu.arena_page_bitmap_set_after_thread_done=%d\n", index, arena_page_set[index] ? 1 : 0);
    printf("trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.page%zu.mapped_abandoned_after_thread_done=%d\n", index, mapped_abandoned[index] ? 1 : 0);
    printf("trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.page%zu.dynamic_abandoned_bitmap_set_after_thread_done=%d\n", index, dynamic_bitmap_set[index] ? 1 : 0);
    printf("trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.page%zu.dynamic_abandoned_count_one_after_thread_done=%d\n", index, dynamic_count_one[index] ? 1 : 0);
    printf("trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.page%zu.used_one_after_thread_done=%d\n", index, used_one[index] ? 1 : 0);
  }
  OUT_BOOL("second_page_map_all_slices_unregistered_after_second_free", second_page_map_clear);
  OUT_BOOL("second_arena_page_bitmap_clear_after_second_free", second_arena_page_clear);
  OUT_BOOL("second_arena_slice_released_after_second_free", second_slice_released);
  OUT_BOOL("second_dynamic_abandoned_bitmap_clear_after_second_free", second_dynamic_bitmap_clear);
  OUT_BOOL("second_dynamic_abandoned_count_zero_after_second_free", second_dynamic_count_zero);
  OUT_BOOL("first_page_map_all_slices_registered_after_second_free", first_page_map_registered_after_second);
  OUT_BOOL("first_arena_page_bitmap_set_after_second_free", first_arena_page_set_after_second);
  OUT_BOOL("first_mapped_abandoned_after_second_free", first_mapped_abandoned_after_second);
  OUT_BOOL("first_dynamic_abandoned_bitmap_set_after_second_free", first_dynamic_bitmap_set_after_second);
  OUT_BOOL("first_dynamic_abandoned_count_one_after_second_free", first_dynamic_count_one_after_second);
  OUT_BOOL("first_used_one_after_second_free", first_used_one_after_second);
  OUT_BOOL("first_ordinary_queue_detached_after_second_free", first_ordinary_queue_detached_after_second);
  OUT_BOOL("first_page_map_all_slices_unregistered_after_final_free", first_page_map_clear_after_final);
  OUT_BOOL("first_arena_page_bitmap_clear_after_final_free", first_arena_page_clear_after_final);
  OUT_BOOL("first_arena_slice_released_after_final_free", first_slice_released_after_final);
  OUT_BOOL("first_dynamic_abandoned_bitmap_clear_after_final_free", first_dynamic_bitmap_clear_after_final);
  OUT_BOOL("first_dynamic_abandoned_count_zero_after_final_free", first_dynamic_count_zero_after_final);
  OUT_BOOL("route_empty_after_final_free", route_empty_after_final);
  OUT_BOOL("valid", valid);
  printf("CRABC_MI_DYNAMIC_NONFULL_REGULAR_PAGES_DISTINCT_BIN_AGGREGATE_TRACE_END\n");

  if (producer_started) (void)pthread_join(producer, NULL);
  if (fixture.blocks[0] != NULL) mi_free(fixture.blocks[0]);
  if (fixture.blocks[1] != NULL) mi_free(fixture.blocks[1]);
  if (fixture.heap != NULL) mi_heap_destroy(fixture.heap);
  if (options_changed) {
    mi_option_set(mi_option_page_reclaim_on_free, old_reclaim_on_free);
    mi_option_set(mi_option_page_full_retain, old_full_retain);
  }
  return valid ? 0 : 2;
}
'''


def exactly_matches(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(observed) == set(expected) and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(
            exactly_matches(left, right) for left, right in zip(observed, expected)
        )
    return observed == expected


def _schema_template() -> dict:
    value = _base._schema_template()
    value["schema"] = "crabc-mimalloc-x86_64-dynamic-nonfull-regular-pages-distinct-bin-aggregate-evidence"
    value["profile"] = EXPECTED_PROFILE
    value["harness_dependency"] = {
        "path": relative(BASE_PATH),
        "sha256": sha256_file(BASE_PATH),
    }
    value["scope"] = copy.deepcopy(EXPECTED_SCOPE)
    value["tls"] = copy.deepcopy(EXPECTED_TLS)
    value["source_anchors"] = [
        {"member": member, "start_line": start, "end_line": end, "sha256": digest}
        for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
    ]
    value["c_probe_sha256"] = sha256_bytes(C_TRACE_PROBE.encode("utf-8"))
    value["rust_test"] = {
        "path": relative(RUST_TEST_SOURCE),
        "target_arch": "x86_64",
        "test_filter": RUST_TEST_FILTER,
    }
    value["trace"] = {
        "begin": TRACE_BEGIN,
        "end": TRACE_END,
        "expected_values": dict(EXPECTED_TRACE_VALUES),
    }
    return value


def load_schema(path: Path | None = None) -> dict:
    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read dynamic-nonfull regular-pages aggregate schema") from error
    if not exactly_matches(schema, _schema_template()):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate schema drifted")
    try:
        pin = RUNNER.load_pin()
    except RUNNER.HarnessError as error:
        raise EvidenceError("cannot validate the pinned dynamic-nonfull aggregate upstream") from error
    observed = {
        "archive_root": pin["archive_root"],
        "revision": pin["revision"],
        "version": pin["version"],
    }
    if not exactly_matches(observed, EXPECTED_UPSTREAM) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("dynamic-nonfull regular-pages aggregate upstream archive pin drifted")
    return schema


def require_native_x86_64() -> dict[str, str]:
    try:
        return RUNNER.require_native_x86_64()
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_source_anchors(schema: Mapping[str, object], source: Path) -> list[dict]:
    validated = []
    for anchor in schema["source_anchors"]:
        assert isinstance(anchor, dict)
        contents = (source / str(anchor["member"])).read_bytes()
        observed = sha256_bytes(
            _base.source_range(contents, int(anchor["start_line"]), int(anchor["end_line"]))
        )
        if observed != anchor["sha256"]:
            raise EvidenceError(
                "pinned dynamic-nonfull regular-pages aggregate source anchor drifted: "
                + str(anchor["member"])
            )
        validated.append(dict(anchor))
    return validated


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
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        if non_integer:
            details.append("non-integer values: " + ", ".join(non_integer))
        if mismatches:
            details.append("mismatches: " + ", ".join(mismatches))
        raise EvidenceError(
            f"{description} differs from the fixed dynamic-nonfull aggregate trace: "
            + "; ".join(details)
        )


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return RUNNER.parse_address_independent_trace(
            output, begin=TRACE_BEGIN, end=TRACE_END, description=description
        )
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict:
    validate_trace(c_trace, description="pinned C dynamic-nonfull regular-pages aggregate trace")
    validate_trace(rust_trace, description="Rust dynamic-nonfull regular-pages aggregate trace")
    mismatch = [
        key for key in sorted(EXPECTED_TRACE_VALUES) if c_trace[key] != rust_trace[key]
    ]
    if mismatch:
        raise EvidenceError(
            "Rust dynamic-nonfull regular-pages aggregate trace differs from pinned C: "
            + ", ".join(mismatch)
        )
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized = []
    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            normalized.append(NORMALIZED_PINNED_SOURCE + part[len(source_text) :])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text) :])
        else:
            normalized.append(part)
    return normalized


def c_trace_command(
    compiler: str, source: Path, probe_source: Path, probe_binary: Path, schema: Mapping[str, object]
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


def validate_c_command(command: Sequence[str], schema: Mapping[str, object]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in RUNNER.CONFIGURATION_PROFILES["release"]]
    if schema.get("tls") != EXPECTED_TLS or definitions != list(schema["compile_definitions"]):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate C compile/TLS contract drifted")
    if flags != list(schema["release_flags"]) or "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("dynamic-nonfull regular-pages aggregate C pthread/TLS command drifted")


def validate_normalized_c_command(command: object, schema: Mapping[str, object]) -> None:
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
        f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c",
    ]
    if (not isinstance(command, list) or not command
            or not all(isinstance(part, str) for part in command)
            or Path(command[0]).name != "musl-gcc" or command[1:] != expected):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate normalized C command drifted")


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
    if (not isinstance(command, list) or not command
            or not all(isinstance(part, str) for part in command)
            or Path(command[0]).name != "cargo" or command[1:] != expected):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate normalized Rust command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, object]
) -> dict:
    probe_source = temporary / f"{STEM}.c"
    probe_binary = temporary / f"{STEM}-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        RUNNER.require_success(
            RUNNER.command_record(command, cwd=source),
            "pinned C dynamic-nonfull regular-pages aggregate build",
        )
        header = RUNNER.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        RUNNER.require_success(header, "pinned C dynamic-nonfull regular-pages aggregate ELF identity")
        elf = RUNNER.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = RUNNER.command_record((str(probe_binary),), cwd=source)
        RUNNER.require_success(execution, "pinned C dynamic-nonfull regular-pages aggregate execution")
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(
        str(execution["stdout"]), description="pinned C dynamic-nonfull regular-pages aggregate trace"
    )
    validate_trace(trace, description="pinned C dynamic-nonfull regular-pages aggregate trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def build_rust_trace(cargo: str, temporary: Path) -> dict:
    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = RUNNER.command_record(command, cwd=ROOT, env=environment)
        RUNNER.require_success(execution, "Rust dynamic-nonfull regular-pages aggregate fixture")
        passed = RUNNER.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(
            f"Rust dynamic-nonfull regular-pages aggregate fixture passed {passed} tests, expected one"
        )
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust dynamic-nonfull regular-pages aggregate trace",
    )
    validate_trace(trace, description="Rust dynamic-nonfull regular-pages aggregate trace")
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
    schema: Mapping[str, object],
    provenance: Mapping[str, str],
    archive_sha256: str,
    anchors: Sequence[Mapping[str, object]],
    c_probe: Mapping[str, object],
    rust_probe: Mapping[str, object],
) -> dict:
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report inputs lack trace records")
    report = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": KIND,
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


def validate_report(report: Mapping[str, object]) -> None:
    required = {
        "c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe",
        "scope", "source", "status", "target", "trace", "upstream",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report shape drifted")
    if report["format"] != 1 or report["status"] != "passed" or report["kind"] != KIND:
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report identity/status drifted")
    if (not exactly_matches(report["target"], EXPECTED_TARGET)
            or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM)
            or report["profile"] != EXPECTED_PROFILE
            or not exactly_matches(report["scope"], EXPECTED_SCOPE)):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report boundary drifted")
    if report["provenance"] not in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    ):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report lacks native provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report trace contract drifted")
    source = report["source"]
    if (not isinstance(source, dict)
            or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}
            or source["archive_sha256"] != EXPECTED_ARCHIVE_SHA256
            or not exactly_matches(source["anchors"], schema["source_anchors"])
            or not exactly_matches(source["release_flags"], schema["release_flags"])
            or not exactly_matches(source["release_source_set"], schema["release_source_set"])):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report source drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if (not isinstance(c_probe, dict)
            or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}
            or not isinstance(rust_probe, dict)
            or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report probe shape drifted")
    if (not exactly_matches(c_probe["elf"], EXPECTED_C_ELF)
            or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"]
            or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8"))):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report C probe drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if (rust_probe["passed_test_count"] != 1
            or not exactly_matches(rust_probe["target_dir"], {
                "isolated": True,
                "retained": False,
                "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
            })
            or not exactly_matches(rust_probe["lockfile"], {
                "path": relative(LOCKFILE),
                "sha256": sha256_file(LOCKFILE),
            })
            or not exactly_matches(rust_probe["source"], {
                "path": relative(RUST_TEST_SOURCE),
                "sha256": sha256_file(RUST_TEST_SOURCE),
            })):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report Rust probe drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not isinstance(c_probe["trace"], Mapping) or not isinstance(rust_probe["trace"], Mapping):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report lacks C/Rust traces")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise EvidenceError("dynamic-nonfull regular-pages aggregate report comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = RUNNER.load_pin()
        archive = RUNNER.fetch_archive(pin, offline)
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(
        prefix="crabc-mimalloc-x86_64-dynamic-nonfull-regular-pages-distinct-bin-aggregate-"
    ) as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = RUNNER.safe_extract(archive, temporary / "source", pin["archive_root"])
            compiler = RUNNER.require_tool("musl-gcc")
            readelf = RUNNER.require_tool("readelf")
            cargo = RUNNER.require_tool("cargo")
        except RUNNER.HarnessError as error:
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
    RUNNER.write_json(report_path, report)
    return report


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, ValueError) as error:
        print(
            "allocator x86-64 dynamic-nonfull-regular-pages-distinct-bin-aggregate differential: FAIL: "
            + str(error),
            file=os.sys.stderr,
        )
        return 1
    print(
        "allocator x86-64 dynamic-nonfull-regular-pages-distinct-bin-aggregate differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
