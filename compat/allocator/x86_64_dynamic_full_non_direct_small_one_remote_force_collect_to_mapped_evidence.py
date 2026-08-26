#!/usr/bin/env python3
"""Differentially prove one dynamic full non-direct-small one-remote exit route.

The native pinned-C fixture fills one arena-backed 1280-byte non-direct-small
page on a worker pthread while ``page_full_retain=2`` keeps that full small
page in its ordinary regular bin. The consumer publishes exactly one remote
free, then the worker calls real ``mi_thread_done``. Forced collection consumes
the remote block, abandons the still-live page through the dynamic mapped
process route, and the joined consumer performs the remaining normal-collector
frees through final PageMap and arena-slice release.

The direct-cache image is observed only while the worker theap is live. The
fixture never dereferences that worker theap after real ``mi_thread_done``.
This is narrow private native Linux/x86-64 fixed-mimalloc engine evidence; it
does not claim public x86 support, general teardown, general remote routing,
or any AArch64 result.
"""

from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
_spec = importlib.util.spec_from_file_location("regular_small_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)

SCHEMA_PATH = ROOT / "compat/allocator/x86_64-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/dynamic-full-non-direct-small-one-remote-force-collect-to-mapped.json"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/dynamic_theap.rs"
EXPECTED_PROFILE = "linux-x86_64-private-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped"
RUST_TEST_FILTER = (
    "dynamic_theap::tests::"
    "x86_64_dynamic_full_non_direct_small_one_remote_force_collect_to_mapped_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_EXIT_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_EXIT_TRACE_END"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "dynamic_full_non_direct_small_one_remote_regular_bin_only": True,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_remote_free_routing_claimed": False,
    "mapped_process_route_only": True,
    "native_linux_x86_64_required": True,
    "one_joined_remote_free_during_thread_exit_only": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
    "sequential_joined_consumer_frees_only": True,
}
EXPECTED_SOURCE_ANCHORS = (
    ("src/theap.c", 23, 48, "4df1e18388900637745d7867bb5a4b6e1bac86679b550bb8ff77ac6ff9a68679"),
    ("src/theap.c", 97, 114, "9c66a394ded8185fc4af733ddcf4fd2f60db3922fc8c547400bc612def40f2d5"),
    ("src/page.c", 216, 243, "daede7b55470e95a37bd1eb59ad1ca67fd53dd3ab47bee302478b9ebdce173f7"),
    ("src/page.c", 291, 303, "d363079d5e484919082b5602cc3757a3e3a357e68594fc040d902232c7458bbf"),
    ("src/page.c", 771, 798, "4e2872a2891831c5b9982dcfc21e22471655a0cf4037e01dc072f7ba094ca477"),
    ("src/arena.c", 1304, 1409, "6a6d08e7cb4a45803619ce1c9d7efab31808068a756a727a4d3fd3d48d30413f"),
    ("src/free.c", 365, 515, "4f31b0716f4b8086797a84d1bfc6ca21531d1316ca37bbea18e218937fc941c1"),
    ("src/init.c", 448, 477, "289083292b594ae6e467808000a94f3ddaacdacb0372abee002f4db779137b0c"),
    ("src/page-map.c", 199, 209, "adcac501bd759bc1052bd46a2931adeb23a3740f5437ed15d9f5b2596e132cd0"),
)
EXPECTED_TRACE_VALUES = {
    "trace.dynamic_full_non_direct_small_one_remote_exit.arena_backed": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.small_page": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.non_direct_small": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.full_before_remote": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.ordinary_regular_bin_before_remote": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.direct_cache_empty_before_remote": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.remote_free_published_before_thread_done": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.producer_thread_done_completed": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.producer_joined_before_consumer_frees": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.mapped_after_thread_done": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.abandoned_after_thread_done": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.page_map_registered_after_thread_done": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.arena_page_bitmap_set_after_thread_done": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.ordinary_queue_detached_after_thread_done": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.dynamic_abandoned_bitmap_set_after_thread_done": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.dynamic_abandoned_count_after_thread_done": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.request_size": 1032,
    "trace.dynamic_full_non_direct_small_one_remote_exit.capacity": 51,
    "trace.dynamic_full_non_direct_small_one_remote_exit.reserved": 51,
    "trace.dynamic_full_non_direct_small_one_remote_exit.block_size": 1280,
    "trace.dynamic_full_non_direct_small_one_remote_exit.slice_count": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.used_after_force_collect": 50,
    "trace.dynamic_full_non_direct_small_one_remote_exit.remaining_client_count_after_force_collect": 50,
    "trace.dynamic_full_non_direct_small_one_remote_exit.nonfinal_consumer_free_keeps_mapped": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.page_map_unregistered_after_final_free": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.arena_page_bitmap_clear_after_final_free": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.arena_slice_released_after_final_free": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.dynamic_abandoned_bitmap_clear_after_final_free": 1,
    "trace.dynamic_full_non_direct_small_one_remote_exit.dynamic_abandoned_count_after_final_free": 0,
    "trace.dynamic_full_non_direct_small_one_remote_exit.valid": 1,
}


C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private dynamic full non-direct-small fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0 || MI_PADDING != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native two-level map and unencoded release freelist
#endif

#define CRABC_DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_MAX_BLOCKS 128

typedef struct fixture_s {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  mi_arena_id_t arena_id;
  mi_heap_t* heap;
  void* blocks[CRABC_DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_MAX_BLOCKS];
  size_t block_count;
  bool setup_valid;
  bool worker_ready;
  bool allow_thread_done;
  bool remote_free_published;
  bool producer_done;
  bool ordinary_regular_bin_before_remote;
  bool direct_cache_empty_before_remote;
  int worker_failure_stage;
} fixture_t;

static bool direct_cache_is_empty(const mi_theap_t* theap) {
  if (theap == NULL) return false;
  for (size_t index = 0; index < MI_PAGES_DIRECT; index++) {
    if (theap->pages_free_direct[index] != _mi_page_empty_get()) return false;
  }
  return true;
}

static void fixture_signal_ready(fixture_t* fixture, bool setup_valid) {
  if (pthread_mutex_lock(&fixture->mutex) != 0) return;
  fixture->setup_valid = setup_valid;
  fixture->worker_ready = true;
  (void)pthread_cond_broadcast(&fixture->condition);
  (void)pthread_mutex_unlock(&fixture->mutex);
}

static void* producer_main(void* argument) {
  fixture_t* const fixture = (fixture_t*)argument;
  const size_t request = MI_SMALL_SIZE_MAX + sizeof(void*);
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_queue_t* queue = NULL;
  size_t block_count = 0;
  int failure_stage = 0;

  heap = mi_heap_new_in_arena(fixture->arena_id);
  if (heap == NULL) { failure_stage = 1; goto failed; }
  theap = _mi_heap_theap(heap);
  if (theap == NULL) { failure_stage = 2; goto failed; }

  while (block_count < CRABC_DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_MAX_BLOCKS) {
    void* const block = mi_heap_malloc(heap, request);
    if (block == NULL) { failure_stage = 3; goto failed; }
    if (page == NULL) page = _mi_ptr_page(block);
    if (page == NULL || _mi_ptr_page(block) != page) {
      mi_free(block); failure_stage = 4; goto failed;
    }
    fixture->blocks[block_count++] = block;
    if (mi_page_is_full(page)) break;
  }
  if (page == NULL) { failure_stage = 5; goto failed; }
  queue = mi_page_queue(theap, page->block_size);
  const bool regular = queue != NULL && queue->count == 1 && queue->first == page
      && page->next == NULL && page->prev == NULL && !mi_page_is_in_full(page);
  const bool direct_empty = direct_cache_is_empty(theap);
  if (queue == NULL || block_count != (size_t)page->reserved
      || page->capacity != page->reserved
      || page->block_size <= MI_SMALL_SIZE_MAX
      || page->block_size > MI_SMALL_MAX_OBJ_SIZE
      || page->memid.memkind != MI_MEM_ARENA || !mi_page_is_full(page)
      || !regular || !direct_empty) { failure_stage = 6; goto failed; }
  fixture->heap = heap;
  fixture->block_count = block_count;
  fixture->ordinary_regular_bin_before_remote = regular;
  fixture->direct_cache_empty_before_remote = direct_empty;
  fixture_signal_ready(fixture, true);
  if (pthread_mutex_lock(&fixture->mutex) != 0) return NULL;
  while (!fixture->allow_thread_done) {
    if (pthread_cond_wait(&fixture->condition, &fixture->mutex) != 0) {
      (void)pthread_mutex_unlock(&fixture->mutex); return NULL;
    }
  }
  (void)pthread_mutex_unlock(&fixture->mutex);
  mi_thread_done();
  if (pthread_mutex_lock(&fixture->mutex) != 0) return NULL;
  fixture->producer_done = true;
  (void)pthread_cond_broadcast(&fixture->condition);
  (void)pthread_mutex_unlock(&fixture->mutex);
  return NULL;

failed:
  for (size_t index = 0; index < block_count; index++) {
    if (fixture->blocks[index] != NULL) {
      mi_free(fixture->blocks[index]); fixture->blocks[index] = NULL;
    }
  }
  if (heap != NULL) mi_heap_destroy(heap);
  fixture->worker_failure_stage = failure_stage;
  fixture_signal_ready(fixture, false);
  return NULL;
}

int main(void) {
  fixture_t fixture = {
      .mutex = PTHREAD_MUTEX_INITIALIZER,
      .condition = PTHREAD_COND_INITIALIZER,
      .arena_id = _mi_arena_id_none(),
  };
  pthread_t producer;
  bool producer_started = false;
  mi_page_t* page = NULL;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  mi_heap_t* worker_heap = NULL;
  _Atomic(size_t)* dynamic_abandoned_count = NULL;
  size_t bin = 0, capacity = 0, reserved = 0, block_size = 0;
  size_t slice_index = 0, slice_count = 0;
  uintptr_t saved_address = 0;
  long old_reclaim_on_free = 0, old_full_retain = 0;
  bool options_changed = false, valid = false;
  int stage = 0;
  int arena_backed = 0, small_page = 0, non_direct_small = 0, full_before_remote = 0;
  int ordinary_regular_bin_before_remote = 0, direct_cache_empty_before_remote = 0;
  int remote_free_published_before_thread_done = 0;
  int producer_thread_done_completed = 0, producer_joined_before_consumer_frees = 0;
  int mapped_after_thread_done = 0, abandoned_after_thread_done = 0;
  int page_map_registered_after_thread_done = 0, arena_page_bitmap_set_after_thread_done = 0;
  int ordinary_queue_detached_after_thread_done = 0;
  int dynamic_abandoned_bitmap_set_after_thread_done = 0;
  size_t dynamic_abandoned_count_after_thread_done = 0;
  size_t used_after_force_collect = 0, remaining_client_count_after_force_collect = 0;
  int nonfinal_consumer_free_keeps_mapped = 0;
  int page_map_unregistered_after_final_free = 0, arena_page_bitmap_clear_after_final_free = 0;
  int arena_slice_released_after_final_free = 0;
  int dynamic_abandoned_bitmap_clear_after_final_free = 0;
  size_t dynamic_abandoned_count_after_final_free = 0;
  const size_t request_size = MI_SMALL_SIZE_MAX + sizeof(void*);

  mi_thread_init();
  old_reclaim_on_free = mi_option_get(mi_option_page_reclaim_on_free);
  old_full_retain = mi_option_get(mi_option_page_full_retain);
  mi_option_set(mi_option_page_reclaim_on_free, 0);
  mi_option_set(mi_option_page_full_retain, 2);
  options_changed = true;
  stage = 1;
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &fixture.arena_id) != 0
      || fixture.arena_id == _mi_arena_id_none()) goto output;
  stage = 2;
  if (pthread_create(&producer, NULL, producer_main, &fixture) != 0) goto output;
  producer_started = true;
  stage = 3;
  if (pthread_mutex_lock(&fixture.mutex) != 0) goto output;
  while (!fixture.worker_ready) {
    if (pthread_cond_wait(&fixture.condition, &fixture.mutex) != 0) {
      (void)pthread_mutex_unlock(&fixture.mutex); goto output;
    }
  }
  const bool setup_valid = fixture.setup_valid;
  const size_t block_count = fixture.block_count;
  (void)pthread_mutex_unlock(&fixture.mutex);
  if (!setup_valid || fixture.heap == NULL || block_count < 3
      || block_count > CRABC_DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_MAX_BLOCKS
      || fixture.blocks[0] == NULL || fixture.blocks[1] == NULL) goto output;
  page = _mi_safe_ptr_page(fixture.blocks[0]);
  if (page == NULL) goto output;
  capacity = page->capacity;
  reserved = page->reserved;
  block_size = page->block_size;
  bin = _mi_bin(block_size);
  arena = mi_memid_arena(page->memid);
  worker_heap = fixture.heap;
  if (arena == NULL || arena->arena_idx >= MI_MAX_ARENAS || bin >= MI_ARENA_BIN_COUNT) goto output;
  /* Capture process-heap bookkeeping before worker `mi_thread_done`; never
     inspect its theap or direct-cache image after that real transition. */
  arena_pages = mi_atomic_load_ptr_acquire(
      mi_arena_pages_t, &worker_heap->arena_pages[arena->arena_idx]);
  dynamic_abandoned_count = &worker_heap->abandoned_count[bin];
  if (arena_pages == NULL) goto output;
  slice_index = page->memid.mem.arena.slice_index;
  slice_count = page->memid.mem.arena.slice_count;
  arena_backed = page->memid.memkind == MI_MEM_ARENA;
  small_page = block_size <= MI_SMALL_MAX_OBJ_SIZE;
  non_direct_small = block_size > MI_SMALL_SIZE_MAX && small_page;
  full_before_remote = mi_page_is_full(page) && page->used == page->reserved;
  ordinary_regular_bin_before_remote = fixture.ordinary_regular_bin_before_remote;
  direct_cache_empty_before_remote = fixture.direct_cache_empty_before_remote;
  if (!arena_backed || !small_page || !non_direct_small || !full_before_remote
      || !ordinary_regular_bin_before_remote || !direct_cache_empty_before_remote
      || capacity != block_count || reserved != block_count || slice_count == 0) goto output;
  stage = 4;
  const uintptr_t remote_address = (uintptr_t)fixture.blocks[0];
  mi_free(fixture.blocks[0]);
  fixture.blocks[0] = NULL;
  page = _mi_safe_ptr_page((const void*)remote_address);
  if (page == NULL) goto output;
  remote_free_published_before_thread_done =
      page->used == capacity && mi_page_thread_free(page) != NULL;
  if (!remote_free_published_before_thread_done) goto output;
  stage = 5;
  if (pthread_mutex_lock(&fixture.mutex) != 0) goto output;
  fixture.remote_free_published = true;
  fixture.allow_thread_done = true;
  (void)pthread_cond_broadcast(&fixture.condition);
  (void)pthread_mutex_unlock(&fixture.mutex);
  if (pthread_join(producer, NULL) != 0) goto output;
  producer_started = false;
  stage = 6;
  producer_thread_done_completed = fixture.producer_done;
  producer_joined_before_consumer_frees = producer_thread_done_completed && !producer_started
      && fixture.remote_free_published;
  if (!producer_joined_before_consumer_frees) goto output;
  page = _mi_safe_ptr_page(fixture.blocks[1]);
  if (page == NULL) goto output;
  saved_address = (uintptr_t)fixture.blocks[1];
  mapped_after_thread_done = mi_page_is_abandoned_mapped(page);
  abandoned_after_thread_done = mi_page_is_abandoned(page);
  page_map_registered_after_thread_done = _mi_safe_ptr_page((const void*)saved_address) == page;
  arena_page_bitmap_set_after_thread_done = mi_bitmap_is_setN(arena_pages->pages, slice_index, 1);
  ordinary_queue_detached_after_thread_done = page->next == NULL && page->prev == NULL
      && !mi_page_is_owned(page);
  dynamic_abandoned_bitmap_set_after_thread_done = arena_pages->pages_abandoned[bin] != NULL
      && mi_bitmap_is_setN(arena_pages->pages_abandoned[bin], slice_index, 1);
  dynamic_abandoned_count_after_thread_done = mi_atomic_load_relaxed(dynamic_abandoned_count);
  used_after_force_collect = page->used;
  remaining_client_count_after_force_collect = block_count - 1;
  if (!mapped_after_thread_done || !abandoned_after_thread_done
      || !page_map_registered_after_thread_done || !arena_page_bitmap_set_after_thread_done
      || !ordinary_queue_detached_after_thread_done || !dynamic_abandoned_bitmap_set_after_thread_done
      || dynamic_abandoned_count_after_thread_done != 1
      || used_after_force_collect + 1 != capacity
      || remaining_client_count_after_force_collect != used_after_force_collect) goto output;
  stage = 7;
  mi_free(fixture.blocks[1]);
  fixture.blocks[1] = NULL;
  page = _mi_safe_ptr_page(fixture.blocks[2]);
  nonfinal_consumer_free_keeps_mapped = page != NULL && mi_page_is_abandoned_mapped(page)
      && mi_page_is_abandoned(page) && page->used + 2 == capacity
      && page->next == NULL && page->prev == NULL;
  if (!nonfinal_consumer_free_keeps_mapped) goto output;
  for (size_t index = 2; index + 1 < block_count; index++) {
    mi_free(fixture.blocks[index]);
    fixture.blocks[index] = NULL;
  }
  mi_free(fixture.blocks[block_count - 1]);
  fixture.blocks[block_count - 1] = NULL;
  page_map_unregistered_after_final_free = _mi_safe_ptr_page((const void*)saved_address) == NULL;
  arena_page_bitmap_clear_after_final_free = mi_bitmap_is_clearN(arena_pages->pages, slice_index, 1);
  arena_slice_released_after_final_free =
      mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count);
  dynamic_abandoned_bitmap_clear_after_final_free = arena_pages->pages_abandoned[bin] != NULL
      && mi_bitmap_is_clearN(arena_pages->pages_abandoned[bin], slice_index, 1);
  dynamic_abandoned_count_after_final_free = mi_atomic_load_relaxed(dynamic_abandoned_count);
  valid = request_size == 1032 && capacity == 51 && reserved == 51 && block_size == 1280
      && slice_count == 1 && arena_backed && small_page && non_direct_small && full_before_remote
      && ordinary_regular_bin_before_remote && direct_cache_empty_before_remote
      && remote_free_published_before_thread_done && producer_thread_done_completed
      && producer_joined_before_consumer_frees && mapped_after_thread_done && abandoned_after_thread_done
      && page_map_registered_after_thread_done && arena_page_bitmap_set_after_thread_done
      && ordinary_queue_detached_after_thread_done && dynamic_abandoned_bitmap_set_after_thread_done
      && dynamic_abandoned_count_after_thread_done == 1 && used_after_force_collect == 50
      && remaining_client_count_after_force_collect == 50 && nonfinal_consumer_free_keeps_mapped
      && page_map_unregistered_after_final_free && arena_page_bitmap_clear_after_final_free
      && arena_slice_released_after_final_free && dynamic_abandoned_bitmap_clear_after_final_free
      && dynamic_abandoned_count_after_final_free == 0;
  stage = 8;
output:
  printf("CRABC_MI_DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_EXIT_TRACE_BEGIN\n");
#define OUT_N(k, v) printf("trace.dynamic_full_non_direct_small_one_remote_exit.%s=%zu\n", k, (size_t)(v))
#define OUT_B(k, v) printf("trace.dynamic_full_non_direct_small_one_remote_exit.%s=%d\n", k, (v) ? 1 : 0)
  OUT_B("arena_backed", arena_backed);
  OUT_B("small_page", small_page);
  OUT_B("non_direct_small", non_direct_small);
  OUT_B("full_before_remote", full_before_remote);
  OUT_B("ordinary_regular_bin_before_remote", ordinary_regular_bin_before_remote);
  OUT_B("direct_cache_empty_before_remote", direct_cache_empty_before_remote);
  OUT_B("remote_free_published_before_thread_done", remote_free_published_before_thread_done);
  OUT_B("producer_thread_done_completed", producer_thread_done_completed);
  OUT_B("producer_joined_before_consumer_frees", producer_joined_before_consumer_frees);
  OUT_B("mapped_after_thread_done", mapped_after_thread_done);
  OUT_B("abandoned_after_thread_done", abandoned_after_thread_done);
  OUT_B("page_map_registered_after_thread_done", page_map_registered_after_thread_done);
  OUT_B("arena_page_bitmap_set_after_thread_done", arena_page_bitmap_set_after_thread_done);
  OUT_B("ordinary_queue_detached_after_thread_done", ordinary_queue_detached_after_thread_done);
  OUT_B("dynamic_abandoned_bitmap_set_after_thread_done", dynamic_abandoned_bitmap_set_after_thread_done);
  OUT_N("dynamic_abandoned_count_after_thread_done", dynamic_abandoned_count_after_thread_done);
  OUT_N("request_size", request_size);
  OUT_N("capacity", capacity);
  OUT_N("reserved", reserved);
  OUT_N("block_size", block_size);
  OUT_N("slice_count", slice_count);
  OUT_N("used_after_force_collect", used_after_force_collect);
  OUT_N("remaining_client_count_after_force_collect", remaining_client_count_after_force_collect);
  OUT_B("nonfinal_consumer_free_keeps_mapped", nonfinal_consumer_free_keeps_mapped);
  OUT_B("page_map_unregistered_after_final_free", page_map_unregistered_after_final_free);
  OUT_B("arena_page_bitmap_clear_after_final_free", arena_page_bitmap_clear_after_final_free);
  OUT_B("arena_slice_released_after_final_free", arena_slice_released_after_final_free);
  OUT_B("dynamic_abandoned_bitmap_clear_after_final_free", dynamic_abandoned_bitmap_clear_after_final_free);
  OUT_N("dynamic_abandoned_count_after_final_free", dynamic_abandoned_count_after_final_free);
  OUT_B("valid", valid);
  printf("CRABC_MI_DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_EXIT_TRACE_END\n");
  if (producer_started) {
    if (pthread_mutex_lock(&fixture.mutex) == 0) {
      fixture.allow_thread_done = true;
      (void)pthread_cond_broadcast(&fixture.condition);
      (void)pthread_mutex_unlock(&fixture.mutex);
    }
    (void)pthread_join(producer, NULL);
  }
  for (size_t index = 0; index < fixture.block_count; index++) {
    if (fixture.blocks[index] != NULL) {
      mi_free(fixture.blocks[index]);
      fixture.blocks[index] = NULL;
    }
  }
  if (fixture.heap != NULL) mi_heap_destroy(fixture.heap);
  if (options_changed) {
    mi_option_set(mi_option_page_reclaim_on_free, old_reclaim_on_free);
    mi_option_set(mi_option_page_full_retain, old_full_retain);
  }
  if (!valid) {
    fprintf(stderr,
        "dynamic full non-direct-small one-remote force-collect fixture stopped at stage %d (worker=%d)\n",
        stage, fixture.worker_failure_stage);
  }
  return valid ? 0 : 2;
}
'''


DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_EXIT_KIND = (
    "mimalloc-x86_64-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped-differential-evidence"
)
_BASE_SCHEMA_TEMPLATE = _base._schema_template
_BASE_REPORT_FROM_RESULTS = _base.report_from_results
_BASE_VALIDATE_REPORT = _base.validate_report
_BASE_VALIDATE_NORMALIZED_C_COMMAND = _base.validate_normalized_c_command


def _schema_template() -> dict:
    value = _BASE_SCHEMA_TEMPLATE()
    value["schema"] = "crabc-mimalloc-x86_64-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped-evidence"
    value["profile"] = EXPECTED_PROFILE
    value["harness_dependency"] = {
        "path": relative(BASE_PATH),
        "sha256": sha256_file(BASE_PATH),
    }
    value["scope"] = dict(EXPECTED_SCOPE)
    value["source_anchors"] = [
        {"member": member, "start_line": start, "end_line": end, "sha256": digest}
        for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
    ]
    value["c_probe_sha256"] = sha256_bytes(C_TRACE_PROBE.encode("utf-8"))
    value["rust_test"] = {
        "path": "crabc-mimalloc/src/dynamic_theap.rs",
        "target_arch": "x86_64",
        "test_filter": RUST_TEST_FILTER,
    }
    value["trace"] = {
        "begin": TRACE_BEGIN,
        "end": TRACE_END,
        "expected_values": dict(EXPECTED_TRACE_VALUES),
    }
    return value


def c_trace_command(
    compiler: str, source: Path, probe_source: Path, probe_binary: Path, schema: dict
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


def validate_c_command(command: list[str], schema: dict) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in _base.run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(EXPECTED_COMPILE_DEFINITIONS) or definitions != list(
        schema["compile_definitions"]
    ):
        raise EvidenceError("dynamic-full-non-direct-small-one-remote C command compile definitions drifted")
    if (
        flags != list(schema["release_flags"])
        or "-pthread" not in command
        or "-ftls-model=initial-exec" not in command
    ):
        raise EvidenceError(
            "dynamic-full-non-direct-small-one-remote C command release pthread/TLS selection drifted"
        )


def validate_normalized_c_command(command: object, schema: dict) -> None:
    stem = "dynamic-full-non-direct-small-one-remote-force-collect-to-mapped"
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
        f"{NORMALIZED_EVIDENCE_ROOT}/{stem}.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/{stem}-c",
    ]
    if (
        not isinstance(command, list)
        or not command
        or Path(command[0]).name != "musl-gcc"
        or command[1:] != expected
    ):
        raise EvidenceError("dynamic-full-non-direct-small-one-remote report C command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: dict
) -> dict:
    stem = "dynamic-full-non-direct-small-one-remote-force-collect-to-mapped"
    probe_source = temporary / f"{stem}.c"
    probe_binary = temporary / f"{stem}-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        _base.run.require_success(
            _base.run.command_record(command, cwd=source),
            "pinned C dynamic-full-non-direct-small-one-remote fixture build",
        )
        header = _base.run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        _base.run.require_success(
            header, "pinned C dynamic-full-non-direct-small-one-remote fixture ELF identity"
        )
        elf = _base.run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = _base.run.command_record((str(probe_binary),), cwd=source)
        _base.run.require_success(
            execution, "pinned C dynamic-full-non-direct-small-one-remote fixture execution"
        )
    except _base.run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(
        str(execution["stdout"]),
        description="pinned C dynamic-full-non-direct-small-one-remote trace",
    )
    validate_trace(trace, description="pinned C dynamic-full-non-direct-small-one-remote trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/{stem}-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def report_from_results(**kwargs):
    checker = _base.validate_report
    _base.validate_report = lambda _report: None
    try:
        report = _BASE_REPORT_FROM_RESULTS(**kwargs)
    finally:
        _base.validate_report = checker
    report["kind"] = DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_EXIT_KIND
    validate_report(report)
    return report


def validate_report(report: dict) -> None:
    if report.get("kind") != DYNAMIC_FULL_NON_DIRECT_SMALL_ONE_REMOTE_EXIT_KIND:
        raise EvidenceError("dynamic-full-non-direct-small-one-remote report kind drifted")
    c_probe = report.get("c_probe")
    stem = "dynamic-full-non-direct-small-one-remote-force-collect-to-mapped"
    expected_run = [f"{NORMALIZED_EVIDENCE_ROOT}/{stem}-c"]
    if not isinstance(c_probe, dict) or c_probe.get("run_command") != expected_run:
        raise EvidenceError("dynamic-full-non-direct-small-one-remote report C command drifted")
    if c_probe.get("source_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("dynamic-full-non-direct-small-one-remote report C source hash drifted")
    validate_normalized_c_command(c_probe.get("build_command"), load_schema())
    compatible = copy.deepcopy(report)
    compatible["kind"] = "mimalloc-x86_64-regular-small-retire-quick-collect-differential-evidence"
    compatible["c_probe"]["run_command"] = [f"{NORMALIZED_EVIDENCE_ROOT}/regular-small-c"]
    compatible["c_probe"]["build_command"] = [
        part.replace(stem, "regular-small") for part in compatible["c_probe"]["build_command"]
    ]
    try:
        _base.validate_normalized_c_command = _BASE_VALIDATE_NORMALIZED_C_COMMAND
        _BASE_VALIDATE_REPORT(compatible)
    finally:
        _base.validate_normalized_c_command = validate_normalized_c_command


for _name in (
    "SCHEMA_PATH",
    "REPORT_DEFAULT",
    "EXPECTED_PROFILE",
    "RUST_TEST_FILTER",
    "TRACE_BEGIN",
    "TRACE_END",
    "EXPECTED_SCOPE",
    "EXPECTED_SOURCE_ANCHORS",
    "EXPECTED_TRACE_VALUES",
    "C_TRACE_PROBE",
    "RUST_TEST_SOURCE",
):
    setattr(_base, _name, globals()[_name])

_base._schema_template = _schema_template
_base.c_trace_command = c_trace_command
_base.validate_c_command = validate_c_command
_base.validate_normalized_c_command = validate_normalized_c_command
_base.build_c_trace = build_c_trace
_base.report_from_results = report_from_results
_base.validate_report = validate_report

for _name in (
    "EvidenceError",
    "sha256_bytes",
    "sha256_file",
    "relative",
    "load_schema",
    "validate_source_anchors",
    "parse_trace",
    "validate_trace",
    "compare_traces",
    "normalize_command",
    "c_trace_command",
    "validate_c_command",
    "validate_normalized_c_command",
    "rust_trace_command",
    "validate_normalized_rust_command",
    "run_evidence",
    "EXPECTED_TARGET",
    "EXPECTED_UPSTREAM",
    "EXPECTED_ARCHIVE_SHA256",
    "EXPECTED_COMPILE_DEFINITIONS",
    "EXPECTED_C_ELF",
    "LOCKFILE",
    "RUST_TEST_SOURCE",
    "TARGET",
    "NORMALIZED_EVIDENCE_ROOT",
    "NORMALIZED_PINNED_SOURCE",
):
    globals()[_name] = getattr(_base, _name)


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
            f"allocator x86-64 dynamic-full-non-direct-small-one-remote differential: FAIL: {error}",
            file=os.sys.stderr,
        )
        return 1
    print(
        "allocator x86-64 dynamic-full-non-direct-small-one-remote differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
