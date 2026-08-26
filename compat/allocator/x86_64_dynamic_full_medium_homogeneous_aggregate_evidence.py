#!/usr/bin/env python3
"""Differentially prove two homogeneous dynamic full-medium pages.

This is a private native Linux/x86-64 mimalloc v3.5.0 engine lane.  A real
worker pthread fills two same-size arena-backed full-medium pages, runs
``mi_thread_done``, and is joined before the consumer re-resolves either page
through the persistent PageMap.  Each page independently exercises the
unmapped five-free prefix, mapped reabandon boundary, and terminal eight-slice
release.  The Rust side is a typed current-thread owner-exit model; it does
not claim literal pthread creation or join parity.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
_spec = importlib.util.spec_from_file_location("regular_small_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
RUNNER = _base.run

SCHEMA_PATH = ROOT / "compat/allocator/x86_64-dynamic-full-medium-homogeneous-aggregate-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/dynamic-full-medium-homogeneous-aggregate.json"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/dynamic_theap.rs"
EXPECTED_PROFILE = "linux-x86_64-private-dynamic-full-medium-homogeneous-aggregate"
RUST_TEST_FILTER = (
    "dynamic_theap::tests::"
    "x86_64_dynamic_full_medium_homogeneous_aggregate_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_DYNAMIC_FULL_MEDIUM_HOMOGENEOUS_AGGREGATE_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DYNAMIC_FULL_MEDIUM_HOMOGENEOUS_AGGREGATE_TRACE_END"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "c_oracle_no_remote_free_before_thread_done_only": True,
    "c_oracle_real_thread_exit_and_join_required": True,
    "c_oracle_sequential_joined_consumer_frees_only": True,
    "c_oracle_two_pages_before_thread_done": True,
    "c_oracle_independent_page_release_only": True,
    "dynamic_full_medium_full_bin_only": True,
    "dynamic_full_medium_homogeneous_aggregate_only": True,
    "dynamic_unmapped_then_mapped_route_only": True,
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
    "two_or_more_full_medium_pages_required": True,
}
EXPECTED_TLS = {
    "compiler_model": "initial-exec",
    "mimalloc_model": "MI_TLS_MODEL_LOCAL",
    "thread_pointer_path": "x86_64-fs-tls-slot-fallback",
}
EXPECTED_SOURCE_ANCHORS = (
    ("src/theap.c", 23, 48, "4df1e18388900637745d7867bb5a4b6e1bac86679b550bb8ff77ac6ff9a68679"),
    ("src/theap.c", 97, 114, "9c66a394ded8185fc4af733ddcf4fd2f60db3922fc8c547400bc612def40f2d5"),
    ("src/theap.c", 123, 152, "c7811179e91e8cd66dc0587e824265cff4db6ce660ba0639309d909dd0df519c"),
    ("src/theap.c", 228, 232, "16c0e73a20b9a94bf994c4e83836c976f5683e3c6e8b18935782a934405adba0"),
    ("src/page-queue.c", 252, 274, "d72c1999eec27a2818fd657c62aa93ada275b1e63911569154a16619ca2f202b"),
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


def _page_values(prefix: str) -> dict[str, int]:
    return {
        f"{prefix}.unmapped_after_thread_done": 1,
        f"{prefix}.abandoned_after_thread_done": 1,
        f"{prefix}.page_map_registered_after_thread_done": 1,
        f"{prefix}.page_map_slice_count_after_thread_done": 8,
        f"{prefix}.page_map_all_slices_registered_after_thread_done": 1,
        f"{prefix}.slice_count_after_thread_done": 8,
        f"{prefix}.arena_page_bitmap_set_after_thread_done": 1,
        f"{prefix}.full_queue_detached_after_thread_done": 1,
        f"{prefix}.used_after_thread_done": 42,
        f"{prefix}.unmapped_prefix_free_count": 5,
        f"{prefix}.used_after_unmapped_prefix": 37,
        f"{prefix}.unmapped_after_unmapped_prefix": 1,
        f"{prefix}.mapped_after_reabandon_boundary": 1,
        f"{prefix}.dynamic_abandoned_bitmap_set_after_reabandon_boundary": 1,
        f"{prefix}.used_after_reabandon_boundary": 36,
        f"{prefix}.page_map_unregistered_after_terminal_free": 1,
        f"{prefix}.arena_page_bitmap_clear_after_terminal_free": 1,
        f"{prefix}.arena_slice_released_after_terminal_free": 1,
        f"{prefix}.dynamic_abandoned_bitmap_clear_after_terminal_free": 1,
    }


EXPECTED_TRACE_VALUES = {
    "trace.dynamic_full_medium_homogeneous_aggregate.arena_backed": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.medium_page": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.page_count": 2,
    "trace.dynamic_full_medium_homogeneous_aggregate.same_size": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.full_before_thread_done": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.full_queue_count_before_thread_done": 2,
    "trace.dynamic_full_medium_homogeneous_aggregate.direct_cache_empty_before_thread_done": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.no_remote_free_before_thread_done": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.request_size": 10248,
    "trace.dynamic_full_medium_homogeneous_aggregate.block_size": 12288,
    "trace.dynamic_full_medium_homogeneous_aggregate.capacity": 42,
    "trace.dynamic_full_medium_homogeneous_aggregate.reserved": 42,
    "trace.dynamic_full_medium_homogeneous_aggregate.slice_count": 8,
    "trace.dynamic_full_medium_homogeneous_aggregate.dynamic_abandoned_count_after_thread_done": 0,
    "trace.dynamic_full_medium_homogeneous_aggregate.first_terminal_released_only": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.second_page_retained_after_first_terminal": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.dynamic_abandoned_count_after_first_terminal": 0,
    "trace.dynamic_full_medium_homogeneous_aggregate.dynamic_abandoned_count_after_second_boundary": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.dynamic_abandoned_count_after_final_terminal": 0,
    "trace.dynamic_full_medium_homogeneous_aggregate.route_empty_after_final_terminal": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.valid": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.page1.page_map_registered_after_first_terminal": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.page1.page_map_slice_count_after_first_terminal": 8,
    "trace.dynamic_full_medium_homogeneous_aggregate.page1.page_map_all_slices_registered_after_first_terminal": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.page1.arena_page_bitmap_set_after_first_terminal": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.page1.unmapped_after_first_terminal": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.page1.abandoned_after_first_terminal": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.page1.dynamic_abandoned_bitmap_clear_after_first_terminal": 1,
    "trace.dynamic_full_medium_homogeneous_aggregate.page1.used_after_first_terminal": 42,
}
EXPECTED_TRACE_VALUES.update(_page_values("trace.dynamic_full_medium_homogeneous_aggregate.page0"))
EXPECTED_TRACE_VALUES.update(_page_values("trace.dynamic_full_medium_homogeneous_aggregate.page1"))


# Keep the C oracle deliberately self-contained.  In particular, after the
# worker calls mi_thread_done the consumer never reads its Theap/full queue or
# direct cache; all page observations go back through safe PageMap lookup.
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

#define MAX_BLOCKS 128
#define PAGE_COUNT 2
typedef struct fixture_s {
  pthread_mutex_t mutex; pthread_cond_t condition; mi_arena_id_t arena_id;
  mi_heap_t* heap; void* blocks[MAX_BLOCKS]; size_t block_count;
  mi_page_t* pages[PAGE_COUNT]; size_t page_blocks[PAGE_COUNT];
  bool ready; bool setup_valid; bool allow_thread_done; bool producer_done;
  bool full_queue; bool direct_cache_empty; int failure_stage;
} fixture_t;

static bool direct_empty(const mi_theap_t* theap) {
  if (theap == NULL) return false;
  for (size_t i = 0; i < MI_PAGES_DIRECT; i++) if (theap->pages_free_direct[i] != _mi_page_empty_get()) return false;
  return true;
}
static void signal_ready(fixture_t* f, bool valid) {
  if (pthread_mutex_lock(&f->mutex) != 0) return;
  f->setup_valid = valid; f->ready = true; (void)pthread_cond_broadcast(&f->condition);
  (void)pthread_mutex_unlock(&f->mutex);
}
static bool full_queue_has_two(const mi_page_queue_t* q, mi_page_t* a, mi_page_t* b) {
  if (q == NULL || q->count != 2 || q->first == NULL) return false;
  size_t count = 0; bool has_a = false, has_b = false;
  for (mi_page_t* p = q->first; p != NULL && count <= 2; p = p->next) {
    if (p == a) has_a = true; if (p == b) has_b = true; count++;
  }
  return count == 2 && has_a && has_b;
}
static size_t page_map_count(mi_page_t* page, uintptr_t* slice_start, size_t slice_count) {
  size_t area_size = 0; uint8_t* area = mi_page_area(page, &area_size);
  uint8_t* start = mi_page_slice_start(page);
  if (area == NULL || start == NULL || area < start || area_size > MI_MEDIUM_PAGE_SIZE) return 0;
  if (area_size > MI_MEDIUM_PAGE_SIZE) area_size = MI_MEDIUM_PAGE_SIZE - MI_ARENA_SLICE_SIZE;
  size_t count = mi_slice_count_of_size(area_size) + (size_t)((area - start) / MI_ARENA_SLICE_SIZE);
  if (count > slice_count) return 0; *slice_start = (uintptr_t)start; return count;
}
static bool map_span_is(mi_page_t* page, uintptr_t start, size_t count, bool mapped) {
  (void)page;
  for (size_t i = 0; i < count; i++) if ((_mi_safe_ptr_page((const void*)(start + i * MI_ARENA_SLICE_SIZE)) != NULL) != mapped) return false;
  return true;
}
static void out_page_bool(size_t page, const char* name, int value) {
  printf("trace.dynamic_full_medium_homogeneous_aggregate.page%zu.%s=%d\n", page, name, value ? 1 : 0);
}
static void out_page_number(size_t page, const char* name, size_t value) {
  printf("trace.dynamic_full_medium_homogeneous_aggregate.page%zu.%s=%zu\n", page, name, value);
}
static void* producer_main(void* arg) {
  fixture_t* f = (fixture_t*)arg; const size_t request = MI_SMALL_MAX_OBJ_SIZE + sizeof(void*);
  mi_heap_t* heap = mi_heap_new_in_arena(f->arena_id); mi_theap_t* theap = NULL; int failure = 0;
  if (heap == NULL) { signal_ready(f, false); f->failure_stage = 1; return NULL; }
  theap = _mi_heap_theap(heap); if (theap == NULL) { f->failure_stage = 2; goto failed; }
  while (f->block_count < MAX_BLOCKS && f->page_blocks[1] < 42) {
    void* block = mi_heap_malloc(heap, request); if (block == NULL) { failure = 3; goto failed; }
    mi_page_t* page = _mi_ptr_page(block); if (page == NULL) { mi_free(block); failure = 4; goto failed; }
    size_t slot = (f->pages[0] == NULL || page == f->pages[0]) ? 0 : 1;
    if (f->pages[slot] == NULL) f->pages[slot] = page;
    if (page != f->pages[slot] || slot == 1 && f->pages[0] == NULL) { mi_free(block); failure = 5; goto failed; }
    f->blocks[f->block_count++] = block; f->page_blocks[slot]++;
    if (f->page_blocks[slot] == 42 && slot == 0) continue;
  }
  if (f->pages[0] == NULL || f->pages[1] == NULL || f->page_blocks[0] != 42 || f->page_blocks[1] != 42) { failure = 6; goto failed; }
  f->full_queue = full_queue_has_two(&theap->pages[MI_BIN_FULL], f->pages[0], f->pages[1]);
  f->direct_cache_empty = direct_empty(theap);
  for (size_t i = 0; i < PAGE_COUNT; i++) if (!mi_page_is_full(f->pages[i]) || f->pages[i]->capacity != f->pages[i]->reserved || f->pages[i]->block_size <= MI_SMALL_MAX_OBJ_SIZE || f->pages[i]->block_size > MI_MEDIUM_MAX_OBJ_SIZE || f->pages[i]->memid.memkind != MI_MEM_ARENA) { failure = 7; goto failed; }
  f->heap = heap; signal_ready(f, f->full_queue && f->direct_cache_empty); if (!f->setup_valid) goto failed;
  if (pthread_mutex_lock(&f->mutex) != 0) return NULL;
  while (!f->allow_thread_done) if (pthread_cond_wait(&f->condition, &f->mutex) != 0) { (void)pthread_mutex_unlock(&f->mutex); return NULL; }
  (void)pthread_mutex_unlock(&f->mutex); mi_thread_done();
  if (pthread_mutex_lock(&f->mutex) == 0) { f->producer_done = true; (void)pthread_cond_broadcast(&f->condition); (void)pthread_mutex_unlock(&f->mutex); }
  return NULL;
failed:
  for (size_t i = 0; i < f->block_count; i++) if (f->blocks[i] != NULL) { mi_free(f->blocks[i]); f->blocks[i] = NULL; }
  if (heap != NULL) mi_heap_destroy(heap); f->heap = NULL; f->failure_stage = failure ? failure : 8; signal_ready(f, false); return NULL;
}

int main(void) {
  fixture_t f = { .mutex = PTHREAD_MUTEX_INITIALIZER, .condition = PTHREAD_COND_INITIALIZER, .arena_id = _mi_arena_id_none() };
  pthread_t worker; bool started = false, valid = false; mi_arena_t* arena = NULL; mi_arena_pages_t* arena_pages = NULL;
  _Atomic(size_t)* abandoned_count = NULL; size_t bin = 0, block_size = 0, capacity = 0, reserved = 0, slice_count = 0; uintptr_t starts[2] = {0,0};
  int arena_backed = 0, medium_page = 0, full = 0, direct = 0, no_remote = 0, same_size = 0; size_t dynamic_exit = 0, dynamic_first = 0, dynamic_second = 0, dynamic_final = 0;
  int page_map_reg[2] = {0,0}, page_map_all_slices_registered[2] = {0,0}, unmapped[2] = {0,0}, abandoned[2] = {0,0}, arena_set[2] = {0,0}, detached[2] = {0,0};
  size_t map_count[2] = {0,0}, page_slice_count[2] = {0,0}, used_exit[2] = {0,0}, prefix[2] = {0,0}, used_prefix[2] = {0,0}, used_boundary[2] = {0,0}; int unmapped_prefix[2] = {0,0}, mapped_boundary[2] = {0,0}, abandoned_set[2] = {0,0};
  size_t page1_first_map_count = 0, page1_first_used = 0; int page1_first_map_registered = 0, page1_first_all_slices_registered = 0, page1_first_arena_set = 0, page1_first_unmapped = 0, page1_first_abandoned = 0, page1_first_dynamic_clear = 0;
  int map_clear[2] = {0,0}, arena_clear[2] = {0,0}, slices_free[2] = {0,0}, abandoned_clear[2] = {0,0}; int first_only = 0, second_retained = 0, route_empty = 0; const size_t request = MI_SMALL_MAX_OBJ_SIZE + sizeof(void*);
  mi_thread_init(); mi_option_set(mi_option_page_reclaim_on_free, 0); mi_option_set(mi_option_page_full_retain, -1);
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &f.arena_id) != 0 || f.arena_id == _mi_arena_id_none()) goto output;
  if (pthread_create(&worker, NULL, producer_main, &f) != 0) goto output; started = true;
  if (pthread_mutex_lock(&f.mutex) != 0) goto output; while (!f.ready) if (pthread_cond_wait(&f.condition, &f.mutex) != 0) { (void)pthread_mutex_unlock(&f.mutex); goto output; } (void)pthread_mutex_unlock(&f.mutex);
  if (!f.setup_valid || f.heap == NULL) goto output;
  mi_page_t* before = f.pages[0]; if (before == NULL) goto output; block_size = before->block_size; capacity = before->capacity; reserved = before->reserved; slice_count = before->memid.mem.arena.slice_count; bin = _mi_bin(block_size); arena = mi_memid_arena(before->memid); if (arena == NULL || bin >= MI_ARENA_BIN_COUNT || slice_count != 8) goto output;
  arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t, &f.heap->arena_pages[arena->arena_idx]); abandoned_count = &f.heap->abandoned_count[bin]; if (arena_pages == NULL) goto output;
  arena_backed = before->memid.memkind == MI_MEM_ARENA; medium_page = block_size > MI_SMALL_MAX_OBJ_SIZE && block_size <= MI_MEDIUM_MAX_OBJ_SIZE; full = mi_page_is_full(f.pages[0]) && mi_page_is_full(f.pages[1]); direct = f.direct_cache_empty; no_remote = mi_page_thread_free(f.pages[0]) == NULL && mi_page_thread_free(f.pages[1]) == NULL; same_size = f.pages[1]->block_size == block_size && f.pages[1]->capacity == capacity && f.pages[1]->reserved == reserved;
  if (!arena_backed || !medium_page || !full || !direct || !no_remote || !same_size || capacity != 42 || reserved != 42 || block_size != 12288 || f.full_queue == false) goto output;
  if (pthread_mutex_lock(&f.mutex) != 0) goto output; f.allow_thread_done = true; (void)pthread_cond_broadcast(&f.condition); (void)pthread_mutex_unlock(&f.mutex); if (pthread_join(worker, NULL) != 0) goto output; started = false; if (!f.producer_done) goto output;
  for (size_t p = 0; p < 2; p++) {
    mi_page_t* page = _mi_safe_ptr_page(f.blocks[p * 42]); if (page == NULL || page->block_size != block_size) goto output; page_slice_count[p] = page->memid.mem.arena.slice_count; size_t count = page_map_count(page, &starts[p], slice_count); map_count[p] = count; page_map_reg[p] = count == 8 && map_span_is(page, starts[p], count, true); page_map_all_slices_registered[p] = page_map_reg[p] && count == slice_count; unmapped[p] = !mi_page_is_abandoned_mapped(page); abandoned[p] = mi_page_is_abandoned(page); arena_set[p] = mi_bitmap_is_setN(arena_pages->pages, page->memid.mem.arena.slice_index, 1); detached[p] = !mi_page_is_in_full(page) && page->next == NULL && page->prev == NULL && !mi_page_is_owned(page); used_exit[p] = page->used;
  }
  dynamic_exit = mi_atomic_load_relaxed(abandoned_count); if (dynamic_exit != 0) goto output;
  for (size_t p = 0; p < 2; p++) {
    mi_page_t* page = _mi_safe_ptr_page(f.blocks[p * 42]); size_t start = p * 42; prefix[p] = reserved / 8; for (size_t i = 0; i < prefix[p]; i++) { mi_free(f.blocks[start + i]); f.blocks[start + i] = NULL; }
    page = _mi_safe_ptr_page(f.blocks[start + prefix[p]]); if (page == NULL) goto output; used_prefix[p] = page->used; unmapped_prefix[p] = !mi_page_is_abandoned_mapped(page) && mi_page_is_abandoned(page) && mi_page_thread_free(page) == NULL; if (!unmapped_prefix[p] || used_prefix[p] != 37) goto output;
    mi_free(f.blocks[start + prefix[p]]); f.blocks[start + prefix[p]] = NULL; page = _mi_safe_ptr_page(f.blocks[start + prefix[p] + 1]); if (page == NULL) goto output; used_boundary[p] = page->used; mapped_boundary[p] = mi_page_is_abandoned_mapped(page) && mi_page_is_abandoned(page); abandoned_set[p] = arena_pages->pages_abandoned[bin] != NULL && mi_bitmap_is_setN(arena_pages->pages_abandoned[bin], page->memid.mem.arena.slice_index, 1); if (!mapped_boundary[p] || !abandoned_set[p] || used_boundary[p] != 36) goto output; if (p == 1) dynamic_second = mi_atomic_load_relaxed(abandoned_count);
    for (size_t i = prefix[p] + 1; i < 42; i++) { mi_free(f.blocks[start + i]); f.blocks[start + i] = NULL; }
    map_clear[p] = map_span_is(page, starts[p], slice_count, false); arena_clear[p] = mi_bitmap_is_clearN(arena_pages->pages, page->memid.mem.arena.slice_index, 1); slices_free[p] = mi_bbitmap_is_setN(arena->slices_free, page->memid.mem.arena.slice_index, slice_count); abandoned_clear[p] = arena_pages->pages_abandoned[bin] == NULL || mi_bitmap_is_clearN(arena_pages->pages_abandoned[bin], page->memid.mem.arena.slice_index, 1); if (!map_clear[p] || !arena_clear[p] || !slices_free[p] || !abandoned_clear[p]) goto output; if (p == 0) { dynamic_first = mi_atomic_load_relaxed(abandoned_count); page = _mi_safe_ptr_page(f.blocks[42]); if (page == NULL) goto output; uintptr_t retained_start = 0; page1_first_map_count = page_map_count(page, &retained_start, slice_count); page1_first_map_registered = page1_first_map_count == 8 && retained_start == starts[1] && map_span_is(page, starts[1], 8, true); page1_first_all_slices_registered = page1_first_map_registered && page1_first_map_count == slice_count; page1_first_arena_set = mi_bitmap_is_setN(arena_pages->pages, page->memid.mem.arena.slice_index, 1); page1_first_unmapped = !mi_page_is_abandoned_mapped(page); page1_first_abandoned = mi_page_is_abandoned(page); page1_first_dynamic_clear = arena_pages->pages_abandoned[bin] == NULL || mi_bitmap_is_clearN(arena_pages->pages_abandoned[bin], page->memid.mem.arena.slice_index, 1); page1_first_used = page->used; second_retained = page1_first_all_slices_registered && page1_first_arena_set && page1_first_unmapped && page1_first_abandoned && page1_first_dynamic_clear && page1_first_used == 42; first_only = second_retained; }
    if (p == 1) dynamic_final = mi_atomic_load_relaxed(abandoned_count);
  }
  route_empty = dynamic_final == 0; valid = arena_backed && medium_page && full && f.full_queue && direct && no_remote && same_size && page_slice_count[0] == 8 && page_slice_count[1] == 8 && dynamic_exit == 0 && first_only && second_retained && dynamic_first == 0 && dynamic_second == 1 && dynamic_final == 0 && page1_first_map_registered && page1_first_all_slices_registered && page1_first_arena_set && page1_first_unmapped && page1_first_abandoned && page1_first_dynamic_clear && page1_first_used == 42;
output:
  printf("CRABC_MI_DYNAMIC_FULL_MEDIUM_HOMOGENEOUS_AGGREGATE_TRACE_BEGIN\n");
#define B(k,v) printf("trace.dynamic_full_medium_homogeneous_aggregate.%s=%d\n", k, (v)?1:0)
#define N(k,v) printf("trace.dynamic_full_medium_homogeneous_aggregate.%s=%zu\n", k, (size_t)(v))
  B("arena_backed",arena_backed); B("medium_page",medium_page); N("page_count",2); B("same_size",same_size); B("full_before_thread_done",full); N("full_queue_count_before_thread_done",f.full_queue?2:0); B("direct_cache_empty_before_thread_done",direct); B("no_remote_free_before_thread_done",no_remote); N("request_size",request); N("block_size",block_size); N("capacity",capacity); N("reserved",reserved); N("slice_count",slice_count); N("dynamic_abandoned_count_after_thread_done",dynamic_exit);
  for (size_t p=0;p<2;p++) {
    out_page_bool(p,"unmapped_after_thread_done",unmapped[p]); out_page_bool(p,"abandoned_after_thread_done",abandoned[p]); out_page_bool(p,"page_map_registered_after_thread_done",page_map_reg[p]); out_page_number(p,"page_map_slice_count_after_thread_done",map_count[p]); out_page_bool(p,"page_map_all_slices_registered_after_thread_done",page_map_all_slices_registered[p]); out_page_number(p,"slice_count_after_thread_done",page_slice_count[p]); out_page_bool(p,"arena_page_bitmap_set_after_thread_done",arena_set[p]); out_page_bool(p,"full_queue_detached_after_thread_done",detached[p]); out_page_number(p,"used_after_thread_done",used_exit[p]); out_page_number(p,"unmapped_prefix_free_count",prefix[p]); out_page_number(p,"used_after_unmapped_prefix",used_prefix[p]); out_page_bool(p,"unmapped_after_unmapped_prefix",unmapped_prefix[p]); out_page_bool(p,"mapped_after_reabandon_boundary",mapped_boundary[p]); out_page_bool(p,"dynamic_abandoned_bitmap_set_after_reabandon_boundary",abandoned_set[p]); out_page_number(p,"used_after_reabandon_boundary",used_boundary[p]); out_page_bool(p,"page_map_unregistered_after_terminal_free",map_clear[p]); out_page_bool(p,"arena_page_bitmap_clear_after_terminal_free",arena_clear[p]); out_page_bool(p,"arena_slice_released_after_terminal_free",slices_free[p]); out_page_bool(p,"dynamic_abandoned_bitmap_clear_after_terminal_free",abandoned_clear[p]); }
  out_page_bool(1,"page_map_registered_after_first_terminal",page1_first_map_registered); out_page_number(1,"page_map_slice_count_after_first_terminal",page1_first_map_count); out_page_bool(1,"page_map_all_slices_registered_after_first_terminal",page1_first_all_slices_registered); out_page_bool(1,"arena_page_bitmap_set_after_first_terminal",page1_first_arena_set); out_page_bool(1,"unmapped_after_first_terminal",page1_first_unmapped); out_page_bool(1,"abandoned_after_first_terminal",page1_first_abandoned); out_page_bool(1,"dynamic_abandoned_bitmap_clear_after_first_terminal",page1_first_dynamic_clear); out_page_number(1,"used_after_first_terminal",page1_first_used);
  N("dynamic_abandoned_count_after_first_terminal",dynamic_first); N("dynamic_abandoned_count_after_second_boundary",dynamic_second); N("dynamic_abandoned_count_after_final_terminal",dynamic_final); B("first_terminal_released_only",first_only); B("second_page_retained_after_first_terminal",second_retained); B("route_empty_after_final_terminal",route_empty); B("valid",valid); printf("CRABC_MI_DYNAMIC_FULL_MEDIUM_HOMOGENEOUS_AGGREGATE_TRACE_END\n");
  if (started) { if (pthread_mutex_lock(&f.mutex)==0) { f.allow_thread_done=true; (void)pthread_cond_broadcast(&f.condition); (void)pthread_mutex_unlock(&f.mutex); } (void)pthread_join(worker,NULL); }
  for (size_t i=0;i<MAX_BLOCKS;i++) if (f.blocks[i]!=NULL) { mi_free(f.blocks[i]); f.blocks[i]=NULL; } if (f.heap!=NULL) mi_heap_destroy(f.heap); return valid?0:2;
}
'''

_BASE_SCHEMA_TEMPLATE = _base._schema_template


def exactly_matches(observed, expected):
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
    value = _BASE_SCHEMA_TEMPLATE()
    value["schema"] = "crabc-mimalloc-x86_64-dynamic-full-medium-homogeneous-aggregate-evidence"
    value["profile"] = EXPECTED_PROFILE
    value["harness_dependency"] = {"path": relative(BASE_PATH), "sha256": sha256_file(BASE_PATH)}
    value["scope"] = copy.deepcopy(EXPECTED_SCOPE)
    value["tls"] = copy.deepcopy(EXPECTED_TLS)
    value["source_anchors"] = [
        {"member": m, "start_line": s, "end_line": e, "sha256": d}
        for m, s, e, d in EXPECTED_SOURCE_ANCHORS
    ]
    value["c_probe_sha256"] = sha256_bytes(C_TRACE_PROBE.encode())
    value["rust_test"] = {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER}
    value["trace"] = {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": dict(EXPECTED_TRACE_VALUES)}
    return value


def load_schema(path=None):
    """Load the aggregate schema without crossing the singleton module globals."""
    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read dynamic-full-medium-homogeneous-aggregate schema") from error
    if not exactly_matches(schema, _schema_template()):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate checked-in schema drifted")
    try:
        pin = RUNNER.load_pin()
    except RUNNER.HarnessError as error:
        raise EvidenceError("cannot validate pinned dynamic-full-medium-homogeneous-aggregate upstream") from error
    observed = {"archive_root": pin["archive_root"], "revision": pin["revision"], "version": pin["version"]}
    if not exactly_matches(observed, EXPECTED_UPSTREAM) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate upstream archive pin drifted")
    return schema


def validate_trace(trace, *, description):
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
        raise EvidenceError(f"{description} differs from the fixed aggregate trace: " + "; ".join(details))


def parse_trace(output, *, description):
    try:
        return RUNNER.parse_address_independent_trace(
            output, begin=TRACE_BEGIN, end=TRACE_END, description=description
        )
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error


def c_trace_command(compiler, source, probe_source, probe_binary, schema):
    return [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"), *schema["release_flags"], str(probe_source), *(str(source / member) for member in schema["release_source_set"]), "-pthread", "-o", str(probe_binary)]


def validate_c_command(command, schema):
    definitions = [part for part in command if part in _base.EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in RUNNER.CONFIGURATION_PROFILES["release"]]
    if schema.get("tls") != EXPECTED_TLS or definitions != list(schema["compile_definitions"]):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate C command contract drifted")
    if flags != list(schema["release_flags"]) or "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate C command release pthread/TLS drifted")


def validate_normalized_c_command(command, schema):
    stem = "dynamic-full-medium-homogeneous-aggregate"
    expected = ["-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src", *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/{stem}.c", *(f"{NORMALIZED_PINNED_SOURCE}/{m}" for m in schema["release_source_set"]), "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/{stem}-c"]
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report C command drifted")


def build_c_trace(compiler, readelf, source, temporary, schema):
    stem = "dynamic-full-medium-homogeneous-aggregate"
    probe_source, probe_binary = temporary / f"{stem}.c", temporary / f"{stem}-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema); validate_c_command(command, schema)
    try:
        RUNNER.require_success(RUNNER.command_record(command, cwd=source), "pinned C dynamic full-medium homogeneous aggregate build")
        header = RUNNER.command_record((readelf, "-h", str(probe_binary)), cwd=source); RUNNER.require_success(header, "pinned C dynamic full-medium homogeneous aggregate ELF identity")
        elf = RUNNER.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = RUNNER.command_record((str(probe_binary),), cwd=source); RUNNER.require_success(execution, "pinned C dynamic full-medium homogeneous aggregate execution")
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C dynamic full-medium homogeneous aggregate trace"); validate_trace(trace, description="pinned C dynamic full-medium homogeneous aggregate trace")
    return {"build_command": normalize_command(command, temporary, source), "elf": elf, "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/{stem}-c"], "source_sha256": sha256_bytes(C_TRACE_PROBE.encode()), "trace": trace}


def compare_traces(c_trace, rust_trace):
    validate_trace(c_trace, description="pinned C dynamic full-medium homogeneous aggregate trace")
    validate_trace(rust_trace, description="Rust dynamic full-medium homogeneous aggregate trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise EvidenceError("Rust dynamic full-medium homogeneous aggregate trace differs from pinned C: " + ", ".join(mismatches))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def report_from_results(*, schema, provenance, archive_sha256, anchors, c_probe, rust_probe):
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report inputs lack trace records")
    report = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": "mimalloc-x86_64-dynamic-full-medium-homogeneous-aggregate-differential-evidence",
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


def validate_report(report):
    kind = "mimalloc-x86_64-dynamic-full-medium-homogeneous-aggregate-differential-evidence"
    required = {
        "c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe",
        "scope", "source", "status", "target", "trace", "upstream",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report schema drifted")
    if report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report format/status drifted")
    if report["kind"] != kind:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report kind drifted")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report target/upstream drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report private boundary drifted")
    if not any(
        exactly_matches(report["provenance"], candidate)
        for candidate in (
            {"execution_mode": "native", "host_architecture": "x86_64"},
            {"execution_mode": "native", "host_architecture": "amd64"},
        )
    ):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report trace contract drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report source record is malformed")
    if source["archive_sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report archive identity drifted")
    if not exactly_matches(source["anchors"], schema["source_anchors"]):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report source anchors drifted")
    if not exactly_matches(source["release_flags"], schema["release_flags"]):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report release flags drifted")
    if not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report source set drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report Rust probe record drifted")
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report C ELF identity drifted")
    stem = "dynamic-full-medium-homogeneous-aggregate"
    if c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/{stem}-c"]:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report C run command drifted")
    if c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode()):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report C source hash drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if type(rust_probe["passed_test_count"]) is not int or rust_probe["passed_test_count"] != 1:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report Rust test selection drifted")
    if not exactly_matches(rust_probe["target_dir"], {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report Rust target directory drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report Rust lockfile identity drifted")
    if not exactly_matches(rust_probe["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report Rust source identity drifted")
    if not isinstance(c_probe["trace"], Mapping) or not isinstance(rust_probe["trace"], Mapping):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report lacks C/Rust traces")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report comparison drifted")


def validate_normalized_rust_command(command):
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report Rust command is malformed")
    expected = [
        "test", "--locked", "--target", TARGET, "--target-dir",
        f"{NORMALIZED_EVIDENCE_ROOT}/rust-target", "-p", "crabc-mimalloc", "--lib",
        "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture",
        "--test-threads=1",
    ]
    if Path(command[0]).name != "cargo" or command[1:] != expected:
        raise EvidenceError("dynamic-full-medium-homogeneous-aggregate report Rust command drifted")


def require_native_x86_64():
    try:
        return RUNNER.require_native_x86_64()
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_source_anchors(schema, source):
    validated = []
    for anchor in schema["source_anchors"]:
        member = str(anchor["member"])
        contents = (source / member).read_bytes()
        observed = sha256_bytes(
            _base.source_range(contents, int(anchor["start_line"]), int(anchor["end_line"]))
        )
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned dynamic-full-medium-homogeneous-aggregate source anchor drifted: {member}")
        validated.append(dict(anchor))
    return validated


def normalize_command(command, temporary, source):
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


def rust_trace_command(cargo, target_dir):
    return [cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir), "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]


def build_rust_trace(cargo, temporary):
    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = RUNNER.command_record(command, cwd=ROOT, environment=environment)
        RUNNER.require_success(execution, "Rust dynamic-full-medium-homogeneous aggregate fixture")
        passed = RUNNER.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust dynamic-full-medium-homogeneous aggregate fixture passed {passed} tests, expected one")
    trace = parse_trace(str(execution["stdout"]) + "\n" + str(execution["stderr"]), description="Rust dynamic-full-medium-homogeneous aggregate trace")
    validate_trace(trace, description="Rust dynamic-full-medium-homogeneous aggregate trace")
    return {
        "cargo_command": normalize_command(command, temporary, None),
        "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
        "passed_test_count": passed,
        "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)},
        "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"},
        "trace": trace,
    }


def run_evidence(*, offline, report_path):
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = RUNNER.load_pin()
        archive = RUNNER.fetch_archive(pin, offline)
    except RUNNER.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-dynamic-full-medium-homogeneous-aggregate-") as temporary_name:
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
        report = report_from_results(schema=schema, provenance=provenance, archive_sha256=sha256_file(archive), anchors=anchors, c_probe=c_probe, rust_probe=rust_probe)
    if sha256_file(LOCKFILE) != before_lockfile:
        raise EvidenceError("Cargo.lock changed despite the required --locked Rust trace command")
    RUNNER.write_json(report_path, report)
    return report


for _name in ("EvidenceError", "sha256_bytes", "sha256_file", "relative", "EXPECTED_TARGET", "EXPECTED_UPSTREAM", "EXPECTED_ARCHIVE_SHA256", "EXPECTED_COMPILE_DEFINITIONS", "EXPECTED_C_ELF", "LOCKFILE", "TARGET", "NORMALIZED_EVIDENCE_ROOT", "NORMALIZED_PINNED_SOURCE"):
    globals()[_name] = getattr(_base, _name)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--offline", action="store_true"); parser.add_argument("--report", type=Path, default=REPORT_DEFAULT); args = parser.parse_args()
    try: report = run_evidence(offline=args.offline, report_path=args.report)
    except (EvidenceError, OSError, ValueError) as error:
        print("allocator x86-64 dynamic-full-medium-homogeneous-aggregate differential: FAIL: " + str(error), file=os.sys.stderr); return 1
    print("allocator x86-64 dynamic-full-medium-homogeneous-aggregate differential: PASS " f"({report['comparison']['compared_value_count']} logical values; report: {relative(args.report)})"); return 0


if __name__ == "__main__":
    raise SystemExit(main())
