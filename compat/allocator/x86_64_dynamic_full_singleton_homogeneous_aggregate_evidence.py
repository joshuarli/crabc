#!/usr/bin/env python3
"""Differentially prove the private native full-singleton aggregate route.

The pinned C fixture deliberately proves only two same-size arena-backed
singleton pages. A worker fills both pages, calls real ``mi_thread_done``, and
is joined before the consumer resolves saved addresses through PageMap and
frees the blocks in order. The Rust side is an explicitly bounded typed model
of the same transition; it does not claim a Rust thread or join boundary.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
_spec = importlib.util.spec_from_file_location("regular_small_base_singleton", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
RUNNER = _base.run

SCHEMA_PATH = ROOT / "compat/allocator/x86_64-dynamic-full-singleton-homogeneous-aggregate-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/dynamic-full-singleton-homogeneous-aggregate.json"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/dynamic_theap.rs"
EXPECTED_PROFILE = "linux-x86_64-private-dynamic-full-singleton-homogeneous-aggregate"
RUST_TEST_FILTER = (
    "dynamic_theap::tests::"
    "x86_64_dynamic_full_singleton_homogeneous_aggregate_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_DYNAMIC_FULL_SINGLETON_HOMOGENEOUS_AGGREGATE_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DYNAMIC_FULL_SINGLETON_HOMOGENEOUS_AGGREGATE_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

EXPECTED_TARGET = {"architecture": "x86_64", "endianness": "little", "rust_target": "x86_64-unknown-linux-musl", "system": "linux"}
EXPECTED_UPSTREAM = {"archive_root": "mimalloc-3.5.0", "revision": "18b08671c9302247bfb682286e6bf3cc1773f801", "version": "3.5.0"}
EXPECTED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
EXPECTED_COMPILE_DEFINITIONS = ("-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1")
EXPECTED_C_ELF = {"class": "ELF64", "endianness": "little", "machine": "Advanced Micro Devices X86-64"}
EXPECTED_TLS = {"compiler_model": "initial-exec", "mimalloc_model": "MI_TLS_MODEL_LOCAL", "thread_pointer_path": "x86_64-fs-tls-slot-fallback"}
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "c_oracle_real_thread_exit_and_join_required": True,
    "c_oracle_sequential_joined_consumer_frees_only": True,
    "c_oracle_two_full_singleton_pages_before_thread_done": True,
    "c_oracle_independent_singleton_terminal_release_only": True,
    "dynamic_full_singleton_full_bin_only": True,
    "dynamic_full_singleton_homogeneous_aggregate_only": True,
    "dynamic_unmapped_then_terminal_release_only": True,
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
    "two_or_more_full_singleton_pages_required": True,
    "dynamic_abandoned_bitmap_or_count_claimed": False,
}

# These are the source regions governing page queues, PageMap, arena ownership,
# thread exit, and the release path in the pinned v3.5.0 archive.
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
)


def _page_values(prefix: str) -> dict[str, int]:
    return {
        f"{prefix}.unmapped_after_thread_done": 1,
        f"{prefix}.unowned_after_thread_done": 1,
        f"{prefix}.abandoned_after_thread_done": 1,
        f"{prefix}.page_map_registered_after_thread_done": 1,
        f"{prefix}.page_map_slice_count_after_thread_done": 9,
        f"{prefix}.page_map_all_slices_registered_after_thread_done": 1,
        f"{prefix}.slice_count_after_thread_done": 9,
        f"{prefix}.arena_page_bitmap_set_after_thread_done": 1,
        f"{prefix}.full_queue_detached_after_thread_done": 1,
        f"{prefix}.used_after_thread_done": 1,
        f"{prefix}.page_map_unregistered_after_terminal_free": 1,
        f"{prefix}.arena_page_bitmap_clear_after_terminal_free": 1,
        f"{prefix}.arena_slice_released_after_terminal_free": 1,
    }


EXPECTED_TRACE_VALUES = {
    "trace.dynamic_full_singleton_homogeneous_aggregate.arena_backed": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.large_singleton": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.page_count": 2,
    "trace.dynamic_full_singleton_homogeneous_aggregate.same_size": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.full_before_thread_done": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.full_queue_count_before_thread_done": 2,
    "trace.dynamic_full_singleton_homogeneous_aggregate.direct_cache_empty_before_thread_done": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.no_remote_free_before_thread_done": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.request_size": 524289,
    "trace.dynamic_full_singleton_homogeneous_aggregate.block_size": 589824,
    "trace.dynamic_full_singleton_homogeneous_aggregate.capacity": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.reserved": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.slice_count": 9,
    "trace.dynamic_full_singleton_homogeneous_aggregate.first_terminal_released_only": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.second_page_retained_after_first_terminal": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.second_terminal_clean": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.valid": 1,
}
EXPECTED_TRACE_VALUES.update(_page_values("trace.dynamic_full_singleton_homogeneous_aggregate.page0"))
EXPECTED_TRACE_VALUES.update(_page_values("trace.dynamic_full_singleton_homogeneous_aggregate.page1"))
EXPECTED_TRACE_VALUES.update({
    "trace.dynamic_full_singleton_homogeneous_aggregate.page1.page_map_registered_after_first_terminal": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.page1.page_map_slice_count_after_first_terminal": 9,
    "trace.dynamic_full_singleton_homogeneous_aggregate.page1.page_map_all_slices_registered_after_first_terminal": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.page1.arena_page_bitmap_set_after_first_terminal": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.page1.unmapped_after_first_terminal": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.page1.unowned_after_first_terminal": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.page1.abandoned_after_first_terminal": 1,
    "trace.dynamic_full_singleton_homogeneous_aggregate.page1.used_after_first_terminal": 1,
})


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
typedef struct fixture_s { pthread_mutex_t mutex; pthread_cond_t condition; mi_arena_id_t arena_id; mi_arena_pages_t* arena_pages; mi_arena_t* arena; void* blocks[PAGE_COUNT]; mi_page_t* pages[PAGE_COUNT]; bool ready; bool setup_valid; bool allow_thread_done; bool worker_done; bool full_queue; bool direct_empty; } fixture_t;
static void signal_ready(fixture_t* f, bool valid) { if (pthread_mutex_lock(&f->mutex) != 0) return; f->setup_valid = valid; f->ready = true; (void)pthread_cond_broadcast(&f->condition); (void)pthread_mutex_unlock(&f->mutex); }
static bool full_queue_has_two(const mi_page_queue_t* q, mi_page_t* a, mi_page_t* b) { if (q == NULL || q->count != 2) return false; size_t n = 0; bool aa = false, bb = false; for (mi_page_t* p = q->first; p != NULL && n <= 2; p = p->next) { aa |= p == a; bb |= p == b; n++; } return n == 2 && aa && bb; }
static bool direct_cache_empty(const mi_theap_t* t) { if (t == NULL) return false; for (size_t i = 0; i < MI_PAGES_DIRECT; i++) if (t->pages_free_direct[i] != _mi_page_empty_get()) return false; return true; }
static size_t page_map_count(mi_page_t* page, uintptr_t* start_out) { size_t area_size = 0; uint8_t* area = mi_page_area(page, &area_size); uint8_t* start = mi_page_slice_start(page); if (area == NULL || start == NULL || area < start || area_size > MI_LARGE_PAGE_SIZE) return 0; *start_out = (uintptr_t)start; return mi_slice_count_of_size(area_size) + (size_t)((area - start) / MI_ARENA_SLICE_SIZE); }
static bool map_span_is(uintptr_t start, size_t count, bool mapped) { for (size_t i = 0; i < count; i++) if ((_mi_safe_ptr_page((const void*)(start + i * MI_ARENA_SLICE_SIZE)) != NULL) != mapped) return false; return true; }
static bool detached_unowned(mi_page_t* p) { return p != NULL && p->next == NULL && p->prev == NULL && !mi_page_is_owned(p); }
static void* worker_main(void* arg) {
  fixture_t* f = (fixture_t*)arg; const size_t request = MI_LARGE_MAX_OBJ_SIZE + 1; mi_heap_t* heap = mi_heap_new_in_arena(f->arena_id); if (heap == NULL) { signal_ready(f, false); return NULL; }
  for (size_t i = 0; i < PAGE_COUNT; i++) { f->blocks[i] = mi_heap_malloc(heap, request); if (f->blocks[i] == NULL) { signal_ready(f, false); return NULL; } f->pages[i] = _mi_ptr_page(f->blocks[i]); if (f->pages[i] == NULL || (i != 0 && f->pages[i] == f->pages[0])) { signal_ready(f, false); return NULL; } }
  mi_theap_t* t = _mi_heap_theap(heap); mi_arena_t* arena = mi_memid_arena(f->pages[0]->memid); mi_arena_pages_t* arena_pages = arena == NULL ? NULL : mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]); f->full_queue = full_queue_has_two(&t->pages[MI_BIN_FULL], f->pages[0], f->pages[1]); f->direct_empty = direct_cache_empty(t); f->arena = arena; f->arena_pages = arena_pages; f->setup_valid = f->full_queue && f->direct_empty && arena != NULL && arena_pages != NULL;
  for (size_t i = 0; i < PAGE_COUNT; i++) f->setup_valid = f->setup_valid && mi_page_is_full(f->pages[i]) && mi_page_is_singleton(f->pages[i]) && f->pages[i]->block_size == 589824 && f->pages[i]->capacity == 1 && f->pages[i]->reserved == 1 && f->pages[i]->memid.memkind == MI_MEM_ARENA && mi_memid_arena(f->pages[i]->memid) == arena;
  signal_ready(f, f->setup_valid); if (!f->setup_valid) return NULL;
  if (pthread_mutex_lock(&f->mutex) != 0) return NULL; while (!f->allow_thread_done) if (pthread_cond_wait(&f->condition, &f->mutex) != 0) { (void)pthread_mutex_unlock(&f->mutex); return NULL; } (void)pthread_mutex_unlock(&f->mutex);
  mi_thread_done(); if (pthread_mutex_lock(&f->mutex) == 0) { f->worker_done = true; (void)pthread_cond_broadcast(&f->condition); (void)pthread_mutex_unlock(&f->mutex); } return NULL;
}
int main(void) {
  fixture_t f = { .mutex = PTHREAD_MUTEX_INITIALIZER, .condition = PTHREAD_COND_INITIALIZER, .arena_id = _mi_arena_id_none() }; pthread_t worker; bool started = false, valid = false; uintptr_t starts[2] = {0,0}; size_t slice_indices[2] = {0,0}; int arena_backed = 0, large_singleton = 0, full = 0, direct = 0, no_remote = 0, same_size = 0, first_only = 0, second_retained = 0, second_clean = 0; size_t block_size = 0, capacity = 0, reserved = 0, slice_count = 0, map_count[2] = {0,0}, used_exit[2] = {0,0}; int unmapped[2] = {0,0}, unowned[2] = {0,0}, abandoned[2] = {0,0}, map_registered[2] = {0,0}, arena_set[2] = {0,0}, detached[2] = {0,0}, map_clear[2] = {0,0}, arena_clear[2] = {0,0}, slices_free[2] = {0,0}; int first_map_registered = 0, first_arena_set = 0, first_unmapped = 0, first_unowned = 0, first_abandoned = 0; size_t first_map_count = 0, first_used = 0; const size_t request = MI_LARGE_MAX_OBJ_SIZE + 1;
  mi_thread_init(); mi_option_set(mi_option_page_reclaim_on_free, 0); mi_option_set(mi_option_page_full_retain, -1); if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &f.arena_id) != 0) goto output; if (pthread_create(&worker, NULL, worker_main, &f) != 0) goto output; started = true; if (pthread_mutex_lock(&f.mutex) != 0) goto output; while (!f.ready) if (pthread_cond_wait(&f.condition, &f.mutex) != 0) { (void)pthread_mutex_unlock(&f.mutex); goto output; } (void)pthread_mutex_unlock(&f.mutex); if (!f.setup_valid || f.arena == NULL || f.arena_pages == NULL) goto output;
  mi_page_t* before = f.pages[0]; block_size = before->block_size; capacity = before->capacity; reserved = before->reserved; slice_count = before->memid.mem.arena.slice_count; arena_backed = before->memid.memkind == MI_MEM_ARENA; large_singleton = block_size > MI_MEDIUM_MAX_OBJ_SIZE && mi_page_is_singleton(before); full = mi_page_is_full(f.pages[0]) && mi_page_is_full(f.pages[1]); direct = f.direct_empty; no_remote = mi_page_thread_free(f.pages[0]) == NULL && mi_page_thread_free(f.pages[1]) == NULL; same_size = f.pages[1]->block_size == block_size && f.pages[1]->capacity == capacity && f.pages[1]->reserved == reserved; if (!arena_backed || !large_singleton || !full || !direct || !no_remote || !same_size || block_size != 589824 || capacity != 1 || reserved != 1 || slice_count != 9 || !f.full_queue) goto output;
  if (pthread_mutex_lock(&f.mutex) != 0) goto output; f.allow_thread_done = true; (void)pthread_cond_broadcast(&f.condition); (void)pthread_mutex_unlock(&f.mutex); if (pthread_join(worker, NULL) != 0) goto output; started = false; if (!f.worker_done) goto output;
  mi_arena_pages_t* ap = f.arena_pages; mi_arena_t* arena = f.arena; if (ap == NULL || arena == NULL) goto output; for (size_t i = 0; i < 2; i++) { mi_page_t* p = _mi_safe_ptr_page(f.blocks[i]); if (p == NULL) goto output; slice_indices[i] = p->memid.mem.arena.slice_index; map_count[i] = page_map_count(p, &starts[i]); used_exit[i] = p->used; map_registered[i] = map_count[i] == 9 && map_span_is(starts[i], 9, true); unmapped[i] = !mi_page_is_abandoned_mapped(p); unowned[i] = !mi_page_is_owned(p); abandoned[i] = mi_page_is_abandoned(p); arena_set[i] = mi_bitmap_is_setN(ap->pages, slice_indices[i], 1); detached[i] = detached_unowned(p); if (!map_registered[i] || !unmapped[i] || !unowned[i] || !abandoned[i] || !arena_set[i] || !detached[i] || used_exit[i] != 1) goto output; }
  mi_free(f.blocks[0]); f.blocks[0] = NULL; mi_page_t* retained = _mi_safe_ptr_page(f.blocks[1]); if (retained == NULL) goto output; first_map_count = page_map_count(retained, &starts[1]); first_map_registered = first_map_count == 9 && map_span_is(starts[1], 9, true); first_arena_set = mi_bitmap_is_setN(ap->pages, retained->memid.mem.arena.slice_index, 1); first_unmapped = !mi_page_is_abandoned_mapped(retained); first_unowned = !mi_page_is_owned(retained); first_abandoned = mi_page_is_abandoned(retained); first_used = retained->used; second_retained = first_map_registered && first_arena_set && first_unmapped && first_unowned && first_abandoned && first_used == 1; map_clear[0] = !map_span_is(starts[0], 9, true); arena_clear[0] = mi_bitmap_is_clearN(ap->pages, slice_indices[0], 1); slices_free[0] = mi_bbitmap_is_setN(arena->slices_free, slice_indices[0], 9); first_only = second_retained && map_clear[0] && arena_clear[0] && slices_free[0]; mi_free(f.blocks[1]); f.blocks[1] = NULL; map_clear[1] = !map_span_is(starts[1], 9, true); arena_clear[1] = mi_bitmap_is_clearN(ap->pages, slice_indices[1], 1); slices_free[1] = mi_bbitmap_is_setN(arena->slices_free, slice_indices[1], 9); second_clean = map_clear[1] && arena_clear[1] && slices_free[1]; valid = first_only && second_clean;
output:
  printf("CRABC_MI_DYNAMIC_FULL_SINGLETON_HOMOGENEOUS_AGGREGATE_TRACE_BEGIN\n");
  #define B(k,v) printf("trace.dynamic_full_singleton_homogeneous_aggregate.%s=%d\n", k, (v) ? 1 : 0)
  #define N(k,v) printf("trace.dynamic_full_singleton_homogeneous_aggregate.%s=%zu\n", k, (size_t)(v))
  B("arena_backed",arena_backed); B("large_singleton",large_singleton); N("page_count",2); B("same_size",same_size); B("full_before_thread_done",full); N("full_queue_count_before_thread_done",f.full_queue ? 2 : 0); B("direct_cache_empty_before_thread_done",direct); B("no_remote_free_before_thread_done",no_remote); N("request_size",request); N("block_size",block_size); N("capacity",capacity); N("reserved",reserved); N("slice_count",slice_count); for (size_t i=0;i<2;i++) { char key[96]; (void)key; printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.unmapped_after_thread_done=%d\n",i,unmapped[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.unowned_after_thread_done=%d\n",i,unowned[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.abandoned_after_thread_done=%d\n",i,abandoned[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.page_map_registered_after_thread_done=%d\n",i,map_registered[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.page_map_slice_count_after_thread_done=%zu\n",i,map_count[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.page_map_all_slices_registered_after_thread_done=%d\n",i,map_registered[i] && map_count[i] == slice_count); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.slice_count_after_thread_done=%zu\n",i,slice_count); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.arena_page_bitmap_set_after_thread_done=%d\n",i,arena_set[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.full_queue_detached_after_thread_done=%d\n",i,detached[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.used_after_thread_done=%zu\n",i,used_exit[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.page_map_unregistered_after_terminal_free=%d\n",i,map_clear[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.arena_page_bitmap_clear_after_terminal_free=%d\n",i,arena_clear[i]); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page%zu.arena_slice_released_after_terminal_free=%d\n",i,slices_free[i]); }
  printf("trace.dynamic_full_singleton_homogeneous_aggregate.page1.page_map_registered_after_first_terminal=%d\n",first_map_registered); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page1.page_map_slice_count_after_first_terminal=%zu\n",first_map_count); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page1.page_map_all_slices_registered_after_first_terminal=%d\n",first_map_registered && first_map_count == slice_count); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page1.arena_page_bitmap_set_after_first_terminal=%d\n",first_arena_set); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page1.unmapped_after_first_terminal=%d\n",first_unmapped); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page1.unowned_after_first_terminal=%d\n",first_unowned); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page1.abandoned_after_first_terminal=%d\n",first_abandoned); printf("trace.dynamic_full_singleton_homogeneous_aggregate.page1.used_after_first_terminal=%zu\n",first_used); B("first_terminal_released_only",first_only); B("second_page_retained_after_first_terminal",second_retained); B("second_terminal_clean",second_clean); B("valid",valid); printf("CRABC_MI_DYNAMIC_FULL_SINGLETON_HOMOGENEOUS_AGGREGATE_TRACE_END\n");
  if (started) { if (pthread_mutex_lock(&f.mutex) == 0) { f.allow_thread_done = true; (void)pthread_cond_broadcast(&f.condition); (void)pthread_mutex_unlock(&f.mutex); } (void)pthread_join(worker, NULL); } for (size_t i=0;i<2;i++) if (f.blocks[i] != NULL) { mi_free(f.blocks[i]); f.blocks[i] = NULL; } return valid ? 0 : 2;
}
'''


def exactly_matches(observed, expected):
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(observed) == set(expected) and all(exactly_matches(observed[k], expected[k]) for k in expected)
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(exactly_matches(a, b) for a, b in zip(observed, expected))
    return observed == expected


def _schema_template() -> dict:
    value = _base._schema_template()
    value.update({"schema": "crabc-mimalloc-x86_64-dynamic-full-singleton-homogeneous-aggregate-evidence", "profile": EXPECTED_PROFILE, "harness_dependency": {"path": _base.relative(BASE_PATH), "sha256": _base.sha256_file(BASE_PATH)}, "scope": copy.deepcopy(EXPECTED_SCOPE), "tls": copy.deepcopy(EXPECTED_TLS), "source_anchors": [{"member": m, "start_line": s, "end_line": e, "sha256": d} for m, s, e, d in EXPECTED_SOURCE_ANCHORS], "c_probe_sha256": _base.sha256_bytes(C_TRACE_PROBE.encode()), "rust_test": {"path": _base.relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER}, "trace": {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": dict(EXPECTED_TRACE_VALUES)}})
    value["target"] = EXPECTED_TARGET
    value["upstream"] = EXPECTED_UPSTREAM
    return value


def load_schema(path=None):
    path = SCHEMA_PATH if path is None else Path(path)
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise _base.EvidenceError("cannot read dynamic-full-singleton-homogeneous-aggregate schema") from error
    if not exactly_matches(schema, _schema_template()):
        raise _base.EvidenceError("dynamic-full-singleton-homogeneous-aggregate checked-in schema drifted")
    pin = RUNNER.load_pin()
    if {k: pin[k] for k in ("archive_root", "revision", "version")} != EXPECTED_UPSTREAM or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise _base.EvidenceError("dynamic-full-singleton-homogeneous-aggregate upstream archive pin drifted")
    return schema


def validate_trace(trace, *, description):
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace)); unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES)); mismatches = [f"{k} (expected {EXPECTED_TRACE_VALUES[k]}, observed {trace[k]})" for k in sorted(set(trace) & set(EXPECTED_TRACE_VALUES)) if type(trace[k]) is not int or trace[k] != EXPECTED_TRACE_VALUES[k]]
    if missing or unexpected or mismatches:
        raise _base.EvidenceError(f"{description} differs from the fixed singleton trace: missing={missing}, unexpected={unexpected}, mismatches={mismatches}")


def parse_trace(output, *, description):
    try:
        return RUNNER.parse_address_independent_trace(output, begin=TRACE_BEGIN, end=TRACE_END, description=description)
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error


def validate_worker_teardown_source(source: str) -> None:
    """Reject worker-side teardown that could fake owner exit semantics."""
    match = re.search(
        r"static void\* worker_main\s*\([^)]*\)\s*\{(?P<body>.*?)(?=\n\}\s*\nint main)",
        source,
        re.DOTALL,
    )
    if match is None:
        raise _base.EvidenceError("singleton C probe worker_main boundary is missing")
    body = match.group("body")
    if body.count("mi_thread_done()") != 1:
        raise _base.EvidenceError("singleton C probe worker must call real mi_thread_done exactly once")
    forbidden = (
        "mi_free(",
        "mi_heap_destroy(",
        "mi_heap_collect(",
        "mi_abandon(",
        "_mi_page_free(",
        "mi_page_queue_remove(",
        "pthread_exit(",
    )
    found = [token for token in forbidden if token in body]
    if found:
        raise _base.EvidenceError("singleton C probe worker contains forbidden teardown shortcut: " + ", ".join(found))
    post_thread_done = body.split("mi_thread_done();", 1)[1]
    if "f->heap" in post_thread_done or "_mi_heap_theap(" in post_thread_done:
        raise _base.EvidenceError("singleton C probe accesses the worker Theap after mi_thread_done")
    join = source.find("pthread_join(worker")
    first_free = source.find("mi_free(f.blocks[0])")
    if join < 0 or first_free < 0 or join > first_free:
        raise _base.EvidenceError("singleton C probe must join worker before sequential consumer frees")


def validate_source_anchors(schema, source):
    for anchor in schema["source_anchors"]:
        contents = (source / str(anchor["member"])).read_bytes()
        observed = _base.sha256_bytes(_base.source_range(contents, int(anchor["start_line"]), int(anchor["end_line"])))
        if observed != anchor["sha256"]:
            raise _base.EvidenceError(f"pinned singleton source anchor drifted: {anchor['member']}")
    return [dict(a) for a in schema["source_anchors"]]


def c_trace_command(compiler, source, probe_source, probe_binary, schema):
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


def validate_c_command(command, schema):
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in RUNNER.CONFIGURATION_PROFILES["release"]]
    if schema.get("tls") != EXPECTED_TLS or definitions != list(schema["compile_definitions"]):
        raise _base.EvidenceError("singleton C command release contract drifted")
    if flags != list(schema["release_flags"]) or "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise _base.EvidenceError("singleton C command pthread/TLS contract drifted")


def validate_normalized_c_command(command, schema):
    stem = "dynamic-full-singleton-homogeneous-aggregate"
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
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise _base.EvidenceError("singleton report C command drifted")


def normalize_command(command, temporary, source):
    normalized = []
    source_text = str(source) if source is not None else None
    temporary_text = str(temporary)
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            normalized.append(NORMALIZED_PINNED_SOURCE + part[len(source_text):])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text):])
        else:
            normalized.append(part)
    return normalized


def build_c_trace(compiler, readelf, source, temporary, schema):
    stem = "dynamic-full-singleton-homogeneous-aggregate"
    probe_source = temporary / f"{stem}.c"
    probe_binary = temporary / f"{stem}-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    validate_worker_teardown_source(C_TRACE_PROBE)
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        RUNNER.require_success(RUNNER.command_record(command, cwd=source), "pinned C singleton build")
        header = RUNNER.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        RUNNER.require_success(header, "pinned C singleton ELF identity")
        elf = RUNNER.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = RUNNER.command_record((str(probe_binary),), cwd=source)
        RUNNER.require_success(execution, "pinned C singleton execution")
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C singleton trace")
    validate_trace(trace, description="pinned C singleton trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/{stem}-c"],
        "source_sha256": _base.sha256_bytes(C_TRACE_PROBE.encode()),
        "trace": trace,
    }


def compare_traces(c_trace, rust_trace):
    validate_trace(c_trace, description="pinned C singleton trace")
    validate_trace(rust_trace, description="Rust singleton trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise _base.EvidenceError("Rust singleton trace differs from pinned C: " + ", ".join(mismatches))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def report_from_results(*, schema, provenance, archive_sha256, anchors, c_probe, rust_probe):
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise _base.EvidenceError("singleton report inputs lack C/Rust trace records")
    report = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": "mimalloc-x86_64-dynamic-full-singleton-homogeneous-aggregate-differential-evidence",
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
    kind = "mimalloc-x86_64-dynamic-full-singleton-homogeneous-aggregate-differential-evidence"
    required = {
        "c_probe",
        "comparison",
        "format",
        "kind",
        "profile",
        "provenance",
        "rust_probe",
        "scope",
        "source",
        "status",
        "target",
        "trace",
        "upstream",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise _base.EvidenceError("singleton report schema drifted")
    if report["format"] != 1 or report["status"] != "passed":
        raise _base.EvidenceError("singleton report format/status drifted")
    if report["kind"] != kind:
        raise _base.EvidenceError("singleton report kind drifted")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM):
        raise _base.EvidenceError("singleton report target/upstream drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise _base.EvidenceError("singleton report private boundary drifted")
    if not any(
        exactly_matches(report["provenance"], candidate)
        for candidate in (
            {"execution_mode": "native", "host_architecture": "x86_64"},
            {"execution_mode": "native", "host_architecture": "amd64"},
        )
    ):
        raise _base.EvidenceError("singleton report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise _base.EvidenceError("singleton report trace contract drifted")
    source = report["source"]
    required_source = {"archive_sha256", "anchors", "release_flags", "release_source_set"}
    if not isinstance(source, dict) or set(source) != required_source:
        raise _base.EvidenceError("singleton report source record is malformed")
    if source["archive_sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise _base.EvidenceError("singleton report archive identity drifted")
    if not exactly_matches(source["anchors"], schema["source_anchors"]):
        raise _base.EvidenceError("singleton report source anchors drifted")
    if not exactly_matches(source["release_flags"], schema["release_flags"]):
        raise _base.EvidenceError("singleton report release flags drifted")
    if not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise _base.EvidenceError("singleton report source set drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise _base.EvidenceError("singleton report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise _base.EvidenceError("singleton report Rust probe record drifted")
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF):
        raise _base.EvidenceError("singleton report C ELF identity drifted")
    stem = "dynamic-full-singleton-homogeneous-aggregate"
    if c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/{stem}-c"]:
        raise _base.EvidenceError("singleton report C run command drifted")
    if c_probe["source_sha256"] != _base.sha256_bytes(C_TRACE_PROBE.encode()):
        raise _base.EvidenceError("singleton report C source hash drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if type(rust_probe["passed_test_count"]) is not int or rust_probe["passed_test_count"] != 1:
        raise _base.EvidenceError("singleton report Rust test selection drifted")
    expected_target_dir = {
        "isolated": True,
        "retained": False,
        "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
    }
    if not exactly_matches(rust_probe["target_dir"], expected_target_dir):
        raise _base.EvidenceError("singleton report Rust target directory drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    expected_lockfile = {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}
    if not exactly_matches(rust_probe["lockfile"], expected_lockfile):
        raise _base.EvidenceError("singleton report Rust lockfile identity drifted")
    expected_source = {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}
    if not exactly_matches(rust_probe["source"], expected_source):
        raise _base.EvidenceError("singleton report Rust source identity drifted")
    if not isinstance(c_probe["trace"], Mapping) or not isinstance(rust_probe["trace"], Mapping):
        raise _base.EvidenceError("singleton report lacks C/Rust traces")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise _base.EvidenceError("singleton report comparison drifted")


def validate_normalized_rust_command(command):
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise _base.EvidenceError("singleton report Rust command is malformed")
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
    if Path(command[0]).name != "cargo" or command[1:] != expected:
        raise _base.EvidenceError("singleton report Rust command drifted")


def rust_trace_command(cargo, target_dir):
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


def build_rust_trace(cargo, temporary):
    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = RUNNER.command_record(command, cwd=ROOT, environment=environment)
        RUNNER.require_success(execution, "Rust dynamic full-singleton homogeneous aggregate fixture")
        passed = RUNNER.parse_rust_test_count(
            str(execution["stdout"]) + "\n" + str(execution["stderr"])
        )
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error
    if passed != 1:
        raise _base.EvidenceError(
            "Rust dynamic full-singleton homogeneous aggregate fixture "
            f"passed {passed} tests, expected one"
        )
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust singleton trace",
    )
    validate_trace(trace, description="Rust singleton trace")
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


def require_native_x86_64():
    try:
        return RUNNER.require_native_x86_64()
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error


def run_evidence(*, offline, report_path):
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = RUNNER.load_pin()
        archive = RUNNER.fetch_archive(pin, offline)
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(
        prefix="crabc-mimalloc-x86_64-dynamic-full-singleton-homogeneous-aggregate-"
    ) as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = RUNNER.safe_extract(archive, temporary / "source", pin["archive_root"])
            compiler = RUNNER.require_tool("musl-gcc")
            readelf = RUNNER.require_tool("readelf")
            cargo = RUNNER.require_tool("cargo")
        except RUNNER.HarnessError as error:
            raise _base.EvidenceError(str(error)) from error
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
        raise _base.EvidenceError("Cargo.lock changed despite the required --locked Rust trace command")
    RUNNER.write_json(report_path, report)
    return report


for _name in (
    "EvidenceError",
    "sha256_bytes",
    "sha256_file",
    "relative",
    "EXPECTED_TARGET",
    "EXPECTED_UPSTREAM",
    "EXPECTED_ARCHIVE_SHA256",
    "EXPECTED_COMPILE_DEFINITIONS",
    "EXPECTED_C_ELF",
    "LOCKFILE",
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
    args = parser.parse_args()
    try:
        report = run_evidence(offline=args.offline, report_path=args.report)
    except (EvidenceError, OSError, ValueError) as error:
        print(
            "allocator x86-64 dynamic-full-singleton-homogeneous-aggregate differential: FAIL: "
            + str(error),
            file=os.sys.stderr,
        )
        return 1
    print(
        "allocator x86-64 dynamic-full-singleton-homogeneous-aggregate differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; report: {relative(args.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
