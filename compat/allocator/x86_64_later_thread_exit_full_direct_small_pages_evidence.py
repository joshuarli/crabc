#!/usr/bin/env python3
"""Differentially prove the bounded later-main full direct-small aggregate.

This private native Linux/x86-64 lane compares a pinned mimalloc v3.5.0 C
worker with the narrow Rust later-main fixture.  The C oracle fills exactly two
same-bin arena-backed 1024-byte direct-small pages on a real pthread, calls
``mi_thread_done()``, joins it, and only then lets one consumer free each
member sequentially.  It proves the source direct-cache image before the
worker exits, the partial-collector unmapped-to-mapped threshold for each
member, and every member's terminal PageMap/arena/slice release.

The Rust trace is a crate-private test fixture, not a claim of crabc pthread
or TLS-callback ABI parity.  This is fixed-source evidence only; it does not
add public x86-64 runtime support or any non-native execution mode.
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
BASE_PATH = (
    ROOT
    / "compat/allocator/x86_64_dynamic_full_non_direct_small_homogeneous_aggregate_evidence.py"
)
_spec = importlib.util.spec_from_file_location("full_non_direct_small_aggregate_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
RUNNER = _base.RUNNER

SCHEMA_PATH = (
    ROOT
    / "compat/allocator/x86_64-later-thread-exit-full-direct-small-pages-evidence-v3.5.0.json"
)
REPORT_DEFAULT = (
    ROOT
    / "compat/reports/allocator/x86_64/later-thread-exit-full-direct-small-pages.json"
)
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/main_heap_page.rs"
LOCKFILE = ROOT / "Cargo.lock"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = (
    "main_heap_page::tests::"
    "x86_64_later_thread_exit_full_direct_small_pages_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_LATER_THREAD_EXIT_FULL_DIRECT_SMALL_PAGES_TRACE_BEGIN"
TRACE_END = "CRABC_MI_LATER_THREAD_EXIT_FULL_DIRECT_SMALL_PAGES_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"
STEM = "later-thread-exit-full-direct-small-pages"

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
EXPECTED_ARCHIVE_SHA256 = (
    "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
)
EXPECTED_PROFILE = "linux-x86_64-private-later-thread-exit-full-direct-small-pages"
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
EXPECTED_TLS = {
    "compiler_model": "initial-exec",
    "mimalloc_model": "MI_TLS_MODEL_LOCAL",
    "thread_pointer_path": "x86_64-fs-tls-slot-fallback",
}
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "c_oracle_complete_direct_cache_image_before_thread_done": True,
    "c_oracle_independent_member_release_only": True,
    "c_oracle_real_pthread_thread_done_and_join_required": True,
    "c_oracle_sequential_joined_consumer_frees_only": True,
    "c_oracle_two_full_direct_small_pages_before_thread_done": True,
    "c_rust_common_trace_facts_only": True,
    "c_oracle_direct_small_regular_bin_only": True,
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
    "rust_crabc_pthread_or_tls_callback_parity_claimed": False,
    "rust_later_main_typed_route_only": True,
    "rust_scoped_test_worker_and_join_observed": True,
    "two_or_more_full_direct_small_pages_required": True,
}

# This union covers the aggregate source traversal, the direct-cache update,
# the partial collector, PageMap lifetime, and the pinned local TLS model.
EXPECTED_SOURCE_ANCHORS = (
    ("src/theap.c", 23, 48, "4df1e18388900637745d7867bb5a4b6e1bac86679b550bb8ff77ac6ff9a68679"),
    ("src/theap.c", 97, 114, "9c66a394ded8185fc4af733ddcf4fd2f60db3922fc8c547400bc612def40f2d5"),
    ("src/theap.c", 123, 152, "c7811179e91e8cd66dc0587e824265cff4db6ce660ba0639309d909dd0df519c"),
    ("src/theap.c", 228, 232, "16c0e73a20b9a94bf994c4e83836c976f5683e3c6e8b18935782a934405adba0"),
    ("src/page-queue.c", 204, 244, "4216ce3f998d0a8c3891e0c89e1feaa34aff407d10e14135e68334ce833d6e6b"),
    ("src/page-queue.c", 252, 274, "d72c1999eec27a2818fd657c62aa93ada275b1e63911569154a16619ca2f202b"),
    ("src/page.c", 214, 243, "35148cff687e602b8de307ca1abad524655f48bf4410b2c64a7e44af8909203b"),
    ("src/page.c", 245, 268, "e154cd246df21cf66e7bf2b966567c3c9bb58aad09e97434818da52581a0354c"),
    ("src/page.c", 291, 303, "d363079d5e484919082b5602cc3757a3e3a357e68594fc040d902232c7458bbf"),
    ("src/page.c", 771, 798, "4e2872a2891831c5b9982dcfc21e22471655a0cf4037e01dc072f7ba094ca477"),
    ("src/page.c", 1072, 1081, "c0e6b4f003a664d9a0e78a4b7036b760ad37ba0f91755fc534facfdd05f779d4"),
    ("src/arena.c", 631, 651, "f413bc26c42c40483f59f3b79042a836113403fa1ed9501d9d7baf4a130b5ee0"),
    ("src/arena.c", 1216, 1298, "f03933764ea1a18dd674a80738205efcd294b87e15fbdaa5f2f7add5c3263645"),
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

PREFIX = "trace.later_thread_exit_full_direct_small_pages."


def _page_values(index: int) -> dict[str, int]:
    prefix = f"{PREFIX}page{index}."
    return {
        prefix + "unmapped_after_thread_done": 1,
        prefix + "abandoned_after_thread_done": 1,
        prefix + "page_map_registered_after_thread_done": 1,
        prefix + "page_map_slice_count_after_thread_done": 1,
        prefix + "page_map_all_slices_registered_after_thread_done": 1,
        prefix + "arena_page_bitmap_set_after_thread_done": 1,
        prefix + "ordinary_queue_detached_after_thread_done": 1,
        prefix + "abandoned_bitmap_clear_after_thread_done": 1,
        prefix + "used_after_thread_done": 64,
        prefix + "used_after_first_consumer_free": 64,
        prefix + "unmapped_prefix_free_count": 9,
        prefix + "used_after_unmapped_prefix": 56,
        prefix + "unmapped_after_unmapped_prefix": 1,
        prefix + "mapped_after_reabandon_boundary": 1,
        prefix + "abandoned_bitmap_set_after_reabandon_boundary": 1,
        prefix + "used_after_reabandon_boundary": 54,
        prefix + "page_map_unregistered_after_terminal_free": 1,
        prefix + "arena_page_bitmap_clear_after_terminal_free": 1,
        prefix + "arena_slice_released_after_terminal_free": 1,
        prefix + "abandoned_bitmap_clear_after_terminal_free": 1,
    }


EXPECTED_TRACE_VALUES = {
    PREFIX + "arena_backed": 1,
    PREFIX + "small_page": 1,
    PREFIX + "direct_small": 1,
    PREFIX + "page_count": 2,
    PREFIX + "same_size": 1,
    PREFIX + "full_before_thread_done": 1,
    PREFIX + "ordinary_regular_bin_before_thread_done": 1,
    PREFIX + "ordinary_queue_count_before_thread_done": 2,
    PREFIX + "direct_cache_range_matches_before_thread_done": 1,
    PREFIX + "direct_cache_range_start": 113,
    PREFIX + "direct_cache_range_end": 128,
    PREFIX + "no_remote_free_before_thread_done": 1,
    PREFIX + "source_thread_teardown_completed": 1,
    PREFIX + "source_thread_joined_before_client_frees": 1,
    PREFIX + "request_size": 1024,
    PREFIX + "block_size": 1024,
    PREFIX + "capacity": 64,
    PREFIX + "reserved": 64,
    PREFIX + "slice_count": 1,
    PREFIX + "abandoned_count_after_thread_done": 0,
    PREFIX + "first_terminal_released_only": 1,
    PREFIX + "second_page_retained_after_first_terminal": 1,
    PREFIX + "abandoned_count_after_first_terminal": 0,
    PREFIX + "abandoned_count_after_second_boundary": 1,
    PREFIX + "abandoned_count_after_final_terminal": 0,
    PREFIX + "route_empty_after_final_terminal": 1,
    PREFIX + "valid": 1,
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
#define BLOCKS_PER_PAGE 64
#define MAX_BLOCKS (PAGE_COUNT * BLOCKS_PER_PAGE)

typedef struct fixture_s {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  mi_arena_id_t arena_id;
  mi_heap_t* heap;
  void* blocks[MAX_BLOCKS];
  mi_page_t* pages[PAGE_COUNT];
  size_t block_count;
  size_t page_blocks[PAGE_COUNT];
  bool ready;
  bool setup_valid;
  bool allow_thread_done;
  bool producer_done;
  bool ordinary_queue;
  bool direct_cache_range_matches;
  size_t direct_cache_range_start;
  size_t direct_cache_range_end;
  int failure_stage;
} fixture_t;

static bool direct_cache_range(
    const mi_theap_t* theap,
    const mi_page_queue_t* queue,
    const mi_page_t* page,
    size_t* start_out,
    size_t* end_out
) {
  if (theap == NULL || queue == NULL || page == NULL || queue->first != page) return false;
  const size_t index = _mi_wsize_from_size(queue->block_size);
  if (index >= MI_PAGES_DIRECT || queue->block_size > MI_SMALL_SIZE_MAX) return false;
  size_t start = 0;
  if (index > 1) {
    const size_t bin = _mi_bin(queue->block_size);
    const mi_page_queue_t* previous = queue - 1;
    while (bin == _mi_bin(previous->block_size) && previous > &theap->pages[0]) previous--;
    start = 1 + _mi_wsize_from_size(previous->block_size);
    if (start > index) start = index;
  }
  for (size_t slot = 0; slot < MI_PAGES_DIRECT; slot++) {
    const mi_page_t* expected =
        (slot >= start && slot <= index) ? page : _mi_page_empty_get();
    if (theap->pages_free_direct[slot] != expected) return false;
  }
  if (start_out != NULL) *start_out = start;
  if (end_out != NULL) *end_out = index;
  return true;
}

static bool ordinary_queue_has_two(
    const mi_page_queue_t* queue,
    const mi_page_t* first,
    const mi_page_t* second
) {
  if (queue == NULL || queue->count != PAGE_COUNT || queue->first == NULL) return false;
  size_t count = 0;
  bool has_first = false;
  bool has_second = false;
  for (const mi_page_t* page = queue->first; page != NULL && count <= PAGE_COUNT; page = page->next) {
    if (page == first) has_first = true;
    if (page == second) has_second = true;
    count++;
  }
  return count == PAGE_COUNT && has_first && has_second;
}

static bool map_span_is(uintptr_t start, size_t count, bool mapped) {
  for (size_t index = 0; index < count; index++) {
    if ((_mi_safe_ptr_page((const void*)(start + index * MI_ARENA_SLICE_SIZE)) != NULL) != mapped) {
      return false;
    }
  }
  return true;
}

static bool map_span_is_page(const mi_page_t* page, uintptr_t start, size_t count) {
  if (page == NULL || count == 0) return false;
  for (size_t index = 0; index < count; index++) {
    if (_mi_safe_ptr_page((const void*)(start + index * MI_ARENA_SLICE_SIZE)) != page) {
      return false;
    }
  }
  return true;
}

static bool page_map_span(mi_page_t* page, uintptr_t* start_out, size_t* count_out) {
  if (page == NULL) return false;
  uint8_t* start = mi_page_slice_start(page);
  const size_t count = page->memid.mem.arena.slice_count;
  if (start == NULL || count == 0) return false;
  *start_out = (uintptr_t)start;
  *count_out = count;
  return map_span_is_page(page, *start_out, *count_out);
}

static bool detached_unowned(const mi_page_t* page) {
  return page != NULL
      && page->next == NULL
      && page->prev == NULL
      && !mi_page_is_in_full(page)
      && !mi_page_is_owned(page);
}

static void signal_ready(fixture_t* fixture, bool valid) {
  if (pthread_mutex_lock(&fixture->mutex) != 0) return;
  fixture->setup_valid = valid;
  fixture->ready = true;
  (void)pthread_cond_broadcast(&fixture->condition);
  (void)pthread_mutex_unlock(&fixture->mutex);
}

static void* producer_main(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  const size_t request = MI_SMALL_SIZE_MAX;
  mi_heap_t* heap = mi_heap_new_in_arena(fixture->arena_id);
  mi_theap_t* theap = NULL;
  mi_page_queue_t* queue = NULL;
  int failure = 0;

  if (heap == NULL) {
    fixture->failure_stage = 1;
    signal_ready(fixture, false);
    return NULL;
  }
  theap = _mi_heap_theap(heap);
  if (theap == NULL) {
    failure = 2;
    goto failed;
  }
  while (fixture->block_count < MAX_BLOCKS
      && fixture->page_blocks[PAGE_COUNT - 1] < BLOCKS_PER_PAGE) {
    void* block = mi_heap_malloc_small(heap, request);
    if (block == NULL) {
      failure = 3;
      goto failed;
    }
    mi_page_t* page = _mi_ptr_page(block);
    if (page == NULL) {
      mi_free(block);
      failure = 4;
      goto failed;
    }
    size_t slot = 0;
    if (fixture->pages[0] == NULL || page == fixture->pages[0]) {
      slot = 0;
    } else if (fixture->pages[1] == NULL || page == fixture->pages[1]) {
      slot = 1;
    } else {
      mi_free(block);
      failure = 5;
      goto failed;
    }
    if (fixture->pages[slot] == NULL) fixture->pages[slot] = page;
    if (page != fixture->pages[slot]) {
      mi_free(block);
      failure = 6;
      goto failed;
    }
    fixture->blocks[fixture->block_count++] = block;
    fixture->page_blocks[slot]++;
  }
  if (fixture->pages[0] == NULL || fixture->pages[1] == NULL
      || fixture->page_blocks[0] != BLOCKS_PER_PAGE
      || fixture->page_blocks[1] != BLOCKS_PER_PAGE) {
    failure = 7;
    goto failed;
  }
  queue = mi_page_queue(theap, fixture->pages[0]->block_size);
  fixture->ordinary_queue = ordinary_queue_has_two(
      queue, fixture->pages[0], fixture->pages[1]);
  fixture->direct_cache_range_matches = direct_cache_range(
      theap, queue, queue == NULL ? NULL : queue->first,
      &fixture->direct_cache_range_start, &fixture->direct_cache_range_end);
  for (size_t index = 0; index < PAGE_COUNT; index++) {
    mi_page_t* page = fixture->pages[index];
    if (!mi_page_is_full(page)
        || page->used != BLOCKS_PER_PAGE
        || page->capacity != BLOCKS_PER_PAGE
        || page->reserved != BLOCKS_PER_PAGE
        || page->block_size != request
        || page->memid.memkind != MI_MEM_ARENA
        || mi_page_is_in_full(page)) {
      failure = 8;
      goto failed;
    }
  }
  if (!fixture->ordinary_queue || !fixture->direct_cache_range_matches
      || fixture->direct_cache_range_start != 113
      || fixture->direct_cache_range_end != 128) {
    failure = 9;
    goto failed;
  }
  fixture->heap = heap;
  signal_ready(fixture, true);
  if (!fixture->setup_valid) goto failed;

  if (pthread_mutex_lock(&fixture->mutex) != 0) return NULL;
  while (!fixture->allow_thread_done) {
    if (pthread_cond_wait(&fixture->condition, &fixture->mutex) != 0) {
      (void)pthread_mutex_unlock(&fixture->mutex);
      return NULL;
    }
  }
  (void)pthread_mutex_unlock(&fixture->mutex);
  mi_thread_done();
  if (pthread_mutex_lock(&fixture->mutex) == 0) {
    fixture->producer_done = true;
    (void)pthread_cond_broadcast(&fixture->condition);
    (void)pthread_mutex_unlock(&fixture->mutex);
  }
  return NULL;

failed:
  for (size_t index = 0; index < fixture->block_count; index++) {
    if (fixture->blocks[index] != NULL) {
      mi_free(fixture->blocks[index]);
      fixture->blocks[index] = NULL;
    }
  }
  mi_heap_destroy(heap);
  fixture->failure_stage = failure;
  signal_ready(fixture, false);
  return NULL;
}

static void out_page_bool(size_t page, const char* name, int value) {
  printf("trace.later_thread_exit_full_direct_small_pages.page%zu.%s=%d\n",
      page, name, value ? 1 : 0);
}

static void out_page_number(size_t page, const char* name, size_t value) {
  printf("trace.later_thread_exit_full_direct_small_pages.page%zu.%s=%zu\n",
      page, name, value);
}

int main(void) {
  fixture_t fixture = {
      .mutex = PTHREAD_MUTEX_INITIALIZER,
      .condition = PTHREAD_COND_INITIALIZER,
      .arena_id = _mi_arena_id_none(),
  };
  pthread_t producer;
  bool producer_started = false;
  bool options_changed = false;
  bool valid = false;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  mi_heap_t* worker_heap = NULL;
  _Atomic(size_t)* dynamic_abandoned_count = NULL;
  uintptr_t starts[PAGE_COUNT] = {0, 0};
  size_t page_slice_count[PAGE_COUNT] = {0, 0};
  size_t map_count[PAGE_COUNT] = {0, 0};
  size_t slice_index[PAGE_COUNT] = {0, 0};
  size_t prefix[PAGE_COUNT] = {0, 0};
  size_t used_exit[PAGE_COUNT] = {0, 0};
  size_t used_first[PAGE_COUNT] = {0, 0};
  size_t used_prefix[PAGE_COUNT] = {0, 0};
  size_t used_boundary[PAGE_COUNT] = {0, 0};
  int page_map_registered[PAGE_COUNT] = {0, 0};
  int page_map_all[PAGE_COUNT] = {0, 0};
  int unmapped[PAGE_COUNT] = {0, 0};
  int abandoned[PAGE_COUNT] = {0, 0};
  int arena_set[PAGE_COUNT] = {0, 0};
  int detached[PAGE_COUNT] = {0, 0};
  int abandoned_clear[PAGE_COUNT] = {0, 0};
  int unmapped_prefix[PAGE_COUNT] = {0, 0};
  int mapped_boundary[PAGE_COUNT] = {0, 0};
  int abandoned_set[PAGE_COUNT] = {0, 0};
  int map_clear[PAGE_COUNT] = {0, 0};
  int arena_clear[PAGE_COUNT] = {0, 0};
  int slices_free[PAGE_COUNT] = {0, 0};
  int abandoned_final_clear[PAGE_COUNT] = {0, 0};
  long old_reclaim_on_free = 0;
  long old_full_retain = 0;
  size_t bin = 0;
  size_t block_size = 0;
  size_t capacity = 0;
  size_t reserved = 0;
  size_t slice_count = 0;
  size_t dynamic_after_exit = 0;
  size_t dynamic_after_first_terminal = 0;
  size_t dynamic_after_second_boundary = 0;
  size_t dynamic_after_final_terminal = 0;
  int arena_backed = 0;
  int small_page = 0;
  int direct_small = 0;
  int same_size = 0;
  int full = 0;
  int ordinary = 0;
  int direct_cache = 0;
  int no_remote = 0;
  int source_thread_teardown = 0;
  int source_thread_joined = 0;
  int first_terminal_only = 0;
  int second_retained = 0;
  int route_empty = 0;
  const size_t request = MI_SMALL_SIZE_MAX;

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
  if (pthread_mutex_lock(&fixture.mutex) != 0) goto output;
  while (!fixture.ready) {
    if (pthread_cond_wait(&fixture.condition, &fixture.mutex) != 0) {
      (void)pthread_mutex_unlock(&fixture.mutex);
      goto output;
    }
  }
  (void)pthread_mutex_unlock(&fixture.mutex);
  if (!fixture.setup_valid || fixture.heap == NULL
      || fixture.blocks[0] == NULL || fixture.blocks[BLOCKS_PER_PAGE] == NULL) goto output;

  mi_page_t* before = fixture.pages[0];
  mi_page_t* second_before = fixture.pages[1];
  if (before == NULL || second_before == NULL) goto output;
  block_size = before->block_size;
  capacity = before->capacity;
  reserved = before->reserved;
  slice_count = before->memid.mem.arena.slice_count;
  bin = _mi_bin(block_size);
  arena = mi_memid_arena(before->memid);
  worker_heap = fixture.heap;
  if (arena == NULL || bin >= MI_ARENA_BIN_COUNT || slice_count != 1) goto output;
  arena_pages = mi_atomic_load_ptr_acquire(
      mi_arena_pages_t, &worker_heap->arena_pages[arena->arena_idx]);
  dynamic_abandoned_count = &worker_heap->abandoned_count[bin];
  if (arena_pages == NULL) goto output;
  arena_backed = before->memid.memkind == MI_MEM_ARENA
      && second_before->memid.memkind == MI_MEM_ARENA;
  small_page = block_size <= MI_SMALL_MAX_OBJ_SIZE;
  direct_small = block_size <= MI_SMALL_SIZE_MAX;
  same_size = second_before->block_size == block_size
      && second_before->capacity == capacity
      && second_before->reserved == reserved;
  full = mi_page_is_full(before) && mi_page_is_full(second_before)
      && before->used == before->reserved
      && second_before->used == second_before->reserved;
  ordinary = fixture.ordinary_queue;
  direct_cache = fixture.direct_cache_range_matches;
  no_remote = mi_page_thread_free(before) == NULL
      && mi_page_thread_free(second_before) == NULL;
  if (!arena_backed || !small_page || !direct_small || !same_size || !full
      || !ordinary || !direct_cache || !no_remote
      || capacity != BLOCKS_PER_PAGE || reserved != BLOCKS_PER_PAGE
      || block_size != request
      || fixture.direct_cache_range_start != 113
      || fixture.direct_cache_range_end != 128) goto output;

  if (pthread_mutex_lock(&fixture.mutex) != 0) goto output;
  fixture.allow_thread_done = true;
  (void)pthread_cond_broadcast(&fixture.condition);
  (void)pthread_mutex_unlock(&fixture.mutex);
  if (pthread_join(producer, NULL) != 0) goto output;
  producer_started = false;
  source_thread_teardown = fixture.producer_done;
  source_thread_joined = source_thread_teardown && !producer_started;
  if (!source_thread_joined) goto output;

  for (size_t index = 0; index < PAGE_COUNT; index++) {
    mi_page_t* page = _mi_safe_ptr_page(fixture.blocks[index * BLOCKS_PER_PAGE]);
    if (page == NULL || page->block_size != block_size) goto output;
    page_map_registered[index] = page_map_span(
        page, &starts[index], &map_count[index]);
    page_slice_count[index] = page->memid.mem.arena.slice_count;
    slice_index[index] = page->memid.mem.arena.slice_index;
    page_map_all[index] = page_map_registered[index]
        && map_count[index] == page_slice_count[index];
    unmapped[index] = !mi_page_is_abandoned_mapped(page);
    abandoned[index] = mi_page_is_abandoned(page);
    arena_set[index] = mi_bitmap_is_setN(
        arena_pages->pages, slice_index[index], page_slice_count[index]);
    detached[index] = detached_unowned(page);
    abandoned_clear[index] = arena_pages->pages_abandoned[bin] == NULL
        || mi_bitmap_is_clearN(
            arena_pages->pages_abandoned[bin], slice_index[index], page_slice_count[index]);
    used_exit[index] = page->used;
    if (!page_map_registered[index] || !page_map_all[index]
        || page_slice_count[index] != 1 || !unmapped[index] || !abandoned[index]
        || !arena_set[index] || !detached[index] || !abandoned_clear[index]
        || used_exit[index] != BLOCKS_PER_PAGE) goto output;
  }
  dynamic_after_exit = mi_atomic_load_relaxed(dynamic_abandoned_count);
  if (dynamic_after_exit != 0) goto output;

  /* Each joined consumer free follows the direct-small partial collector. */
  for (size_t page_index = 0; page_index < PAGE_COUNT; page_index++) {
    const size_t begin = page_index * BLOCKS_PER_PAGE;
    prefix[page_index] = reserved / 8 + 1;
    if (prefix[page_index] != 9 || prefix[page_index] + 1 >= BLOCKS_PER_PAGE) goto output;

    mi_free(fixture.blocks[begin]);
    fixture.blocks[begin] = NULL;
    mi_page_t* page = _mi_safe_ptr_page(fixture.blocks[begin + 1]);
    if (page == NULL) goto output;
    used_first[page_index] = page->used;
    if (used_first[page_index] != BLOCKS_PER_PAGE) goto output;

    for (size_t index = 1; index < prefix[page_index]; index++) {
      mi_free(fixture.blocks[begin + index]);
      fixture.blocks[begin + index] = NULL;
    }
    page = _mi_safe_ptr_page(fixture.blocks[begin + prefix[page_index]]);
    if (page == NULL) goto output;
    used_prefix[page_index] = page->used;
    unmapped_prefix[page_index] = !mi_page_is_abandoned_mapped(page)
        && mi_page_is_abandoned(page)
        && detached_unowned(page)
        && mi_page_thread_free(page) != NULL
        && map_span_is_page(page, starts[page_index], page_slice_count[page_index])
        && mi_bitmap_is_setN(
            arena_pages->pages, slice_index[page_index], page_slice_count[page_index])
        && (arena_pages->pages_abandoned[bin] == NULL
            || mi_bitmap_is_clearN(
                arena_pages->pages_abandoned[bin], slice_index[page_index], page_slice_count[page_index]))
        && mi_atomic_load_relaxed(dynamic_abandoned_count) == 0;
    if (!unmapped_prefix[page_index] || used_prefix[page_index] != 56) goto output;

    mi_free(fixture.blocks[begin + prefix[page_index]]);
    fixture.blocks[begin + prefix[page_index]] = NULL;
    page = _mi_safe_ptr_page(fixture.blocks[begin + prefix[page_index] + 1]);
    if (page == NULL) goto output;
    used_boundary[page_index] = page->used;
    mapped_boundary[page_index] = mi_page_is_abandoned_mapped(page)
        && mi_page_is_abandoned(page)
        && detached_unowned(page)
        && mi_page_thread_free(page) == NULL
        && map_span_is_page(page, starts[page_index], page_slice_count[page_index]);
    abandoned_set[page_index] = arena_pages->pages_abandoned[bin] != NULL
        && mi_bitmap_is_setN(
            arena_pages->pages_abandoned[bin], slice_index[page_index], page_slice_count[page_index]);
    if (!mapped_boundary[page_index] || !abandoned_set[page_index]
        || used_boundary[page_index] != 54
        || mi_atomic_load_relaxed(dynamic_abandoned_count) != 1) goto output;
    if (page_index == 1) {
      dynamic_after_second_boundary = mi_atomic_load_relaxed(dynamic_abandoned_count);
    }

    for (size_t index = prefix[page_index] + 1; index + 1 < BLOCKS_PER_PAGE; index++) {
      mi_free(fixture.blocks[begin + index]);
      fixture.blocks[begin + index] = NULL;
    }
    mi_free(fixture.blocks[begin + BLOCKS_PER_PAGE - 1]);
    fixture.blocks[begin + BLOCKS_PER_PAGE - 1] = NULL;
    map_clear[page_index] = map_span_is(
        starts[page_index], page_slice_count[page_index], false);
    arena_clear[page_index] = mi_bitmap_is_clearN(
        arena_pages->pages, slice_index[page_index], page_slice_count[page_index]);
    slices_free[page_index] = mi_bbitmap_is_setN(
        arena->slices_free, slice_index[page_index], page_slice_count[page_index]);
    abandoned_final_clear[page_index] = arena_pages->pages_abandoned[bin] == NULL
        || mi_bitmap_is_clearN(
            arena_pages->pages_abandoned[bin], slice_index[page_index], page_slice_count[page_index]);
    if (!map_clear[page_index] || !arena_clear[page_index]
        || !slices_free[page_index] || !abandoned_final_clear[page_index]) goto output;

    if (page_index == 0) {
      dynamic_after_first_terminal = mi_atomic_load_relaxed(dynamic_abandoned_count);
      mi_page_t* second = _mi_safe_ptr_page(fixture.blocks[BLOCKS_PER_PAGE]);
      if (second == NULL) goto output;
      second_retained = page_map_span(second, &starts[1], &map_count[1])
          && map_count[1] == 1
          && mi_bitmap_is_setN(arena_pages->pages, second->memid.mem.arena.slice_index, 1)
          && !mi_page_is_abandoned_mapped(second)
          && mi_page_is_abandoned(second)
          && detached_unowned(second)
          && second->used == BLOCKS_PER_PAGE
          && (arena_pages->pages_abandoned[bin] == NULL
              || mi_bitmap_is_clearN(
                  arena_pages->pages_abandoned[bin], second->memid.mem.arena.slice_index, 1));
      first_terminal_only = second_retained && dynamic_after_first_terminal == 0;
      if (!first_terminal_only) goto output;
    } else {
      dynamic_after_final_terminal = mi_atomic_load_relaxed(dynamic_abandoned_count);
    }
  }

  route_empty = map_clear[0] && map_clear[1]
      && dynamic_after_final_terminal == 0;
  valid = arena_backed && small_page && direct_small && same_size && full
      && ordinary && direct_cache && no_remote && source_thread_teardown
      && source_thread_joined && block_size == 1024 && capacity == 64
      && reserved == 64 && slice_count == 1 && dynamic_after_exit == 0
      && first_terminal_only && second_retained
      && dynamic_after_first_terminal == 0
      && dynamic_after_second_boundary == 1
      && dynamic_after_final_terminal == 0 && route_empty;
output:
  printf("CRABC_MI_LATER_THREAD_EXIT_FULL_DIRECT_SMALL_PAGES_TRACE_BEGIN\n");
#define B(key, value) printf("trace.later_thread_exit_full_direct_small_pages.%s=%d\n", key, (value) ? 1 : 0)
#define N(key, value) printf("trace.later_thread_exit_full_direct_small_pages.%s=%zu\n", key, (size_t)(value))
  B("arena_backed", arena_backed);
  B("small_page", small_page);
  B("direct_small", direct_small);
  N("page_count", PAGE_COUNT);
  B("same_size", same_size);
  B("full_before_thread_done", full);
  B("ordinary_regular_bin_before_thread_done", ordinary);
  N("ordinary_queue_count_before_thread_done", fixture.ordinary_queue ? PAGE_COUNT : 0);
  B("direct_cache_range_matches_before_thread_done", direct_cache);
  N("direct_cache_range_start", fixture.direct_cache_range_start);
  N("direct_cache_range_end", fixture.direct_cache_range_end);
  B("no_remote_free_before_thread_done", no_remote);
  B("source_thread_teardown_completed", source_thread_teardown);
  B("source_thread_joined_before_client_frees", source_thread_joined);
  N("request_size", request);
  N("block_size", block_size);
  N("capacity", capacity);
  N("reserved", reserved);
  N("slice_count", slice_count);
  N("abandoned_count_after_thread_done", dynamic_after_exit);
  for (size_t index = 0; index < PAGE_COUNT; index++) {
    out_page_bool(index, "unmapped_after_thread_done", unmapped[index]);
    out_page_bool(index, "abandoned_after_thread_done", abandoned[index]);
    out_page_bool(index, "page_map_registered_after_thread_done", page_map_registered[index]);
    out_page_number(index, "page_map_slice_count_after_thread_done", map_count[index]);
    out_page_bool(index, "page_map_all_slices_registered_after_thread_done", page_map_all[index]);
    out_page_bool(index, "arena_page_bitmap_set_after_thread_done", arena_set[index]);
    out_page_bool(index, "ordinary_queue_detached_after_thread_done", detached[index]);
    out_page_bool(index, "abandoned_bitmap_clear_after_thread_done", abandoned_clear[index]);
    out_page_number(index, "used_after_thread_done", used_exit[index]);
    out_page_number(index, "used_after_first_consumer_free", used_first[index]);
    out_page_number(index, "unmapped_prefix_free_count", prefix[index]);
    out_page_number(index, "used_after_unmapped_prefix", used_prefix[index]);
    out_page_bool(index, "unmapped_after_unmapped_prefix", unmapped_prefix[index]);
    out_page_bool(index, "mapped_after_reabandon_boundary", mapped_boundary[index]);
    out_page_bool(index, "abandoned_bitmap_set_after_reabandon_boundary", abandoned_set[index]);
    out_page_number(index, "used_after_reabandon_boundary", used_boundary[index]);
    out_page_bool(index, "page_map_unregistered_after_terminal_free", map_clear[index]);
    out_page_bool(index, "arena_page_bitmap_clear_after_terminal_free", arena_clear[index]);
    out_page_bool(index, "arena_slice_released_after_terminal_free", slices_free[index]);
    out_page_bool(index, "abandoned_bitmap_clear_after_terminal_free", abandoned_final_clear[index]);
  }
  B("first_terminal_released_only", first_terminal_only);
  B("second_page_retained_after_first_terminal", second_retained);
  N("abandoned_count_after_first_terminal", dynamic_after_first_terminal);
  N("abandoned_count_after_second_boundary", dynamic_after_second_boundary);
  N("abandoned_count_after_final_terminal", dynamic_after_final_terminal);
  B("route_empty_after_final_terminal", route_empty);
  B("valid", valid);
  printf("CRABC_MI_LATER_THREAD_EXIT_FULL_DIRECT_SMALL_PAGES_TRACE_END\n");
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
  if (options_changed) {
    mi_option_set(mi_option_page_reclaim_on_free, old_reclaim_on_free);
    mi_option_set(mi_option_page_full_retain, old_full_retain);
  }
  if (!valid) {
    fprintf(stderr,
        "later-thread-exit full direct-small aggregate stopped at stage %d\n",
        fixture.failure_stage);
  }
  return valid ? 0 : 2;
}
'''


def exactly_matches(observed, expected):
    """Compare JSON-shaped evidence values without bool/int coercion."""
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, Mapping):
        return observed.keys() == expected.keys() and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, (list, tuple)):
        return len(observed) == len(expected) and all(
            exactly_matches(actual, required)
            for actual, required in zip(observed, expected, strict=True)
        )
    return observed == expected


def _schema_template() -> dict:
    base_schema = _base._schema_template()
    return {
        "format": 1,
        "schema": "crabc-mimalloc-x86_64-later-thread-exit-full-direct-small-pages-evidence",
        "profile": EXPECTED_PROFILE,
        "target": copy.deepcopy(EXPECTED_TARGET),
        "upstream": copy.deepcopy(EXPECTED_UPSTREAM),
        "harness_dependency": {
            "path": _base.relative(BASE_PATH),
            "sha256": _base.sha256_file(BASE_PATH),
        },
        "scope": copy.deepcopy(EXPECTED_SCOPE),
        "tls": copy.deepcopy(EXPECTED_TLS),
        "compile_definitions": list(EXPECTED_COMPILE_DEFINITIONS),
        "release_flags": copy.deepcopy(base_schema["release_flags"]),
        "release_source_set": copy.deepcopy(base_schema["release_source_set"]),
        "source_anchors": [
            {
                "member": member,
                "start_line": start_line,
                "end_line": end_line,
                "sha256": digest,
            }
            for member, start_line, end_line, digest in EXPECTED_SOURCE_ANCHORS
        ],
        "c_probe_sha256": _base.sha256_bytes(C_TRACE_PROBE.encode()),
        "rust_test": {
            "path": _base.relative(RUST_TEST_SOURCE),
            "target_arch": "x86_64",
            "test_filter": RUST_TEST_FILTER,
        },
        "trace": {
            "begin": TRACE_BEGIN,
            "end": TRACE_END,
            "expected_values": dict(EXPECTED_TRACE_VALUES),
        },
    }


def load_schema(path: Path | None = None) -> dict:
    path = SCHEMA_PATH if path is None else Path(path)
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise _base.EvidenceError(
            "cannot read later-thread-exit full-direct-small aggregate schema"
        ) from error
    if not exactly_matches(schema, _schema_template()):
        raise _base.EvidenceError(
            "later-thread-exit full-direct-small aggregate checked-in schema drifted"
        )
    try:
        pin = RUNNER.load_pin()
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(
            "cannot validate later-thread-exit full-direct-small pinned upstream"
        ) from error
    upstream = {
        "archive_root": pin["archive_root"],
        "revision": pin["revision"],
        "version": pin["version"],
    }
    if not exactly_matches(upstream, EXPECTED_UPSTREAM) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise _base.EvidenceError(
            "later-thread-exit full-direct-small upstream archive pin drifted"
        )
    return schema


def validate_trace(trace, *, description: str) -> None:
    if not isinstance(trace, Mapping):
        raise _base.EvidenceError(f"{description} is not a trace mapping")
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
        raise _base.EvidenceError(
            f"{description} differs from the fixed direct-small aggregate trace: "
            + "; ".join(details)
        )


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return RUNNER.parse_address_independent_trace(
            output, begin=TRACE_BEGIN, end=TRACE_END, description=description
        )
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error


def compare_traces(c_trace, rust_trace) -> dict[str, int | str]:
    validate_trace(c_trace, description="pinned C full direct-small aggregate trace")
    validate_trace(rust_trace, description="Rust full direct-small aggregate trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise _base.EvidenceError(
            "Rust full direct-small aggregate trace differs from pinned C: "
            + ", ".join(mismatches)
        )
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    """Return one inclusive pinned-source range without sibling helper coupling."""
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise _base.EvidenceError("full-direct-small aggregate source anchor range is invalid")
    return b"".join(lines[start_line - 1 : end_line])


def validate_source_anchors(schema: dict, source: Path) -> list[dict]:
    validated = []
    for anchor in schema["source_anchors"]:
        member = str(anchor["member"])
        contents = (source / member).read_bytes()
        observed = _base.sha256_bytes(
            source_range(contents, int(anchor["start_line"]), int(anchor["end_line"]))
        )
        if observed != anchor["sha256"]:
            raise _base.EvidenceError(
                "pinned later-thread-exit full-direct-small source anchor drifted: "
                + member
            )
        validated.append(dict(anchor))
    return validated


def validate_c_probe_contract(probe: str) -> None:
    """Keep the C oracle's real pthread boundary and complete PageMap proof explicit."""
    if probe.count("pthread_create(&producer") != 1:
        raise _base.EvidenceError("full-direct-small C probe must create one real worker pthread")
    worker = probe.split("static void* producer_main", 1)[1].split("\nstatic void out_page_bool", 1)[0]
    if worker.count("mi_thread_done()") != 1:
        raise _base.EvidenceError("full-direct-small C worker must call mi_thread_done exactly once")
    post_done = worker.split("mi_thread_done();", 1)[1]
    if "theap->" in post_done or "pages_free_direct" in post_done or "direct_cache_range(" in post_done:
        raise _base.EvidenceError(
            "full-direct-small C worker reads departed Theap/direct-cache state after mi_thread_done"
        )
    join = probe.find("if (pthread_join(producer, NULL) != 0) goto output;")
    consumer = probe.find("/* Each joined consumer free follows the direct-small partial collector. */")
    if join < 0 or consumer < 0 or join > consumer:
        raise _base.EvidenceError(
            "full-direct-small C probe must join before client frees"
        )
    required = (
        "fixture->direct_cache_range_matches = direct_cache_range(",
        "theap, queue, queue == NULL ? NULL : queue->first,",
        "return map_span_is_page(page, *start_out, *count_out);",
        "&& !mi_page_is_owned(page);",
        "page_map_registered[index] = page_map_span(",
        "map_span_is_page(page, starts[page_index], page_slice_count[page_index])",
        "map_clear[page_index] = map_span_is(",
        "starts[page_index], page_slice_count[page_index], false);",
        "mi_bbitmap_is_setN(",
    )
    missing = [token for token in required if token not in probe]
    if missing:
        raise _base.EvidenceError(
            "full-direct-small C probe lacks required oracle contract: "
            + ", ".join(missing)
        )


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
    flags = [
        part
        for part in command
        if part in RUNNER.CONFIGURATION_PROFILES["release"]
    ]
    if not exactly_matches(schema.get("tls"), EXPECTED_TLS):
        raise _base.EvidenceError("full-direct-small C TLS contract drifted")
    if not exactly_matches(definitions, list(schema["compile_definitions"])):
        raise _base.EvidenceError("full-direct-small C compile definitions drifted")
    if not exactly_matches(flags, schema["release_flags"]):
        raise _base.EvidenceError("full-direct-small C release flags drifted")
    if command.count("-pthread") != 1 or command.count("-ftls-model=initial-exec") != 1:
        raise _base.EvidenceError(
            "full-direct-small C command pthread/TLS selection drifted"
        )


def normalize_command(command, temporary: Path, source: Path | None) -> list[str]:
    normalized = []
    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    for part in command:
        text = str(part)
        if source_text is not None and (
            text == source_text or text.startswith(source_text + "/")
        ):
            normalized.append(NORMALIZED_PINNED_SOURCE + text[len(source_text) :])
        elif text == temporary_text or text.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + text[len(temporary_text) :])
        else:
            normalized.append(text)
    return normalized


def validate_normalized_c_command(command, schema: dict) -> None:
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
        *(
            f"{NORMALIZED_PINNED_SOURCE}/{member}"
            for member in schema["release_source_set"]
        ),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c",
    ]
    if (
        not isinstance(command, list)
        or not command
        or Path(command[0]).name != "musl-gcc"
        or not exactly_matches(command[1:], expected)
    ):
        raise _base.EvidenceError(
            "full-direct-small aggregate report C command drifted"
        )


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: dict
) -> dict:
    probe_source = temporary / f"{STEM}.c"
    probe_binary = temporary / f"{STEM}-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    validate_c_probe_contract(C_TRACE_PROBE)
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        RUNNER.require_success(
            RUNNER.command_record(command, cwd=source),
            "pinned C later-thread-exit full-direct-small aggregate build",
        )
        header = RUNNER.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        RUNNER.require_success(
            header,
            "pinned C later-thread-exit full-direct-small aggregate ELF identity",
        )
        elf = RUNNER.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = RUNNER.command_record((str(probe_binary),), cwd=source)
        RUNNER.require_success(
            execution,
            "pinned C later-thread-exit full-direct-small aggregate execution",
        )
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error
    trace = parse_trace(
        str(execution["stdout"]),
        description="pinned C later-thread-exit full-direct-small aggregate trace",
    )
    validate_trace(
        trace,
        description="pinned C later-thread-exit full-direct-small aggregate trace",
    )
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"],
        "source_sha256": _base.sha256_bytes(C_TRACE_PROBE.encode()),
        "trace": trace,
    }


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


def validate_normalized_rust_command(command) -> None:
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
    if (
        not isinstance(command, list)
        or not command
        or Path(command[0]).name != "cargo"
        or not exactly_matches(command[1:], expected)
    ):
        raise _base.EvidenceError(
            "full-direct-small aggregate report Rust command drifted"
        )


def build_rust_trace(cargo: str, temporary: Path) -> dict:
    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = RUNNER.command_record(command, cwd=ROOT, environment=environment)
        RUNNER.require_success(
            execution, "Rust later-thread-exit full-direct-small aggregate fixture"
        )
        passed = RUNNER.parse_rust_test_count(
            str(execution["stdout"]) + "\n" + str(execution["stderr"])
        )
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error
    if passed != 1:
        raise _base.EvidenceError(
            "Rust later-thread-exit full-direct-small aggregate fixture passed "
            f"{passed} tests, expected one"
        )
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust later-thread-exit full-direct-small aggregate trace",
    )
    validate_trace(
        trace, description="Rust later-thread-exit full-direct-small aggregate trace"
    )
    return {
        "cargo_command": normalize_command(command, temporary, None),
        "lockfile": {
            "path": _base.relative(LOCKFILE),
            "sha256": _base.sha256_file(LOCKFILE),
        },
        "passed_test_count": passed,
        "source": {
            "path": _base.relative(RUST_TEST_SOURCE),
            "sha256": _base.sha256_file(RUST_TEST_SOURCE),
        },
        "target_dir": {
            "isolated": True,
            "retained": False,
            "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        },
        "trace": trace,
    }


def report_from_results(
    *, schema: dict, provenance: dict, archive_sha256: str, anchors: list[dict],
    c_probe: dict, rust_probe: dict
) -> dict:
    if not isinstance(c_probe.get("trace"), Mapping) or not isinstance(
        rust_probe.get("trace"), Mapping
    ):
        raise _base.EvidenceError(
            "full-direct-small aggregate report inputs lack C/Rust traces"
        )
    report = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_probe["trace"], rust_probe["trace"]),
        "format": 1,
        "kind": (
            "mimalloc-x86_64-later-thread-exit-full-direct-small-pages-"
            "differential-evidence"
        ),
        "profile": schema["profile"],
        "provenance": dict(provenance),
        "rust_probe": dict(rust_probe),
        "scope": copy.deepcopy(schema["scope"]),
        "source": {
            "archive_sha256": archive_sha256,
            "anchors": [dict(anchor) for anchor in anchors],
            "release_flags": list(schema["release_flags"]),
            "release_source_set": list(schema["release_source_set"]),
        },
        "status": "passed",
        "target": copy.deepcopy(schema["target"]),
        "trace": copy.deepcopy(schema["trace"]),
        "upstream": copy.deepcopy(schema["upstream"]),
    }
    validate_report(report)
    return report


def validate_report(report: dict) -> None:
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
        raise _base.EvidenceError("full-direct-small aggregate report schema drifted")
    if (
        type(report["format"]) is not int
        or report["format"] != 1
        or report["status"] != "passed"
    ):
        raise _base.EvidenceError("full-direct-small aggregate report format/status drifted")
    if report["kind"] != (
        "mimalloc-x86_64-later-thread-exit-full-direct-small-pages-"
        "differential-evidence"
    ) or report["profile"] != EXPECTED_PROFILE:
        raise _base.EvidenceError("full-direct-small aggregate report identity drifted")
    expected_comparison = {
        "compared_value_count": len(EXPECTED_TRACE_VALUES),
        "status": "matched",
    }
    if not exactly_matches(report["comparison"], expected_comparison):
        raise _base.EvidenceError("full-direct-small aggregate report comparison drifted")
    if not (
        exactly_matches(report["target"], EXPECTED_TARGET)
        and exactly_matches(report["upstream"], EXPECTED_UPSTREAM)
        and exactly_matches(report["scope"], EXPECTED_SCOPE)
    ):
        raise _base.EvidenceError("full-direct-small aggregate report boundary drifted")
    native_provenance = (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    )
    if not any(exactly_matches(report["provenance"], value) for value in native_provenance):
        raise _base.EvidenceError(
            "full-direct-small aggregate report lacks native x86-64 provenance"
        )

    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {
        "archive_sha256",
        "anchors",
        "release_flags",
        "release_source_set",
    }:
        raise _base.EvidenceError(
            "full-direct-small aggregate report source record is malformed"
        )
    if (
        source["archive_sha256"] != EXPECTED_ARCHIVE_SHA256
        or not exactly_matches(source["anchors"], schema["source_anchors"])
        or not exactly_matches(source["release_flags"], schema["release_flags"])
        or not exactly_matches(
            source["release_source_set"], schema["release_source_set"]
        )
        or not exactly_matches(report["trace"], schema["trace"])
    ):
        raise _base.EvidenceError(
            "full-direct-small aggregate report source/trace contract drifted"
        )

    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {
        "build_command",
        "elf",
        "run_command",
        "source_sha256",
        "trace",
    }:
        raise _base.EvidenceError("full-direct-small aggregate C probe record drifted")
    if (
        not exactly_matches(c_probe["elf"], EXPECTED_C_ELF)
        or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"]
        or c_probe["source_sha256"] != _base.sha256_bytes(C_TRACE_PROBE.encode())
    ):
        raise _base.EvidenceError("full-direct-small aggregate C probe identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)

    if not isinstance(rust_probe, dict) or set(rust_probe) != {
        "cargo_command",
        "lockfile",
        "passed_test_count",
        "source",
        "target_dir",
        "trace",
    }:
        raise _base.EvidenceError(
            "full-direct-small aggregate Rust probe record drifted"
        )
    if type(rust_probe["passed_test_count"]) is not int or rust_probe["passed_test_count"] != 1:
        raise _base.EvidenceError(
            "full-direct-small aggregate Rust test selection drifted"
        )
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(
        rust_probe["lockfile"],
        {"path": _base.relative(LOCKFILE), "sha256": _base.sha256_file(LOCKFILE)},
    ) or not exactly_matches(
        rust_probe["source"],
        {
            "path": _base.relative(RUST_TEST_SOURCE),
            "sha256": _base.sha256_file(RUST_TEST_SOURCE),
        },
    ) or not exactly_matches(
        rust_probe["target_dir"],
        {
            "isolated": True,
            "retained": False,
            "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        },
    ):
        raise _base.EvidenceError(
            "full-direct-small aggregate Rust identity drifted"
        )
    if not isinstance(c_probe["trace"], Mapping) or not isinstance(
        rust_probe["trace"], Mapping
    ):
        raise _base.EvidenceError(
            "full-direct-small aggregate report lacks C/Rust traces"
        )
    observed_comparison = compare_traces(c_probe["trace"], rust_probe["trace"])
    if not exactly_matches(report["comparison"], observed_comparison):
        raise _base.EvidenceError(
            "full-direct-small aggregate report comparison drifted"
        )


def require_native_x86_64() -> dict:
    try:
        return RUNNER.require_native_x86_64()
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error


def run_evidence(*, offline: bool, report_path: Path) -> dict:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = _base.sha256_file(LOCKFILE)
    try:
        pin = RUNNER.load_pin()
        archive = RUNNER.fetch_archive(pin, offline)
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(
        prefix="crabc-mimalloc-x86_64-later-thread-exit-full-direct-small-pages-"
    ) as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = RUNNER.safe_extract(
                archive, temporary / "source", pin["archive_root"]
            )
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
            archive_sha256=_base.sha256_file(archive),
            anchors=anchors,
            c_probe=c_probe,
            rust_probe=rust_probe,
        )
    if _base.sha256_file(LOCKFILE) != before_lockfile:
        raise _base.EvidenceError(
            "Cargo.lock changed despite the required --locked Rust trace command"
        )
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
    except (_base.EvidenceError, OSError, ValueError) as error:
        print(
            "allocator x86-64 later-thread-exit full-direct-small aggregate: FAIL: "
            + str(error),
            file=os.sys.stderr,
        )
        return 1
    print(
        "allocator x86-64 later-thread-exit full-direct-small aggregate: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {_base.relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
