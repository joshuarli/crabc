#!/usr/bin/env python3
"""Prove the pinned C oracle's automatic pthread-destructor page teardown.

The native fixture gives a worker pthread one private arena-backed medium
page with two live blocks.  The worker returns naturally: it does not invoke
an explicit allocator thread-done entry point or ``pthread_exit``.  The
pinned mimalloc pthread key therefore owns the only source-recognized path to
``_mi_thread_done``.  After ``pthread_join`` the consumer observes the
selected mapped-abandoned page and then frees both clients.

This is C-oracle-only native Linux/x86-64 evidence.  It establishes neither
Rust callback parity nor a public x86 runtime, allocator, libc, or loader
surface.
"""

from __future__ import annotations

import argparse
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-automatic-pthread-destructor-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/automatic-pthread-destructor.json"
TRACE_BEGIN = "CRABC_MI_AUTOMATIC_PTHREAD_DESTRUCTOR_TRACE_BEGIN"
TRACE_END = "CRABC_MI_AUTOMATIC_PTHREAD_DESTRUCTOR_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The automatic pthread-destructor probe could not prove its boundary."""


EXPECTED_TARGET = {
    "architecture": "x86_64",
    "endianness": "little",
    "rust_target": "x86_64-unknown-linux-musl",
    "system": "linux",
}
EXPECTED_UPSTREAM = {
    "archive_root": "mimalloc-3.5.0",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "version": "3.5.0",
}
EXPECTED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
EXPECTED_PROFILE = "linux-x86_64-private-c-automatic-pthread-destructor"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "automatic_pthread_destructor_only": True,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_process_shutdown_claimed": False,
    "general_pthread_destructor_ordering_claimed": False,
    "general_remote_free_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "no_explicit_thread_done_in_worker": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_automatic_pthread_destructor": True,
    "rust_automatic_pthread_destructor_claimed": False,
    "worker_natural_return_only": True,
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
    ("src/prim/unix/prim.c", 1011, 1040, "eef3c9b9715fec9a271f8a966febe73d3ff3113165c5bc9c930fa46c657aa87a"),
    ("src/init.c", 426, 445, "0906b88ed6f860824fa817dd499be4f47989cc70681bd09a992ffa781d7e9870"),
    ("src/init.c", 448, 477, "289083292b594ae6e467808000a94f3ddaacdacb0372abee002f4db779137b0c"),
    ("src/init.c", 504, 511, "f301f6ed5563f1b351bd5839830ed0725917b21b250428573eb1cb8dc41b3d87"),
    ("src/threadlocal.c", 205, 214, "f15d366c5bf21e176e97e68da940447dd55a4966c5787874c7e3f130c4e329c1"),
    ("src/theap.c", 97, 115, "62d9e01e6c2d397f6b2147fcc079c9f3ce5001811a664d4601e2c1e17c51ebe7"),
    ("src/theap.c", 123, 152, "c7811179e91e8cd66dc0587e824265cff4db6ce660ba0639309d909dd0df519c"),
    ("src/page.c", 291, 303, "d363079d5e484919082b5602cc3757a3e3a357e68594fc040d902232c7458bbf"),
    ("src/arena.c", 674, 723, "e0e2e4f68015a17b3a61ecc3e81c48bfd8f168f4027994aec2bad5e2461b21a0"),
    ("src/arena.c", 1304, 1409, "6a6d08e7cb4a45803619ce1c9d7efab31808068a756a727a4d3fd3d48d30413f"),
    ("src/free.c", 365, 515, "4f31b0716f4b8086797a84d1bfc6ca21531d1316ca37bbea18e218937fc941c1"),
    ("src/page-map.c", 468, 510, "d0ad150ae8a42e3954052d0ee707b960901cf180417c20f54f3c3bd052b23ca5"),
    ("include/mimalloc/prim-tls.h", 412, 421, "466e1c5ef5f6fcddae9a518965638676a61bd41b8cbde85a5c0bcba76e2710dd"),
)
EXPECTED_TRACE_VALUES = {
    "trace.automatic_pthread_destructor.request_size": 10241,
    "trace.automatic_pthread_destructor.block_size": 12288,
    "trace.automatic_pthread_destructor.capacity": 2,
    "trace.automatic_pthread_destructor.reserved": 42,
    "trace.automatic_pthread_destructor.slice_count": 8,
    "trace.automatic_pthread_destructor.arena_backed": 1,
    "trace.automatic_pthread_destructor.medium_page": 1,
    "trace.automatic_pthread_destructor.same_page": 1,
    "trace.automatic_pthread_destructor.worker_theap_initialized": 1,
    "trace.automatic_pthread_destructor.worker_page_used_before_return": 2,
    "trace.automatic_pthread_destructor.worker_page_full_before_return": 0,
    "trace.automatic_pthread_destructor.worker_local_free_empty": 1,
    "trace.automatic_pthread_destructor.worker_remote_free_empty": 1,
    "trace.automatic_pthread_destructor.origin_theap_present_before_return": 1,
    "trace.automatic_pthread_destructor.auto_key_valid_before_return": 1,
    "trace.automatic_pthread_destructor.auto_key_associated_before_return": 1,
    "trace.automatic_pthread_destructor.worker_returned_naturally": 1,
    "trace.automatic_pthread_destructor.join_completed": 1,
    "trace.automatic_pthread_destructor.mapped_after_join": 1,
    "trace.automatic_pthread_destructor.abandoned_after_join": 1,
    "trace.automatic_pthread_destructor.page_map_registered_after_join": 1,
    "trace.automatic_pthread_destructor.arena_page_bitmap_set_after_join": 1,
    "trace.automatic_pthread_destructor.queue_detached_after_join": 1,
    "trace.automatic_pthread_destructor.page_used_after_join": 2,
    "trace.automatic_pthread_destructor.consumer_associated_theap_unavailable": 1,
    "trace.automatic_pthread_destructor.automatic_teardown_effect": 1,
    "trace.automatic_pthread_destructor.first_free_same_page": 1,
    "trace.automatic_pthread_destructor.survivor_keeps_page_live": 1,
    "trace.automatic_pthread_destructor.mapped_after_first_free": 1,
    "trace.automatic_pthread_destructor.abandoned_after_first_free": 1,
    "trace.automatic_pthread_destructor.queue_detached_after_first_free": 1,
    "trace.automatic_pthread_destructor.used_after_first_free": 1,
    "trace.automatic_pthread_destructor.page_map_unregistered_after_final_free": 1,
    "trace.automatic_pthread_destructor.arena_page_bitmap_clear_after_final_free": 1,
    "trace.automatic_pthread_destructor.arena_slice_released_after_final_free": 1,
    "trace.automatic_pthread_destructor.abandoned_bitmap_clear_after_final_free": 1,
    "trace.automatic_pthread_destructor.valid": 1,
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
#error this private automatic pthread-destructor fixture requires native Linux/x86_64
#endif
#if !defined(MI_USE_PTHREADS)
#error this fixture requires the pinned pthread automatic-teardown source path
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native two-level map and unencoded release freelist
#endif

// `src/prim/unix/prim.c` owns this private key. It is intentionally observed
// only before natural worker return; the consumer never reads the old Theap.
extern pthread_key_t _mi_heap_default_key;

typedef struct worker_context_s {
  mi_arena_id_t arena_id;
  mi_heap_t* heap;
  void* block;
  void* survivor;
  bool setup_valid;
  bool worker_theap_initialized;
  bool origin_theap_present_before_return;
  bool auto_key_valid_before_return;
  bool auto_key_associated_before_return;
  bool worker_returned_naturally;
  int failure_stage;
  size_t block_size;
  size_t capacity;
  size_t reserved;
  size_t used_before_return;
  bool full_before_return;
  bool local_free_empty_before_return;
  bool remote_free_empty_before_return;
} worker_context_t;

static const size_t request_size = MI_SMALL_MAX_OBJ_SIZE + 1;
static const size_t expected_medium_slice_count = 8;

static void* worker_main(void* argument) {
  worker_context_t* const context = (worker_context_t*)argument;
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_theap_t* default_theap = NULL;
  mi_page_t* page = NULL;
  void* block = NULL;
  void* survivor = NULL;

  mi_thread_init();
  heap = mi_heap_new_in_arena(context->arena_id);
  if (heap == NULL) { context->failure_stage = 1; goto failed; }
  block = mi_heap_malloc(heap, request_size);
  survivor = mi_heap_malloc(heap, request_size);
  if (block == NULL || survivor == NULL) { context->failure_stage = 2; goto failed; }

  page = _mi_ptr_page(block);
  theap = _mi_heap_theap(heap);
  default_theap = _mi_theap_default();
  if (page == NULL || theap == NULL || default_theap == NULL
      || _mi_ptr_page(survivor) != page
      || page->block_size <= MI_SMALL_MAX_OBJ_SIZE
      || page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || page->memid.memkind != MI_MEM_ARENA
      || page->used != 2 || mi_page_is_full(page)) {
    context->failure_stage = 3;
    goto failed;
  }

  context->worker_theap_initialized = mi_theap_is_initialized(theap);
  context->origin_theap_present_before_return =
      (page->theap == theap && _mi_page_associated_theap_peek(page) == theap);
  context->auto_key_valid_before_return =
      (_mi_heap_default_key != MI_PTHREAD_KEY_INVALID);
  context->auto_key_associated_before_return =
      (context->auto_key_valid_before_return
       && pthread_getspecific(_mi_heap_default_key) == default_theap);
  context->block_size = page->block_size;
  context->capacity = page->capacity;
  context->reserved = page->reserved;
  context->used_before_return = page->used;
  context->full_before_return = mi_page_is_full(page);
  context->local_free_empty_before_return = (page->local_free == NULL);
  context->remote_free_empty_before_return =
      (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  context->heap = heap;
  context->block = block;
  context->survivor = survivor;
  context->setup_valid = (context->worker_theap_initialized
                          && context->origin_theap_present_before_return
                          && context->auto_key_valid_before_return
                          && context->auto_key_associated_before_return
                          && context->block_size == 12288
                          && context->capacity == 2
                          && context->reserved == 42
                          && context->used_before_return == 2
                          && !context->full_before_return
                          && context->local_free_empty_before_return
                          && context->remote_free_empty_before_return);
  if (!context->setup_valid) {
    fprintf(stderr,
            "worker setup failed: init=%d origin=%d key-valid=%d key-associated=%d "
            "block=%zu capacity=%zu reserved=%zu used=%zu full=%d local=%d remote=%d\\n",
            context->worker_theap_initialized, context->origin_theap_present_before_return,
            context->auto_key_valid_before_return, context->auto_key_associated_before_return,
            context->block_size, context->capacity, context->reserved, context->used_before_return,
            context->full_before_return, context->local_free_empty_before_return,
            context->remote_free_empty_before_return);
    context->failure_stage = 4;
    goto failed;
  }

  context->worker_returned_naturally = true;
  return NULL;

failed:
  if (block != NULL) mi_free(block);
  if (survivor != NULL) mi_free(survivor);
  if (heap != NULL) mi_heap_destroy(heap);
  context->heap = NULL;
  context->block = NULL;
  context->survivor = NULL;
  context->setup_valid = false;
  return NULL;
}

int main(void) {
  worker_context_t context = { 0 };
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  mi_page_t* page = NULL;
  mi_heap_t* heap = NULL;
  void* block = NULL;
  void* survivor = NULL;
  pthread_t worker;
  bool worker_started = false;
  long old_reclaim = 0;
  long old_full_retain = 0;
  bool options_changed = false;
  bool valid = false;
  int stage = 0;

  size_t block_size = 0;
  size_t capacity = 0;
  size_t reserved = 0;
  size_t used_after_join_count = 0;
  size_t slice_index = 0;
  size_t slice_count = 0;
  size_t bin = 0;
  uintptr_t page_start_address = 0;
  int arena_backed = 0;
  int medium_page = 0;
  int same_page = 0;
  int worker_theap_initialized = 0;
  int worker_page_used_before_return = 0;
  int worker_page_full_before_return = 0;
  int worker_local_free_empty = 0;
  int worker_remote_free_empty = 0;
  int origin_theap_present_before_return = 0;
  int auto_key_valid_before_return = 0;
  int auto_key_associated_before_return = 0;
  int worker_returned_naturally = 0;
  int join_completed = 0;
  int mapped_after_join = 0;
  int abandoned_after_join = 0;
  int page_map_registered_after_join = 0;
  int arena_page_bitmap_set_after_join = 0;
  int queue_detached_after_join = 0;
  int page_used_after_join = 0;
  int consumer_associated_theap_unavailable = 0;
  int automatic_teardown_effect = 0;
  int first_free_same_page = 0;
  int survivor_keeps_page_live = 0;
  int mapped_after_first_free = 0;
  int abandoned_after_first_free = 0;
  int queue_detached_after_first_free = 0;
  int used_after_first_free = 0;
  int page_map_unregistered_after_final_free = 0;
  int arena_page_bitmap_clear_after_final_free = 0;
  int arena_slice_released_after_final_free = 0;
  int abandoned_bitmap_clear_after_final_free = 0;

  mi_thread_init();
  old_reclaim = mi_option_get(mi_option_page_reclaim_on_free);
  old_full_retain = mi_option_get(mi_option_page_full_retain);
  mi_option_set(mi_option_page_reclaim_on_free, 0);
  mi_option_set(mi_option_page_full_retain, 2);
  options_changed = true;
  stage = 1;

  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto output;
  context.arena_id = arena_id;
  stage = 2;
  if (pthread_create(&worker, NULL, worker_main, &context) != 0) goto output;
  worker_started = true;
  stage = 3;
  if (pthread_join(worker, NULL) != 0) goto output;
  worker_started = false;
  join_completed = 1;
  stage = 4;

  heap = context.heap;
  block = context.block;
  survivor = context.survivor;
  if (!context.setup_valid || !context.worker_returned_naturally
      || heap == NULL || block == NULL || survivor == NULL || block == survivor) {
    stage = 40 + context.failure_stage;
    goto output;
  }

  page = _mi_safe_ptr_page(block);
  if (page == NULL || _mi_safe_ptr_page(survivor) != page) goto output;
  block_size = page->block_size;
  capacity = page->capacity;
  reserved = page->reserved;
  arena_backed = (page->memid.memkind == MI_MEM_ARENA);
  medium_page = (page->block_size > MI_SMALL_MAX_OBJ_SIZE
                 && page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE);
  same_page = (_mi_ptr_page(block) == page && _mi_ptr_page(survivor) == page);
  worker_theap_initialized = context.worker_theap_initialized;
  worker_page_used_before_return = (context.used_before_return == 2);
  worker_page_full_before_return = context.full_before_return;
  worker_local_free_empty = context.local_free_empty_before_return;
  worker_remote_free_empty = context.remote_free_empty_before_return;
  origin_theap_present_before_return = context.origin_theap_present_before_return;
  auto_key_valid_before_return = context.auto_key_valid_before_return;
  auto_key_associated_before_return = context.auto_key_associated_before_return;
  worker_returned_naturally = context.worker_returned_naturally;
  mapped_after_join = mi_page_is_abandoned_mapped(page);
  abandoned_after_join = mi_page_is_abandoned(page);
  page_map_registered_after_join = (_mi_safe_ptr_page(block) == page);
  queue_detached_after_join = (page->next == NULL && page->prev == NULL && !mi_page_is_owned(page));
  used_after_join_count = page->used;
  page_used_after_join = (used_after_join_count == 2);
  consumer_associated_theap_unavailable = (_mi_page_associated_theap_peek(page) == NULL);
  bin = _mi_bin(page->block_size);
  arena = mi_memid_arena(page->memid);
  slice_index = page->memid.mem.arena.slice_index;
  slice_count = page->memid.mem.arena.slice_count;
  if (arena != NULL && arena->arena_idx < MI_MAX_ARENAS) {
    arena_pages = mi_atomic_load_ptr_acquire(
        mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  }
  if (arena == NULL || arena_pages == NULL || bin >= MI_ARENA_BIN_COUNT
      || slice_count != expected_medium_slice_count) goto output;
  arena_page_bitmap_set_after_join = !mi_bitmap_is_clearN(arena_pages->pages, slice_index, 1);
  automatic_teardown_effect = (join_completed && worker_returned_naturally
                               && mapped_after_join && abandoned_after_join
                               && page_map_registered_after_join
                               && arena_page_bitmap_set_after_join
                               && queue_detached_after_join
                               && page_used_after_join
                               && consumer_associated_theap_unavailable);
  page_start_address = (uintptr_t)mi_page_start(page);
  if (!arena_backed || !medium_page || !same_page
      || block_size != 12288 || capacity != 2 || reserved != 42
      || !worker_theap_initialized || !worker_page_used_before_return
      || worker_page_full_before_return || !worker_local_free_empty
      || !worker_remote_free_empty || !origin_theap_present_before_return
      || !auto_key_valid_before_return || !auto_key_associated_before_return
      || !automatic_teardown_effect || page_start_address == 0) goto output;

  mi_free(block);
  block = NULL;
  page = _mi_safe_ptr_page(survivor);
  if (page == NULL || (uintptr_t)mi_page_start(page) != page_start_address) goto output;
  first_free_same_page = 1;
  survivor_keeps_page_live = (_mi_ptr_page(survivor) == page && !mi_page_all_free(page));
  mapped_after_first_free = mi_page_is_abandoned_mapped(page);
  abandoned_after_first_free = mi_page_is_abandoned(page);
  queue_detached_after_first_free =
      (page->next == NULL && page->prev == NULL && !mi_page_is_owned(page));
  used_after_first_free = (page->used == 1);
  if (!first_free_same_page || !survivor_keeps_page_live || !mapped_after_first_free
      || !abandoned_after_first_free || !queue_detached_after_first_free
      || !used_after_first_free) goto output;

  mi_free(survivor);
  survivor = NULL;
  page_map_unregistered_after_final_free =
      (_mi_safe_ptr_page((const void*)(uintptr_t)page_start_address) == NULL);
  arena_page_bitmap_clear_after_final_free =
      mi_bitmap_is_clearN(arena_pages->pages, slice_index, 1);
  arena_slice_released_after_final_free =
      mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count);
  abandoned_bitmap_clear_after_final_free =
      mi_bitmap_is_clearN(arena_pages->pages_abandoned[bin], slice_index, 1);
  valid = (page_map_unregistered_after_final_free
           && arena_page_bitmap_clear_after_final_free
           && arena_slice_released_after_final_free
           && abandoned_bitmap_clear_after_final_free);

output:
  printf("CRABC_MI_AUTOMATIC_PTHREAD_DESTRUCTOR_TRACE_BEGIN\n");
#define OUT_N(k,v) printf("trace.automatic_pthread_destructor.%s=%zu\n", k, (size_t)(v))
#define OUT_B(k,v) printf("trace.automatic_pthread_destructor.%s=%d\n", k, (v) ? 1 : 0)
  OUT_N("request_size", request_size);
  OUT_N("block_size", block_size);
  OUT_N("capacity", capacity);
  OUT_N("reserved", reserved);
  OUT_N("slice_count", slice_count);
  OUT_B("arena_backed", arena_backed);
  OUT_B("medium_page", medium_page);
  OUT_B("same_page", same_page);
  OUT_B("worker_theap_initialized", worker_theap_initialized);
  OUT_N("worker_page_used_before_return", context.used_before_return);
  OUT_B("worker_page_full_before_return", worker_page_full_before_return);
  OUT_B("worker_local_free_empty", worker_local_free_empty);
  OUT_B("worker_remote_free_empty", worker_remote_free_empty);
  OUT_B("origin_theap_present_before_return", origin_theap_present_before_return);
  OUT_B("auto_key_valid_before_return", auto_key_valid_before_return);
  OUT_B("auto_key_associated_before_return", auto_key_associated_before_return);
  OUT_B("worker_returned_naturally", worker_returned_naturally);
  OUT_B("join_completed", join_completed);
  OUT_B("mapped_after_join", mapped_after_join);
  OUT_B("abandoned_after_join", abandoned_after_join);
  OUT_B("page_map_registered_after_join", page_map_registered_after_join);
  OUT_B("arena_page_bitmap_set_after_join", arena_page_bitmap_set_after_join);
  OUT_B("queue_detached_after_join", queue_detached_after_join);
  OUT_N("page_used_after_join", used_after_join_count);
  OUT_B("consumer_associated_theap_unavailable", consumer_associated_theap_unavailable);
  OUT_B("automatic_teardown_effect", automatic_teardown_effect);
  OUT_B("first_free_same_page", first_free_same_page);
  OUT_B("survivor_keeps_page_live", survivor_keeps_page_live);
  OUT_B("mapped_after_first_free", mapped_after_first_free);
  OUT_B("abandoned_after_first_free", abandoned_after_first_free);
  OUT_B("queue_detached_after_first_free", queue_detached_after_first_free);
  OUT_B("used_after_first_free", used_after_first_free);
  OUT_B("page_map_unregistered_after_final_free", page_map_unregistered_after_final_free);
  OUT_B("arena_page_bitmap_clear_after_final_free", arena_page_bitmap_clear_after_final_free);
  OUT_B("arena_slice_released_after_final_free", arena_slice_released_after_final_free);
  OUT_B("abandoned_bitmap_clear_after_final_free", abandoned_bitmap_clear_after_final_free);
  OUT_B("valid", valid);
  printf("CRABC_MI_AUTOMATIC_PTHREAD_DESTRUCTOR_TRACE_END\n");

  if (worker_started) (void)pthread_join(worker, NULL);
  if (block != NULL) mi_free(block);
  if (survivor != NULL) mi_free(survivor);
  if (heap != NULL) mi_heap_destroy(heap);
  if (options_changed) {
    mi_option_set(mi_option_page_reclaim_on_free, old_reclaim);
    mi_option_set(mi_option_page_full_retain, old_full_retain);
  }
  if (!valid) fprintf(stderr, "automatic pthread-destructor fixture stopped at stage %d\n", stage);
  return valid ? 0 : 2;
}
'''

FORBIDDEN_WORKER_EXIT_CALL = re.compile(r"\b(?:_?mi_thread_done|pthread_exit)\s*\(")
WORKER_BODY = re.compile(
    r"static\s+void\s*\*\s*worker_main\s*\([^)]*\)\s*\{(?P<body>.*?)^\}\n\nint main",
    re.DOTALL | re.MULTILINE,
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
            exactly_matches(actual, wanted) for actual, wanted in zip(observed, expected)
        )
    return observed == expected


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise EvidenceError("automatic pthread-destructor source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def validate_probe_source(probe: str = C_TRACE_PROBE) -> None:
    worker = WORKER_BODY.search(probe)
    if worker is None:
        raise EvidenceError("automatic pthread-destructor worker body is missing")
    body = worker.group("body")
    if FORBIDDEN_WORKER_EXIT_CALL.search(body) is not None:
        raise EvidenceError("automatic pthread-destructor worker contains an explicit teardown call")
    required = (
        "extern pthread_key_t _mi_heap_default_key;",
        "pthread_getspecific(_mi_heap_default_key) == default_theap",
        "context->worker_returned_naturally = true;",
        "return NULL;",
        "#if !defined(MI_USE_PTHREADS)",
    )
    if not all(fragment in probe for fragment in required):
        raise EvidenceError("automatic pthread-destructor probe loses its source boundary")


def load_schema(path: Path | None = None) -> dict[str, Any]:
    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 automatic pthread-destructor schema") from error
    expected_fields = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "schema", "scope", "source_anchors", "target", "trace", "upstream",
    }
    if not isinstance(schema, dict) or set(schema) != expected_fields:
        raise EvidenceError("automatic pthread-destructor schema fields drifted")
    if type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("unsupported automatic pthread-destructor evidence format")
    if schema["schema"] != "crabc-mimalloc-x86_64-automatic-pthread-destructor-evidence":
        raise EvidenceError("unsupported automatic pthread-destructor evidence schema")
    if schema["profile"] != EXPECTED_PROFILE or not exactly_matches(schema["target"], EXPECTED_TARGET):
        raise EvidenceError("automatic pthread-destructor target/profile drifted")
    if not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("automatic pthread-destructor upstream drifted")
    if not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("automatic pthread-destructor scope drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate pinned automatic pthread-destructor upstream identity") from error
    if (pin["sha256"] != EXPECTED_ARCHIVE_SHA256
            or pin["archive_root"] != EXPECTED_UPSTREAM["archive_root"]
            or pin["revision"] != EXPECTED_UPSTREAM["revision"]
            or pin["version"] != EXPECTED_UPSTREAM["version"]):
        raise EvidenceError("automatic pthread-destructor upstream pin drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("automatic pthread-destructor C source set drifted")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("automatic pthread-destructor release flags drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("automatic pthread-destructor compile definitions drifted")
    if not exactly_matches(schema["trace"], {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES}):
        raise EvidenceError("automatic pthread-destructor trace contract drifted")
    validate_probe_source()
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("automatic pthread-destructor C probe hash drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("automatic pthread-destructor source anchors drifted")
    observed = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("automatic pthread-destructor source anchor shape drifted")
        observed.append((anchor.get("member"), anchor.get("start_line"), anchor.get("end_line"), anchor.get("sha256")))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("automatic pthread-destructor source anchor contract drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated = []
    for anchor in schema["source_anchors"]:
        path = source / str(anchor["member"])
        digest = sha256_bytes(source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))) if path.is_file() else None
        if digest != anchor["sha256"]:
            raise EvidenceError(f"automatic pthread-destructor source anchor drifted: {anchor['member']}")
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(
            output,
            begin=TRACE_BEGIN,
            end=TRACE_END,
            description="pinned C automatic pthread-destructor trace",
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    non_integer = sorted(key for key, value in trace.items() if type(value) is not int)
    mismatches = sorted(
        key for key, expected in EXPECTED_TRACE_VALUES.items()
        if type(trace.get(key)) is int and trace[key] != expected
    )
    if missing or unexpected or non_integer or mismatches:
        raise EvidenceError(f"{description} violates the fixed {len(EXPECTED_TRACE_VALUES)}-field trace contract")


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


def c_trace_command(
    compiler: str, source: Path, probe_source: Path, binary: Path, schema: Mapping[str, Any]
) -> list[str]:
    return [
        compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"),
        *schema["release_flags"], str(probe_source),
        *(str(source / member) for member in schema["release_source_set"]),
        "-pthread", "-o", str(binary),
    ]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(schema["compile_definitions"]) or flags != list(schema["release_flags"]):
        raise EvidenceError("automatic pthread-destructor C release command drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("automatic pthread-destructor C command lacks pthread/TLS requirements")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc":
        raise EvidenceError("automatic pthread-destructor C compiler drifted")
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/automatic-pthread-destructor.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/automatic-pthread-destructor-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("automatic pthread-destructor C command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]
) -> dict[str, Any]:
    probe_source = temporary / "automatic-pthread-destructor.c"
    binary = temporary / "automatic-pthread-destructor-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C automatic pthread-destructor fixture build")
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "pinned C automatic pthread-destructor ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source)
        if int(execution["status"]) != 0:
            raise EvidenceError(
                "pinned C automatic pthread-destructor fixture execution failed "
                f"({execution['status']}):\n{execution['stdout']}{execution['stderr']}"
            )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]))
    try:
        validate_trace(trace, description="pinned C automatic pthread-destructor trace")
    except EvidenceError as error:
        raise EvidenceError(f"{error}: {json.dumps(trace, sort_keys=True)}") from error
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/automatic-pthread-destructor-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def report_from_results(
    schema: Mapping[str, Any],
    provenance: Mapping[str, str],
    archive_sha256: str,
    anchors: Sequence[Mapping[str, Any]],
    c_probe: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "c_probe": dict(c_probe),
        "format": 1,
        "kind": "mimalloc-x86_64-automatic-pthread-destructor-c-oracle-evidence",
        "profile": schema["profile"],
        "provenance": dict(provenance),
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
    required = {"c_probe", "format", "kind", "profile", "provenance", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("automatic pthread-destructor report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("automatic pthread-destructor report must be a passing format-1 result")
    if report["kind"] != "mimalloc-x86_64-automatic-pthread-destructor-c-oracle-evidence" or report["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("automatic pthread-destructor report identity drifted")
    if (not exactly_matches(report["target"], EXPECTED_TARGET)
            or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM)
            or not exactly_matches(report["scope"], EXPECTED_SCOPE)):
        raise EvidenceError("automatic pthread-destructor report boundary drifted")
    if not any(exactly_matches(report["provenance"], value) for value in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    )):
        raise EvidenceError("automatic pthread-destructor report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("automatic pthread-destructor report trace contract drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("automatic pthread-destructor report source drifted")
    if (source["archive_sha256"] != run.load_pin()["sha256"]
            or not exactly_matches(source["anchors"], schema["source_anchors"])
            or not exactly_matches(source["release_flags"], schema["release_flags"])
            or not exactly_matches(source["release_source_set"], schema["release_source_set"])):
        raise EvidenceError("automatic pthread-destructor report source identity drifted")
    c_probe = report["c_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("automatic pthread-destructor C probe record drifted")
    if (not exactly_matches(c_probe["elf"], EXPECTED_C_ELF)
            or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/automatic-pthread-destructor-c"]
            or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8"))):
        raise EvidenceError("automatic pthread-destructor C probe identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    validate_trace(c_probe["trace"], description="recorded automatic pthread-destructor trace")


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-automatic-pthread-destructor-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
            compiler = run.require_tool("musl-gcc")
            readelf = run.require_tool("readelf")
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source)
        c_probe = build_c_trace(compiler, readelf, source, temporary, schema)
        report = report_from_results(schema, provenance, sha256_bytes(archive.read_bytes()), anchors, c_probe)
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
        print(f"allocator x86-64 automatic pthread-destructor evidence: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 automatic pthread-destructor evidence: PASS "
        f"({len(report['trace']['expected_values'])} logical values; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
