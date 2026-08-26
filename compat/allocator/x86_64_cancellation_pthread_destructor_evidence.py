#!/usr/bin/env python3
"""Prove the pinned C key-destructor path after deferred pthread cancellation.

The native fixture keeps cancellation disabled while one worker initializes
mimalloc and creates two live arena-medium clients.  It then enables only
deferred cancellation, waits on a non-cancellation-point atomic gate, and
reaches exactly one explicit ``pthread_testcancel`` after the consumer has
issued ``pthread_cancel``.  The worker does not invoke an explicit allocator
teardown entry point or ``pthread_exit``.  After ``pthread_join`` reports
``PTHREAD_CANCELED``, the consumer observes the selected abandoned page and
performs its two terminal frees.

This is C-oracle-only native Linux/x86-64 evidence.  It does not establish
crabc pthread-cancellation behavior, Rust callback parity, a public x86
runtime, allocator, libc, or loader surface.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_automatic_pthread_destructor_evidence.py"
_spec = importlib.util.spec_from_file_location("automatic_pthread_destructor_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)


SCHEMA_PATH = ROOT / "compat/allocator/x86_64-cancellation-pthread-destructor-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/cancellation-pthread-destructor.json"
TRACE_BEGIN = "CRABC_MI_CANCELLATION_PTHREAD_DESTRUCTOR_TRACE_BEGIN"
TRACE_END = "CRABC_MI_CANCELLATION_PTHREAD_DESTRUCTOR_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

run = _base.run
EvidenceError = _base.EvidenceError
sha256_bytes = _base.sha256_bytes
exactly_matches = _base.exactly_matches
relative = _base.relative

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
EXPECTED_PROFILE = "linux-x86_64-private-c-cancel-testcancel-automatic-pthread-destructor"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "automatic_pthread_destructor_only": True,
    "cancellation_triggered_only": True,
    "crabc_pthread_cancel_parity_claimed": False,
    "deferred_cancellation_only": True,
    "emulation_accepted": False,
    "explicit_cancel_then_testcancel_only": True,
    "general_abandonment_or_adoption_claimed": False,
    "general_cancellation_ordering_claimed": False,
    "general_lifecycle_claimed": False,
    "general_process_shutdown_claimed": False,
    "general_pthread_destructor_ordering_claimed": False,
    "general_remote_free_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "no_explicit_pthread_exit_in_worker": True,
    "no_explicit_thread_done_in_worker": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_automatic_pthread_destructor": True,
    "rust_automatic_pthread_destructor_claimed": False,
    "worker_async_cancellation_accepted": False,
    "worker_natural_return_claimed": False,
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
    "trace.cancellation_pthread_destructor.request_size": 10241,
    "trace.cancellation_pthread_destructor.block_size": 12288,
    "trace.cancellation_pthread_destructor.capacity": 2,
    "trace.cancellation_pthread_destructor.reserved": 42,
    "trace.cancellation_pthread_destructor.slice_count": 8,
    "trace.cancellation_pthread_destructor.arena_backed": 1,
    "trace.cancellation_pthread_destructor.medium_page": 1,
    "trace.cancellation_pthread_destructor.same_page": 1,
    "trace.cancellation_pthread_destructor.worker_theap_initialized": 1,
    "trace.cancellation_pthread_destructor.worker_page_used_before_cancel": 2,
    "trace.cancellation_pthread_destructor.worker_page_full_before_cancel": 0,
    "trace.cancellation_pthread_destructor.worker_local_free_empty": 1,
    "trace.cancellation_pthread_destructor.worker_remote_free_empty": 1,
    "trace.cancellation_pthread_destructor.origin_theap_present_before_cancel": 1,
    "trace.cancellation_pthread_destructor.auto_key_valid_before_cancel": 1,
    "trace.cancellation_pthread_destructor.auto_key_associated_before_cancel": 1,
    "trace.cancellation_pthread_destructor.worker_cancellation_disabled_during_setup": 1,
    "trace.cancellation_pthread_destructor.worker_deferred_cancellation_before_ready": 1,
    "trace.cancellation_pthread_destructor.worker_ready_before_cancel": 1,
    "trace.cancellation_pthread_destructor.cancel_request_succeeded": 1,
    "trace.cancellation_pthread_destructor.cancel_gate_opened": 1,
    "trace.cancellation_pthread_destructor.worker_entered_testcancel": 1,
    "trace.cancellation_pthread_destructor.worker_continued_after_testcancel": 0,
    "trace.cancellation_pthread_destructor.worker_returned_naturally": 0,
    "trace.cancellation_pthread_destructor.join_completed": 1,
    "trace.cancellation_pthread_destructor.join_result_is_pthread_canceled": 1,
    "trace.cancellation_pthread_destructor.cancellation_terminated_at_testcancel": 1,
    "trace.cancellation_pthread_destructor.mapped_after_join": 1,
    "trace.cancellation_pthread_destructor.abandoned_after_join": 1,
    "trace.cancellation_pthread_destructor.page_map_registered_after_join": 1,
    "trace.cancellation_pthread_destructor.arena_page_bitmap_set_after_join": 1,
    "trace.cancellation_pthread_destructor.queue_detached_after_join": 1,
    "trace.cancellation_pthread_destructor.page_used_after_join": 2,
    "trace.cancellation_pthread_destructor.consumer_associated_theap_unavailable": 1,
    "trace.cancellation_pthread_destructor.automatic_teardown_effect": 1,
    "trace.cancellation_pthread_destructor.first_free_same_page": 1,
    "trace.cancellation_pthread_destructor.survivor_keeps_page_live": 1,
    "trace.cancellation_pthread_destructor.mapped_after_first_free": 1,
    "trace.cancellation_pthread_destructor.abandoned_after_first_free": 1,
    "trace.cancellation_pthread_destructor.queue_detached_after_first_free": 1,
    "trace.cancellation_pthread_destructor.used_after_first_free": 1,
    "trace.cancellation_pthread_destructor.page_map_unregistered_after_final_free": 1,
    "trace.cancellation_pthread_destructor.arena_page_bitmap_clear_after_final_free": 1,
    "trace.cancellation_pthread_destructor.arena_slice_released_after_final_free": 1,
    "trace.cancellation_pthread_destructor.abandoned_bitmap_clear_after_final_free": 1,
    "trace.cancellation_pthread_destructor.valid": 1,
}


C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private cancellation pthread-destructor fixture requires native Linux/x86_64
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
// only before the parent requests cancellation; the consumer never reads the
// former worker Theap after `pthread_join`.
extern pthread_key_t _mi_heap_default_key;

typedef struct worker_context_s {
  mi_arena_id_t arena_id;
  mi_heap_t* heap;
  void* block;
  void* survivor;
  _Atomic int ready;
  _Atomic int cancel_gate;
  bool setup_valid;
  bool worker_theap_initialized;
  bool origin_theap_present_before_cancel;
  bool auto_key_valid_before_cancel;
  bool auto_key_associated_before_cancel;
  bool cancellation_disabled_during_setup;
  bool deferred_cancellation_before_ready;
  bool entered_testcancel;
  bool continued_after_testcancel;
  bool worker_returned_naturally;
  int failure_stage;
  size_t block_size;
  size_t capacity;
  size_t reserved;
  size_t used_before_cancel;
  bool full_before_cancel;
  bool local_free_empty_before_cancel;
  bool remote_free_empty_before_cancel;
} worker_context_t;

static const size_t request_size = MI_SMALL_MAX_OBJ_SIZE + 1;
static const size_t expected_medium_slice_count = 8;
static const size_t wait_limit = 100000000;

static bool wait_for_ready(worker_context_t* context) {
  for (size_t spin = 0; spin < wait_limit; spin++) {
    const int value = atomic_load_explicit(&context->ready, memory_order_acquire);
    if (value == 1) return true;
    if (value < 0) return false;
  }
  return false;
}

static void* worker_main(void* argument) {
  worker_context_t* const context = (worker_context_t*)argument;
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_theap_t* default_theap = NULL;
  mi_page_t* page = NULL;
  void* block = NULL;
  void* survivor = NULL;
  int old_cancel_state = -1;
  int old_cancel_type = -1;

  if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state) != 0
      || old_cancel_state != PTHREAD_CANCEL_ENABLE) {
    context->failure_stage = 1;
    goto failed;
  }
  context->cancellation_disabled_during_setup = true;
  if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old_cancel_type) != 0
      || old_cancel_type != PTHREAD_CANCEL_DEFERRED) {
    context->failure_stage = 2;
    goto failed;
  }

  mi_thread_init();
  heap = mi_heap_new_in_arena(context->arena_id);
  if (heap == NULL) { context->failure_stage = 3; goto failed; }
  block = mi_heap_malloc(heap, request_size);
  survivor = mi_heap_malloc(heap, request_size);
  if (block == NULL || survivor == NULL) { context->failure_stage = 4; goto failed; }

  page = _mi_ptr_page(block);
  theap = _mi_heap_theap(heap);
  default_theap = _mi_theap_default();
  if (page == NULL || theap == NULL || default_theap == NULL
      || _mi_ptr_page(survivor) != page
      || page->block_size <= MI_SMALL_MAX_OBJ_SIZE
      || page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || page->memid.memkind != MI_MEM_ARENA
      || page->used != 2 || mi_page_is_full(page)) {
    context->failure_stage = 5;
    goto failed;
  }

  context->worker_theap_initialized = mi_theap_is_initialized(theap);
  context->origin_theap_present_before_cancel =
      (page->theap == theap && _mi_page_associated_theap_peek(page) == theap);
  context->auto_key_valid_before_cancel =
      (_mi_heap_default_key != MI_PTHREAD_KEY_INVALID);
  context->auto_key_associated_before_cancel =
      (context->auto_key_valid_before_cancel
       && pthread_getspecific(_mi_heap_default_key) == default_theap);
  context->block_size = page->block_size;
  context->capacity = page->capacity;
  context->reserved = page->reserved;
  context->used_before_cancel = page->used;
  context->full_before_cancel = mi_page_is_full(page);
  context->local_free_empty_before_cancel = (page->local_free == NULL);
  context->remote_free_empty_before_cancel =
      (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  context->heap = heap;
  context->block = block;
  context->survivor = survivor;
  context->setup_valid = (context->worker_theap_initialized
                          && context->origin_theap_present_before_cancel
                          && context->auto_key_valid_before_cancel
                          && context->auto_key_associated_before_cancel
                          && context->cancellation_disabled_during_setup
                          && context->block_size == 12288
                          && context->capacity == 2
                          && context->reserved == 42
                          && context->used_before_cancel == 2
                          && !context->full_before_cancel
                          && context->local_free_empty_before_cancel
                          && context->remote_free_empty_before_cancel);
  if (!context->setup_valid) {
    context->failure_stage = 6;
    goto failed;
  }

  // The parent cannot request cancellation until this release publication.
  // The following atomic gate has no cancellation point, so the one explicit
  // `pthread_testcancel` below is the only valid cancellation delivery site.
  if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) {
    context->failure_stage = 7;
    goto failed;
  }
  context->deferred_cancellation_before_ready = true;
  atomic_store_explicit(&context->ready, 1, memory_order_release);
  while (atomic_load_explicit(&context->cancel_gate, memory_order_acquire) == 0) {
  }
  context->entered_testcancel = true;
  pthread_testcancel();
  context->continued_after_testcancel = true;
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
  atomic_store_explicit(&context->ready, -1, memory_order_release);
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
  void* join_result = NULL;

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
  int worker_page_used_before_cancel = 0;
  int worker_page_full_before_cancel = 0;
  int worker_local_free_empty = 0;
  int worker_remote_free_empty = 0;
  int origin_theap_present_before_cancel = 0;
  int auto_key_valid_before_cancel = 0;
  int auto_key_associated_before_cancel = 0;
  int worker_cancellation_disabled_during_setup = 0;
  int worker_deferred_cancellation_before_ready = 0;
  int worker_ready_before_cancel = 0;
  int cancel_request_succeeded = 0;
  int cancel_gate_opened = 0;
  int worker_entered_testcancel = 0;
  int worker_continued_after_testcancel = 0;
  int worker_returned_naturally = 0;
  int join_completed = 0;
  int join_result_is_pthread_canceled = 0;
  int cancellation_terminated_at_testcancel = 0;
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

  atomic_init(&context.ready, 0);
  atomic_init(&context.cancel_gate, 0);
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
  if (!wait_for_ready(&context)) goto output;
  worker_ready_before_cancel = 1;
  if (pthread_cancel(worker) != 0) goto output;
  cancel_request_succeeded = 1;
  atomic_store_explicit(&context.cancel_gate, 1, memory_order_release);
  cancel_gate_opened = 1;
  if (pthread_join(worker, &join_result) != 0) goto output;
  worker_started = false;
  join_completed = 1;
  join_result_is_pthread_canceled = (join_result == PTHREAD_CANCELED);
  stage = 4;

  heap = context.heap;
  block = context.block;
  survivor = context.survivor;
  if (!context.setup_valid || heap == NULL || block == NULL || survivor == NULL || block == survivor) {
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
  worker_page_used_before_cancel = (context.used_before_cancel == 2);
  worker_page_full_before_cancel = context.full_before_cancel;
  worker_local_free_empty = context.local_free_empty_before_cancel;
  worker_remote_free_empty = context.remote_free_empty_before_cancel;
  origin_theap_present_before_cancel = context.origin_theap_present_before_cancel;
  auto_key_valid_before_cancel = context.auto_key_valid_before_cancel;
  auto_key_associated_before_cancel = context.auto_key_associated_before_cancel;
  worker_cancellation_disabled_during_setup = context.cancellation_disabled_during_setup;
  worker_deferred_cancellation_before_ready = context.deferred_cancellation_before_ready;
  worker_entered_testcancel = context.entered_testcancel;
  worker_continued_after_testcancel = context.continued_after_testcancel;
  worker_returned_naturally = context.worker_returned_naturally;
  cancellation_terminated_at_testcancel = (join_result_is_pthread_canceled
      && worker_entered_testcancel && !worker_continued_after_testcancel
      && !worker_returned_naturally);
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
  automatic_teardown_effect = (join_completed && join_result_is_pthread_canceled
                               && cancellation_terminated_at_testcancel
                               && mapped_after_join && abandoned_after_join
                               && page_map_registered_after_join
                               && arena_page_bitmap_set_after_join
                               && queue_detached_after_join
                               && page_used_after_join
                               && consumer_associated_theap_unavailable);
  page_start_address = (uintptr_t)mi_page_start(page);
  if (!arena_backed || !medium_page || !same_page
      || block_size != 12288 || capacity != 2 || reserved != 42
      || !worker_theap_initialized || !worker_page_used_before_cancel
      || worker_page_full_before_cancel || !worker_local_free_empty
      || !worker_remote_free_empty || !origin_theap_present_before_cancel
      || !auto_key_valid_before_cancel || !auto_key_associated_before_cancel
      || !worker_cancellation_disabled_during_setup
      || !worker_deferred_cancellation_before_ready || !worker_ready_before_cancel
      || !cancel_request_succeeded || !cancel_gate_opened || !worker_entered_testcancel
      || worker_continued_after_testcancel || worker_returned_naturally
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
  printf("CRABC_MI_CANCELLATION_PTHREAD_DESTRUCTOR_TRACE_BEGIN\n");
#define OUT_N(k,v) printf("trace.cancellation_pthread_destructor.%s=%zu\n", k, (size_t)(v))
#define OUT_B(k,v) printf("trace.cancellation_pthread_destructor.%s=%d\n", k, (v) ? 1 : 0)
  OUT_N("request_size", request_size);
  OUT_N("block_size", block_size);
  OUT_N("capacity", capacity);
  OUT_N("reserved", reserved);
  OUT_N("slice_count", slice_count);
  OUT_B("arena_backed", arena_backed);
  OUT_B("medium_page", medium_page);
  OUT_B("same_page", same_page);
  OUT_B("worker_theap_initialized", worker_theap_initialized);
  OUT_N("worker_page_used_before_cancel", context.used_before_cancel);
  OUT_B("worker_page_full_before_cancel", worker_page_full_before_cancel);
  OUT_B("worker_local_free_empty", worker_local_free_empty);
  OUT_B("worker_remote_free_empty", worker_remote_free_empty);
  OUT_B("origin_theap_present_before_cancel", origin_theap_present_before_cancel);
  OUT_B("auto_key_valid_before_cancel", auto_key_valid_before_cancel);
  OUT_B("auto_key_associated_before_cancel", auto_key_associated_before_cancel);
  OUT_B("worker_cancellation_disabled_during_setup", worker_cancellation_disabled_during_setup);
  OUT_B("worker_deferred_cancellation_before_ready", worker_deferred_cancellation_before_ready);
  OUT_B("worker_ready_before_cancel", worker_ready_before_cancel);
  OUT_B("cancel_request_succeeded", cancel_request_succeeded);
  OUT_B("cancel_gate_opened", cancel_gate_opened);
  OUT_B("worker_entered_testcancel", worker_entered_testcancel);
  OUT_B("worker_continued_after_testcancel", worker_continued_after_testcancel);
  OUT_B("worker_returned_naturally", worker_returned_naturally);
  OUT_B("join_completed", join_completed);
  OUT_B("join_result_is_pthread_canceled", join_result_is_pthread_canceled);
  OUT_B("cancellation_terminated_at_testcancel", cancellation_terminated_at_testcancel);
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
  printf("CRABC_MI_CANCELLATION_PTHREAD_DESTRUCTOR_TRACE_END\n");

  if (worker_started) {
    atomic_store_explicit(&context.cancel_gate, 1, memory_order_release);
    (void)pthread_join(worker, NULL);
  }
  if (block != NULL) mi_free(block);
  if (survivor != NULL) mi_free(survivor);
  if (heap != NULL) mi_heap_destroy(heap);
  if (options_changed) {
    mi_option_set(mi_option_page_reclaim_on_free, old_reclaim);
    mi_option_set(mi_option_page_full_retain, old_full_retain);
  }
  if (!valid) fprintf(stderr, "cancellation pthread-destructor fixture stopped at stage %d\n", stage);
  return valid ? 0 : 2;
}
'''

FORBIDDEN_WORKER_EXIT_CALL = re.compile(r"\b(?:_?mi_thread_done|pthread_exit)\s*\(")
WORKER_BODY = re.compile(
    r"static\s+void\s*\*\s*worker_main\s*\([^)]*\)\s*\{(?P<body>.*?)^\}\n\nint main",
    re.DOTALL | re.MULTILINE,
)


def validate_probe_source(probe: str = C_TRACE_PROBE) -> None:
    worker = WORKER_BODY.search(probe)
    if worker is None:
        raise EvidenceError("cancellation pthread-destructor worker body is missing")
    body = worker.group("body")
    if FORBIDDEN_WORKER_EXIT_CALL.search(body) is not None:
        raise EvidenceError("cancellation pthread-destructor worker contains an explicit teardown call")
    if probe.count("pthread_cancel(worker)") != 1:
        raise EvidenceError("cancellation pthread-destructor probe must contain exactly one parent cancellation request")
    if body.count("pthread_testcancel();") != 1:
        raise EvidenceError("cancellation pthread-destructor worker must contain exactly one cancellation delivery")
    if probe.count("pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old_cancel_type)") != 1:
        raise EvidenceError("cancellation pthread-destructor worker must select deferred cancellation exactly once")
    if "PTHREAD_CANCEL_ASYNCHRONOUS" in probe:
        raise EvidenceError("cancellation pthread-destructor probe must not accept asynchronous cancellation")
    required_worker = (
        "pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state)",
        "pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old_cancel_type)",
        "pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)",
        "atomic_store_explicit(&context->ready, 1, memory_order_release);",
        "context->entered_testcancel = true;",
        "pthread_testcancel();",
        "context->continued_after_testcancel = true;",
    )
    required_probe = (
        "extern pthread_key_t _mi_heap_default_key;",
        "pthread_getspecific(_mi_heap_default_key) == default_theap",
        "pthread_cancel(worker)",
        "join_result == PTHREAD_CANCELED",
        "#include <stdatomic.h>",
    )
    if not all(fragment in body for fragment in required_worker) or not all(
        fragment in probe for fragment in required_probe
    ):
        raise EvidenceError("cancellation pthread-destructor probe loses its source boundary")

    worker_order = (
        "pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state)",
        "pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old_cancel_type)",
        "pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)",
        "atomic_store_explicit(&context->ready, 1, memory_order_release);",
        "while (atomic_load_explicit(&context->cancel_gate, memory_order_acquire) == 0)",
        "context->entered_testcancel = true;",
        "pthread_testcancel();",
        "context->continued_after_testcancel = true;",
    )
    worker_positions = tuple(body.find(fragment) for fragment in worker_order)
    if -1 in worker_positions or worker_positions != tuple(sorted(worker_positions)):
        raise EvidenceError("cancellation pthread-destructor worker cancellation ordering drifted")

    main_start = probe.find("int main(void) {")
    if main_start < 0:
        raise EvidenceError("cancellation pthread-destructor parent body is missing")
    parent = probe[main_start:]
    parent_order = (
        "if (!wait_for_ready(&context)) goto output;",
        "worker_ready_before_cancel = 1;",
        "if (pthread_cancel(worker) != 0) goto output;",
        "cancel_request_succeeded = 1;",
        "atomic_store_explicit(&context.cancel_gate, 1, memory_order_release);",
        "cancel_gate_opened = 1;",
        "if (pthread_join(worker, &join_result) != 0) goto output;",
        "join_result_is_pthread_canceled = (join_result == PTHREAD_CANCELED);",
    )
    parent_positions = tuple(parent.find(fragment) for fragment in parent_order)
    if -1 in parent_positions or parent_positions != tuple(sorted(parent_positions)):
        raise EvidenceError("cancellation pthread-destructor parent cancellation ordering drifted")


def load_schema(path: Path | None = None) -> dict[str, Any]:
    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 cancellation pthread-destructor schema") from error
    expected_fields = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "schema", "scope", "source_anchors", "target", "trace", "upstream",
    }
    if not isinstance(schema, dict) or set(schema) != expected_fields:
        raise EvidenceError("cancellation pthread-destructor schema fields drifted")
    if type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("unsupported cancellation pthread-destructor evidence format")
    if schema["schema"] != "crabc-mimalloc-x86_64-cancellation-pthread-destructor-evidence":
        raise EvidenceError("unsupported cancellation pthread-destructor evidence schema")
    if schema["profile"] != EXPECTED_PROFILE or not exactly_matches(schema["target"], EXPECTED_TARGET):
        raise EvidenceError("cancellation pthread-destructor target/profile drifted")
    if not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("cancellation pthread-destructor upstream drifted")
    if not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("cancellation pthread-destructor scope drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate pinned cancellation pthread-destructor upstream identity") from error
    if (pin["sha256"] != EXPECTED_ARCHIVE_SHA256
            or pin["archive_root"] != EXPECTED_UPSTREAM["archive_root"]
            or pin["revision"] != EXPECTED_UPSTREAM["revision"]
            or pin["version"] != EXPECTED_UPSTREAM["version"]):
        raise EvidenceError("cancellation pthread-destructor upstream pin drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("cancellation pthread-destructor C source set drifted")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("cancellation pthread-destructor release flags drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("cancellation pthread-destructor compile definitions drifted")
    if not exactly_matches(
        schema["trace"],
        {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES},
    ):
        raise EvidenceError("cancellation pthread-destructor trace contract drifted")
    validate_probe_source()
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("cancellation pthread-destructor C probe hash drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("cancellation pthread-destructor source anchors drifted")
    observed = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("cancellation pthread-destructor source anchor shape drifted")
        observed.append((anchor.get("member"), anchor.get("start_line"), anchor.get("end_line"), anchor.get("sha256")))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("cancellation pthread-destructor source anchor contract drifted")
    return schema


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
        raise EvidenceError("cancellation pthread-destructor C release command drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("cancellation pthread-destructor C command lacks pthread/TLS requirements")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc":
        raise EvidenceError("cancellation pthread-destructor C compiler drifted")
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/cancellation-pthread-destructor.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/cancellation-pthread-destructor-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("cancellation pthread-destructor C command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]
) -> dict[str, Any]:
    probe_source = temporary / "cancellation-pthread-destructor.c"
    binary = temporary / "cancellation-pthread-destructor-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(
            run.command_record(command, cwd=source),
            "pinned C cancellation pthread-destructor fixture build",
        )
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "pinned C cancellation pthread-destructor ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source)
        if int(execution["status"]) != 0:
            raise EvidenceError(
                "pinned C cancellation pthread-destructor fixture execution failed "
                f"({execution['status']}):\n{execution['stdout']}{execution['stderr']}"
            )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    try:
        trace = run.parse_address_independent_trace(
            str(execution["stdout"]),
            begin=TRACE_BEGIN,
            end=TRACE_END,
            description="pinned C cancellation pthread-destructor trace",
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    try:
        _base.validate_trace(trace, description="pinned C cancellation pthread-destructor trace")
    except EvidenceError as error:
        raise EvidenceError(f"{error}: {json.dumps(trace, sort_keys=True)}") from error
    return {
        "build_command": _base.normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/cancellation-pthread-destructor-c"],
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
        "kind": "mimalloc-x86_64-cancellation-pthread-destructor-c-oracle-evidence",
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
        raise EvidenceError("cancellation pthread-destructor report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("cancellation pthread-destructor report must be a passing format-1 result")
    if (report["kind"] != "mimalloc-x86_64-cancellation-pthread-destructor-c-oracle-evidence"
            or report["profile"] != EXPECTED_PROFILE):
        raise EvidenceError("cancellation pthread-destructor report identity drifted")
    if (not exactly_matches(report["target"], EXPECTED_TARGET)
            or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM)
            or not exactly_matches(report["scope"], EXPECTED_SCOPE)):
        raise EvidenceError("cancellation pthread-destructor report boundary drifted")
    if not any(exactly_matches(report["provenance"], value) for value in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    )):
        raise EvidenceError("cancellation pthread-destructor report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("cancellation pthread-destructor report trace contract drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("cancellation pthread-destructor report source drifted")
    if (source["archive_sha256"] != run.load_pin()["sha256"]
            or not exactly_matches(source["anchors"], schema["source_anchors"])
            or not exactly_matches(source["release_flags"], schema["release_flags"])
            or not exactly_matches(source["release_source_set"], schema["release_source_set"])):
        raise EvidenceError("cancellation pthread-destructor report source identity drifted")
    c_probe = report["c_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("cancellation pthread-destructor C probe record drifted")
    if (not exactly_matches(c_probe["elf"], EXPECTED_C_ELF)
            or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/cancellation-pthread-destructor-c"]
            or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8"))):
        raise EvidenceError("cancellation pthread-destructor C probe identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    _base.validate_trace(c_probe["trace"], description="recorded cancellation pthread-destructor trace")


for _name in (
    "SCHEMA_PATH",
    "REPORT_DEFAULT",
    "TRACE_BEGIN",
    "TRACE_END",
    "NORMALIZED_EVIDENCE_ROOT",
    "NORMALIZED_PINNED_SOURCE",
    "EXPECTED_TARGET",
    "EXPECTED_UPSTREAM",
    "EXPECTED_ARCHIVE_SHA256",
    "EXPECTED_PROFILE",
    "EXPECTED_SCOPE",
    "EXPECTED_COMPILE_DEFINITIONS",
    "EXPECTED_C_ELF",
    "EXPECTED_SOURCE_ANCHORS",
    "EXPECTED_TRACE_VALUES",
    "C_TRACE_PROBE",
):
    setattr(_base, _name, globals()[_name])

_base.validate_probe_source = validate_probe_source
_base.load_schema = load_schema
_base.c_trace_command = c_trace_command
_base.validate_c_command = validate_c_command
_base.validate_normalized_c_command = validate_normalized_c_command
_base.build_c_trace = build_c_trace
_base.report_from_results = report_from_results
_base.validate_report = validate_report

parse_trace = _base.parse_trace
validate_trace = _base.validate_trace
normalize_command = _base.normalize_command
validate_source_anchors = _base.validate_source_anchors
require_native_x86_64 = _base.require_native_x86_64
run_evidence = _base.run_evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 cancellation pthread-destructor evidence: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 cancellation pthread-destructor evidence: PASS "
        f"({len(report['trace']['expected_values'])} logical values; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
