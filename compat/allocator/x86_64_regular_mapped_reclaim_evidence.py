#!/usr/bin/env python3
"""Differentially prove ordinary static-main mapped-regular reclaim on x86-64.

The pinned C fixture drives ordinary ``mi_heap_malloc`` from an exited source
pthread into either another pthread Theap or the source main-heap receiver. It
covers direct Small, Medium, and normal regular Large pages, then proves a
Medium-to-Large bin mismatch leaves the source mapped and takes the fresh
fallback. It also keeps twelve mixed one- and eight-byte
``mi_heap_malloc_aligned(..., 16)`` clients live for each receiver, because
the aligned source predicate cannot treat the one-word ordinary bin as a
sixteen-byte-strided path. A separate source cleanup record retains the prior
per-page Medium release observation. The Rust trace runs the actual persistent
later and reactivated initial receiver paths in isolated process images.

This is private native allocator-engine evidence. It neither qualifies public
x86 runtime support nor broad dynamic-arena scanning, metadata snapshots,
arena destruction, huge-page success, or AArch64 behavior.
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-regular-mapped-reclaim-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/regular-mapped-reclaim.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/tests/native_ordinary_mapped_regular_reclaim.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_TARGET = "native_ordinary_mapped_regular_reclaim"
RUST_TEST_FILTER = "regular_mapped_reclaim_trace_matches_pinned_c_protocol"
TRACE_BEGIN = "CRABC_MI_REGULAR_MAPPED_RECLAIM_TRACE_BEGIN"
TRACE_END = "CRABC_MI_REGULAR_MAPPED_RECLAIM_TRACE_END"
CLEANUP_BEGIN = "CRABC_MI_REGULAR_RECLAIM_CLEANUP_BEGIN"
CLEANUP_END = "CRABC_MI_REGULAR_RECLAIM_CLEANUP_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The fixed native regular reclaim differential did not close."""


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
EXPECTED_PROFILE = "linux-x86_64-private-static-main-mapped-regular-reclaim"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "arena_backed_regular_only": True,
    "dynamic_all_suitable_arena_scanning_claimed": False,
    "emulation_accepted": False,
    "huge_page_success_claimed": False,
    "metadata_snapshot_or_arena_destruction_claimed": False,
    "native_linux_x86_64_required": True,
    "ordinary_small_malloc_16_alignment_claimed": False,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "regular_kinds": ["direct-small", "medium", "large"],
    "rust_receivers": ["later-persistent", "initial-persistent"],
    "static_main_selected_arena_only": True,
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
# Hashes bind the direct-small empty-page fallback, the regular selector and
# fresh fallback, the source reclaim/queue transition, and actual thread
# teardown to exact ranges from the pinned v3.5.0 archive.
EXPECTED_SOURCE_ANCHORS: tuple[tuple[str, int, int, str], ...] = (
    ("src/alloc.c", 29, 48, "604349215a5d7c553dc4756d7c2d3310c58e57417ae3017e36e0c2c40c8b2d2a"),
    ("src/alloc-aligned.c", 18, 28, "d621621aad93434ebba31509340146099ab7a5040b251f1c40bf6fcb71545b79"),
    ("src/alloc-aligned.c", 160, 187, "7079fee31229ec56a2fada1b5a7ba252d0870b263c75bf4658a62713e25937e4"),
    ("src/arena.c", 725, 778, "cea2c222a6d9754bf442637478f635fea6691cdede21ec003e1e3a59f481550f"),
    ("src/arena.c", 1129, 1152, "12763921cec4e0a8546a559f5c7e780161593559bdd5755174c855827c00ab63"),
    ("src/page.c", 276, 350, "5fa49c4f2655f5afe7646ac99acc59f0b094eb2509dca6cc67b4c92cb8c70c3b"),
    ("src/init.c", 448, 480, "81710fd90ab37ebaf517e33c88e82c8a847eafad277c376eb18c196d9d86838d"),
)
EXPECTED_TRACE_VALUES = {
    "trace.regular_mapped_reclaim.later.direct_small.same_page": 1,
    "trace.regular_mapped_reclaim.later.medium.same_page": 1,
    "trace.regular_mapped_reclaim.later.large.same_page": 1,
    "trace.regular_mapped_reclaim.initial.direct_small.same_page": 1,
    "trace.regular_mapped_reclaim.initial.medium.same_page": 1,
    "trace.regular_mapped_reclaim.initial.large.same_page": 1,
    "trace.regular_mapped_reclaim.fallback.medium_to_large.fresh": 1,
    "trace.regular_mapped_reclaim.later.medium.cleanup_release": 1,
    "trace.regular_mapped_reclaim.initial.natural_alignment.request1.all_live": 1,
    "trace.regular_mapped_reclaim.initial.natural_alignment.request8.all_live": 1,
    "trace.regular_mapped_reclaim.later.natural_alignment.request1.all_live": 1,
    "trace.regular_mapped_reclaim.later.natural_alignment.request8.all_live": 1,
}
EXPECTED_CLEANUP_TRACE = {
    "trace.regular_reclaim.cleanup.source_mapped": 1,
    "trace.regular_reclaim.cleanup.source_nonfull": 1,
    "trace.regular_reclaim.cleanup.after_first_abandoned": 1,
    "trace.regular_reclaim.cleanup.after_first_mapped": 1,
    "trace.regular_reclaim.cleanup.after_first_one_live": 1,
    "trace.regular_reclaim.cleanup.released_before_collect": 1,
    "trace.regular_reclaim.cleanup.retired_before_collect": 0,
    "trace.regular_reclaim.cleanup.released_after_worker_collect": 1,
    "trace.regular_reclaim.cleanup.released_after_main_collect": 1,
    "trace.regular_reclaim.cleanup.valid": 1,
}


# This source-local fixture invokes no synthetic claim result. A exits through
# the actual source thread teardown; the receiver then enters the normal public
# allocation primitive on the same selected heap. The direct-small case is
# specifically a real empty-direct-page generic fallback. It prints only
# fixed boolean state, never process addresses or raw allocation values.
C_TRACE_PROBE = r"""
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private regular reclaim fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private regular reclaim fixture requires the fixed release profile
#endif
#if MI_MAX_ALIGN_SIZE != 16
#error this private regular reclaim fixture requires the pinned native x86 C alignment profile
#endif

typedef struct actor_state_s {
  mi_heap_t* heap;
  size_t request;
  void* block;
  mi_page_t* page;
  mi_page_t* expected_page;
  int allocated_regular;
  int same_page;
  int claimed_before_done;
} actor_state_t;

typedef struct regular_result_s {
  int valid;
} regular_result_t;

typedef struct natural_alignment_state_s {
  mi_heap_t* heap;
  int request1_all_live;
  int request8_all_live;
  int valid;
} natural_alignment_state_t;

typedef struct cleanup_state_s {
  void* first;
  void* second;
  mi_page_t* page;
  mi_arena_t* arena;
  size_t slice_index;
  size_t slice_count;
  int after_first_abandoned;
  int after_first_mapped;
  int after_first_one_live;
  int released_before_collect;
  int retired_before_collect;
  int released_after_worker_collect;
} cleanup_state_t;

static bool actor_page_is_regular(const actor_state_t* state) {
  return state->page != NULL
      && state->page->memid.memkind == MI_MEM_ARENA
      && !mi_page_is_full(state->page);
}

static void* source_worker(void* raw) {
  actor_state_t* const state = (actor_state_t*)raw;
  state->block = mi_heap_malloc(state->heap, state->request);
  if (state->block != NULL) {
    state->page = _mi_ptr_page(state->block);
    state->allocated_regular = actor_page_is_regular(state);
  }
  mi_thread_done();
  return NULL;
}

static void* later_receiver_worker(void* raw) {
  actor_state_t* const state = (actor_state_t*)raw;
  state->block = mi_heap_malloc(state->heap, state->request);
  if (state->block != NULL) {
    state->page = _mi_ptr_page(state->block);
    state->allocated_regular = actor_page_is_regular(state);
    state->same_page = (state->page == state->expected_page);
    state->claimed_before_done = (state->same_page
        && !mi_page_is_abandoned(state->page)
        && !mi_page_is_abandoned_mapped(state->page)
        && state->page->used == 2);
  }
  mi_thread_done();
  return NULL;
}

static bool run_same_regular(size_t request, bool main_receiver, regular_result_t* result) {
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  actor_state_t source = {0};
  actor_state_t receiver = {0};
  pthread_t source_thread;
  pthread_t receiver_thread;
  bool source_started = false;
  bool receiver_started = false;
  bool valid = false;

  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto cleanup;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto cleanup;
  source.heap = heap;
  source.request = request;
  if (pthread_create(&source_thread, NULL, source_worker, &source) != 0) goto cleanup;
  source_started = true;
  if (pthread_join(source_thread, NULL) != 0) goto cleanup;
  source_started = false;
  if (!source.allocated_regular || !mi_page_is_abandoned(source.page)
      || !mi_page_is_abandoned_mapped(source.page)) goto cleanup;
  const size_t bin = _mi_bin(source.page->block_size);
  if (bin >= MI_ARENA_BIN_COUNT
      || mi_atomic_load_relaxed(&heap->abandoned_count[bin]) != 1) goto cleanup;

  if (main_receiver) {
    receiver.heap = heap;
    receiver.request = request;
    receiver.expected_page = source.page;
    receiver.block = mi_heap_malloc(heap, request);
    if (receiver.block != NULL) {
      receiver.page = _mi_ptr_page(receiver.block);
      receiver.allocated_regular = actor_page_is_regular(&receiver);
      receiver.same_page = (receiver.page == source.page);
      receiver.claimed_before_done = (receiver.same_page
          && !mi_page_is_abandoned(receiver.page)
          && !mi_page_is_abandoned_mapped(receiver.page)
          && receiver.page->used == 2);
    }
  }
  else {
    receiver.heap = heap;
    receiver.request = request;
    receiver.expected_page = source.page;
    if (pthread_create(&receiver_thread, NULL, later_receiver_worker, &receiver) != 0) goto cleanup;
    receiver_started = true;
    if (pthread_join(receiver_thread, NULL) != 0) goto cleanup;
    receiver_started = false;
  }

  valid = source.allocated_regular && receiver.allocated_regular
      && receiver.same_page && receiver.claimed_before_done;

cleanup:
  if (receiver_started) (void)pthread_join(receiver_thread, NULL);
  if (source_started) (void)pthread_join(source_thread, NULL);
  if (receiver.block != NULL) mi_free(receiver.block);
  if (source.block != NULL) mi_free(source.block);
  if (main_receiver) mi_thread_done();
  else mi_collect(true);
  if (heap != NULL) mi_heap_destroy(heap);
  result->valid = valid;
  return valid;
}

static bool run_medium_to_large_fallback(void) {
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  actor_state_t source = {0};
  actor_state_t receiver = {0};
  pthread_t source_thread;
  pthread_t receiver_thread;
  bool source_started = false;
  bool receiver_started = false;
  bool valid = false;

  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto cleanup;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto cleanup;
  source.heap = heap;
  source.request = MI_SMALL_SIZE_MAX + 1024;
  if (pthread_create(&source_thread, NULL, source_worker, &source) != 0) goto cleanup;
  source_started = true;
  if (pthread_join(source_thread, NULL) != 0) goto cleanup;
  source_started = false;
  if (!source.allocated_regular || !mi_page_is_abandoned(source.page)
      || !mi_page_is_abandoned_mapped(source.page)) goto cleanup;
  const size_t source_bin = _mi_bin(source.page->block_size);
  if (source_bin >= MI_ARENA_BIN_COUNT
      || mi_atomic_load_relaxed(&heap->abandoned_count[source_bin]) != 1) goto cleanup;

  receiver.heap = heap;
  receiver.request = 86699;
  receiver.expected_page = source.page;
  if (pthread_create(&receiver_thread, NULL, later_receiver_worker, &receiver) != 0) goto cleanup;
  receiver_started = true;
  if (pthread_join(receiver_thread, NULL) != 0) goto cleanup;
  receiver_started = false;

  valid = receiver.allocated_regular && receiver.page != source.page
      && mi_page_is_abandoned(source.page)
      && mi_page_is_abandoned_mapped(source.page)
      && mi_atomic_load_relaxed(&heap->abandoned_count[source_bin]) == 1;

cleanup:
  if (receiver_started) (void)pthread_join(receiver_thread, NULL);
  if (source_started) (void)pthread_join(source_thread, NULL);
  if (receiver.block != NULL) mi_free(receiver.block);
  if (source.block != NULL) mi_free(source.block);
  mi_collect(true);
  if (heap != NULL) mi_heap_destroy(heap);
  return valid;
}

static bool natural_alignment_clients(natural_alignment_state_t* state) {
  static const size_t requests[12] = { 1, 8, 1, 8, 1, 8, 1, 8, 1, 8, 1, 8 };
  void* clients[12] = { 0 };
  bool valid = true;
  state->request1_all_live = 1;
  state->request8_all_live = 1;

  for (size_t index = 0; index < 12; index++) {
    const size_t request = requests[index];
    clients[index] = mi_heap_malloc_aligned(state->heap, request, MI_MAX_ALIGN_SIZE);
    const bool aligned = (clients[index] != NULL
                          && (((uintptr_t)clients[index] & (MI_MAX_ALIGN_SIZE - 1)) == 0));
    if (request == 1) state->request1_all_live &= aligned;
    else state->request8_all_live &= aligned;
    if (!aligned) {
      valid = false;
      break;
    }
    for (size_t earlier = 0; earlier < index; earlier++) {
      if (clients[index] == clients[earlier]) {
        valid = false;
        break;
      }
    }
    if (!valid) break;
    ((uint8_t*)clients[index])[0] = (uint8_t)(index + 1);
    if (((uint8_t*)clients[index])[0] != (uint8_t)(index + 1)) {
      valid = false;
      break;
    }
  }
  for (size_t index = 0; index < 12; index++) mi_free(clients[index]);
  state->valid = (valid && state->request1_all_live && state->request8_all_live);
  return state->valid;
}

static void* natural_alignment_worker(void* raw) {
  natural_alignment_state_t* const state = (natural_alignment_state_t*)raw;
  (void)natural_alignment_clients(state);
  mi_thread_done();
  return NULL;
}

static bool run_natural_alignment_small(bool main_receiver,
                                        natural_alignment_state_t* state) {
  mi_arena_id_t arena_id = _mi_arena_id_none();
  pthread_t worker;
  bool worker_started = false;
  bool valid = false;

  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto cleanup;
  state->heap = mi_heap_new_in_arena(arena_id);
  if (state->heap == NULL) goto cleanup;
  if (main_receiver) {
    valid = natural_alignment_clients(state);
  }
  else {
    if (pthread_create(&worker, NULL, natural_alignment_worker, state) != 0) goto cleanup;
    worker_started = true;
    if (pthread_join(worker, NULL) != 0) goto cleanup;
    worker_started = false;
    valid = state->valid;
  }

cleanup:
  if (worker_started) (void)pthread_join(worker, NULL);
  mi_collect(true);
  if (state->heap != NULL) mi_heap_destroy(state->heap);
  return valid;
}

static bool cleanup_slices_released(const cleanup_state_t* state) {
  return mi_bbitmap_is_setN(state->arena->slices_free, state->slice_index, state->slice_count);
}

static void* cleanup_worker(void* raw) {
  cleanup_state_t* const state = (cleanup_state_t*)raw;
  mi_free(state->second);
  state->second = NULL;
  state->after_first_abandoned = mi_page_is_abandoned(state->page);
  state->after_first_mapped = mi_page_is_abandoned_mapped(state->page);
  state->after_first_one_live = (state->page->used == 1 && !mi_page_all_free(state->page));

  mi_free(state->first);
  state->first = NULL;
  state->released_before_collect = cleanup_slices_released(state);
  state->retired_before_collect = (!state->released_before_collect
                                  && state->page->retire_expire != 0);
  mi_collect(true);
  state->released_after_worker_collect = cleanup_slices_released(state);
  return NULL;
}

static bool run_medium_cleanup(cleanup_state_t* state, int* source_mapped,
                               int* source_nonfull, int* final_after_main_collect) {
  const size_t request = MI_SMALL_SIZE_MAX + 1024;
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_queue_t* queue = NULL;
  pthread_t worker;
  bool worker_started = false;
  bool valid = false;

  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto cleanup;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto cleanup;
  state->first = mi_heap_malloc(heap, request);
  state->second = mi_heap_malloc(heap, request);
  if (state->first == NULL || state->second == NULL) goto cleanup;
  state->page = _mi_ptr_page(state->first);
  theap = _mi_heap_theap(heap);
  if (state->page == NULL || theap == NULL || _mi_ptr_page(state->second) != state->page
      || state->page->memid.memkind != MI_MEM_ARENA || mi_page_is_full(state->page)) goto cleanup;
  state->arena = state->page->memid.mem.arena.arena;
  state->slice_index = state->page->memid.mem.arena.slice_index;
  state->slice_count = state->page->memid.mem.arena.slice_count;
  queue = mi_page_queue(theap, state->page->block_size);
  if (state->arena == NULL || state->slice_count == 0 || queue == NULL || queue->count != 1) goto cleanup;

  _mi_page_abandon(state->page, queue);
  *source_mapped = mi_page_is_abandoned(state->page) && mi_page_is_abandoned_mapped(state->page);
  *source_nonfull = (!mi_page_all_free(state->page) && state->page->used == 2);
  if (!*source_mapped || !*source_nonfull || cleanup_slices_released(state)) goto cleanup;
  if (pthread_create(&worker, NULL, cleanup_worker, state) != 0) goto cleanup;
  worker_started = true;
  if (pthread_join(worker, NULL) != 0) goto cleanup;
  worker_started = false;
  mi_collect(true);
  *final_after_main_collect = cleanup_slices_released(state);
  valid = (*source_mapped && *source_nonfull && state->after_first_one_live
           && *final_after_main_collect);

cleanup:
  if (worker_started) (void)pthread_join(worker, NULL);
  if (state->second != NULL) mi_free(state->second);
  if (state->first != NULL) mi_free(state->first);
  if (heap != NULL) mi_heap_destroy(heap);
  return valid;
}

int main(void) {
  regular_result_t later_small = {0};
  regular_result_t later_medium = {0};
  regular_result_t later_large = {0};
  regular_result_t initial_small = {0};
  regular_result_t initial_medium = {0};
  regular_result_t initial_large = {0};
  natural_alignment_state_t initial_alignment = {0};
  natural_alignment_state_t later_alignment = {0};
  cleanup_state_t cleanup = {0};
  int cleanup_source_mapped = 0;
  int cleanup_source_nonfull = 0;
  int cleanup_after_main_collect = 0;

  const int fallback = run_medium_to_large_fallback();
  const int cleanup_valid = run_medium_cleanup(&cleanup, &cleanup_source_mapped,
                                                &cleanup_source_nonfull,
                                                &cleanup_after_main_collect);
  run_same_regular(1024, false, &later_small);
  run_same_regular(65536, false, &later_medium);
  run_same_regular(86699, false, &later_large);
  run_same_regular(1024, true, &initial_small);
  run_same_regular(65536, true, &initial_medium);
  run_same_regular(86699, true, &initial_large);
  const int initial_alignment_valid = run_natural_alignment_small(true, &initial_alignment);
  const int later_alignment_valid = run_natural_alignment_small(false, &later_alignment);

  printf("CRABC_MI_REGULAR_MAPPED_RECLAIM_TRACE_BEGIN\n");
  printf("trace.regular_mapped_reclaim.later.direct_small.same_page=%d\n", later_small.valid);
  printf("trace.regular_mapped_reclaim.later.medium.same_page=%d\n", later_medium.valid);
  printf("trace.regular_mapped_reclaim.later.large.same_page=%d\n", later_large.valid);
  printf("trace.regular_mapped_reclaim.initial.direct_small.same_page=%d\n", initial_small.valid);
  printf("trace.regular_mapped_reclaim.initial.medium.same_page=%d\n", initial_medium.valid);
  printf("trace.regular_mapped_reclaim.initial.large.same_page=%d\n", initial_large.valid);
  printf("trace.regular_mapped_reclaim.fallback.medium_to_large.fresh=%d\n", fallback);
  printf("trace.regular_mapped_reclaim.later.medium.cleanup_release=%d\n", cleanup_valid);
  printf("trace.regular_mapped_reclaim.initial.natural_alignment.request1.all_live=%d\n", initial_alignment.request1_all_live);
  printf("trace.regular_mapped_reclaim.initial.natural_alignment.request8.all_live=%d\n", initial_alignment.request8_all_live);
  printf("trace.regular_mapped_reclaim.later.natural_alignment.request1.all_live=%d\n", later_alignment.request1_all_live);
  printf("trace.regular_mapped_reclaim.later.natural_alignment.request8.all_live=%d\n", later_alignment.request8_all_live);
  printf("CRABC_MI_REGULAR_MAPPED_RECLAIM_TRACE_END\n");

  printf("CRABC_MI_REGULAR_RECLAIM_CLEANUP_BEGIN\n");
  printf("trace.regular_reclaim.cleanup.source_mapped=%d\n", cleanup_source_mapped);
  printf("trace.regular_reclaim.cleanup.source_nonfull=%d\n", cleanup_source_nonfull);
  printf("trace.regular_reclaim.cleanup.after_first_abandoned=%d\n", cleanup.after_first_abandoned);
  printf("trace.regular_reclaim.cleanup.after_first_mapped=%d\n", cleanup.after_first_mapped);
  printf("trace.regular_reclaim.cleanup.after_first_one_live=%d\n", cleanup.after_first_one_live);
  printf("trace.regular_reclaim.cleanup.released_before_collect=%d\n", cleanup.released_before_collect);
  printf("trace.regular_reclaim.cleanup.retired_before_collect=%d\n", cleanup.retired_before_collect);
  printf("trace.regular_reclaim.cleanup.released_after_worker_collect=%d\n", cleanup.released_after_worker_collect);
  printf("trace.regular_reclaim.cleanup.released_after_main_collect=%d\n", cleanup_after_main_collect);
  printf("trace.regular_reclaim.cleanup.valid=%d\n", cleanup_valid);
  printf("CRABC_MI_REGULAR_RECLAIM_CLEANUP_END\n");

  return (later_small.valid && later_medium.valid && later_large.valid
          && initial_small.valid && initial_medium.valid && initial_large.valid
          && initial_alignment_valid && later_alignment_valid
          && fallback && cleanup_valid) ? 0 : 2;
}
"""


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
            exactly_matches(actual, wanted) for actual, wanted in zip(observed, expected)
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
        raise EvidenceError("regular mapped-reclaim source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 regular mapped-reclaim schema") from error
    if not isinstance(schema, dict):
        raise EvidenceError("x86-64 regular mapped-reclaim schema is not an object")
    expected_fields = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "rust_test", "schema", "scope", "source_anchors", "target",
        "trace", "upstream",
    }
    if set(schema) != expected_fields:
        raise EvidenceError("regular mapped-reclaim schema fields drifted")
    if type(schema.get("format")) is not int or schema["format"] != 1 or schema.get("schema") != "crabc-mimalloc-x86_64-regular-mapped-reclaim-evidence":
        raise EvidenceError("unsupported regular mapped-reclaim schema")
    if not exactly_matches(schema.get("target"), EXPECTED_TARGET):
        raise EvidenceError("regular mapped-reclaim schema target is not native Linux/x86-64")
    if not exactly_matches(schema.get("upstream"), EXPECTED_UPSTREAM):
        raise EvidenceError("regular mapped-reclaim schema upstream is not pinned mimalloc 3.5.0")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate the pinned regular mapped-reclaim upstream") from error
    if not exactly_matches(
        {"archive_root": pin["archive_root"], "revision": pin["revision"], "version": pin["version"]},
        EXPECTED_UPSTREAM,
    ) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("regular mapped-reclaim upstream pin drifted")
    if schema.get("profile") != EXPECTED_PROFILE or not exactly_matches(schema.get("scope"), EXPECTED_SCOPE):
        raise EvidenceError("regular mapped-reclaim private boundary drifted")
    if not exactly_matches(schema.get("release_source_set"), list(run.ORACLE_SOURCES)):
        raise EvidenceError("regular mapped-reclaim C source set differs from the pinned oracle")
    if not exactly_matches(schema.get("release_flags"), list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("regular mapped-reclaim C release flags drifted")
    if not exactly_matches(schema.get("compile_definitions"), list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("regular mapped-reclaim C compile definitions drifted")
    if not exactly_matches(schema.get("rust_test"), {
        "path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "target": RUST_TEST_TARGET,
        "test_filter": RUST_TEST_FILTER,
    }):
        raise EvidenceError("regular mapped-reclaim Rust test selection drifted")
    if not exactly_matches(schema.get("trace"), {
        "begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES,
    }):
        raise EvidenceError("regular mapped-reclaim trace contract drifted")
    if schema.get("c_probe_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("regular mapped-reclaim C probe source hash drifted")

    anchors = schema.get("source_anchors")
    observed: list[tuple[str, int, int, str]] = []
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("regular mapped-reclaim source anchors drifted")
    for anchor, expected in zip(anchors, EXPECTED_SOURCE_ANCHORS):
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("regular mapped-reclaim source anchor has an invalid shape")
        member, start_line, end_line, digest = (
            anchor.get("member"), anchor.get("start_line"), anchor.get("end_line"), anchor.get("sha256")
        )
        if (
            not isinstance(member, str) or type(start_line) is not int or type(end_line) is not int
            or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise EvidenceError("regular mapped-reclaim source anchor has invalid values")
        if (member, start_line, end_line) != expected[:3]:
            raise EvidenceError("regular mapped-reclaim source anchor contract drifted")
        observed.append((member, start_line, end_line, digest))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("regular mapped-reclaim source anchor hash drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    for anchor in schema["source_anchors"]:
        assert isinstance(anchor, dict)
        path = source / str(anchor["member"])
        if not path.is_file():
            raise EvidenceError(f"pinned source lacks regular mapped-reclaim anchor: {anchor['member']}")
        observed = sha256_bytes(source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"])))
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned regular mapped-reclaim source anchor drifted: {anchor['member']}")
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str, *, begin: str, end: str, description: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(output, begin=begin, end=end, description=description)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, int], expected: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(expected).difference(trace))
    unexpected = sorted(set(trace).difference(expected))
    invalid = sorted(key for key, value in trace.items() if type(value) is not int)
    mismatches = [
        f"{key} (expected {expected[key]}, observed {trace[key]})"
        for key in sorted(set(trace).intersection(expected))
        if type(trace[key]) is int and trace[key] != expected[key]
    ]
    if missing or unexpected or invalid or mismatches:
        pieces: list[str] = []
        if missing:
            pieces.append("missing: " + ", ".join(missing))
        if unexpected:
            pieces.append("unexpected: " + ", ".join(unexpected))
        if invalid:
            pieces.append("non-integer values: " + ", ".join(invalid))
        if mismatches:
            pieces.append("value mismatches: " + ", ".join(mismatches))
        raise EvidenceError(f"{description} differs from its fixed trace: " + "; ".join(pieces))


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, EXPECTED_TRACE_VALUES, description="pinned C regular mapped-reclaim trace")
    validate_trace(rust_trace, EXPECTED_TRACE_VALUES, description="Rust regular mapped-reclaim trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES) if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise EvidenceError("Rust regular mapped-reclaim trace differs from pinned C: " + ", ".join(mismatches))
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


def c_trace_command(compiler: str, source: Path, probe: Path, binary: Path, schema: Mapping[str, Any]) -> list[str]:
    return [
        compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", str(source / "include"), "-I", str(source / "src"), *schema["release_flags"],
        str(probe), *(str(source / member) for member in schema["release_source_set"]), "-pthread", "-o", str(binary),
    ]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(schema["compile_definitions"]) or flags != list(schema["release_flags"]):
        raise EvidenceError("regular mapped-reclaim C command profile drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("regular mapped-reclaim C command lacks fixed pthread/TLS mode")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("regular mapped-reclaim report C command is malformed")
    if Path(command[0]).name != "musl-gcc":
        raise EvidenceError("regular mapped-reclaim report C compiler drifted")
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/regular-mapped-reclaim.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/regular-mapped-reclaim-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("regular mapped-reclaim report C command drifted")


def rust_trace_command(cargo: str, target_dir: Path) -> list[str]:
    return [
        cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir),
        "-p", "crabc-mimalloc", "--features", "native-runtime-test-audit", "--test", RUST_TEST_TARGET,
        "--", "--exact", RUST_TEST_FILTER, "--nocapture", "--test-threads=1",
    ]


def validate_normalized_rust_command(command: object) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("regular mapped-reclaim report Rust command is malformed")
    if Path(command[0]).name != "cargo":
        raise EvidenceError("regular mapped-reclaim report Rust compiler drifted")
    expected = [
        "test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        "-p", "crabc-mimalloc", "--features", "native-runtime-test-audit", "--test", RUST_TEST_TARGET,
        "--", "--exact", RUST_TEST_FILTER, "--nocapture", "--test-threads=1",
    ]
    if command[1:] != expected:
        raise EvidenceError("regular mapped-reclaim report Rust command drifted")


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    probe = temporary / "regular-mapped-reclaim.c"
    binary = temporary / "regular-mapped-reclaim-c"
    probe.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe, binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C regular mapped-reclaim fixture build")
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "pinned C regular mapped-reclaim ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source)
        run.require_success(execution, "pinned C regular mapped-reclaim fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), begin=TRACE_BEGIN, end=TRACE_END, description="pinned C regular mapped-reclaim trace")
    cleanup = parse_trace(str(execution["stdout"]), begin=CLEANUP_BEGIN, end=CLEANUP_END, description="pinned C regular mapped-reclaim cleanup trace")
    validate_trace(trace, EXPECTED_TRACE_VALUES, description="pinned C regular mapped-reclaim trace")
    validate_trace(cleanup, EXPECTED_CLEANUP_TRACE, description="pinned C regular mapped-reclaim cleanup trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "cleanup_trace": cleanup,
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/regular-mapped-reclaim-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, env=environment)
        run.require_success(execution, "Rust regular mapped-reclaim trace fixture")
        combined = str(execution["stdout"]) + "\n" + str(execution["stderr"])
        passed = run.parse_rust_test_count(combined)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust regular mapped-reclaim fixture passed {passed} tests, expected one")
    trace = parse_trace(combined, begin=TRACE_BEGIN, end=TRACE_END, description="Rust regular mapped-reclaim trace")
    validate_trace(trace, EXPECTED_TRACE_VALUES, description="Rust regular mapped-reclaim trace")
    return {
        "cargo_command": normalize_command(command, temporary, None),
        "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
        "passed_test_count": passed,
        "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)},
        "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"},
        "trace": trace,
    }


def report_from_results(*, schema: Mapping[str, Any], provenance: Mapping[str, str], archive_sha256: str,
                        anchors: Sequence[Mapping[str, Any]], c_probe: Mapping[str, Any], rust_probe: Mapping[str, Any]) -> dict[str, Any]:
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("regular mapped-reclaim report inputs lack trace records")
    report: dict[str, Any] = {
        "c_probe": dict(c_probe), "comparison": compare_traces(c_trace, rust_trace), "format": 1,
        "kind": "mimalloc-x86_64-static-main-mapped-regular-reclaim-differential-evidence",
        "profile": schema["profile"], "provenance": dict(provenance), "rust_probe": dict(rust_probe),
        "scope": schema["scope"], "source": {
            "archive_sha256": archive_sha256, "anchors": [dict(anchor) for anchor in anchors],
            "release_flags": list(schema["release_flags"]), "release_source_set": list(schema["release_source_set"]),
        }, "status": "passed", "target": schema["target"], "trace": schema["trace"], "upstream": schema["upstream"],
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("regular mapped-reclaim report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("regular mapped-reclaim report must record a passing format-1 result")
    if report["kind"] != "mimalloc-x86_64-static-main-mapped-regular-reclaim-differential-evidence":
        raise EvidenceError("regular mapped-reclaim report kind drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["target"], EXPECTED_TARGET):
        raise EvidenceError("regular mapped-reclaim report target/profile drifted")
    if not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("regular mapped-reclaim report source or private boundary drifted")
    if not exactly_matches(report["trace"], {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES}):
        raise EvidenceError("regular mapped-reclaim report trace contract drifted")
    if not any(exactly_matches(report["provenance"], candidate) for candidate in (
        {"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"},
    )):
        raise EvidenceError("regular mapped-reclaim report lacks native x86-64 provenance")

    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("regular mapped-reclaim report source record is malformed")
    if source.get("archive_sha256") != run.load_pin()["sha256"] or not exactly_matches(source.get("anchors"), schema["source_anchors"]):
        raise EvidenceError("regular mapped-reclaim report archive or anchors drifted")
    if not exactly_matches(source.get("release_flags"), schema["release_flags"]) or not exactly_matches(source.get("release_source_set"), schema["release_source_set"]):
        raise EvidenceError("regular mapped-reclaim report release source binding drifted")

    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "cleanup_trace", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("regular mapped-reclaim report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("regular mapped-reclaim report Rust probe record drifted")
    if not exactly_matches(c_probe.get("elf"), EXPECTED_C_ELF):
        raise EvidenceError("regular mapped-reclaim report C ELF identity drifted")
    if c_probe.get("run_command") != [f"{NORMALIZED_EVIDENCE_ROOT}/regular-mapped-reclaim-c"]:
        raise EvidenceError("regular mapped-reclaim report C run command drifted")
    if c_probe.get("source_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("regular mapped-reclaim report C source hash drifted")
    validate_normalized_c_command(c_probe.get("build_command"), schema)
    validate_trace(c_probe.get("cleanup_trace", {}), EXPECTED_CLEANUP_TRACE, description="report C cleanup trace")
    if type(rust_probe.get("passed_test_count")) is not int or rust_probe["passed_test_count"] != 1:
        raise EvidenceError("regular mapped-reclaim report Rust selection did not pass exactly one test")
    if not exactly_matches(rust_probe.get("target_dir"), {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}):
        raise EvidenceError("regular mapped-reclaim report Rust target directory drifted")
    validate_normalized_rust_command(rust_probe.get("cargo_command"))
    if not exactly_matches(rust_probe.get("lockfile"), {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}):
        raise EvidenceError("regular mapped-reclaim report Rust lockfile identity drifted")
    if not exactly_matches(rust_probe.get("source"), {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}):
        raise EvidenceError("regular mapped-reclaim report Rust source identity drifted")
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("regular mapped-reclaim report lacks C/Rust trace records")
    if not exactly_matches(report["comparison"], compare_traces(c_trace, rust_trace)):
        raise EvidenceError("regular mapped-reclaim report comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    work = Path(os.environ.get("CRABC_WORK_DIR", ROOT / ".work/allocator-x86_64"))
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="regular-mapped-reclaim-", dir=work) as temporary_name:
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
            schema=schema, provenance=provenance, archive_sha256=sha256_file(archive), anchors=anchors,
            c_probe=c_probe, rust_probe=rust_probe,
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
        print(f"allocator x86-64 regular mapped-reclaim differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    comparison = report["comparison"]
    print("allocator x86-64 regular mapped-reclaim differential: PASS "
          f"({comparison['compared_value_count']} logical values; report: {relative(arguments.report)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
