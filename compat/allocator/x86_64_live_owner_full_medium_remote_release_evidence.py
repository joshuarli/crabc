#!/usr/bin/env python3
"""Differentially prove one live-owner full-medium remote-release transition.

This private native Linux/x86-64 evidence lane compiles a pinned mimalloc
v3.5.0 C fixture and compares its fixed address-independent state record with
one crate-private Rust test. The owner uses the source non-abandoning option
image, fills one arena-backed medium page and one successor, joins a real
pthread that remotely frees every allocation on the full page, and invokes
the normal false collector while the owner remains live. The full-page pass
must detach the remote list and release only the now-empty first page.

It is not public mi API evidence, public x86 support, a general remote-free
claim, thread teardown evidence, or an AArch64/emulation path.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = (
    ROOT
    / "compat/allocator/x86_64-live-owner-full-medium-remote-release-evidence-v3.5.0.json"
)
REPORT_DEFAULT = (
    ROOT
    / "compat/reports/allocator/x86_64/live-owner-full-medium-remote-release.json"
)
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/single_thread.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = (
    "single_thread::tests::"
    "x86_64_live_owner_full_medium_remote_release_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_LIVE_OWNER_FULL_MEDIUM_REMOTE_RELEASE_TRACE_BEGIN"
TRACE_END = "CRABC_MI_LIVE_OWNER_FULL_MEDIUM_REMOTE_RELEASE_TRACE_END"
PREFIX = "trace.live_owner_full_medium_release."
STEM = "live-owner-full-medium-remote-release"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded native differential could not establish its contract."""


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
EXPECTED_PROFILE = "linux-x86_64-private-live-owner-full-medium-remote-release"
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
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "c_oracle_all_first_page_remote_frees_required": True,
    "c_oracle_join_before_non_atomic_owner_observation_required": True,
    "c_oracle_live_owner_only": True,
    "c_oracle_no_thread_teardown": True,
    "c_oracle_non_abandoning_full_queue_only": True,
    "c_oracle_real_pthread_required": True,
    "c_oracle_successor_survives_first_page_release": True,
    "c_rust_common_trace_facts_only": True,
    "emulation_accepted": False,
    "general_allocation_routing_claimed": False,
    "general_lifecycle_claimed": False,
    "general_remote_free_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
    "rust_scoped_joined_remote_producers_only": True,
}
EXPECTED_SOURCE_ANCHORS = (
    ("src/free.c", 62, 97, "6dc25419bcef550d5626841cfc8d3121526ceaaa3698bf215c16bfa5de665bd6"),
    ("src/free.c", 155, 161, "51e79e158647a1a84d2f61321344600941750b4881632ead891b446a1ff1d8ea"),
    ("src/free.c", 223, 249, "e755fc43b602a94ee89305924c28fcdbea5901bbccc2927c6cf5aa77f9e43942"),
    ("src/page.c", 150, 201, "01d8f3f6a09d7d7b30e9e4f90f59c6738954fe5231d8fe9dac1ef5d0f96b967a"),
    ("src/page.c", 214, 243, "35148cff687e602b8de307ca1abad524655f48bf4410b2c64a7e44af8909203b"),
    ("src/page.c", 350, 413, "5b409a75471fbfec55eca726ffaeda2748f1ca0fd919d157dea9a04be01fbde6"),
    ("src/page.c", 460, 518, "9e0c373ed5a817f9e9998319442aaf7b5870509e4821a57686179b54ff6428af"),
    ("src/page-queue.c", 252, 274, "d72c1999eec27a2818fd657c62aa93ada275b1e63911569154a16619ca2f202b"),
    ("src/page-queue.c", 344, 418, "575fa161a6e18b56f57b1e09dcb713e90c32f650193a9c9dbff03645c476c653"),
    ("src/theap.c", 123, 165, "a84d17ad1b74eb93e79bb3b756f099fd60fe611eda6279c17db283c44cccc1bb"),
    ("src/theap.c", 228, 232, "16c0e73a20b9a94bf994c4e83836c976f5683e3c6e8b18935782a934405adba0"),
    ("src/page-map.c", 460, 515, "c752c966d40e6ebd16795295a1a87d3b8a762cdfc4ba752aa3a043df44dfb495"),
    ("src/arena.c", 1285, 1308, "d6649da0e0a6903b0e0bde04d12df78a99159d8c64b2acfb4c51a1827af9f3d1"),
)
EXPECTED_TRACE_VALUES = {
    PREFIX + "request": 10248,
    PREFIX + "block_size": 12288,
    PREFIX + "capacity": 42,
    PREFIX + "reserved": 42,
    PREFIX + "slice_count": 8,
    PREFIX + "arena_backed": 1,
    PREFIX + "ordinary_medium": 1,
    PREFIX + "non_abandoning_theap": 1,
    PREFIX + "first_full_member_before_remote": 1,
    PREFIX + "successor_regular_member_before_remote": 1,
    PREFIX + "full_queue_count_before_remote": 1,
    PREFIX + "regular_queue_count_before_remote": 1,
    PREFIX + "page_count_before_remote": 2,
    PREFIX + "first_page_map_all_slices_before_remote": 1,
    PREFIX + "first_arena_page_bitmap_set_before_remote": 1,
    PREFIX + "first_slices_unreleased_before_remote": 1,
    PREFIX + "initial_used": 42,
    PREFIX + "initial_remote_head_owned": 1,
    PREFIX + "initial_remote_empty": 1,
    PREFIX + "joined_remote_free_count": 42,
    PREFIX + "worker_joined_before_owner_collect": 1,
    PREFIX + "published_used_unchanged": 1,
    PREFIX + "published_remote_head_owned": 1,
    PREFIX + "published_remote_count": 42,
    PREFIX + "published_list_acyclic": 1,
    PREFIX + "owner_false_collect_called": 1,
    PREFIX + "full_queue_empty_after_collect": 1,
    PREFIX + "regular_queue_count_after_collect": 1,
    PREFIX + "page_count_after_collect": 1,
    PREFIX + "successor_regular_member_after_collect": 1,
    PREFIX + "successor_page_map_all_slices_after_collect": 1,
    PREFIX + "first_page_map_all_slices_clear_after_collect": 1,
    PREFIX + "first_arena_page_bitmap_clear_after_collect": 1,
    PREFIX + "first_slices_free_after_collect": 1,
    PREFIX + "valid": 1,
}


C_TRACE_PROBE = r"""
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

#define MAX_FIRST_PAGE_BLOCKS 64

typedef struct remote_fixture_s {
  void* blocks[MAX_FIRST_PAGE_BLOCKS];
  size_t first_count;
} remote_fixture_t;

static bool queue_contains_member(
    const mi_page_queue_t* queue,
    const mi_page_t* member
) {
  if (queue == NULL || member == NULL || queue->count == 0) return false;
  size_t visited = 0;
  for (const mi_page_t* page = queue->first; page != NULL; page = page->next) {
    if (page == member) return true;
    visited++;
    if (visited > queue->count) return false;
  }
  return false;
}

static bool queue_has_only_member(
    const mi_page_queue_t* queue,
    const mi_page_t* member
) {
  return queue != NULL && member != NULL && queue->count == 1
      && queue->first == member && queue->last == member
      && member->prev == NULL && member->next == NULL
      && queue_contains_member(queue, member);
}

static bool map_span_is_page(
    const mi_page_t* page,
    uintptr_t start,
    size_t slice_count
) {
  if (page == NULL || slice_count == 0) return false;
  for (size_t index = 0; index < slice_count; index++) {
    if (_mi_safe_ptr_page(
            (const void*)(start + index * MI_ARENA_SLICE_SIZE)
        ) != page) {
      return false;
    }
  }
  return true;
}

static bool map_span_is_clear(uintptr_t start, size_t slice_count) {
  if (slice_count == 0) return false;
  for (size_t index = 0; index < slice_count; index++) {
    if (_mi_safe_ptr_page(
            (const void*)(start + index * MI_ARENA_SLICE_SIZE)
        ) != NULL) {
      return false;
    }
  }
  return true;
}

static size_t bounded_remote_count(
    mi_page_t* page,
    mi_block_t* head,
    size_t maximum,
    bool* acyclic
) {
  size_t count = 0;
  while (head != NULL && count < maximum) {
    count++;
    head = mi_block_next(page, head);
  }
  *acyclic = (head == NULL);
  return count;
}

static void* remote_worker(void* argument) {
  remote_fixture_t* fixture = (remote_fixture_t*)argument;
  for (size_t index = 0; index < fixture->first_count; index++) {
    void* const block = fixture->blocks[index];
    if (block == NULL) return (void*)1;
    mi_free(block);
    fixture->blocks[index] = NULL;
  }
  return NULL;
}

int main(void) {
  const size_t request = MI_SMALL_MAX_OBJ_SIZE + sizeof(void*);
  remote_fixture_t fixture = { 0 };
  pthread_t worker;
  void* worker_result = (void*)1;
  bool worker_started = false;
  bool worker_joined = false;
  bool options_changed = false;
  bool valid = false;
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* first_page = NULL;
  mi_page_t* successor_page = NULL;
  mi_page_queue_t* regular = NULL;
  mi_page_queue_t* full = NULL;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  void* successor = NULL;
  uintptr_t first_span_start = 0;
  uintptr_t successor_span_start = 0;
  size_t first_slice_count = 0;
  size_t successor_slice_count = 0;
  size_t first_slice_index = 0;
  size_t block_size = 0;
  size_t capacity = 0;
  size_t reserved = 0;
  size_t full_queue_count_before_remote = 0;
  size_t regular_queue_count_before_remote = 0;
  size_t page_count_before_remote = 0;
  size_t initial_used = 0;
  size_t joined_remote_free_count = 0;
  size_t published_remote_count = 0;
  size_t regular_queue_count_after_collect = 0;
  size_t page_count_after_collect = 0;
  long old_full_retain = 0;
  int arena_backed = 0;
  int ordinary_medium = 0;
  int non_abandoning_theap = 0;
  int first_full_member_before_remote = 0;
  int successor_regular_member_before_remote = 0;
  int first_page_map_all_slices_before_remote = 0;
  int first_arena_page_bitmap_set_before_remote = 0;
  int first_slices_unreleased_before_remote = 0;
  int initial_remote_head_owned = 0;
  int initial_remote_empty = 0;
  int worker_joined_before_owner_collect = 0;
  int published_used_unchanged = 0;
  int published_remote_head_owned = 0;
  int published_list_acyclic = 0;
  int owner_false_collect_called = 0;
  int full_queue_empty_after_collect = 0;
  int successor_regular_member_after_collect = 0;
  int successor_page_map_all_slices_after_collect = 0;
  int first_page_map_all_slices_clear_after_collect = 0;
  int first_arena_page_bitmap_clear_after_collect = 0;
  int first_slices_free_after_collect = 0;

  mi_thread_init();
  old_full_retain = mi_option_get(mi_option_page_full_retain);
  mi_option_set(mi_option_page_full_retain, -1);
  options_changed = true;
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto output;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto output;
  theap = _mi_heap_theap(heap);
  if (theap == NULL) goto output;
  non_abandoning_theap = (!theap->allow_page_abandon
      && theap->page_full_retain == -1);
  if (!non_abandoning_theap) goto output;

  fixture.blocks[0] = mi_heap_malloc(heap, request);
  if (fixture.blocks[0] == NULL) goto output;
  fixture.first_count = 1;
  first_page = _mi_ptr_page(fixture.blocks[0]);
  if (first_page == NULL) goto output;
  block_size = first_page->block_size;
  reserved = first_page->reserved;
  if (reserved == 0 || reserved > MAX_FIRST_PAGE_BLOCKS) goto output;
  while (fixture.first_count < reserved) {
    void* const block = mi_heap_malloc(heap, request);
    if (block == NULL || _mi_ptr_page(block) != first_page) goto output;
    fixture.blocks[fixture.first_count++] = block;
  }
  capacity = first_page->capacity;
  successor = mi_heap_malloc(heap, request);
  if (successor == NULL) goto output;
  successor_page = _mi_ptr_page(successor);
  if (successor_page == NULL || successor_page == first_page) goto output;

  regular = mi_page_queue(theap, first_page->block_size);
  full = &theap->pages[MI_BIN_FULL];
  arena = mi_memid_arena(first_page->memid);
  if (arena == NULL || arena->arena_idx >= MI_MAX_ARENAS) goto output;
  arena_pages = mi_atomic_load_ptr_acquire(
      mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  if (arena_pages == NULL) goto output;

  first_slice_count = first_page->memid.mem.arena.slice_count;
  successor_slice_count = successor_page->memid.mem.arena.slice_count;
  first_slice_index = first_page->memid.mem.arena.slice_index;
  first_span_start = (uintptr_t)mi_page_slice_start(first_page);
  successor_span_start = (uintptr_t)mi_page_slice_start(successor_page);
  if (first_span_start == 0 || successor_span_start == 0
      || first_slice_count == 0 || successor_slice_count == 0) goto output;

  arena_backed = (first_page->memid.memkind == MI_MEM_ARENA
      && successor_page->memid.memkind == MI_MEM_ARENA);
  ordinary_medium = (block_size > MI_SMALL_MAX_OBJ_SIZE
      && block_size <= MI_MEDIUM_MAX_OBJ_SIZE);
  first_full_member_before_remote = (
      queue_has_only_member(full, first_page)
      && mi_page_is_in_full(first_page)
      && mi_page_is_full(first_page));
  successor_regular_member_before_remote = (
      queue_has_only_member(regular, successor_page)
      && !mi_page_is_in_full(successor_page));
  full_queue_count_before_remote = (full == NULL ? 0 : full->count);
  regular_queue_count_before_remote = (regular == NULL ? 0 : regular->count);
  page_count_before_remote = theap->page_count;
  first_page_map_all_slices_before_remote = map_span_is_page(
      first_page, first_span_start, first_slice_count);
  first_arena_page_bitmap_set_before_remote = mi_bitmap_is_setN(
      arena_pages->pages, first_slice_index, 1);
  first_slices_unreleased_before_remote = mi_bbitmap_is_clearN(
      arena->slices_free, first_slice_index, first_slice_count);
  const mi_thread_free_t initial_head = mi_atomic_load_acquire(
      &first_page->xthread_free);
  initial_used = first_page->used;
  initial_remote_head_owned = mi_tf_is_owned(initial_head);
  initial_remote_empty = (mi_tf_block(initial_head) == NULL);
  if (!arena_backed || !ordinary_medium || block_size != 12288
      || capacity != 42 || reserved != 42 || first_slice_count != 8
      || successor_slice_count != 8 || fixture.first_count != reserved
      || !first_full_member_before_remote
      || !successor_regular_member_before_remote
      || full_queue_count_before_remote != 1
      || regular_queue_count_before_remote != 1
      || page_count_before_remote != 2
      || !first_page_map_all_slices_before_remote
      || !first_arena_page_bitmap_set_before_remote
      || !first_slices_unreleased_before_remote
      || initial_used != reserved
      || !initial_remote_head_owned || !initial_remote_empty) goto output;

  if (pthread_create(&worker, NULL, remote_worker, &fixture) != 0) goto output;
  worker_started = true;
  if (pthread_join(worker, &worker_result) != 0) goto output;
  worker_joined = true;
  worker_joined_before_owner_collect = (worker_result == NULL);
  if (!worker_joined_before_owner_collect) goto output;

  const mi_thread_free_t published_head = mi_atomic_load_acquire(
      &first_page->xthread_free);
  bool published_list_acyclic_bool = false;
  published_remote_count = bounded_remote_count(
      first_page, mi_tf_block(published_head), reserved + 1,
      &published_list_acyclic_bool);
  joined_remote_free_count = reserved;
  published_used_unchanged = (first_page->used == initial_used);
  published_remote_head_owned = mi_tf_is_owned(published_head);
  published_list_acyclic = published_list_acyclic_bool;
  if (!published_used_unchanged || !published_remote_head_owned
      || published_remote_count != reserved || !published_list_acyclic) goto output;

  mi_heap_collect(heap, false);
  owner_false_collect_called = 1;
  full_queue_empty_after_collect = (
      full != NULL && full->count == 0 && full->first == NULL
      && full->last == NULL);
  regular_queue_count_after_collect = (regular == NULL ? 0 : regular->count);
  page_count_after_collect = theap->page_count;
  successor_regular_member_after_collect = queue_has_only_member(
      regular, successor_page);
  successor_page_map_all_slices_after_collect = map_span_is_page(
      successor_page, successor_span_start, successor_slice_count);
  first_page_map_all_slices_clear_after_collect = map_span_is_clear(
      first_span_start, first_slice_count);
  first_arena_page_bitmap_clear_after_collect = mi_bitmap_is_clearN(
      arena_pages->pages, first_slice_index, 1);
  first_slices_free_after_collect = mi_bbitmap_is_setN(
      arena->slices_free, first_slice_index, first_slice_count);
  valid = (request == 10248 && block_size == 12288
      && capacity == 42 && reserved == 42 && first_slice_count == 8
      && arena_backed && ordinary_medium && non_abandoning_theap
      && first_full_member_before_remote
      && successor_regular_member_before_remote
      && full_queue_count_before_remote == 1
      && regular_queue_count_before_remote == 1
      && page_count_before_remote == 2
      && first_page_map_all_slices_before_remote
      && first_arena_page_bitmap_set_before_remote
      && first_slices_unreleased_before_remote
      && initial_used == 42 && initial_remote_head_owned && initial_remote_empty
      && joined_remote_free_count == 42 && worker_joined_before_owner_collect
      && published_used_unchanged && published_remote_head_owned
      && published_remote_count == 42 && published_list_acyclic
      && owner_false_collect_called && full_queue_empty_after_collect
      && regular_queue_count_after_collect == 1 && page_count_after_collect == 1
      && successor_regular_member_after_collect
      && successor_page_map_all_slices_after_collect
      && first_page_map_all_slices_clear_after_collect
      && first_arena_page_bitmap_clear_after_collect
      && first_slices_free_after_collect);

output:
  printf("CRABC_MI_LIVE_OWNER_FULL_MEDIUM_REMOTE_RELEASE_TRACE_BEGIN\n");
#define OUT_N(name, value) printf("trace.live_owner_full_medium_release.%s=%zu\n", name, (size_t)(value))
#define OUT_B(name, value) printf("trace.live_owner_full_medium_release.%s=%d\n", name, (value) ? 1 : 0)
  OUT_N("request", request);
  OUT_N("block_size", block_size);
  OUT_N("capacity", capacity);
  OUT_N("reserved", reserved);
  OUT_N("slice_count", first_slice_count);
  OUT_B("arena_backed", arena_backed);
  OUT_B("ordinary_medium", ordinary_medium);
  OUT_B("non_abandoning_theap", non_abandoning_theap);
  OUT_B("first_full_member_before_remote", first_full_member_before_remote);
  OUT_B("successor_regular_member_before_remote", successor_regular_member_before_remote);
  OUT_N("full_queue_count_before_remote", full_queue_count_before_remote);
  OUT_N("regular_queue_count_before_remote", regular_queue_count_before_remote);
  OUT_N("page_count_before_remote", page_count_before_remote);
  OUT_B("first_page_map_all_slices_before_remote", first_page_map_all_slices_before_remote);
  OUT_B("first_arena_page_bitmap_set_before_remote", first_arena_page_bitmap_set_before_remote);
  OUT_B("first_slices_unreleased_before_remote", first_slices_unreleased_before_remote);
  OUT_N("initial_used", initial_used);
  OUT_B("initial_remote_head_owned", initial_remote_head_owned);
  OUT_B("initial_remote_empty", initial_remote_empty);
  OUT_N("joined_remote_free_count", joined_remote_free_count);
  OUT_B("worker_joined_before_owner_collect", worker_joined_before_owner_collect);
  OUT_B("published_used_unchanged", published_used_unchanged);
  OUT_B("published_remote_head_owned", published_remote_head_owned);
  OUT_N("published_remote_count", published_remote_count);
  OUT_B("published_list_acyclic", published_list_acyclic);
  OUT_B("owner_false_collect_called", owner_false_collect_called);
  OUT_B("full_queue_empty_after_collect", full_queue_empty_after_collect);
  OUT_N("regular_queue_count_after_collect", regular_queue_count_after_collect);
  OUT_N("page_count_after_collect", page_count_after_collect);
  OUT_B("successor_regular_member_after_collect", successor_regular_member_after_collect);
  OUT_B("successor_page_map_all_slices_after_collect", successor_page_map_all_slices_after_collect);
  OUT_B("first_page_map_all_slices_clear_after_collect", first_page_map_all_slices_clear_after_collect);
  OUT_B("first_arena_page_bitmap_clear_after_collect", first_arena_page_bitmap_clear_after_collect);
  OUT_B("first_slices_free_after_collect", first_slices_free_after_collect);
  OUT_B("valid", valid);
  printf("CRABC_MI_LIVE_OWNER_FULL_MEDIUM_REMOTE_RELEASE_TRACE_END\n");
#undef OUT_N
#undef OUT_B

  if (worker_started && !worker_joined) {
    if (pthread_join(worker, &worker_result) == 0) worker_joined = true;
  }
  if (!worker_started || worker_joined) {
    for (size_t index = 0; index < fixture.first_count; index++) {
      if (fixture.blocks[index] != NULL) {
        mi_free(fixture.blocks[index]);
        fixture.blocks[index] = NULL;
      }
    }
    if (successor != NULL) {
      mi_free(successor);
      successor = NULL;
    }
    if (heap != NULL) {
      mi_heap_collect(heap, true);
      mi_heap_destroy(heap);
    }
  }
  if (options_changed) mi_option_set(mi_option_page_full_retain, old_full_retain);
  return valid ? 0 : 2;
}
"""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"required evidence input is missing: {relative(path)}")
    return sha256_bytes(path.read_bytes())


def exactly_matches(observed: object, expected: object) -> bool:
    """Recursively compare JSON-shaped values without bool/int coercion."""

    if type(observed) is not type(expected):
        return False
    if isinstance(expected, Mapping):
        assert isinstance(observed, Mapping)
        return observed.keys() == expected.keys() and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, (list, tuple)):
        assert isinstance(observed, (list, tuple))
        return len(observed) == len(expected) and all(
            exactly_matches(actual, required)
            for actual, required in zip(observed, expected, strict=True)
        )
    return observed == expected


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def _schema_template() -> dict[str, Any]:
    return {
        "format": 1,
        "schema": (
            "crabc-mimalloc-x86_64-live-owner-full-medium-remote-release-evidence"
        ),
        "profile": EXPECTED_PROFILE,
        "target": dict(EXPECTED_TARGET),
        "upstream": dict(EXPECTED_UPSTREAM),
        "scope": dict(EXPECTED_SCOPE),
        "compile_definitions": list(EXPECTED_COMPILE_DEFINITIONS),
        "release_flags": list(run.CONFIGURATION_PROFILES["release"]),
        "release_source_set": list(run.ORACLE_SOURCES),
        "source_anchors": [
            {
                "member": member,
                "start_line": start_line,
                "end_line": end_line,
                "sha256": digest,
            }
            for member, start_line, end_line, digest in EXPECTED_SOURCE_ANCHORS
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
    """Load the checked-in schema and reject every contract drift exactly."""

    path = SCHEMA_PATH if path is None else Path(path)
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(
            "cannot read live-owner full-medium remote-release schema"
        ) from error
    if not exactly_matches(schema, _schema_template()):
        raise EvidenceError(
            "live-owner full-medium remote-release checked-in schema drifted"
        )
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError(
            "cannot validate the pinned live-owner full-medium upstream"
        ) from error
    observed_upstream = {
        "archive_root": pin["archive_root"],
        "revision": pin["revision"],
        "version": pin["version"],
    }
    if (
        not exactly_matches(observed_upstream, EXPECTED_UPSTREAM)
        or pin["sha256"] != EXPECTED_ARCHIVE_SHA256
    ):
        raise EvidenceError(
            "live-owner full-medium remote-release upstream pin drifted"
        )
    return schema


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise EvidenceError(
            "live-owner full-medium remote-release source anchor range is invalid"
        )
    return b"".join(lines[start_line - 1 : end_line])


def validate_source_anchors(
    schema: Mapping[str, Any], source: Path
) -> list[dict[str, Any]]:
    """Bind every lifecycle observation to the extracted pinned source bytes."""

    anchors = schema["source_anchors"]
    assert isinstance(anchors, list)
    validated: list[dict[str, Any]] = []
    for anchor in anchors:
        assert isinstance(anchor, dict)
        member = str(anchor["member"])
        path = source / member
        if not path.is_file():
            raise EvidenceError(
                "pinned source lacks live-owner full-medium anchor member: " + member
            )
        observed = sha256_bytes(
            source_range(
                path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"])
            )
        )
        if observed != anchor["sha256"]:
            raise EvidenceError(
                "pinned live-owner full-medium source anchor drifted: " + member
            )
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(
            output, begin=TRACE_BEGIN, end=TRACE_END, description=description
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, object], *, description: str) -> None:
    """Require exactly the fixed common trace and only integer observations."""

    if not isinstance(trace, Mapping):
        raise EvidenceError(f"{description} is not a trace mapping")
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    non_integer = sorted(
        key for key, value in trace.items() if type(value) is not int
    )
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
        raise EvidenceError(
            f"{description} differs from the fixed full-medium remote-release trace: "
            + "; ".join(details)
        )


def compare_traces(
    c_trace: Mapping[str, object], rust_trace: Mapping[str, object]
) -> dict[str, int | str]:
    """Require independently parsed C and Rust records to be exactly equal."""

    validate_trace(c_trace, description="pinned C full-medium remote-release trace")
    validate_trace(rust_trace, description="Rust full-medium remote-release trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise EvidenceError(
            "Rust full-medium remote-release trace differs from pinned C: "
            + ", ".join(mismatches)
        )
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def validate_c_probe_contract(probe: str) -> None:
    """Keep the real pthread, join boundary, full collector, and release proof."""

    create = "if (pthread_create(&worker, NULL, remote_worker, &fixture) != 0) goto output;"
    join = "if (pthread_join(worker, &worker_result) != 0) goto output;"
    published = "const mi_thread_free_t published_head"
    collect = "mi_heap_collect(heap, false);"
    if probe.count(create) != 1:
        raise EvidenceError(
            "full-medium C probe must create exactly one real worker pthread"
        )
    if probe.count(join) != 1:
        raise EvidenceError(
            "full-medium C probe must have exactly one successful-path pthread join"
        )
    if published not in probe or collect not in probe:
        raise EvidenceError(
            "full-medium C probe lacks the required owner observation or false collector"
        )
    if "mi_thread_done" in probe:
        raise EvidenceError(
            "full-medium C probe must remain a live-owner route without teardown"
        )
    worker = probe.split("static void* remote_worker", 1)[1].split(
        "\nint main(void)", 1
    )[0]
    if worker.count("mi_free(block);") != 1:
        raise EvidenceError(
            "full-medium C worker must perform the real C remote free in one loop"
        )
    create_index = probe.index(create)
    join_index = probe.index(join)
    published_index = probe.index(published)
    collect_index = probe.index(collect)
    if not (create_index < join_index < published_index < collect_index):
        raise EvidenceError(
            "full-medium C probe must join before non-atomic observation and collection"
        )
    during_worker = probe[create_index:join_index]
    forbidden = ("first_page->", "mi_block_next(", "_mi_safe_ptr_page(")
    if any(token in during_worker for token in forbidden):
        raise EvidenceError(
            "full-medium C probe observes ordinary page state while the worker may run"
        )
    option = "mi_option_set(mi_option_page_full_retain, -1);"
    heap_create = "heap = mi_heap_new_in_arena(arena_id);"
    if option not in probe or heap_create not in probe or probe.index(option) > probe.index(heap_create):
        raise EvidenceError(
            "full-medium C probe must select the non-abandoning option before heap creation"
        )
    reserved_sample = "reserved = first_page->reserved;"
    fill_loop = """while (fixture.first_count < reserved) {
    void* const block = mi_heap_malloc(heap, request);
    if (block == NULL || _mi_ptr_page(block) != first_page) goto output;
    fixture.blocks[fixture.first_count++] = block;
  }"""
    capacity_sample = "capacity = first_page->capacity;"
    successor_allocate = "successor = mi_heap_malloc(heap, request);"
    if any(
        token not in probe
        for token in (reserved_sample, fill_loop, capacity_sample, successor_allocate)
    ) or not (
        probe.index(reserved_sample)
        < probe.index(fill_loop)
        < probe.index(capacity_sample)
        < probe.index(successor_allocate)
    ):
        raise EvidenceError(
            "full-medium C probe must sample lazy capacity after filling the reserved page"
        )
    required = (
        "queue_has_only_member(full, first_page)",
        "queue_has_only_member(regular, successor_page)",
        "return queue != NULL && member != NULL && queue->count == 1",
        "&& queue->first == member && queue->last == member",
        "&& member->prev == NULL && member->next == NULL",
        "&& queue_contains_member(queue, member);",
        "full != NULL && full->count == 0 && full->first == NULL\n      && full->last == NULL",
        "map_span_is_page(\n      first_page, first_span_start, first_slice_count)",
        "map_span_is_page(\n      successor_page, successor_span_start, successor_slice_count)",
        "map_span_is_clear(\n      first_span_start, first_slice_count)",
        "mi_bitmap_is_setN(",
        "mi_bitmap_is_clearN(",
        "mi_bbitmap_is_clearN(",
        "mi_bbitmap_is_setN(",
        "theap->allow_page_abandon",
        "mi_heap_collect(heap, false);",
    )
    missing = [token for token in required if token not in probe]
    if missing:
        raise EvidenceError(
            "full-medium C probe lacks required oracle contract: "
            + ", ".join(missing)
        )


def normalize_command(
    command: Sequence[str], temporary: Path, source: Path | None
) -> list[str]:
    """Normalize only temporary paths while preserving every command token."""

    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    normalized: list[str] = []
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


def validate_c_command(
    command: Sequence[str], schema: Mapping[str, Any]
) -> None:
    """Reject profile, source-selection, pthread, or TLS drift in the C build."""

    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    release_flags = [
        part for part in command if part in run.CONFIGURATION_PROFILES["release"]
    ]
    if not exactly_matches(
        definitions, list(schema["compile_definitions"])
    ) or not exactly_matches(definitions, list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("full-medium C command compile definitions drifted")
    if not exactly_matches(release_flags, schema["release_flags"]):
        raise EvidenceError("full-medium C command release flags drifted")
    if command.count("-pthread") != 1 or command.count("-ftls-model=initial-exec") != 1:
        raise EvidenceError("full-medium C command pthread/TLS selection drifted")


def validate_normalized_c_command(
    command: object, schema: Mapping[str, Any]
) -> None:
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
        or not all(isinstance(part, str) for part in command)
        or Path(command[0]).name != "musl-gcc"
        or not exactly_matches(command[1:], expected)
    ):
        raise EvidenceError("full-medium remote-release report C command drifted")


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
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(part, str) for part in command)
        or Path(command[0]).name != "cargo"
        or not exactly_matches(command[1:], expected)
    ):
        raise EvidenceError("full-medium remote-release report Rust command drifted")


def build_c_trace(
    compiler: str,
    readelf: str,
    source: Path,
    temporary: Path,
    schema: Mapping[str, Any],
) -> dict[str, Any]:
    probe_source = temporary / f"{STEM}.c"
    probe_binary = temporary / f"{STEM}-c"
    validate_c_probe_contract(C_TRACE_PROBE)
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        build = run.command_record(command, cwd=source)
        run.require_success(build, "pinned C full-medium remote-release fixture build")
        header = run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        run.require_success(
            header, "pinned C full-medium remote-release fixture ELF identity"
        )
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(probe_binary),), cwd=source)
        run.require_success(
            execution, "pinned C full-medium remote-release fixture execution"
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(
        str(execution["stdout"]),
        description="pinned C full-medium remote-release trace",
    )
    validate_trace(trace, description="pinned C full-medium remote-release trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"],
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
        run.require_success(execution, "Rust full-medium remote-release fixture")
        passed = run.parse_rust_test_count(
            str(execution["stdout"]) + "\n" + str(execution["stderr"])
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(
            "Rust full-medium remote-release fixture passed "
            f"{passed} tests, expected one"
        )
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust full-medium remote-release trace",
    )
    validate_trace(trace, description="Rust full-medium remote-release trace")
    return {
        "cargo_command": normalize_command(command, temporary, None),
        "lockfile": {
            "path": relative(LOCKFILE),
            "sha256": sha256_file(LOCKFILE),
        },
        "passed_test_count": passed,
        "source": {
            "path": relative(RUST_TEST_SOURCE),
            "sha256": sha256_file(RUST_TEST_SOURCE),
        },
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
        raise EvidenceError(
            "full-medium remote-release report inputs lack C/Rust traces"
        )
    report: dict[str, Any] = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": (
            "mimalloc-x86_64-live-owner-full-medium-remote-release-"
            "differential-evidence"
        ),
        "profile": schema["profile"],
        "provenance": dict(provenance),
        "rust_probe": dict(rust_probe),
        "scope": dict(schema["scope"]),
        "source": {
            "archive_sha256": archive_sha256,
            "anchors": [dict(anchor) for anchor in anchors],
            "release_flags": list(schema["release_flags"]),
            "release_source_set": list(schema["release_source_set"]),
        },
        "status": "passed",
        "target": dict(schema["target"]),
        "trace": dict(schema["trace"]),
        "upstream": dict(schema["upstream"]),
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    """Fail closed on provenance, configuration, comparison, or trace drift."""

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
        raise EvidenceError("full-medium remote-release report schema drifted")
    if (
        type(report["format"]) is not int
        or report["format"] != 1
        or report["status"] != "passed"
    ):
        raise EvidenceError(
            "full-medium remote-release report must record a passing format-1 result"
        )
    if report["kind"] != (
        "mimalloc-x86_64-live-owner-full-medium-remote-release-"
        "differential-evidence"
    ) or report["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("full-medium remote-release report identity drifted")
    expected_comparison = {
        "compared_value_count": len(EXPECTED_TRACE_VALUES),
        "status": "matched",
    }
    if not exactly_matches(report["comparison"], expected_comparison):
        raise EvidenceError("full-medium remote-release report comparison drifted")
    if not (
        exactly_matches(report["target"], EXPECTED_TARGET)
        and exactly_matches(report["upstream"], EXPECTED_UPSTREAM)
        and exactly_matches(report["scope"], EXPECTED_SCOPE)
    ):
        raise EvidenceError(
            "full-medium remote-release report source or private boundary drifted"
        )
    native_provenance = (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    )
    if not any(
        exactly_matches(report["provenance"], expected)
        for expected in native_provenance
    ):
        raise EvidenceError(
            "full-medium remote-release report lacks native x86-64 provenance"
        )

    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {
        "archive_sha256",
        "anchors",
        "release_flags",
        "release_source_set",
    }:
        raise EvidenceError(
            "full-medium remote-release report source record is malformed"
        )
    if (
        source.get("archive_sha256") != EXPECTED_ARCHIVE_SHA256
        or not exactly_matches(source.get("anchors"), schema["source_anchors"])
        or not exactly_matches(
            source.get("release_flags"), schema["release_flags"]
        )
        or not exactly_matches(
            source.get("release_source_set"), schema["release_source_set"]
        )
        or not exactly_matches(report["trace"], schema["trace"])
    ):
        raise EvidenceError(
            "full-medium remote-release report source/trace contract drifted"
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
        raise EvidenceError("full-medium remote-release C probe record drifted")
    if (
        not exactly_matches(c_probe["elf"], EXPECTED_C_ELF)
        or not exactly_matches(
            c_probe["run_command"],
            [f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"],
        )
        or c_probe["source_sha256"]
        != sha256_bytes(C_TRACE_PROBE.encode("utf-8"))
    ):
        raise EvidenceError("full-medium remote-release C probe identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)

    if not isinstance(rust_probe, dict) or set(rust_probe) != {
        "cargo_command",
        "lockfile",
        "passed_test_count",
        "source",
        "target_dir",
        "trace",
    }:
        raise EvidenceError("full-medium remote-release Rust probe record drifted")
    if (
        type(rust_probe["passed_test_count"]) is not int
        or rust_probe["passed_test_count"] != 1
    ):
        raise EvidenceError(
            "full-medium remote-release Rust selection did not pass exactly one test"
        )
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(
        rust_probe["lockfile"],
        {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
    ) or not exactly_matches(
        rust_probe["source"],
        {
            "path": relative(RUST_TEST_SOURCE),
            "sha256": sha256_file(RUST_TEST_SOURCE),
        },
    ) or not exactly_matches(
        rust_probe["target_dir"],
        {
            "isolated": True,
            "retained": False,
            "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        },
    ):
        raise EvidenceError("full-medium remote-release Rust identity drifted")
    if not isinstance(c_probe["trace"], Mapping) or not isinstance(
        rust_probe["trace"], Mapping
    ):
        raise EvidenceError(
            "full-medium remote-release report lacks C/Rust trace records"
        )
    observed_comparison = compare_traces(c_probe["trace"], rust_probe["trace"])
    if not exactly_matches(report["comparison"], observed_comparison):
        raise EvidenceError("full-medium remote-release report comparison drifted")


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    """Execute the exact pinned C/Rust live-owner differential once."""

    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(
        prefix="crabc-mimalloc-x86_64-live-owner-full-medium-"
    ) as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(
                archive, temporary / "source", pin["archive_root"]
            )
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
        raise EvidenceError(
            "Cargo.lock changed despite the required --locked Rust trace command"
        )
    report_path.parent.mkdir(parents=True, exist_ok=True)
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
        print(
            "allocator x86-64 live-owner full-medium remote-release differential: "
            f"FAIL: {error}",
            file=os.sys.stderr,
        )
        return 1
    comparison = report["comparison"]
    print(
        "allocator x86-64 live-owner full-medium remote-release differential: PASS "
        f"({comparison['compared_value_count']} logical values; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
