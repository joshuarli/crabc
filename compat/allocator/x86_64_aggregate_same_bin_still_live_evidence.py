#!/usr/bin/env python3
"""Native C/Rust evidence for one same-bin aggregate StillLive lifecycle.

This private Linux/x86-64 lane starts a real pinned-C worker, creates two
distinct nonfull medium pages in one size-class queue, calls
``mi_thread_done()``, and joins the worker before the consumer frees any
client.  The first free keeps both pages live, the second releases exactly one
page, and the final free releases the aggregate route.  It is deliberately
bounded evidence for the fixed allocator port: it neither provides a public
x86 allocator surface nor claims general teardown, routing, or concurrency.
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-aggregate-same-bin-still-live-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/aggregate-same-bin-still-live.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/main_heap_page.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "main_heap_page::tests::x86_64_aggregate_same_bin_still_live_trace_matches_pinned_c_protocol"
TRACE_BEGIN = "CRABC_MI_AGGREGATE_SAME_BIN_STILL_LIVE_TRACE_BEGIN"
TRACE_END = "CRABC_MI_AGGREGATE_SAME_BIN_STILL_LIVE_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded same-bin aggregate differential could not establish its claim."""


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
EXPECTED_PROFILE = "linux-x86_64-private-aggregate-same-bin-still-live"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "one_two_client_nonfull_medium_page_and_one_same_bin_distinct_one_client_page_only": True,
    "private_engine_evidence_only": True,
    "producer_theap_teardown_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
    "same_bin_queue_count_and_successor_traversal_only": True,
    "selected_still_live_tail_only": True,
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
# These source ranges bind the public allocation/free calls, the source queue
# successor saved during teardown, exact aggregate abandonment publication and
# removal, active two-level PageMap lookup, and private arena/page lifetime
# metadata observed by the C fixture.  The page-queue anchors are intentional:
# this lane distinguishes two live pages in *one* source bin from the prior
# two-bin aggregate evidence.
EXPECTED_SOURCE_ANCHORS = (
    ("src/free.c", 221, 256, "11e0aa2d13e7eba9f7bebb5b5395304041e4c5b492d2b4d09e43ba3bedb942fe"),
    ("src/free.c", 364, 515, "073739d4f87219076fb8f087093b775d3a61ed8bf84c0588765bed0e6d619d68"),
    ("src/page.c", 214, 243, "35148cff687e602b8de307ca1abad524655f48bf4410b2c64a7e44af8909203b"),
    ("src/page.c", 291, 303, "d363079d5e484919082b5602cc3757a3e3a357e68594fc040d902232c7458bbf"),
    ("src/page.c", 392, 412, "f6cd126eaaf724dac35226ff52b3f0166b514321188e9b12dfdd35c2b21ab10f"),
    ("src/page.c", 765, 820, "1478a347682ed663ccd0a88af131a843eb25f8bfc0ab7425c0aec123b94c9336"),
    ("src/page-queue.c", 147, 172, "67dd6914e2d62e8a2efb13d49cc92692b7d8e245363597f16a3ff1c076e9cf5d"),
    ("src/page-queue.c", 252, 304, "bc0497f935d32ea9cb6c976d85d5a296821841aaf7622d03daa7505ae3b34ce0"),
    ("src/theap.c", 21, 51, "801bb68f34d171e9060ae96dc57c136c17999fb7e0fec5bf7dbe5462badb3d53"),
    ("src/theap.c", 97, 115, "62d9e01e6c2d397f6b2147fcc079c9f3ce5001811a664d4601e2c1e17c51ebe7"),
    ("src/init.c", 378, 417, "c31e558c1bf6c292aecab8e4a4fe3ef8c2616d2f10d9ac6549fe987ad72cac62"),
    ("src/init.c", 448, 480, "81710fd90ab37ebaf517e33c88e82c8a847eafad277c376eb18c196d9d86838d"),
    ("include/mimalloc/prim-tls.h", 399, 421, "ddc64d3164ea8b23ec30a325fdf2d750ec93d22c7c7454849e0210221f65bf53"),
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
    ("src/heap.c", 161, 261, "9bf57e560868cfc679d75454bb990e801304fdf417bae2a9a08fbc4ef0b0bac1"),
    ("src/alloc.c", 252, 262, "7f782391729bac2e29ed2c8f120b25970bdf4b5837010f101dd776b959fa15ad"),
    ("src/options.c", 151, 171, "25d0cbe30b42bad4b5db3dfb345706beb1aff79f0d3cc46904317c5e2571f7e9"),
    ("src/options.c", 266, 316, "f18c941578bceffeb5761980aab3c0b89407cfca49f3db2a5ed85ecb40cafc37"),
)
TRACE_FIELDS = (
    "arena_backed",
    "both_medium",
    "first_distinct_clients_share_page",
    "distinct_pages",
    "same_bin",
    "same_bin_queue_count_two_before_exit",
    "same_bin_queue_bidirectional_links_before_exit",
    "same_bin_queue_successor_visits_both_before_exit",
    "first_used_two_before_exit",
    "second_used_one_before_exit",
    "first_nonfull_before_exit",
    "second_nonfull_before_exit",
    "slice_spans_nonempty_and_disjoint",
    "pages_share_paired_arena",
    "route_two_pages_before_join",
    "producer_teardown_completed_before_consumer_free",
    "consumer_joined_before_first_free",
    "first_page_map_registered_after_join",
    "second_page_map_registered_after_join",
    "first_arena_page_bitmap_set_after_join",
    "second_arena_page_bitmap_set_after_join",
    "first_mapped_abandoned_after_join",
    "second_mapped_abandoned_after_join",
    "same_bin_abandoned_count_two_after_join",
    "same_bin_abandoned_bitmap_both_set_after_join",
    "first_free_still_live_route_two_pages",
    "first_page_map_registered_after_first_free",
    "first_arena_page_bitmap_set_after_first_free",
    "first_mapped_abandoned_after_first_free",
    "first_used_one_after_first_free",
    "second_page_map_registered_after_first_free",
    "second_arena_page_bitmap_set_after_first_free",
    "second_mapped_abandoned_after_first_free",
    "second_used_one_after_first_free",
    "same_bin_abandoned_count_two_after_first_free",
    "same_bin_abandoned_bitmap_both_set_after_first_free",
    "second_free_released_page_route_one_page",
    "second_page_map_unregistered_after_second_free",
    "second_arena_page_bitmap_clear_after_second_free",
    "second_arena_slice_released_after_second_free",
    "first_page_map_registered_after_second_free",
    "first_arena_page_bitmap_set_after_second_free",
    "first_mapped_abandoned_after_second_free",
    "first_used_one_after_second_free",
    "same_bin_abandoned_count_one_after_second_free",
    "same_bin_abandoned_bitmap_first_only_after_second_free",
    "final_free_released_all_route_empty",
    "first_page_map_unregistered_after_final_free",
    "first_arena_page_bitmap_clear_after_final_free",
    "first_arena_slice_released_after_final_free",
    "same_bin_abandoned_count_zero_after_final_free",
    "same_bin_abandoned_bitmap_empty_after_final_free",
    "valid",
)
EXPECTED_TRACE_VALUES = {
    f"trace.aggregate_same_bin_still_live.{field}": 1 for field in TRACE_FIELDS
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
#error this fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0
#error this fixture requires the native x86-64 two-level PageMap branch
#endif

#define CRABC_SAME_BIN_REQUEST (MI_SMALL_MAX_OBJ_SIZE + 1)
#define CRABC_MAX_FILLERS (MI_MEDIUM_PAGE_SIZE / CRABC_SAME_BIN_REQUEST)

typedef struct fixture_s {
  mi_arena_id_t arena_id;
  mi_heap_t* heap;
  void* first_client;
  void* first_survivor;
  void* second_client;
  mi_arena_t* arena;
  mi_arena_pages_t* arena_pages;
  size_t first_slice;
  size_t first_slices;
  size_t second_slice;
  size_t second_slices;
  size_t bin;
  uintptr_t first_client_address;
  uintptr_t first_survivor_address;
  uintptr_t second_client_address;
  uintptr_t first_page_identity;
  uintptr_t second_page_identity;
  bool setup;
  bool producer_done;
  bool arena_backed;
  bool both_medium;
  bool first_distinct_clients_share_page;
  bool distinct_pages;
  bool same_bin;
  bool same_bin_queue_count_two;
  bool same_bin_queue_bidirectional_links;
  bool same_bin_queue_successor_visits_both;
  bool first_used_two;
  bool second_used_one;
  bool first_nonfull;
  bool second_nonfull;
  bool slice_spans_nonempty_and_disjoint;
  bool pages_share_paired_arena;
  bool route_two_pages_before_join;
} fixture_t;

static bool spans_are_nonempty_and_disjoint(
    size_t first_slice, size_t first_slices, size_t second_slice, size_t second_slices) {
  if (first_slices == 0 || second_slices == 0) return false;
  if (first_slice < second_slice) return first_slices <= second_slice - first_slice;
  if (second_slice < first_slice) return second_slices <= first_slice - second_slice;
  return false;
}

static bool is_medium_nonfull(const mi_page_t* page) {
  return (page->block_size > MI_SMALL_MAX_OBJ_SIZE
          && page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE
          && page->reserved > 1
          && page->used < page->reserved
          && !mi_page_is_full(page));
}

static bool queue_visits_exactly_both(
    const mi_page_queue_t* queue, const mi_page_t* first, const mi_page_t* second) {
  const mi_page_t* const head = queue->first;
  const mi_page_t* const tail = (head == NULL ? NULL : head->next);
  return (queue->count == 2 && head != NULL && tail != NULL && tail->next == NULL
          && queue->last == tail
          && ((head == first && tail == second) || (head == second && tail == first)));
}

static bool queue_has_exact_bidirectional_two_page_links(
    const mi_page_queue_t* queue, const mi_page_t* first, const mi_page_t* second) {
  const mi_page_t* const head = queue->first;
  const mi_page_t* const tail = (head == NULL ? NULL : head->next);
  return (queue_visits_exactly_both(queue, first, second)
          && head->prev == NULL && tail->prev == head);
}

static void* producer_main(void* arg) {
  fixture_t* const f = (fixture_t*)arg;
  mi_heap_t* heap = mi_heap_new_in_arena(f->arena_id);
  void* first_client = NULL;
  void* first_survivor = NULL;
  void* second_client = NULL;
  void* fillers[CRABC_MAX_FILLERS] = {0};
  size_t filler_count = 0;
  mi_page_t* first_page = NULL;
  mi_page_t* second_page = NULL;

  if (heap == NULL) goto fail;
  first_client = mi_heap_malloc(heap, CRABC_SAME_BIN_REQUEST);
  first_survivor = mi_heap_malloc(heap, CRABC_SAME_BIN_REQUEST);
  if (first_client == NULL || first_survivor == NULL) goto fail;
  first_page = _mi_ptr_page(first_client);
  if (first_page == NULL || first_client == first_survivor
      || _mi_ptr_page(first_survivor) != first_page
      || first_page->reserved <= 2
      || first_page->reserved - 2 > CRABC_MAX_FILLERS) goto fail;

  // Fill A while its owner is live. The next same-size allocation must then
  // make B in the same source bin; the local frees below leave exactly A1/A2.
  for (size_t index = 0; index < first_page->reserved - 2; index++) {
    void* const filler = mi_heap_malloc(heap, CRABC_SAME_BIN_REQUEST);
    if (filler == NULL || _mi_ptr_page(filler) != first_page) goto fail;
    fillers[filler_count++] = filler;
  }
  if (first_page->used != first_page->reserved || !mi_page_is_full(first_page)) goto fail;
  second_client = mi_heap_malloc(heap, CRABC_SAME_BIN_REQUEST);
  second_page = _mi_ptr_page(second_client);
  if (second_client == NULL || second_page == NULL || second_page == first_page) goto fail;
  for (size_t index = 0; index < filler_count; index++) {
    mi_free(fillers[index]);
    fillers[index] = NULL;
  }
  filler_count = 0;

  if (first_page->memid.memkind != MI_MEM_ARENA
      || second_page->memid.memkind != MI_MEM_ARENA
      || !is_medium_nonfull(first_page) || !is_medium_nonfull(second_page)
      || first_page->used != 2 || second_page->used != 1
      || _mi_bin(first_page->block_size) != _mi_bin(second_page->block_size)) goto fail;

  f->arena_backed = (first_page->memid.memkind == MI_MEM_ARENA
                     && second_page->memid.memkind == MI_MEM_ARENA);
  f->both_medium = (first_page->block_size > MI_SMALL_MAX_OBJ_SIZE
                    && first_page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE
                    && second_page->block_size > MI_SMALL_MAX_OBJ_SIZE
                    && second_page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE);
  f->first_distinct_clients_share_page = (
      first_client != first_survivor && _mi_ptr_page(first_survivor) == first_page);
  f->distinct_pages = (first_page != second_page);
  f->bin = _mi_bin(first_page->block_size);
  f->same_bin = (f->bin == _mi_bin(second_page->block_size));
  mi_theap_t* const theap = mi_page_theap(first_page);
  if (theap == NULL || mi_page_theap(second_page) != theap) goto fail;
  mi_page_queue_t* const queue = &theap->pages[f->bin];
  f->same_bin_queue_count_two = (queue->count == 2);
  f->same_bin_queue_bidirectional_links = queue_has_exact_bidirectional_two_page_links(
      queue, first_page, second_page);
  f->same_bin_queue_successor_visits_both = queue_visits_exactly_both(
      queue, first_page, second_page);
  f->first_used_two = (first_page->used == 2);
  f->second_used_one = (second_page->used == 1);
  f->first_nonfull = is_medium_nonfull(first_page);
  f->second_nonfull = is_medium_nonfull(second_page);
  f->arena = mi_memid_arena(first_page->memid);
  f->first_slice = first_page->memid.mem.arena.slice_index;
  f->first_slices = first_page->memid.mem.arena.slice_count;
  f->second_slice = second_page->memid.mem.arena.slice_index;
  f->second_slices = second_page->memid.mem.arena.slice_count;
  f->slice_spans_nonempty_and_disjoint = spans_are_nonempty_and_disjoint(
      f->first_slice, f->first_slices, f->second_slice, f->second_slices);
  f->pages_share_paired_arena = (f->arena != NULL
      && mi_memid_arena(second_page->memid) == f->arena);
  f->first_client_address = (uintptr_t)first_client;
  f->first_survivor_address = (uintptr_t)first_survivor;
  f->second_client_address = (uintptr_t)second_client;
  f->first_page_identity = (uintptr_t)first_page;
  f->second_page_identity = (uintptr_t)second_page;
  if (f->arena == NULL || f->arena->arena_idx >= MI_MAX_ARENAS
      || f->bin >= MI_ARENA_BIN_COUNT || !f->arena_backed || !f->both_medium
      || !f->first_distinct_clients_share_page || !f->distinct_pages || !f->same_bin
      || !f->same_bin_queue_count_two || !f->same_bin_queue_bidirectional_links
      || !f->same_bin_queue_successor_visits_both || !f->first_used_two
      || !f->second_used_one || !f->first_nonfull || !f->second_nonfull
      || !f->slice_spans_nonempty_and_disjoint || !f->pages_share_paired_arena) goto fail;
  f->arena_pages = mi_atomic_load_ptr_acquire(
      mi_arena_pages_t, &heap->arena_pages[f->arena->arena_idx]);
  if (f->arena_pages == NULL) goto fail;

  // The separately-created heap and its arena-page table outlive only this
  // selected route. Save integer page identities, then let real C teardown
  // remove the producer Theap/TLD before any consumer-side free.
  f->heap = heap;
  f->first_client = first_client;
  f->first_survivor = first_survivor;
  f->second_client = second_client;
  mi_thread_done();
  f->producer_done = true;

  // Every post-teardown page dereference is first gated through the active
  // two-level PageMap. The saved identities themselves are integers only.
  mi_page_t* const first_after_teardown = _mi_safe_ptr_page(
      (const void*)(uintptr_t)f->first_client_address);
  mi_page_t* const first_survivor_after_teardown = _mi_safe_ptr_page(
      (const void*)(uintptr_t)f->first_survivor_address);
  mi_page_t* const second_after_teardown = _mi_safe_ptr_page(
      (const void*)(uintptr_t)f->second_client_address);
  if (first_after_teardown == NULL || first_survivor_after_teardown == NULL
      || second_after_teardown == NULL
      || (uintptr_t)first_after_teardown != f->first_page_identity
      || (uintptr_t)first_survivor_after_teardown != f->first_page_identity
      || (uintptr_t)second_after_teardown != f->second_page_identity) {
    f->first_client = NULL;
    f->first_survivor = NULL;
    f->second_client = NULL;
    return NULL;
  }
  f->route_two_pages_before_join = (
      mi_page_is_abandoned_mapped(first_after_teardown)
      && mi_page_is_abandoned_mapped(second_after_teardown)
      && mi_bitmap_is_setN(f->arena_pages->pages, f->first_slice, 1)
      && mi_bitmap_is_setN(f->arena_pages->pages, f->second_slice, 1)
      && mi_bitmap_is_setN(f->arena_pages->pages_abandoned[f->bin], f->first_slice, 1)
      && mi_bitmap_is_setN(f->arena_pages->pages_abandoned[f->bin], f->second_slice, 1)
      && mi_atomic_load_relaxed(&heap->abandoned_count[f->bin]) == 2);
  if (!f->route_two_pages_before_join) {
    f->first_client = NULL;
    f->first_survivor = NULL;
    f->second_client = NULL;
    return NULL;
  }
  f->setup = true;
  return NULL;

fail:
  for (size_t index = 0; index < filler_count; index++) {
    if (fillers[index] != NULL) mi_free(fillers[index]);
  }
  if (first_client != NULL) mi_free(first_client);
  if (first_survivor != NULL) mi_free(first_survivor);
  if (second_client != NULL) mi_free(second_client);
  if (heap != NULL) mi_heap_destroy(heap);
  f->heap = NULL;
  f->first_client = NULL;
  f->first_survivor = NULL;
  f->second_client = NULL;
  return NULL;
}

int main(void) {
  fixture_t f = {0};
  mi_arena_id_t arena_id = _mi_arena_id_none();
  pthread_t worker;
  bool started = false;
  bool consumer_joined = false;
  bool heap_destroy_safe = false;
  bool reclaim_option_changed = false;
  long old_reclaim = 0;
  int valid = 0;

  int arena_backed = 0, both_medium = 0, first_distinct_clients_share_page = 0;
  int distinct_pages = 0, same_bin = 0, same_bin_queue_count_two_before_exit = 0;
  int same_bin_queue_bidirectional_links_before_exit = 0;
  int same_bin_queue_successor_visits_both_before_exit = 0;
  int first_used_two_before_exit = 0, second_used_one_before_exit = 0;
  int first_nonfull_before_exit = 0, second_nonfull_before_exit = 0;
  int slice_spans_nonempty_and_disjoint = 0, pages_share_paired_arena = 0;
  int route_two_pages_before_join = 0;
  int producer_teardown_completed_before_consumer_free = 0;
  int consumer_joined_before_first_free = 0;
  int first_page_map_registered_after_join = 0, second_page_map_registered_after_join = 0;
  int first_arena_page_bitmap_set_after_join = 0, second_arena_page_bitmap_set_after_join = 0;
  int first_mapped_abandoned_after_join = 0, second_mapped_abandoned_after_join = 0;
  int same_bin_abandoned_count_two_after_join = 0;
  int same_bin_abandoned_bitmap_both_set_after_join = 0;
  int first_free_still_live_route_two_pages = 0;
  int first_page_map_registered_after_first_free = 0;
  int first_arena_page_bitmap_set_after_first_free = 0, first_mapped_abandoned_after_first_free = 0;
  int first_used_one_after_first_free = 0;
  int second_page_map_registered_after_first_free = 0;
  int second_arena_page_bitmap_set_after_first_free = 0, second_mapped_abandoned_after_first_free = 0;
  int second_used_one_after_first_free = 0;
  int same_bin_abandoned_count_two_after_first_free = 0;
  int same_bin_abandoned_bitmap_both_set_after_first_free = 0;
  int second_free_released_page_route_one_page = 0;
  int second_page_map_unregistered_after_second_free = 0;
  int second_arena_page_bitmap_clear_after_second_free = 0;
  int second_arena_slice_released_after_second_free = 0;
  int first_page_map_registered_after_second_free = 0;
  int first_arena_page_bitmap_set_after_second_free = 0, first_mapped_abandoned_after_second_free = 0;
  int first_used_one_after_second_free = 0;
  int same_bin_abandoned_count_one_after_second_free = 0;
  int same_bin_abandoned_bitmap_first_only_after_second_free = 0;
  int final_free_released_all_route_empty = 0;
  int first_page_map_unregistered_after_final_free = 0;
  int first_arena_page_bitmap_clear_after_final_free = 0;
  int first_arena_slice_released_after_final_free = 0;
  int same_bin_abandoned_count_zero_after_final_free = 0;
  int same_bin_abandoned_bitmap_empty_after_final_free = 0;

  mi_thread_init();
  // Preserve real source policy selection: 0 permits only origin-Theap
  // reclaim, which is unavailable after the worker's real `mi_thread_done`.
  old_reclaim = mi_option_get(mi_option_page_reclaim_on_free);
  mi_option_set(mi_option_page_reclaim_on_free, 0);
  reclaim_option_changed = true;
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto done;
  f.arena_id = arena_id;
  if (pthread_create(&worker, NULL, producer_main, &f) != 0) goto done;
  started = true;
  if (pthread_join(worker, NULL) != 0) goto done;
  started = false;
  consumer_joined = true;
  if (!f.setup || !f.producer_done || f.heap == NULL || f.arena == NULL
      || f.arena_pages == NULL || f.first_client == NULL
      || f.first_survivor == NULL || f.second_client == NULL) goto done;

  arena_backed = f.arena_backed;
  both_medium = f.both_medium;
  first_distinct_clients_share_page = f.first_distinct_clients_share_page;
  distinct_pages = f.distinct_pages;
  same_bin = f.same_bin;
  same_bin_queue_count_two_before_exit = f.same_bin_queue_count_two;
  same_bin_queue_bidirectional_links_before_exit = f.same_bin_queue_bidirectional_links;
  same_bin_queue_successor_visits_both_before_exit = f.same_bin_queue_successor_visits_both;
  first_used_two_before_exit = f.first_used_two;
  second_used_one_before_exit = f.second_used_one;
  first_nonfull_before_exit = f.first_nonfull;
  second_nonfull_before_exit = f.second_nonfull;
  slice_spans_nonempty_and_disjoint = f.slice_spans_nonempty_and_disjoint;
  pages_share_paired_arena = f.pages_share_paired_arena;
  route_two_pages_before_join = f.route_two_pages_before_join;
  producer_teardown_completed_before_consumer_free = (f.producer_done && consumer_joined && !started);
  consumer_joined_before_first_free = consumer_joined;

  mi_page_t* const first_after_join = _mi_safe_ptr_page(
      (const void*)(uintptr_t)f.first_client_address);
  mi_page_t* const first_survivor_after_join = _mi_safe_ptr_page(
      (const void*)(uintptr_t)f.first_survivor_address);
  mi_page_t* const second_after_join = _mi_safe_ptr_page(
      (const void*)(uintptr_t)f.second_client_address);
  first_page_map_registered_after_join = (first_after_join != NULL
      && first_survivor_after_join != NULL
      && (uintptr_t)first_after_join == f.first_page_identity
      && (uintptr_t)first_survivor_after_join == f.first_page_identity);
  second_page_map_registered_after_join = (second_after_join != NULL
      && (uintptr_t)second_after_join == f.second_page_identity);
  if (!first_page_map_registered_after_join || !second_page_map_registered_after_join) {
    f.first_client = NULL;
    f.first_survivor = NULL;
    f.second_client = NULL;
    goto done;
  }
  first_arena_page_bitmap_set_after_join = mi_bitmap_is_setN(f.arena_pages->pages, f.first_slice, 1);
  second_arena_page_bitmap_set_after_join = mi_bitmap_is_setN(f.arena_pages->pages, f.second_slice, 1);
  first_mapped_abandoned_after_join = mi_page_is_abandoned_mapped(first_after_join);
  second_mapped_abandoned_after_join = mi_page_is_abandoned_mapped(second_after_join);
  same_bin_abandoned_count_two_after_join = (
      mi_atomic_load_relaxed(&f.heap->abandoned_count[f.bin]) == 2);
  same_bin_abandoned_bitmap_both_set_after_join = (
      mi_bitmap_is_setN(f.arena_pages->pages_abandoned[f.bin], f.first_slice, 1)
      && mi_bitmap_is_setN(f.arena_pages->pages_abandoned[f.bin], f.second_slice, 1));
  if (!arena_backed || !both_medium || !first_distinct_clients_share_page || !distinct_pages
      || !same_bin || !same_bin_queue_count_two_before_exit
      || !same_bin_queue_bidirectional_links_before_exit
      || !same_bin_queue_successor_visits_both_before_exit
      || !first_used_two_before_exit || !second_used_one_before_exit
      || !first_nonfull_before_exit || !second_nonfull_before_exit
      || !slice_spans_nonempty_and_disjoint || !pages_share_paired_arena
      || !route_two_pages_before_join || !producer_teardown_completed_before_consumer_free
      || !consumer_joined_before_first_free || !first_arena_page_bitmap_set_after_join
      || !second_arena_page_bitmap_set_after_join || !first_mapped_abandoned_after_join
      || !second_mapped_abandoned_after_join || !same_bin_abandoned_count_two_after_join
      || !same_bin_abandoned_bitmap_both_set_after_join || !_mi_thread_is_initialized()
      || _mi_page_associated_theap_peek(first_after_join) != NULL) {
    f.first_client = NULL;
    f.first_survivor = NULL;
    f.second_client = NULL;
    goto done;
  }

  mi_free(f.first_client);
  f.first_client = NULL;
  mi_page_t* const first_after_first_free = _mi_safe_ptr_page(
      (const void*)(uintptr_t)f.first_survivor_address);
  mi_page_t* const second_after_first_free = _mi_safe_ptr_page(
      (const void*)(uintptr_t)f.second_client_address);
  first_page_map_registered_after_first_free = (first_after_first_free != NULL
      && (uintptr_t)first_after_first_free == f.first_page_identity);
  second_page_map_registered_after_first_free = (second_after_first_free != NULL
      && (uintptr_t)second_after_first_free == f.second_page_identity);
  if (!first_page_map_registered_after_first_free || !second_page_map_registered_after_first_free) {
    f.first_survivor = NULL;
    f.second_client = NULL;
    goto done;
  }
  first_arena_page_bitmap_set_after_first_free = mi_bitmap_is_setN(f.arena_pages->pages, f.first_slice, 1);
  first_mapped_abandoned_after_first_free = mi_page_is_abandoned_mapped(first_after_first_free);
  first_used_one_after_first_free = (first_after_first_free->used == 1);
  second_arena_page_bitmap_set_after_first_free = mi_bitmap_is_setN(f.arena_pages->pages, f.second_slice, 1);
  second_mapped_abandoned_after_first_free = mi_page_is_abandoned_mapped(second_after_first_free);
  second_used_one_after_first_free = (second_after_first_free->used == 1);
  same_bin_abandoned_count_two_after_first_free = (
      mi_atomic_load_relaxed(&f.heap->abandoned_count[f.bin]) == 2);
  same_bin_abandoned_bitmap_both_set_after_first_free = (
      mi_bitmap_is_setN(f.arena_pages->pages_abandoned[f.bin], f.first_slice, 1)
      && mi_bitmap_is_setN(f.arena_pages->pages_abandoned[f.bin], f.second_slice, 1));
  first_free_still_live_route_two_pages = (
      first_page_map_registered_after_first_free && second_page_map_registered_after_first_free
      && first_arena_page_bitmap_set_after_first_free && second_arena_page_bitmap_set_after_first_free
      && first_mapped_abandoned_after_first_free && second_mapped_abandoned_after_first_free
      && first_used_one_after_first_free && second_used_one_after_first_free
      && same_bin_abandoned_count_two_after_first_free
      && same_bin_abandoned_bitmap_both_set_after_first_free
      && !mi_page_is_owned(first_after_first_free));
  if (!first_free_still_live_route_two_pages) {
    f.first_survivor = NULL;
    f.second_client = NULL;
    goto done;
  }

  mi_free(f.second_client);
  f.second_client = NULL;
  second_page_map_unregistered_after_second_free = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.second_client_address) == NULL);
  second_arena_page_bitmap_clear_after_second_free = mi_bitmap_is_clearN(
      f.arena_pages->pages, f.second_slice, 1);
  second_arena_slice_released_after_second_free = mi_bbitmap_is_setN(
      f.arena->slices_free, f.second_slice, f.second_slices);
  mi_page_t* const first_after_second_free = _mi_safe_ptr_page(
      (const void*)(uintptr_t)f.first_survivor_address);
  first_page_map_registered_after_second_free = (first_after_second_free != NULL
      && (uintptr_t)first_after_second_free == f.first_page_identity);
  if (!first_page_map_registered_after_second_free) {
    f.first_survivor = NULL;
    goto done;
  }
  first_arena_page_bitmap_set_after_second_free = mi_bitmap_is_setN(
      f.arena_pages->pages, f.first_slice, 1);
  first_mapped_abandoned_after_second_free = mi_page_is_abandoned_mapped(first_after_second_free);
  first_used_one_after_second_free = (first_after_second_free->used == 1);
  same_bin_abandoned_count_one_after_second_free = (
      mi_atomic_load_relaxed(&f.heap->abandoned_count[f.bin]) == 1);
  same_bin_abandoned_bitmap_first_only_after_second_free = (
      mi_bitmap_is_setN(f.arena_pages->pages_abandoned[f.bin], f.first_slice, 1)
      && mi_bitmap_is_clearN(f.arena_pages->pages_abandoned[f.bin], f.second_slice, 1));
  second_free_released_page_route_one_page = (
      second_page_map_unregistered_after_second_free
      && second_arena_page_bitmap_clear_after_second_free
      && second_arena_slice_released_after_second_free
      && first_page_map_registered_after_second_free
      && first_arena_page_bitmap_set_after_second_free
      && first_mapped_abandoned_after_second_free && first_used_one_after_second_free
      && same_bin_abandoned_count_one_after_second_free
      && same_bin_abandoned_bitmap_first_only_after_second_free);
  if (!second_free_released_page_route_one_page) {
    f.first_survivor = NULL;
    goto done;
  }

  mi_free(f.first_survivor);
  f.first_survivor = NULL;
  // After the terminal release no page pointer is dereferenced; all remaining
  // observations are PageMap/arena/heap metadata with their stable owners.
  first_page_map_unregistered_after_final_free = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.first_survivor_address) == NULL);
  first_arena_page_bitmap_clear_after_final_free = mi_bitmap_is_clearN(
      f.arena_pages->pages, f.first_slice, 1);
  first_arena_slice_released_after_final_free = mi_bbitmap_is_setN(
      f.arena->slices_free, f.first_slice, f.first_slices);
  same_bin_abandoned_count_zero_after_final_free = (
      mi_atomic_load_relaxed(&f.heap->abandoned_count[f.bin]) == 0);
  same_bin_abandoned_bitmap_empty_after_final_free = (
      mi_bitmap_is_clearN(f.arena_pages->pages_abandoned[f.bin], f.first_slice, 1)
      && mi_bitmap_is_clearN(f.arena_pages->pages_abandoned[f.bin], f.second_slice, 1));
  final_free_released_all_route_empty = (
      first_page_map_unregistered_after_final_free
      && second_page_map_unregistered_after_second_free
      && same_bin_abandoned_count_zero_after_final_free
      && same_bin_abandoned_bitmap_empty_after_final_free);
  heap_destroy_safe = true;

  valid = arena_backed && both_medium && first_distinct_clients_share_page && distinct_pages
      && same_bin && same_bin_queue_count_two_before_exit
      && same_bin_queue_bidirectional_links_before_exit
      && same_bin_queue_successor_visits_both_before_exit
      && first_used_two_before_exit && second_used_one_before_exit
      && first_nonfull_before_exit && second_nonfull_before_exit
      && slice_spans_nonempty_and_disjoint && pages_share_paired_arena
      && route_two_pages_before_join && producer_teardown_completed_before_consumer_free
      && consumer_joined_before_first_free && first_page_map_registered_after_join
      && second_page_map_registered_after_join && first_arena_page_bitmap_set_after_join
      && second_arena_page_bitmap_set_after_join && first_mapped_abandoned_after_join
      && second_mapped_abandoned_after_join && same_bin_abandoned_count_two_after_join
      && same_bin_abandoned_bitmap_both_set_after_join && first_free_still_live_route_two_pages
      && first_page_map_registered_after_first_free && first_arena_page_bitmap_set_after_first_free
      && first_mapped_abandoned_after_first_free && first_used_one_after_first_free
      && second_page_map_registered_after_first_free && second_arena_page_bitmap_set_after_first_free
      && second_mapped_abandoned_after_first_free && second_used_one_after_first_free
      && same_bin_abandoned_count_two_after_first_free
      && same_bin_abandoned_bitmap_both_set_after_first_free
      && second_free_released_page_route_one_page && second_page_map_unregistered_after_second_free
      && second_arena_page_bitmap_clear_after_second_free && second_arena_slice_released_after_second_free
      && first_page_map_registered_after_second_free && first_arena_page_bitmap_set_after_second_free
      && first_mapped_abandoned_after_second_free && first_used_one_after_second_free
      && same_bin_abandoned_count_one_after_second_free
      && same_bin_abandoned_bitmap_first_only_after_second_free
      && final_free_released_all_route_empty && first_page_map_unregistered_after_final_free
      && first_arena_page_bitmap_clear_after_final_free && first_arena_slice_released_after_final_free
      && same_bin_abandoned_count_zero_after_final_free
      && same_bin_abandoned_bitmap_empty_after_final_free;

done:
  if (started) pthread_join(worker, NULL);
  // A failed lifetime gate intentionally leaks rather than passing a possibly
  // stale client/page ownership into public free or heap destruction.
  if (heap_destroy_safe && f.heap != NULL) mi_heap_destroy(f.heap);
  if (reclaim_option_changed) mi_option_set(mi_option_page_reclaim_on_free, old_reclaim);
  if (valid) {
    printf("CRABC_MI_AGGREGATE_SAME_BIN_STILL_LIVE_TRACE_BEGIN\n");
    printf("trace.aggregate_same_bin_still_live.arena_backed=%d\n", arena_backed);
    printf("trace.aggregate_same_bin_still_live.both_medium=%d\n", both_medium);
    printf("trace.aggregate_same_bin_still_live.first_distinct_clients_share_page=%d\n", first_distinct_clients_share_page);
    printf("trace.aggregate_same_bin_still_live.distinct_pages=%d\n", distinct_pages);
    printf("trace.aggregate_same_bin_still_live.same_bin=%d\n", same_bin);
    printf("trace.aggregate_same_bin_still_live.same_bin_queue_count_two_before_exit=%d\n", same_bin_queue_count_two_before_exit);
    printf("trace.aggregate_same_bin_still_live.same_bin_queue_bidirectional_links_before_exit=%d\n", same_bin_queue_bidirectional_links_before_exit);
    printf("trace.aggregate_same_bin_still_live.same_bin_queue_successor_visits_both_before_exit=%d\n", same_bin_queue_successor_visits_both_before_exit);
    printf("trace.aggregate_same_bin_still_live.first_used_two_before_exit=%d\n", first_used_two_before_exit);
    printf("trace.aggregate_same_bin_still_live.second_used_one_before_exit=%d\n", second_used_one_before_exit);
    printf("trace.aggregate_same_bin_still_live.first_nonfull_before_exit=%d\n", first_nonfull_before_exit);
    printf("trace.aggregate_same_bin_still_live.second_nonfull_before_exit=%d\n", second_nonfull_before_exit);
    printf("trace.aggregate_same_bin_still_live.slice_spans_nonempty_and_disjoint=%d\n", slice_spans_nonempty_and_disjoint);
    printf("trace.aggregate_same_bin_still_live.pages_share_paired_arena=%d\n", pages_share_paired_arena);
    printf("trace.aggregate_same_bin_still_live.route_two_pages_before_join=%d\n", route_two_pages_before_join);
    printf("trace.aggregate_same_bin_still_live.producer_teardown_completed_before_consumer_free=%d\n", producer_teardown_completed_before_consumer_free);
    printf("trace.aggregate_same_bin_still_live.consumer_joined_before_first_free=%d\n", consumer_joined_before_first_free);
    printf("trace.aggregate_same_bin_still_live.first_page_map_registered_after_join=%d\n", first_page_map_registered_after_join);
    printf("trace.aggregate_same_bin_still_live.second_page_map_registered_after_join=%d\n", second_page_map_registered_after_join);
    printf("trace.aggregate_same_bin_still_live.first_arena_page_bitmap_set_after_join=%d\n", first_arena_page_bitmap_set_after_join);
    printf("trace.aggregate_same_bin_still_live.second_arena_page_bitmap_set_after_join=%d\n", second_arena_page_bitmap_set_after_join);
    printf("trace.aggregate_same_bin_still_live.first_mapped_abandoned_after_join=%d\n", first_mapped_abandoned_after_join);
    printf("trace.aggregate_same_bin_still_live.second_mapped_abandoned_after_join=%d\n", second_mapped_abandoned_after_join);
    printf("trace.aggregate_same_bin_still_live.same_bin_abandoned_count_two_after_join=%d\n", same_bin_abandoned_count_two_after_join);
    printf("trace.aggregate_same_bin_still_live.same_bin_abandoned_bitmap_both_set_after_join=%d\n", same_bin_abandoned_bitmap_both_set_after_join);
    printf("trace.aggregate_same_bin_still_live.first_free_still_live_route_two_pages=%d\n", first_free_still_live_route_two_pages);
    printf("trace.aggregate_same_bin_still_live.first_page_map_registered_after_first_free=%d\n", first_page_map_registered_after_first_free);
    printf("trace.aggregate_same_bin_still_live.first_arena_page_bitmap_set_after_first_free=%d\n", first_arena_page_bitmap_set_after_first_free);
    printf("trace.aggregate_same_bin_still_live.first_mapped_abandoned_after_first_free=%d\n", first_mapped_abandoned_after_first_free);
    printf("trace.aggregate_same_bin_still_live.first_used_one_after_first_free=%d\n", first_used_one_after_first_free);
    printf("trace.aggregate_same_bin_still_live.second_page_map_registered_after_first_free=%d\n", second_page_map_registered_after_first_free);
    printf("trace.aggregate_same_bin_still_live.second_arena_page_bitmap_set_after_first_free=%d\n", second_arena_page_bitmap_set_after_first_free);
    printf("trace.aggregate_same_bin_still_live.second_mapped_abandoned_after_first_free=%d\n", second_mapped_abandoned_after_first_free);
    printf("trace.aggregate_same_bin_still_live.second_used_one_after_first_free=%d\n", second_used_one_after_first_free);
    printf("trace.aggregate_same_bin_still_live.same_bin_abandoned_count_two_after_first_free=%d\n", same_bin_abandoned_count_two_after_first_free);
    printf("trace.aggregate_same_bin_still_live.same_bin_abandoned_bitmap_both_set_after_first_free=%d\n", same_bin_abandoned_bitmap_both_set_after_first_free);
    printf("trace.aggregate_same_bin_still_live.second_free_released_page_route_one_page=%d\n", second_free_released_page_route_one_page);
    printf("trace.aggregate_same_bin_still_live.second_page_map_unregistered_after_second_free=%d\n", second_page_map_unregistered_after_second_free);
    printf("trace.aggregate_same_bin_still_live.second_arena_page_bitmap_clear_after_second_free=%d\n", second_arena_page_bitmap_clear_after_second_free);
    printf("trace.aggregate_same_bin_still_live.second_arena_slice_released_after_second_free=%d\n", second_arena_slice_released_after_second_free);
    printf("trace.aggregate_same_bin_still_live.first_page_map_registered_after_second_free=%d\n", first_page_map_registered_after_second_free);
    printf("trace.aggregate_same_bin_still_live.first_arena_page_bitmap_set_after_second_free=%d\n", first_arena_page_bitmap_set_after_second_free);
    printf("trace.aggregate_same_bin_still_live.first_mapped_abandoned_after_second_free=%d\n", first_mapped_abandoned_after_second_free);
    printf("trace.aggregate_same_bin_still_live.first_used_one_after_second_free=%d\n", first_used_one_after_second_free);
    printf("trace.aggregate_same_bin_still_live.same_bin_abandoned_count_one_after_second_free=%d\n", same_bin_abandoned_count_one_after_second_free);
    printf("trace.aggregate_same_bin_still_live.same_bin_abandoned_bitmap_first_only_after_second_free=%d\n", same_bin_abandoned_bitmap_first_only_after_second_free);
    printf("trace.aggregate_same_bin_still_live.final_free_released_all_route_empty=%d\n", final_free_released_all_route_empty);
    printf("trace.aggregate_same_bin_still_live.first_page_map_unregistered_after_final_free=%d\n", first_page_map_unregistered_after_final_free);
    printf("trace.aggregate_same_bin_still_live.first_arena_page_bitmap_clear_after_final_free=%d\n", first_arena_page_bitmap_clear_after_final_free);
    printf("trace.aggregate_same_bin_still_live.first_arena_slice_released_after_final_free=%d\n", first_arena_slice_released_after_final_free);
    printf("trace.aggregate_same_bin_still_live.same_bin_abandoned_count_zero_after_final_free=%d\n", same_bin_abandoned_count_zero_after_final_free);
    printf("trace.aggregate_same_bin_still_live.same_bin_abandoned_bitmap_empty_after_final_free=%d\n", same_bin_abandoned_bitmap_empty_after_final_free);
    printf("trace.aggregate_same_bin_still_live.valid=%d\n", valid);
    printf("CRABC_MI_AGGREGATE_SAME_BIN_STILL_LIVE_TRACE_END\n");
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
        raise EvidenceError("cannot read aggregate-same-bin-StillLive schema") from error
    required = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "rust_test", "schema", "scope", "source_anchors",
        "target", "trace", "upstream",
    }
    if not isinstance(schema, dict) or set(schema) != required or type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("aggregate-same-bin-StillLive schema fields drifted")
    if schema["schema"] != "crabc-mimalloc-x86_64-aggregate-same-bin-still-live-evidence" or schema["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("aggregate-same-bin-StillLive schema identity drifted")
    if not exactly_matches(schema["target"], EXPECTED_TARGET) or not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("aggregate-same-bin-StillLive boundary drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate pinned aggregate-same-bin-StillLive upstream") from error
    if (pin["sha256"] != EXPECTED_ARCHIVE_SHA256 or pin["archive_root"] != EXPECTED_UPSTREAM["archive_root"]
            or pin["revision"] != EXPECTED_UPSTREAM["revision"] or pin["version"] != EXPECTED_UPSTREAM["version"]):
        raise EvidenceError("aggregate-same-bin-StillLive upstream pin drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("aggregate-same-bin-StillLive C source set drifted")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("aggregate-same-bin-StillLive release flags drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("aggregate-same-bin-StillLive compile definitions drifted")
    if not exactly_matches(schema["rust_test"], {
        "path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER,
    }):
        raise EvidenceError("aggregate-same-bin-StillLive Rust test selection drifted")
    if not exactly_matches(schema["trace"], {
        "begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES,
    }):
        raise EvidenceError("aggregate-same-bin-StillLive trace contract drifted")
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("aggregate-same-bin-StillLive C probe hash drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("aggregate-same-bin-StillLive source anchors drifted")
    observed = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("aggregate-same-bin-StillLive source anchor shape drifted")
        if (type(anchor["member"]) is not str or type(anchor["start_line"]) is not int
                or type(anchor["end_line"]) is not int or type(anchor["sha256"]) is not str):
            raise EvidenceError("aggregate-same-bin-StillLive source anchor type drifted")
        observed.append((anchor["member"], anchor["start_line"], anchor["end_line"], anchor["sha256"]))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("aggregate-same-bin-StillLive source anchors drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated = []
    for anchor in schema["source_anchors"]:
        member = source / str(anchor["member"])
        digest = sha256_bytes(source_range(member.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))) if member.is_file() else None
        if digest != anchor["sha256"]:
            raise EvidenceError(f"aggregate-same-bin-StillLive source anchor drifted: {anchor['member']}")
        validated.append(dict(anchor))
    return validated


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    non_integer = sorted(key for key, value in trace.items() if type(value) is not int)
    wrong = sorted(key for key in EXPECTED_TRACE_VALUES if type(trace.get(key)) is int and trace[key] != 1)
    if missing or unexpected or non_integer or wrong:
        raise EvidenceError(f"{description} violates the fixed {len(EXPECTED_TRACE_VALUES)}-field trace contract")


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        trace = run.parse_address_independent_trace(output, begin=TRACE_BEGIN, end=TRACE_END, description=description)
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
        compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", str(source / "include"), "-I", str(source / "src"), *schema["release_flags"], str(probe),
        *(str(source / member) for member in schema["release_source_set"]), "-pthread", "-o", str(binary),
    ]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    if [item for item in command if item in EXPECTED_COMPILE_DEFINITIONS] != list(schema["compile_definitions"]):
        raise EvidenceError("aggregate-same-bin-StillLive C compile definitions drifted")
    if [item for item in command if item in run.CONFIGURATION_PROFILES["release"]] != list(schema["release_flags"]):
        raise EvidenceError("aggregate-same-bin-StillLive C release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("aggregate-same-bin-StillLive C command lacks pthread/TLS requirements")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/aggregate-same-bin-still-live.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/aggregate-same-bin-still-live-c",
    ]
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise EvidenceError("aggregate-same-bin-StillLive normalized C command drifted")


def rust_command(cargo: str, target_dir: Path) -> list[str]:
    return [
        cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir),
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER,
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]


def validate_normalized_rust_command(command: object) -> None:
    expected = [
        "test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER,
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]
    if not isinstance(command, list) or not command or Path(command[0]).name != "cargo" or command[1:] != expected:
        raise EvidenceError("aggregate-same-bin-StillLive normalized Rust command drifted")


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    probe = temporary / "aggregate-same-bin-still-live.c"
    binary = temporary / "aggregate-same-bin-still-live-c"
    probe.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_command(compiler, source, probe, binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "aggregate-same-bin-StillLive C build")
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "aggregate-same-bin-StillLive C ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source)
        run.require_success(execution, "aggregate-same-bin-StillLive C execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/aggregate-same-bin-still-live-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": parse_trace(str(execution["stdout"]), description="pinned C aggregate-same-bin-StillLive trace"),
    }


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    target_dir = temporary / "rust-target"
    command = rust_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, environment=environment)
        run.require_success(execution, "Rust aggregate-same-bin-StillLive fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust aggregate-same-bin-StillLive fixture passed {passed} tests")
    return {
        "cargo_command": normalize_command(command, temporary, None),
        "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
        "passed_test_count": passed,
        "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)},
        "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"},
        "trace": parse_trace(str(execution["stdout"]) + "\n" + str(execution["stderr"]), description="Rust aggregate-same-bin-StillLive trace"),
    }


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C aggregate-same-bin-StillLive trace")
    validate_trace(rust_trace, description="Rust aggregate-same-bin-StillLive trace")
    mismatch = [key for key in EXPECTED_TRACE_VALUES if c_trace[key] != rust_trace[key]]
    if mismatch:
        raise EvidenceError("C/Rust aggregate-same-bin-StillLive mismatch: " + ", ".join(mismatch))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def report_from_results(schema: Mapping[str, Any], provenance: Mapping[str, str], archive_sha256: str, anchors: Sequence[Mapping[str, Any]], c_probe: Mapping[str, Any], rust_probe: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_probe["trace"], rust_probe["trace"]),
        "format": 1,
        "kind": "mimalloc-x86_64-aggregate-same-bin-still-live-differential-evidence",
        "profile": schema["profile"],
        "provenance": dict(provenance),
        "rust_probe": dict(rust_probe),
        "scope": schema["scope"],
        "source": {"archive_sha256": archive_sha256, "anchors": [dict(anchor) for anchor in anchors], "release_flags": list(schema["release_flags"]), "release_source_set": list(schema["release_source_set"])},
        "status": "passed",
        "target": schema["target"],
        "trace": schema["trace"],
        "upstream": schema["upstream"],
    }


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("aggregate-same-bin-StillLive report shape/status drifted")
    if report["kind"] != "mimalloc-x86_64-aggregate-same-bin-still-live-differential-evidence" or report["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("aggregate-same-bin-StillLive report identity drifted")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("aggregate-same-bin-StillLive report boundary drifted")
    if report["provenance"] not in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"}):
        raise EvidenceError("aggregate-same-bin-StillLive report lacks native provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("aggregate-same-bin-StillLive report trace drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"} or source["archive_sha256"] != run.load_pin()["sha256"] or not exactly_matches(source["anchors"], schema["source_anchors"]) or not exactly_matches(source["release_flags"], schema["release_flags"]) or not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("aggregate-same-bin-StillLive report source drifted")
    c_probe, rust_probe = report["c_probe"], report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("aggregate-same-bin-StillLive C probe shape drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("aggregate-same-bin-StillLive Rust probe shape drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF) or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/aggregate-same-bin-still-live-c"] or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("aggregate-same-bin-StillLive C probe identity drifted")
    if rust_probe["passed_test_count"] != 1 or not exactly_matches(rust_probe["target_dir"], {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}):
        raise EvidenceError("aggregate-same-bin-StillLive Rust result drifted")
    if not exactly_matches(rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}) or not exactly_matches(rust_probe["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}):
        raise EvidenceError("aggregate-same-bin-StillLive Rust provenance drifted")
    validate_trace(c_probe["trace"], description="report C trace")
    validate_trace(rust_probe["trace"], description="report Rust trace")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise EvidenceError("aggregate-same-bin-StillLive comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lock = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-aggregate-same-bin-still-live-") as name:
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


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    parsed = parser.parse_args(arguments)
    try:
        report = run_evidence(offline=parsed.offline, report_path=parsed.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 aggregate-same-bin-StillLive differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 aggregate-same-bin-StillLive differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {relative(parsed.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
