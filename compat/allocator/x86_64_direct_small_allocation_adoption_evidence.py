#!/usr/bin/env python3
"""Prove one native x86-64 direct-small allocation-time adoption differential.

The pinned mimalloc v3.5.0 C fixture abandons one nonfull arena-backed
1024-byte direct-small page with two local allocations. Its next same-heap
small allocation must miss the cleared direct cache, claim that exact
mapped-abandoned page, requeue it, restore the complete rounded direct-cache
range, and consume its third block. The Rust half explicitly consumes the
existing private test-only adoption handoff before the matching allocation.

This is private native Linux/x86-64 fixed-mimalloc engine evidence only. It
does not claim generic Rust abandoned-page scanning, public mi_* behavior,
general or cross-thread abandonment/adoption, remote routing, lifecycle,
public x86 runtime support, or AArch64 evidence.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_mapped_adoption_evidence.py"
_spec = importlib.util.spec_from_file_location("mapped_adoption_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
_BASE_LOAD_SCHEMA = _base.load_schema

SCHEMA_PATH = ROOT / "compat/allocator/x86_64-direct-small-allocation-adoption-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/direct-small-allocation-adoption.json"
EXPECTED_PROFILE = "linux-x86_64-private-direct-small-allocation-time-adoption"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/dynamic_theap.rs"
RUST_TEST_FILTER = (
    "dynamic_theap::tests::"
    "x86_64_direct_small_allocation_adoption_trace_matches_pinned_c_protocol"
)
TRACE_BEGIN = "CRABC_MI_DIRECT_SMALL_ADOPTION_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DIRECT_SMALL_ADOPTION_TRACE_END"
EVIDENCE_SCHEMA = "crabc-mimalloc-x86_64-direct-small-allocation-adoption-evidence"
EVIDENCE_KIND = (
    "mimalloc-x86_64-direct-small-allocation-time-adoption-differential-evidence"
)
EVIDENCE_LABEL = "direct-small-allocation-adoption"
PROBE_STEM = "direct-small-allocation-adoption"
TEMPORARY_PREFIX = "crabc-mimalloc-x86-direct-small-allocation-adoption-"

EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "allocation_time_same_origin_adoption_only": True,
    "arena_backed_only": True,
    "cross_thread_adoption_claimed": False,
    "direct_small_only": True,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_remote_free_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "rust_test_adapter_adopt_before_third_allocation_only": True,
    "same_thread_same_theap_only": True,
    "thread_exit_claimed": False,
}
EXPECTED_SOURCE_ANCHORS = (
    ("include/mimalloc.h", 122, 123, "254ce29a1c8187dae3f5cccd5f98bbf7f71f448f68cbb5e822dd6f74f291778c"),
    ("include/mimalloc/types.h", 430, 449, "9befd05f3264611334cec9745bbd1de88fe83f01b4a1c7f2b9beadb3e6badb5f"),
    ("include/mimalloc/prim-tls.h", 412, 421, "466e1c5ef5f6fcddae9a518965638676a61bd41b8cbde85a5c0bcba76e2710dd"),
    ("src/alloc.c", 29, 58, "ebecab0a27c74739c146a986504e36e8361dbac617a78071cc97ef8d3e67602a"),
    ("src/alloc.c", 204, 240, "d9e591aba82a335db52a1a97e3a5fe8ba080d1bc29ea2b91960cb07f33306164"),
    ("src/arena.c", 725, 775, "bb3a4ff85331df5b441fab7ad8b957afe7b9493a095e6591a046eeedfa2281e5"),
    ("src/arena.c", 1130, 1144, "3ebc454a5a3703d735ed848a6c3fc6e02aef03a8e5c5155b753f32cafe34ac99"),
    ("src/arena.c", 1304, 1355, "d7328658d88aa8c24dabcd1a093e5857b6bc699b03677eb4e8ab3c7d160c6dbb"),
    ("src/page-map.c", 460, 515, "c752c966d40e6ebd16795295a1a87d3b8a762cdfc4ba752aa3a043df44dfb495"),
    ("src/page-queue.c", 204, 244, "4216ce3f998d0a8c3891e0c89e1feaa34aff407d10e14135e68334ce833d6e6b"),
    ("src/page-queue.c", 252, 333, "bed2746841d68f31300727a5bf7716283abbadc318772183d94c56d654cf59a0"),
    ("src/page.c", 277, 289, "fcf1bbb7f05a126878a5d82df3680532710c9a7e457a628e355a716c75c157d1"),
    ("src/page.c", 291, 303, "d363079d5e484919082b5602cc3757a3e3a357e68594fc040d902232c7458bbf"),
    ("src/page.c", 308, 340, "f4494b356b497a4f2b4a78c58c0da8b70db59769db2cdb25bc667f7d6372ff3d"),
    ("src/page.c", 765, 875, "3c8a1de257b88eb5c17b54da1cca31337fc9555aaca6a1cf167f3f0f4aaa7598"),
)
EXPECTED_TRACE_VALUES = {
    "trace.direct_small_adoption.request": 1024,
    "trace.direct_small_adoption.block_size": 1024,
    "trace.direct_small_adoption.reserved": 64,
    "trace.direct_small_adoption.initial_capacity": 8,
    "trace.direct_small_adoption.initial_used": 2,
    "trace.direct_small_adoption.direct_range_start": 113,
    "trace.direct_small_adoption.direct_range_end": 128,
    "trace.direct_small_adoption.arena_backed": 1,
    "trace.direct_small_adoption.direct_small": 1,
    "trace.direct_small_adoption.two_blocks_same_page": 1,
    "trace.direct_small_adoption.initial_direct_range_matches": 1,
    "trace.direct_small_adoption.initial_regular_queue": 1,
    "trace.direct_small_adoption.initial_page_count": 1,
    "trace.direct_small_adoption.initial_remote_list_empty": 1,
    "trace.direct_small_adoption.abandoned_bitmap_before_allocation": 1,
    "trace.direct_small_adoption.abandoned_count_before_allocation": 1,
    "trace.direct_small_adoption.queue_empty_before_allocation": 1,
    "trace.direct_small_adoption.page_count_zero_before_allocation": 1,
    "trace.direct_small_adoption.direct_range_empty_before_allocation": 1,
    "trace.direct_small_adoption.page_map_and_arena_bitmap_preserved": 1,
    "trace.direct_small_adoption.remote_list_empty_before_allocation": 1,
    "trace.direct_small_adoption.allocation_is_same_page": 1,
    "trace.direct_small_adoption.abandoned_bitmap_cleared": 1,
    "trace.direct_small_adoption.abandoned_count_cleared": 1,
    "trace.direct_small_adoption.abandoned_identity_cleared": 1,
    "trace.direct_small_adoption.original_theap_restored": 1,
    "trace.direct_small_adoption.queue_tail_reassociated": 1,
    "trace.direct_small_adoption.page_count_restored": 1,
    "trace.direct_small_adoption.direct_range_restored": 1,
    "trace.direct_small_adoption.remote_list_empty": 1,
    "trace.direct_small_adoption.used_after_allocation": 3,
    "trace.direct_small_adoption.valid": 1,
}

C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private direct-small adoption fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0 || MI_PADDING != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native two-level map and unencoded release freelist
#endif

static bool direct_cache_image(
    const mi_theap_t* theap,
    const mi_page_queue_t* queue,
    const mi_page_t* expected_page,
    size_t* start_out,
    size_t* end_out
) {
  if (theap == NULL || queue == NULL) return false;
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
    const mi_page_t* expected = (expected_page != NULL && slot >= start && slot <= index)
        ? expected_page : _mi_page_empty_get();
    if (theap->pages_free_direct[slot] != expected) return false;
  }
  if (start_out != NULL) *start_out = start;
  if (end_out != NULL) *end_out = index;
  return true;
}

int main(void) {
  const size_t request = MI_SMALL_SIZE_MAX;
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_queue_t* queue = NULL;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  void* first = NULL;
  void* survivor = NULL;
  void* adopted = NULL;
  bool valid = false;

  size_t block_size = 0, reserved = 0, initial_capacity = 0, initial_used = 0;
  size_t direct_start = 0, direct_end = 0, initial_regular_queue = 0, initial_page_count = 0;
  size_t used_after_allocation = 0;
  int arena_backed = 0, direct_small = 0, two_blocks_same_page = 0;
  int initial_direct_range_matches = 0, initial_remote_list_empty = 0;
  int abandoned_bitmap_before_allocation = 0, abandoned_count_before_allocation = 0;
  int queue_empty_before_allocation = 0, page_count_zero_before_allocation = 0;
  int direct_range_empty_before_allocation = 0, page_map_and_arena_bitmap_preserved = 0;
  int remote_list_empty_before_allocation = 0, allocation_is_same_page = 0;
  int abandoned_bitmap_cleared = 0, abandoned_count_cleared = 0;
  int abandoned_identity_cleared = 0, original_theap_restored = 0;
  int queue_tail_reassociated = 0, page_count_restored = 0;
  int direct_range_restored = 0, remote_list_empty = 0;

  mi_thread_init();
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto output;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto output;
  theap = _mi_heap_theap(heap);
  first = mi_heap_malloc_small(heap, request);
  survivor = mi_heap_malloc_small(heap, request);
  if (first == NULL || survivor == NULL || theap == NULL) goto output;

  page = _mi_ptr_page(first);
  if (page == NULL || _mi_ptr_page(survivor) != page
      || page->memid.memkind != MI_MEM_ARENA
      || page->block_size != MI_SMALL_SIZE_MAX
      || mi_page_is_full(page)) goto output;
  queue = mi_page_queue(theap, page->block_size);
  arena = mi_memid_arena(page->memid);
  if (queue == NULL || arena == NULL || queue->count != 1
      || queue->first != page || queue->last != page) goto output;
  arena_pages = mi_atomic_load_ptr_acquire(
      mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  if (arena_pages == NULL || arena_pages->pages == NULL
      || arena_pages->pages_abandoned[_mi_bin(page->block_size)] == NULL) goto output;

  block_size = page->block_size;
  reserved = page->reserved;
  initial_capacity = page->capacity;
  initial_used = page->used;
  direct_small = (page->block_size <= MI_SMALL_SIZE_MAX);
  arena_backed = (page->memid.memkind == MI_MEM_ARENA);
  two_blocks_same_page = (_mi_ptr_page(first) == page && _mi_ptr_page(survivor) == page);
  initial_regular_queue = queue->count;
  initial_page_count = theap->page_count;
  initial_remote_list_empty = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  initial_direct_range_matches = direct_cache_image(
      theap, queue, page, &direct_start, &direct_end);
  if (!arena_backed || !direct_small || !two_blocks_same_page
      || !initial_direct_range_matches || initial_remote_list_empty == 0
      || !mi_bitmap_is_set(arena_pages->pages, page->memid.mem.arena.slice_index)) goto output;

  _mi_page_abandon(page, queue);
  const size_t bin = _mi_bin(page->block_size);
  const size_t slice_index = page->memid.mem.arena.slice_index;
  abandoned_bitmap_before_allocation = (mi_page_is_abandoned(page)
      && mi_page_is_abandoned_mapped(page)
      && mi_bitmap_is_set(arena_pages->pages_abandoned[bin], slice_index));
  abandoned_count_before_allocation = (mi_atomic_load_relaxed(&heap->abandoned_count[bin]) == 1);
  queue_empty_before_allocation = (queue->count == 0 && queue->first == NULL && queue->last == NULL);
  page_count_zero_before_allocation = (theap->page_count == 0);
  direct_range_empty_before_allocation = direct_cache_image(theap, queue, NULL, NULL, NULL);
  page_map_and_arena_bitmap_preserved = (_mi_checked_ptr_page(first) == page
      && _mi_checked_ptr_page(survivor) == page
      && mi_bitmap_is_set(arena_pages->pages, slice_index));
  remote_list_empty_before_allocation =
      (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  if (!abandoned_bitmap_before_allocation || !abandoned_count_before_allocation
      || !queue_empty_before_allocation || !page_count_zero_before_allocation
      || !direct_range_empty_before_allocation || !page_map_and_arena_bitmap_preserved
      || !remote_list_empty_before_allocation) goto output;

  adopted = mi_heap_malloc_small(heap, request);
  if (adopted == NULL) goto output;
  allocation_is_same_page = (_mi_ptr_page(adopted) == page);
  abandoned_bitmap_cleared = (!mi_page_is_abandoned_mapped(page)
      && !mi_bitmap_is_set(arena_pages->pages_abandoned[bin], slice_index));
  abandoned_count_cleared = (mi_atomic_load_relaxed(&heap->abandoned_count[bin]) == 0);
  abandoned_identity_cleared = !mi_page_is_abandoned(page);
  original_theap_restored = (page->theap == theap
      && _mi_page_associated_theap_peek(page) == theap);
  queue_tail_reassociated = (queue->count == 1 && queue->first == page
      && queue->last == page && page->next == NULL && page->prev == NULL);
  page_count_restored = (theap->page_count == 1);
  direct_range_restored = direct_cache_image(theap, queue, page, NULL, NULL);
  remote_list_empty = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  used_after_allocation = page->used;
  valid = (request == 1024 && block_size == 1024 && reserved == 64
      && initial_capacity == 8 && initial_used == 2
      && direct_start == 113 && direct_end == 128
      && arena_backed && direct_small && two_blocks_same_page
      && initial_direct_range_matches && initial_regular_queue == 1
      && initial_page_count == 1 && initial_remote_list_empty
      && abandoned_bitmap_before_allocation && abandoned_count_before_allocation
      && queue_empty_before_allocation && page_count_zero_before_allocation
      && direct_range_empty_before_allocation && page_map_and_arena_bitmap_preserved
      && remote_list_empty_before_allocation && allocation_is_same_page
      && abandoned_bitmap_cleared && abandoned_count_cleared
      && abandoned_identity_cleared && original_theap_restored
      && queue_tail_reassociated && page_count_restored && direct_range_restored
      && remote_list_empty && used_after_allocation == 3);

output:
  printf("CRABC_MI_DIRECT_SMALL_ADOPTION_TRACE_BEGIN\n");
#define OUT_N(k,v) printf("trace.direct_small_adoption.%s=%zu\n", k, (size_t)(v))
#define OUT_B(k,v) printf("trace.direct_small_adoption.%s=%d\n", k, (v) ? 1 : 0)
  OUT_N("request", request); OUT_N("block_size", block_size); OUT_N("reserved", reserved);
  OUT_N("initial_capacity", initial_capacity); OUT_N("initial_used", initial_used);
  OUT_N("direct_range_start", direct_start); OUT_N("direct_range_end", direct_end);
  OUT_B("arena_backed", arena_backed); OUT_B("direct_small", direct_small);
  OUT_B("two_blocks_same_page", two_blocks_same_page);
  OUT_B("initial_direct_range_matches", initial_direct_range_matches);
  OUT_N("initial_regular_queue", initial_regular_queue);
  OUT_N("initial_page_count", initial_page_count);
  OUT_B("initial_remote_list_empty", initial_remote_list_empty);
  OUT_B("abandoned_bitmap_before_allocation", abandoned_bitmap_before_allocation);
  OUT_B("abandoned_count_before_allocation", abandoned_count_before_allocation);
  OUT_B("queue_empty_before_allocation", queue_empty_before_allocation);
  OUT_B("page_count_zero_before_allocation", page_count_zero_before_allocation);
  OUT_B("direct_range_empty_before_allocation", direct_range_empty_before_allocation);
  OUT_B("page_map_and_arena_bitmap_preserved", page_map_and_arena_bitmap_preserved);
  OUT_B("remote_list_empty_before_allocation", remote_list_empty_before_allocation);
  OUT_B("allocation_is_same_page", allocation_is_same_page);
  OUT_B("abandoned_bitmap_cleared", abandoned_bitmap_cleared);
  OUT_B("abandoned_count_cleared", abandoned_count_cleared);
  OUT_B("abandoned_identity_cleared", abandoned_identity_cleared);
  OUT_B("original_theap_restored", original_theap_restored);
  OUT_B("queue_tail_reassociated", queue_tail_reassociated);
  OUT_B("page_count_restored", page_count_restored);
  OUT_B("direct_range_restored", direct_range_restored);
  OUT_B("remote_list_empty", remote_list_empty);
  OUT_N("used_after_allocation", used_after_allocation);
  OUT_B("valid", valid);
  printf("CRABC_MI_DIRECT_SMALL_ADOPTION_TRACE_END\n");

  if (adopted != NULL) mi_free(adopted);
  if (first != NULL) mi_free(first);
  if (survivor != NULL) mi_free(survivor);
  if (heap != NULL) {
    mi_heap_collect(heap, true);
    mi_heap_destroy(heap);
  }
  return valid ? 0 : 2;
}
'''

for _name in (
    "SCHEMA_PATH",
    "REPORT_DEFAULT",
    "EXPECTED_PROFILE",
    "RUST_TEST_SOURCE",
    "RUST_TEST_FILTER",
    "TRACE_BEGIN",
    "TRACE_END",
    "EVIDENCE_SCHEMA",
    "EVIDENCE_KIND",
    "EVIDENCE_LABEL",
    "PROBE_STEM",
    "TEMPORARY_PREFIX",
    "EXPECTED_SCOPE",
    "EXPECTED_SOURCE_ANCHORS",
    "EXPECTED_TRACE_VALUES",
    "C_TRACE_PROBE",
):
    setattr(_base, _name, globals()[_name])


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    """Bind the imported reusable validator to this lane's schema path."""

    # The base function's default path was evaluated while its medium-page
    # module loaded. Passing this lane's path explicitly prevents a direct
    # fixture from silently reading or validating that sibling schema.
    return _BASE_LOAD_SCHEMA(path)


_base.load_schema = load_schema

for _name in (
    "EvidenceError",
    "EXPECTED_ARCHIVE_SHA256",
    "EXPECTED_C_ELF",
    "EXPECTED_COMPILE_DEFINITIONS",
    "EXPECTED_TARGET",
    "EXPECTED_UPSTREAM",
    "LOCKFILE",
    "NORMALIZED_EVIDENCE_ROOT",
    "NORMALIZED_PINNED_SOURCE",
    "TARGET",
    "compare_traces",
    "c_trace_command",
    "load_schema",
    "normalize_command",
    "parse_trace",
    "relative",
    "report_from_results",
    "run_evidence",
    "rust_trace_command",
    "sha256_bytes",
    "sha256_file",
    "validate_c_command",
    "validate_normalized_c_command",
    "validate_normalized_rust_command",
    "validate_report",
    "validate_source_anchors",
    "validate_trace",
):
    globals()[_name] = getattr(_base, _name)


def _schema_template() -> dict:
    return {
        "c_probe_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "compile_definitions": list(EXPECTED_COMPILE_DEFINITIONS),
        "format": 1,
        "profile": EXPECTED_PROFILE,
        "release_flags": list(_base.run.CONFIGURATION_PROFILES["release"]),
        "release_source_set": list(_base.run.ORACLE_SOURCES),
        "rust_test": {
            "path": relative(RUST_TEST_SOURCE),
            "target_arch": "x86_64",
            "test_filter": RUST_TEST_FILTER,
        },
        "schema": EVIDENCE_SCHEMA,
        "scope": dict(EXPECTED_SCOPE),
        "source_anchors": [
            {"member": member, "start_line": start, "end_line": end, "sha256": digest}
            for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
        ],
        "target": dict(EXPECTED_TARGET),
        "trace": {
            "begin": TRACE_BEGIN,
            "end": TRACE_END,
            "expected_values": dict(EXPECTED_TRACE_VALUES),
        },
        "upstream": dict(EXPECTED_UPSTREAM),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, ValueError) as error:
        print(
            f"allocator x86-64 {EVIDENCE_LABEL} differential: FAIL: {error}",
            file=os.sys.stderr,
        )
        return 1
    print(
        f"allocator x86-64 {EVIDENCE_LABEL} differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
