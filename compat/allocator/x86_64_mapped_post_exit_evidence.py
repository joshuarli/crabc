#!/usr/bin/env python3
"""Differentially prove mapped-page free after producer Theap teardown.

The native pinned-C fixture creates an exclusive arena heap on a producer
pthread, allocates two medium blocks on one regular page, and calls the real
``mi_thread_done`` before the producer exits.  The main thread then frees the
first block while the survivor keeps the mapped abandoned page live.  The
consumer thread remains initialized, but its heap-specific associated Theap
is unavailable, so the source failed-reclaim/unowned-mapped tail is selected.

This is bounded private allocator-engine evidence only.  It does not claim
general lifecycle or reclaim parity, public x86 crabc support, or AArch64
evidence.
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-mapped-post-exit-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/mapped-post-exit.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/main_heap_page.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "main_heap_page::tests::x86_64_mapped_post_exit_trace_matches_pinned_c_protocol"
TRACE_BEGIN = "CRABC_MI_MAPPED_POST_EXIT_TRACE_BEGIN"
TRACE_END = "CRABC_MI_MAPPED_POST_EXIT_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded producer-teardown differential could not establish its claim."""


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
EXPECTED_PROFILE = "linux-x86_64-private-mapped-post-producer-theap-teardown"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "producer_theap_teardown_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
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
    ("src/free.c", 365, 515, "4f31b0716f4b8086797a84d1bfc6ca21531d1316ca37bbea18e218937fc941c1"),
    ("src/arena.c", 1304, 1409, "6a6d08e7cb4a45803619ce1c9d7efab31808068a756a727a4d3fd3d48d30413f"),
    ("src/theap.c", 97, 112, "b7615d5546c7e1eda8dd3a444ed8f21b59d1feb5ead8008f9f5c3326b3135012"),
    ("src/theap.c", 123, 152, "c7811179e91e8cd66dc0587e824265cff4db6ce660ba0639309d909dd0df519c"),
    ("src/init.c", 448, 477, "289083292b594ae6e467808000a94f3ddaacdacb0372abee002f4db779137b0c"),
    ("include/mimalloc/prim-tls.h", 412, 421, "466e1c5ef5f6fcddae9a518965638676a61bd41b8cbde85a5c0bcba76e2710dd"),
    ("src/arena.c", 1216, 1297, "5f42cce2e334fe6146608499cfd545049832daaf683cab8d707d044623404437"),
    ("src/arena.c", 1383, 1423, "9c7568705a74690b5c291dce159b31869f817e613c96870e67e96cd1f7d8d22e"),
    ("src/arena.c", 1440, 1485, "c11723e7e068192d119a66c4f4c19ac63975183f611b9065288b8d9be76a382f"),
    ("src/page-map.c", 199, 209, "adcac501bd759bc1052bd46a2931adeb23a3740f5437ed15d9f5b2596e132cd0"),
    ("src/arena.c", 207, 222, "aebd0a1e5aea4a2635853c0330b8eabd1d029891745889fa4007adb3261d53fb"),
    ("src/arena.c", 677, 696, "4c9eddf754a5717b7ed72f11fd7c1b10977afdb3bdb78ef72801e41e8a13d0c0"),
    ("include/mimalloc/types.h", 315, 350, "46e218a5dd1c5456b3e73458c2a8179d6b910d2aa615ef8574d2d9142bd804d2"),
    ("src/bitmap.h", 177, 186, "cf4b43b2a4f327a54e7827e6daa7fe27f517459e2e6c61eb467b2b049e35d4ef"),
    ("src/bitmap.h", 308, 317, "9c25d2dbef5f5a78db4f585724a714f057799339c27cf709a795aeed39e3b20f"),
)
EXPECTED_TRACE_VALUES = {
    "trace.mapped_post_exit.arena_backed": 1,
    "trace.mapped_post_exit.medium_page": 1,
    "trace.mapped_post_exit.same_page": 1,
    "trace.mapped_post_exit.mapped_before_free": 1,
    "trace.mapped_post_exit.abandoned_before_free": 1,
    "trace.mapped_post_exit.origin_theap_present_before_exit": 1,
    "trace.mapped_post_exit.producer_teardown_completed_before_consumer_free": 1,
    "trace.mapped_post_exit.free_block_is_same_page": 1,
    "trace.mapped_post_exit.survivor_keeps_page_live": 1,
    "trace.mapped_post_exit.reclaim_not_performed_after_free": 1,
    "trace.mapped_post_exit.mapped_after_free": 1,
    "trace.mapped_post_exit.abandoned_after_free": 1,
    "trace.mapped_post_exit.page_still_queue_detached": 1,
    "trace.mapped_post_exit.used_one_after_free": 1,
    "trace.mapped_post_exit.page_map_unregistered_after_final_free": 1,
    "trace.mapped_post_exit.arena_page_bitmap_clear_after_final_free": 1,
    "trace.mapped_post_exit.arena_slice_released_after_final_free": 1,
    "trace.mapped_post_exit.valid": 1,
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
#error this private mapped-post-exit fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private mapped-post-exit fixture requires the fixed release profile
#endif

typedef struct producer_context_s {
  mi_arena_id_t arena_id;
  mi_heap_t* heap;
  void* block;
  void* survivor;
  bool setup_valid;
  bool producer_theap_initialized;
  bool producer_reclaim_enabled;
  bool producer_abandon_enabled;
  bool origin_theap_present_before_exit;
  bool producer_done;
} producer_context_t;

// Keep this at the source boundary: the fixture proves one regular-medium
// page, not an arbitrary larger size class.
static const size_t request = MI_SMALL_MAX_OBJ_SIZE + 1;
static const size_t expected_medium_slice_count = 8;

static void* producer_main(void* arg) {
  producer_context_t* const context = (producer_context_t*)arg;
  mi_heap_t* heap = mi_heap_new_in_arena(context->arena_id);
  mi_page_t* page = NULL;
  mi_theap_t* theap = NULL;
  void* block = NULL;
  void* survivor = NULL;

  if (heap == NULL) goto failed;
  block = mi_heap_malloc(heap, request);
  survivor = mi_heap_malloc(heap, request);
  if (block == NULL || survivor == NULL) goto failed;

  page = _mi_ptr_page(block);
  theap = _mi_heap_theap(heap);
  context->producer_theap_initialized = (theap != NULL);
  context->producer_reclaim_enabled = (theap != NULL && theap->allow_page_reclaim);
  context->producer_abandon_enabled = (theap != NULL && theap->allow_page_abandon);
  if (page == NULL || theap == NULL || _mi_ptr_page(survivor) != page
      || page->block_size <= MI_SMALL_MAX_OBJ_SIZE
      || page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || page->memid.memkind != MI_MEM_ARENA
      || mi_page_is_full(page) || page->used != 2) {
    goto failed;
  }
  // This is the only point at which the producer Theap is read directly.
  // Its association must be proved before `mi_thread_done()` can free it.
  context->origin_theap_present_before_exit = (page->theap == theap
                                                && _mi_page_associated_theap_peek(page) == theap);

  context->heap = heap;
  context->block = block;
  context->survivor = survivor;
  context->setup_valid = (context->producer_theap_initialized
                          && context->producer_reclaim_enabled
                          && context->producer_abandon_enabled
                          && context->origin_theap_present_before_exit);
  if (!context->setup_valid) goto failed;

  // The real producer teardown abandons this live arena page and then makes
  // the producer Theap unavailable to future heap-specific associated peeks.
  mi_thread_done();
  context->producer_done = true;
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
  producer_context_t context = { 0 };
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  mi_page_t* page = NULL;
  mi_heap_t* heap = NULL;
  void* block = NULL;
  void* survivor = NULL;
  pthread_t producer;
  bool producer_started = false;
  long old_reclaim = 0;
  long old_full_retain = 0;
  bool options_changed = false;
  bool valid = false;
  int stage = 0;

  int arena_backed = 0;
  int medium_page = 0;
  int same_page = 0;
  int mapped_before_free = 0;
  int abandoned_before_free = 0;
  int origin_theap_present_before_exit = 0;
  int producer_teardown_completed_before_consumer_free = 0;
  int free_block_is_same_page = 0;
  int survivor_keeps_page_live = 0;
  int reclaim_not_performed_after_free = 0;
  int mapped_after_free = 0;
  int abandoned_after_free = 0;
  int page_still_queue_detached = 0;
  int used_one_after_free = 0;
  int page_map_unregistered_after_final_free = 0;
  int arena_page_bitmap_clear_after_final_free = 0;
  int arena_slice_released_after_final_free = 0;
  size_t bin = 0;
  size_t slice_index = 0;
  size_t slice_count = 0;
  uintptr_t page_start_address = 0;

  mi_thread_init();
  old_reclaim = mi_option_get(mi_option_page_reclaim_on_free);
  old_full_retain = mi_option_get(mi_option_page_full_retain);
  // Keep reclaim enabled in the producer, and make its live regular page
  // eligible for the real thread-teardown abandonment path.
  mi_option_set(mi_option_page_reclaim_on_free, 0);
  mi_option_set(mi_option_page_full_retain, 2);
  options_changed = true;
  stage = 1;

  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto cleanup;
  context.arena_id = arena_id;
  stage = 2;
  if (pthread_create(&producer, NULL, producer_main, &context) != 0) goto cleanup;
  producer_started = true;
  stage = 3;
  if (pthread_join(producer, NULL) != 0) goto cleanup;
  producer_started = false;
  stage = 4;

  heap = context.heap;
  block = context.block;
  survivor = context.survivor;
  if (!context.setup_valid || !context.producer_done || heap == NULL
      || block == NULL || survivor == NULL || block == survivor) goto cleanup;

  // The producer owns no live page pointer across `mi_thread_done()`.  After
  // pthread_join, reacquire the page from both still-live client pointers so
  // every subsequent page-field observation has a current safe lookup.
  page = _mi_safe_ptr_page(block);
  if (page == NULL || _mi_safe_ptr_page(survivor) != page) goto cleanup;

  arena_backed = (page->memid.memkind == MI_MEM_ARENA);
  medium_page = (page->block_size > MI_SMALL_MAX_OBJ_SIZE
                 && page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE);
  same_page = (_mi_ptr_page(block) == page && _mi_ptr_page(survivor) == page);
  mapped_before_free = mi_page_is_abandoned_mapped(page);
  abandoned_before_free = mi_page_is_abandoned(page);
  origin_theap_present_before_exit = context.origin_theap_present_before_exit;
  // `mi_thread_done()` returned in the producer and pthread_join establishes
  // that its teardown happens-before this consumer free. The associated-Theap
  // query below is only the consumer-side failed-reclaim precondition: it
  // never dereferences the stale producer `page->theap` pointer.
  producer_teardown_completed_before_consumer_free = (context.producer_done && !producer_started);
  const bool consumer_associated_theap_unavailable = (_mi_thread_is_initialized()
                                                       && _mi_page_associated_theap_peek(page) == NULL);
  free_block_is_same_page = same_page;
  if (!arena_backed || !medium_page || !same_page || !mapped_before_free
      || !abandoned_before_free || !origin_theap_present_before_exit
      || !producer_teardown_completed_before_consumer_free
      || !consumer_associated_theap_unavailable) goto cleanup;
  bin = _mi_bin(page->block_size);
  // Reproduce `mi_page_arena_pages`' stable lookup with the page still live.
  // The helper itself is private to arena.c, so use its pinned source fields
  // directly rather than depending on an unexported cross-TU symbol.
  arena = mi_memid_arena(page->memid);
  slice_index = page->memid.mem.arena.slice_index;
  slice_count = page->memid.mem.arena.slice_count;
  if (arena != NULL && arena->arena_idx < MI_MAX_ARENAS) {
    arena_pages = mi_atomic_load_ptr_acquire(
        mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  }
  if (arena == NULL || arena_pages == NULL || bin >= MI_ARENA_BIN_COUNT
      || slice_count != expected_medium_slice_count) {
    goto cleanup;
  }
  page_start_address = (uintptr_t)mi_page_start(page);
  if (page_start_address == 0) goto cleanup;

  // The requested order is exact: first block, then survivor during cleanup.
  mi_free(block);
  block = NULL;
  // The survivor keeps this page live, so reacquire it rather than retaining
  // a page pointer across the first public free.
  page = _mi_safe_ptr_page(survivor);
  if (page == NULL || (uintptr_t)mi_page_start(page) != page_start_address) goto cleanup;
  mapped_after_free = mi_page_is_abandoned_mapped(page);
  abandoned_after_free = mi_page_is_abandoned(page);
  survivor_keeps_page_live = (_mi_ptr_page(survivor) == page && !mi_page_all_free(page));
  // The failed reclaim is inferred only from safe post-free observations;
  // this fixture must not claim direct visibility into the private helper.
  reclaim_not_performed_after_free = (producer_teardown_completed_before_consumer_free
                                      && consumer_associated_theap_unavailable
                                      && survivor_keeps_page_live
                                      && mapped_after_free && abandoned_after_free
                                      && page->next == NULL && page->prev == NULL
                                      && !mi_page_is_owned(page));
  page_still_queue_detached = (page->next == NULL && page->prev == NULL);
  used_one_after_free = (page->used == 1);
  valid = (arena_backed && medium_page && same_page && mapped_before_free
           && abandoned_before_free && origin_theap_present_before_exit
           && producer_teardown_completed_before_consumer_free && free_block_is_same_page
           && survivor_keeps_page_live && reclaim_not_performed_after_free
           && mapped_after_free && abandoned_after_free
           && page_still_queue_detached && used_one_after_free);
  if (!valid) goto cleanup;

  // The final free retires page metadata. Keep only the page's integer start
  // address and stable reserved-arena structures; `_mi_safe_ptr_page` indexes
  // from that address without dereferencing a freed client block or retired
  // page metadata.
  mi_free(survivor);
  survivor = NULL;
  page_map_unregistered_after_final_free = (
      _mi_safe_ptr_page((const void*)(uintptr_t)page_start_address) == NULL);
  arena_page_bitmap_clear_after_final_free = mi_bitmap_is_clearN(
      arena_pages->pages, slice_index, 1);
  arena_slice_released_after_final_free = mi_bbitmap_is_setN(
      arena->slices_free, slice_index, slice_count);
  const bool abandoned_bitmap_clear_after_final_free = mi_bitmap_is_clearN(
      arena_pages->pages_abandoned[bin], slice_index, 1);
  valid = (valid && page_map_unregistered_after_final_free
           && arena_page_bitmap_clear_after_final_free
           && arena_slice_released_after_final_free
           && abandoned_bitmap_clear_after_final_free);

  printf("CRABC_MI_MAPPED_POST_EXIT_TRACE_BEGIN\n");
  printf("trace.mapped_post_exit.arena_backed=%d\n", arena_backed);
  printf("trace.mapped_post_exit.medium_page=%d\n", medium_page);
  printf("trace.mapped_post_exit.same_page=%d\n", same_page);
  printf("trace.mapped_post_exit.mapped_before_free=%d\n", mapped_before_free);
  printf("trace.mapped_post_exit.abandoned_before_free=%d\n", abandoned_before_free);
  printf("trace.mapped_post_exit.origin_theap_present_before_exit=%d\n", origin_theap_present_before_exit);
  printf("trace.mapped_post_exit.producer_teardown_completed_before_consumer_free=%d\n", producer_teardown_completed_before_consumer_free);
  printf("trace.mapped_post_exit.free_block_is_same_page=%d\n", free_block_is_same_page);
  printf("trace.mapped_post_exit.survivor_keeps_page_live=%d\n", survivor_keeps_page_live);
  printf("trace.mapped_post_exit.reclaim_not_performed_after_free=%d\n", reclaim_not_performed_after_free);
  printf("trace.mapped_post_exit.mapped_after_free=%d\n", mapped_after_free);
  printf("trace.mapped_post_exit.abandoned_after_free=%d\n", abandoned_after_free);
  printf("trace.mapped_post_exit.page_still_queue_detached=%d\n", page_still_queue_detached);
  printf("trace.mapped_post_exit.used_one_after_free=%d\n", used_one_after_free);
  printf("trace.mapped_post_exit.page_map_unregistered_after_final_free=%d\n", page_map_unregistered_after_final_free);
  printf("trace.mapped_post_exit.arena_page_bitmap_clear_after_final_free=%d\n", arena_page_bitmap_clear_after_final_free);
  printf("trace.mapped_post_exit.arena_slice_released_after_final_free=%d\n", arena_slice_released_after_final_free);
  printf("trace.mapped_post_exit.valid=%d\n", valid);
  printf("CRABC_MI_MAPPED_POST_EXIT_TRACE_END\n");

cleanup:
  if (producer_started) pthread_join(producer, NULL);
  if (block != NULL) mi_free(block);
  if (survivor != NULL) mi_free(survivor);
  if (heap != NULL) mi_heap_destroy(heap);
  if (options_changed) {
    mi_option_set(mi_option_page_reclaim_on_free, old_reclaim);
    mi_option_set(mi_option_page_full_retain, old_full_retain);
  }
  if (!valid) fprintf(stderr, "mapped-post-exit fixture stopped at stage %d\n", stage);
  return (valid ? 0 : 2);
}
'''


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
        raise EvidenceError("mapped-post-exit source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def load_schema(path: Path | None = None) -> dict[str, Any]:
    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 mapped-post-exit schema") from error
    expected_fields = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "rust_test", "schema", "scope", "source_anchors",
        "target", "trace", "upstream",
    }
    if not isinstance(schema, dict) or set(schema) != expected_fields:
        raise EvidenceError("mapped-post-exit schema fields drifted")
    if type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("unsupported mapped-post-exit evidence format")
    if schema["schema"] != "crabc-mimalloc-x86_64-mapped-post-exit-evidence":
        raise EvidenceError("unsupported mapped-post-exit evidence schema")
    if schema["profile"] != EXPECTED_PROFILE or not exactly_matches(schema["target"], EXPECTED_TARGET):
        raise EvidenceError("mapped-post-exit target/profile drifted")
    if not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("mapped-post-exit upstream drifted")
    if not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("mapped-post-exit scope drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate pinned mapped-post-exit upstream identity") from error
    if pin["sha256"] != EXPECTED_ARCHIVE_SHA256 or pin["archive_root"] != EXPECTED_UPSTREAM["archive_root"] or pin["revision"] != EXPECTED_UPSTREAM["revision"] or pin["version"] != EXPECTED_UPSTREAM["version"]:
        raise EvidenceError("mapped-post-exit upstream pin drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("mapped-post-exit C source set drifted")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("mapped-post-exit release flags drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("mapped-post-exit compile definitions drifted")
    if not exactly_matches(schema["rust_test"], {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER}):
        raise EvidenceError("mapped-post-exit Rust test selection drifted")
    if not exactly_matches(schema["trace"], {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES}):
        raise EvidenceError("mapped-post-exit trace contract drifted")
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("mapped-post-exit C probe hash drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("mapped-post-exit source anchors drifted")
    observed = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("mapped-post-exit source anchor shape drifted")
        observed.append((anchor.get("member"), anchor.get("start_line"), anchor.get("end_line"), anchor.get("sha256")))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("mapped-post-exit source anchor contract drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated = []
    for anchor in schema["source_anchors"]:
        path = source / str(anchor["member"])
        if not path.is_file() or sha256_bytes(source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))) != anchor["sha256"]:
            raise EvidenceError(f"mapped-post-exit source anchor drifted: {anchor['member']}")
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(output, begin=TRACE_BEGIN, end=TRACE_END, description=description)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    non_integer = sorted(key for key, value in trace.items() if type(value) is not int)
    mismatches = sorted(key for key in EXPECTED_TRACE_VALUES if type(trace.get(key)) is int and trace[key] != 1)
    if missing or unexpected or non_integer or mismatches:
        raise EvidenceError(f"{description} violates the fixed 18-field trace contract")


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C mapped-post-exit trace")
    validate_trace(rust_trace, description="Rust mapped-post-exit trace")
    mismatches = [key for key in EXPECTED_TRACE_VALUES if c_trace[key] != rust_trace[key]]
    if mismatches:
        raise EvidenceError("Rust mapped-post-exit trace differs from pinned C: " + ", ".join(mismatches))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


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


def c_trace_command(compiler: str, source: Path, probe_source: Path, binary: Path, schema: Mapping[str, Any]) -> list[str]:
    return [
        compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"),
        *schema["release_flags"], str(probe_source), *(str(source / member) for member in schema["release_source_set"]),
        "-pthread", "-o", str(binary),
    ]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(schema["compile_definitions"]) or flags != list(schema["release_flags"]):
        raise EvidenceError("mapped-post-exit C release command drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("mapped-post-exit C command lacks pthread/TLS requirements")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc":
        raise EvidenceError("mapped-post-exit C compiler drifted")
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/mapped-post-exit.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/mapped-post-exit-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("mapped-post-exit C command drifted")


def rust_trace_command(cargo: str, target_dir: Path) -> list[str]:
    return [cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir), "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]


def validate_normalized_rust_command(command: object) -> None:
    if not isinstance(command, list) or not command or Path(command[0]).name != "cargo":
        raise EvidenceError("mapped-post-exit Rust compiler drifted")
    expected = ["test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target", "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]
    if command[1:] != expected:
        raise EvidenceError("mapped-post-exit Rust command drifted")


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    probe_source = temporary / "mapped-post-exit.c"
    binary = temporary / "mapped-post-exit-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C mapped-post-exit fixture build")
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "pinned C mapped-post-exit ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source)
        run.require_success(execution, "pinned C mapped-post-exit fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C mapped-post-exit trace")
    validate_trace(trace, description="pinned C mapped-post-exit trace")
    return {"build_command": normalize_command(command, temporary, source), "elf": elf, "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/mapped-post-exit-c"], "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")), "trace": trace}


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, environment=environment)
        run.require_success(execution, "Rust mapped-post-exit fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust mapped-post-exit fixture passed {passed} tests, expected one")
    trace = parse_trace(str(execution["stdout"]) + "\n" + str(execution["stderr"]), description="Rust mapped-post-exit trace")
    validate_trace(trace, description="Rust mapped-post-exit trace")
    return {"cargo_command": normalize_command(command, temporary, None), "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}, "passed_test_count": passed, "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}, "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}, "trace": trace}


def report_from_results(schema: Mapping[str, Any], provenance: Mapping[str, str], archive_sha256: str, anchors: Sequence[Mapping[str, Any]], c_probe: Mapping[str, Any], rust_probe: Mapping[str, Any]) -> dict[str, Any]:
    c_trace = c_probe["trace"]
    rust_trace = rust_probe["trace"]
    return {
        "c_probe": dict(c_probe), "comparison": compare_traces(c_trace, rust_trace), "format": 1,
        "kind": "mimalloc-x86_64-mapped-post-exit-differential-evidence", "profile": schema["profile"],
        "provenance": dict(provenance), "rust_probe": dict(rust_probe), "scope": schema["scope"],
        "source": {"archive_sha256": archive_sha256, "anchors": [dict(anchor) for anchor in anchors], "release_flags": list(schema["release_flags"]), "release_source_set": list(schema["release_source_set"])},
        "status": "passed", "target": schema["target"], "trace": schema["trace"], "upstream": schema["upstream"],
    }


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("mapped-post-exit report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("mapped-post-exit report must be a passing format-1 result")
    if report["kind"] != "mimalloc-x86_64-mapped-post-exit-differential-evidence" or report["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("mapped-post-exit report identity drifted")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("mapped-post-exit report boundary drifted")
    if not any(exactly_matches(report["provenance"], value) for value in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"})):
        raise EvidenceError("mapped-post-exit report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("mapped-post-exit report trace contract drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("mapped-post-exit report source drifted")
    if source["archive_sha256"] != run.load_pin()["sha256"] or not exactly_matches(source["anchors"], schema["source_anchors"]) or not exactly_matches(source["release_flags"], schema["release_flags"]) or not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("mapped-post-exit report source identity drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("mapped-post-exit C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("mapped-post-exit Rust probe record drifted")
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF) or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/mapped-post-exit-c"] or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("mapped-post-exit C probe identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if rust_probe["passed_test_count"] != 1 or not exactly_matches(rust_probe["target_dir"], {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}):
        raise EvidenceError("mapped-post-exit Rust probe result drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}) or not exactly_matches(rust_probe["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}):
        raise EvidenceError("mapped-post-exit Rust provenance drifted")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise EvidenceError("mapped-post-exit comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-mapped-post-exit-") as temporary_name:
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
        report = report_from_results(schema, provenance, sha256_file(archive), anchors, c_probe, rust_probe)
    if sha256_file(LOCKFILE) != before_lockfile:
        raise EvidenceError("Cargo.lock changed despite --locked Rust command")
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
        print(f"allocator x86-64 mapped-post-exit differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(f"allocator x86-64 mapped-post-exit differential: PASS ({report['comparison']['compared_value_count']} logical values; report: {relative(arguments.report)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
