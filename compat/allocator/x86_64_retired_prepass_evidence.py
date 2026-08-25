#!/usr/bin/env python3
"""Differential evidence for the pinned retired-page prepass.

This is native Linux/x86-64, private mimalloc-engine evidence.  The C oracle
uses the public allocation/free/thread APIs, with private metadata reads only
while the corresponding page is live; after terminal release it retains only
integer addresses and stable arena metadata.
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-retired-prepass-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/retired-prepass.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/main_heap_page.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "main_heap_page::tests::x86_64_retired_prepass_trace_matches_pinned_c_protocol"
TRACE_BEGIN = "CRABC_MI_RETIRED_PREPASS_TRACE_BEGIN"
TRACE_END = "CRABC_MI_RETIRED_PREPASS_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    pass


EXPECTED_TARGET = {"architecture": "x86_64", "endianness": "little", "rust_target": TARGET, "system": "linux"}
EXPECTED_UPSTREAM = {"archive_root": "mimalloc-3.5.0", "revision": "18b08671c9302247bfb682286e6bf3cc1773f801", "version": "3.5.0"}
EXPECTED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
EXPECTED_PROFILE = "linux-x86_64-private-retired-page-prepass"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "general_lifecycle_claimed": False,
    "general_retired_page_claimed": False,
    "native_linux_x86_64_required": True,
    "one_retired_page_and_one_live_page_only": True,
    "private_engine_evidence_only": True,
    "producer_theap_teardown_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
}
EXPECTED_COMPILE_DEFINITIONS = ("-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1")
EXPECTED_C_ELF = {"class": "ELF64", "endianness": "little", "machine": "Advanced Micro Devices X86-64"}
EXPECTED_SOURCE_ANCHORS = (
    ("src/free.c", 364, 515, "073739d4f87219076fb8f087093b775d3a61ed8bf84c0588765bed0e6d619d68"),
    ("src/page.c", 414, 518, "7816ab31e29ea080a6e54da8bb851b5b8f6b7c27e987a00149a5f83256f5f5de"),
    ("src/theap.c", 89, 152, "5281d80ac6e2103f30d680e38dff6b5117ae5b7f921e2e28f4082161dec71a06"),
    ("src/init.c", 378, 417, "c31e558c1bf6c292aecab8e4a4fe3ef8c2616d2f10d9ac6549fe987ad72cac62"),
    ("src/init.c", 448, 480, "81710fd90ab37ebaf517e33c88e82c8a847eafad277c376eb18c196d9d86838d"),
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
)
EXPECTED_TRACE_VALUES = {name: 1 for name in (
    "trace.retired_prepass.arena_backed",
    "trace.retired_prepass.both_medium",
    "trace.retired_prepass.distinct_pages",
    "trace.retired_prepass.distinct_bins",
    "trace.retired_prepass.retired_page_map_present_before_local_free",
    "trace.retired_prepass.retired_used_zero_before_exit",
    "trace.retired_prepass.retired_retirement_pending_before_exit",
    "trace.retired_prepass.retired_page_map_present_before_exit",
    "trace.retired_prepass.live_used_one_before_exit",
    "trace.retired_prepass.producer_teardown_completed_before_consumer_free",
    "trace.retired_prepass.retired_page_map_unregistered_after_teardown",
    "trace.retired_prepass.retired_arena_page_bitmap_clear_after_teardown",
    "trace.retired_prepass.retired_arena_slice_released_after_teardown",
    "trace.retired_prepass.live_page_map_registered_after_teardown",
    "trace.retired_prepass.live_arena_page_bitmap_set_after_teardown",
    "trace.retired_prepass.live_mapped_abandoned_after_teardown",
    "trace.retired_prepass.live_page_map_unregistered_after_final_free",
    "trace.retired_prepass.live_arena_page_bitmap_clear_after_final_free",
    "trace.retired_prepass.live_arena_slice_released_after_final_free",
    "trace.retired_prepass.route_empty_after_final_free",
    "trace.retired_prepass.valid",
)}

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

typedef struct fixture_s {
  mi_arena_id_t arena_id;
  mi_heap_t* heap;
  mi_page_t* live_page;
  void* live;
  mi_arena_t* arena;
  mi_arena_pages_t* arena_pages;
  size_t retired_slice, live_slice, retired_slices, live_slices;
  size_t retired_bin, live_bin;
  uintptr_t retired_address, live_address;
  bool setup, producer_done;
  bool arena_backed, both_medium, distinct_pages, distinct_bins;
  bool retired_map_before_local_free, retired_used_zero, retired_pending;
  bool retired_map_before_exit, live_used_one;
} fixture_t;

static void* producer_main(void* arg) {
  fixture_t* const f = (fixture_t*)arg;
  mi_heap_t* heap = mi_heap_new_in_arena(f->arena_id);
  void* retired = NULL;
  void* live = NULL;
  mi_page_t* rp = NULL;
  mi_page_t* lp = NULL;
  if (heap == NULL) goto fail;
  retired = mi_heap_malloc(heap, MI_SMALL_MAX_OBJ_SIZE + 1);
  live = mi_heap_malloc(heap, MI_MEDIUM_MAX_OBJ_SIZE / 2);
  if (retired == NULL || live == NULL) goto fail;
  rp = _mi_ptr_page(retired);
  lp = _mi_ptr_page(live);
  if (rp == NULL || lp == NULL || rp == lp
      || rp->memid.memkind != MI_MEM_ARENA || lp->memid.memkind != MI_MEM_ARENA
      || rp->block_size <= MI_SMALL_MAX_OBJ_SIZE || rp->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || lp->block_size <= MI_SMALL_MAX_OBJ_SIZE || lp->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || _mi_bin(rp->block_size) == _mi_bin(lp->block_size)
      || rp->used != 1 || lp->used != 1) goto fail;
  f->arena_backed = (rp->memid.memkind == MI_MEM_ARENA
                     && lp->memid.memkind == MI_MEM_ARENA);
  f->both_medium = (rp->block_size > MI_SMALL_MAX_OBJ_SIZE
                    && rp->block_size <= MI_MEDIUM_MAX_OBJ_SIZE
                    && lp->block_size > MI_SMALL_MAX_OBJ_SIZE
                    && lp->block_size <= MI_MEDIUM_MAX_OBJ_SIZE);
  f->distinct_pages = (rp != lp);
  f->distinct_bins = (_mi_bin(rp->block_size) != _mi_bin(lp->block_size));
  f->arena = mi_memid_arena(rp->memid);
  f->retired_slice = rp->memid.mem.arena.slice_index;
  f->retired_slices = rp->memid.mem.arena.slice_count;
  f->live_slice = lp->memid.mem.arena.slice_index;
  f->live_slices = lp->memid.mem.arena.slice_count;
  f->retired_bin = _mi_bin(rp->block_size);
  f->live_bin = _mi_bin(lp->block_size);
  f->retired_address = (uintptr_t)retired;
  f->live_address = (uintptr_t)live;
  if (f->arena == NULL || mi_memid_arena(lp->memid) != f->arena
      || f->arena->arena_idx >= MI_MAX_ARENAS
      || f->retired_slices == 0 || f->live_slices == 0) goto fail;
  f->arena_pages = mi_atomic_load_ptr_acquire(
      mi_arena_pages_t, &heap->arena_pages[f->arena->arena_idx]);
  if (f->arena_pages == NULL) goto fail;
  f->retired_map_before_local_free = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f->retired_address) == rp);
  mi_free(retired); retired = NULL;
  f->retired_map_before_exit = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f->retired_address) == rp);
  // The pinned ordinary local-free path retains this page as retired.  Gate
  // its private metadata reads through the PageMap result so an unexpected
  // eager release fails the fixture without dereferencing released metadata.
  if (!f->retired_map_before_exit) goto fail;
  f->retired_used_zero = (rp->used == 0);
  f->retired_pending = (rp->retire_expire != 0);
  f->live_used_one = (lp->used == 1);
  if (!f->retired_map_before_local_free || !f->retired_used_zero
      || !f->retired_pending || !f->retired_map_before_exit
      || !f->live_used_one) goto fail;
  f->heap = heap;
  f->live_page = lp;
  f->live = live;
  // `mi_thread_done()` enters the source MI_ABANDON collector. Its retired
  // prepass is force-enabled before the still-live page is abandoned.
  mi_thread_done();
  f->producer_done = true;
  f->setup = true;
  return NULL;
fail:
  if (retired != NULL) mi_free(retired);
  if (live != NULL) mi_free(live);
  if (heap != NULL) mi_heap_destroy(heap);
  return NULL;
}

int main(void) {
  fixture_t f = {0};
  mi_arena_id_t arena_id = _mi_arena_id_none();
  pthread_t worker;
  bool started = false;
  int valid = 0;
  int arena_backed = 0, both_medium = 0, distinct_pages = 0, distinct_bins = 0;
  int retired_page_map_present_before_local_free = 0, retired_used_zero_before_exit = 0;
  int retired_retirement_pending_before_exit = 0, retired_page_map_present_before_exit = 0;
  int live_used_one_before_exit = 0, producer_teardown_completed_before_consumer_free = 0;
  int retired_page_map_unregistered_after_teardown = 0, retired_arena_page_bitmap_clear_after_teardown = 0;
  int retired_arena_slice_released_after_teardown = 0, live_page_map_registered_after_teardown = 0;
  int live_arena_page_bitmap_set_after_teardown = 0, live_mapped_abandoned_after_teardown = 0;
  int live_page_map_unregistered_after_final_free = 0, live_arena_page_bitmap_clear_after_final_free = 0;
  int live_arena_slice_released_after_final_free = 0, route_empty_after_final_free = 0;
  mi_thread_init();
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto done;
  f.arena_id = arena_id;
  if (pthread_create(&worker, NULL, producer_main, &f) != 0) goto done;
  started = true;
  if (pthread_join(worker, NULL) != 0) goto done;
  started = false;
  if (!f.setup || !f.producer_done || f.heap == NULL || f.arena == NULL || f.arena_pages == NULL) goto done;
  arena_backed = f.arena_backed;
  both_medium = f.both_medium;
  distinct_pages = f.distinct_pages;
  distinct_bins = f.distinct_bins;
  retired_page_map_present_before_local_free = f.retired_map_before_local_free;
  retired_used_zero_before_exit = f.retired_used_zero;
  retired_retirement_pending_before_exit = f.retired_pending;
  retired_page_map_present_before_exit = f.retired_map_before_exit;
  live_used_one_before_exit = f.live_used_one;
  producer_teardown_completed_before_consumer_free = (f.producer_done && !started);
  retired_page_map_unregistered_after_teardown = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.retired_address) == NULL);
  retired_arena_page_bitmap_clear_after_teardown = mi_bitmap_is_clearN(f.arena_pages->pages, f.retired_slice, 1);
  retired_arena_slice_released_after_teardown = mi_bbitmap_is_setN(f.arena->slices_free, f.retired_slice, f.retired_slices);
  live_page_map_registered_after_teardown = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.live_address) == f.live_page);
  // `mi_thread_done()` must leave this client allocation mapped.  Do not
  // inspect its private page fields if a broken source transition released it.
  if (!live_page_map_registered_after_teardown) {
    f.live = NULL;
    goto done;
  }
  live_arena_page_bitmap_set_after_teardown = mi_bitmap_is_setN(f.arena_pages->pages, f.live_slice, 1);
  live_mapped_abandoned_after_teardown = mi_page_is_abandoned_mapped(f.live_page);
  if (!arena_backed || !both_medium || !distinct_pages || !distinct_bins || !retired_page_map_unregistered_after_teardown
      || !retired_arena_page_bitmap_clear_after_teardown || !retired_arena_slice_released_after_teardown
      || !live_page_map_registered_after_teardown || !live_arena_page_bitmap_set_after_teardown
      || !live_mapped_abandoned_after_teardown) goto done;
  mi_free(f.live); f.live = NULL;
  live_page_map_unregistered_after_final_free = (
      _mi_safe_ptr_page((const void*)(uintptr_t)f.live_address) == NULL);
  live_arena_page_bitmap_clear_after_final_free = mi_bitmap_is_clearN(f.arena_pages->pages, f.live_slice, 1);
  live_arena_slice_released_after_final_free = mi_bbitmap_is_setN(f.arena->slices_free, f.live_slice, f.live_slices);
  route_empty_after_final_free = (
      mi_atomic_load_relaxed(&f.heap->abandoned_count[f.live_bin]) == 0);
  valid = arena_backed && both_medium && distinct_pages && distinct_bins
      && retired_page_map_present_before_local_free && retired_used_zero_before_exit
      && retired_retirement_pending_before_exit && retired_page_map_present_before_exit
      && live_used_one_before_exit && producer_teardown_completed_before_consumer_free
      && retired_page_map_unregistered_after_teardown && retired_arena_page_bitmap_clear_after_teardown
      && retired_arena_slice_released_after_teardown && live_page_map_registered_after_teardown
      && live_arena_page_bitmap_set_after_teardown && live_mapped_abandoned_after_teardown
      && live_page_map_unregistered_after_final_free && live_arena_page_bitmap_clear_after_final_free
      && live_arena_slice_released_after_final_free && route_empty_after_final_free;
done:
  if (started) pthread_join(worker, NULL);
  if (f.live != NULL) mi_free(f.live);
  if (f.heap != NULL) mi_heap_destroy(f.heap);
  if (valid) {
    printf("CRABC_MI_RETIRED_PREPASS_TRACE_BEGIN\n");
    printf("trace.retired_prepass.arena_backed=%d\n", arena_backed);
    printf("trace.retired_prepass.both_medium=%d\n", both_medium);
    printf("trace.retired_prepass.distinct_pages=%d\n", distinct_pages);
    printf("trace.retired_prepass.distinct_bins=%d\n", distinct_bins);
    printf("trace.retired_prepass.retired_page_map_present_before_local_free=%d\n", retired_page_map_present_before_local_free);
    printf("trace.retired_prepass.retired_used_zero_before_exit=%d\n", retired_used_zero_before_exit);
    printf("trace.retired_prepass.retired_retirement_pending_before_exit=%d\n", retired_retirement_pending_before_exit);
    printf("trace.retired_prepass.retired_page_map_present_before_exit=%d\n", retired_page_map_present_before_exit);
    printf("trace.retired_prepass.live_used_one_before_exit=%d\n", live_used_one_before_exit);
    printf("trace.retired_prepass.producer_teardown_completed_before_consumer_free=%d\n", producer_teardown_completed_before_consumer_free);
    printf("trace.retired_prepass.retired_page_map_unregistered_after_teardown=%d\n", retired_page_map_unregistered_after_teardown);
    printf("trace.retired_prepass.retired_arena_page_bitmap_clear_after_teardown=%d\n", retired_arena_page_bitmap_clear_after_teardown);
    printf("trace.retired_prepass.retired_arena_slice_released_after_teardown=%d\n", retired_arena_slice_released_after_teardown);
    printf("trace.retired_prepass.live_page_map_registered_after_teardown=%d\n", live_page_map_registered_after_teardown);
    printf("trace.retired_prepass.live_arena_page_bitmap_set_after_teardown=%d\n", live_arena_page_bitmap_set_after_teardown);
    printf("trace.retired_prepass.live_mapped_abandoned_after_teardown=%d\n", live_mapped_abandoned_after_teardown);
    printf("trace.retired_prepass.live_page_map_unregistered_after_final_free=%d\n", live_page_map_unregistered_after_final_free);
    printf("trace.retired_prepass.live_arena_page_bitmap_clear_after_final_free=%d\n", live_arena_page_bitmap_clear_after_final_free);
    printf("trace.retired_prepass.live_arena_slice_released_after_final_free=%d\n", live_arena_slice_released_after_final_free);
    printf("trace.retired_prepass.route_empty_after_final_free=%d\n", route_empty_after_final_free);
    printf("trace.retired_prepass.valid=%d\n", valid);
    printf("CRABC_MI_RETIRED_PREPASS_TRACE_END\n");
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
        return set(observed) == set(expected) and all(exactly_matches(observed[k], expected[k]) for k in expected)
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(exactly_matches(a, b) for a, b in zip(observed, expected))
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
    return b"".join(lines[start - 1:end])


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
        raise EvidenceError("cannot read retired-prepass schema") from error
    required = {"format", "schema", "profile", "target", "upstream", "scope", "compile_definitions", "release_flags", "release_source_set", "source_anchors", "rust_test", "c_probe_sha256", "trace"}
    if not isinstance(schema, dict) or set(schema) != required or schema["format"] != 1 or type(schema["format"]) is not int:
        raise EvidenceError("retired-prepass schema fields drifted")
    if schema["schema"] != "crabc-mimalloc-x86_64-retired-prepass-evidence" or schema["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("retired-prepass schema identity drifted")
    if not exactly_matches(schema["target"], EXPECTED_TARGET) or not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("retired-prepass boundary drifted")
    pin = run.load_pin()
    if pin["sha256"] != EXPECTED_ARCHIVE_SHA256 or pin["archive_root"] != EXPECTED_UPSTREAM["archive_root"] or pin["revision"] != EXPECTED_UPSTREAM["revision"] or pin["version"] != EXPECTED_UPSTREAM["version"]:
        raise EvidenceError("pinned upstream identity drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)) or not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])) or not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("release build contract drifted")
    if not exactly_matches(schema["rust_test"], {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER}):
        raise EvidenceError("Rust test selection drifted")
    if not exactly_matches(schema["trace"], {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES}):
        raise EvidenceError("trace contract drifted")
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode()):
        raise EvidenceError("C probe hash drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("source anchors drifted")
    observed = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("source anchor shape drifted")
        if (type(anchor["member"]) is not str or type(anchor["start_line"]) is not int
                or type(anchor["end_line"]) is not int or type(anchor["sha256"]) is not str):
            raise EvidenceError("source anchor type drifted")
        observed.append((anchor["member"], anchor["start_line"], anchor["end_line"], anchor["sha256"]))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("source anchors drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    result = []
    for anchor in schema["source_anchors"]:
        path = source / anchor["member"]
        if not path.is_file() or sha256_bytes(source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))) != anchor["sha256"]:
            raise EvidenceError(f"source anchor drifted: {anchor['member']}")
        result.append(dict(anchor))
    return result


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = set(EXPECTED_TRACE_VALUES) - set(trace)
    unexpected = set(trace) - set(EXPECTED_TRACE_VALUES)
    bad_type = [k for k, v in trace.items() if type(v) is not int]
    wrong = [k for k in EXPECTED_TRACE_VALUES if type(trace.get(k)) is int and trace[k] != 1]
    if missing or unexpected or bad_type or wrong:
        raise EvidenceError(f"{description} violates the fixed 21-field trace contract")


def parse_trace(output: str, description: str) -> dict[str, int]:
    try:
        trace = run.parse_address_independent_trace(output, begin=TRACE_BEGIN, end=TRACE_END, description=description)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    validate_trace(trace, description=description)
    return trace


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    result = []
    temp, src = str(temporary), str(source) if source is not None else None
    for part in command:
        if src is not None and (part == src or part.startswith(src + "/")):
            result.append(NORMALIZED_PINNED_SOURCE + part[len(src):])
        elif part == temp or part.startswith(temp + "/"):
            result.append(NORMALIZED_EVIDENCE_ROOT + part[len(temp):])
        else:
            result.append(part)
    return result


def c_command(compiler: str, source: Path, probe: Path, binary: Path, schema: Mapping[str, Any]) -> list[str]:
    return [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"), *schema["release_flags"], str(probe), *(str(source / m) for m in schema["release_source_set"]), "-pthread", "-o", str(binary)]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    if [x for x in command if x in EXPECTED_COMPILE_DEFINITIONS] != list(schema["compile_definitions"]):
        raise EvidenceError("C compile definitions drifted")
    if [x for x in command if x in run.CONFIGURATION_PROFILES["release"]] != list(schema["release_flags"]):
        raise EvidenceError("C release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("C command lacks pthread/TLS requirements")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    expected = ["-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src", *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/retired-prepass.c", *(f"{NORMALIZED_PINNED_SOURCE}/{m}" for m in schema["release_source_set"]), "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/retired-prepass-c"]
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise EvidenceError("normalized C command drifted")


def rust_command(cargo: str, target_dir: Path) -> list[str]:
    return [cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir), "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]


def validate_normalized_rust_command(command: object) -> None:
    expected = ["test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target", "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]
    if not isinstance(command, list) or not command or Path(command[0]).name != "cargo" or command[1:] != expected:
        raise EvidenceError("normalized Rust command drifted")


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    probe = temporary / "retired-prepass.c"; binary = temporary / "retired-prepass-c"
    probe.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_command(compiler, source, probe, binary, schema); validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "retired-prepass C build")
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "retired-prepass ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source); run.require_success(execution, "retired-prepass C execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), "pinned C retired-prepass trace")
    return {"build_command": normalize_command(command, temporary, source), "elf": elf, "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/retired-prepass-c"], "source_sha256": sha256_bytes(C_TRACE_PROBE.encode()), "trace": trace}


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    target_dir = temporary / "rust-target"; command = rust_command(cargo, target_dir)
    environment = os.environ.copy(); environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, environment=environment); run.require_success(execution, "Rust retired-prepass fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1: raise EvidenceError(f"Rust retired-prepass fixture passed {passed} tests")
    trace = parse_trace(str(execution["stdout"]) + "\n" + str(execution["stderr"]), "Rust retired-prepass trace")
    return {"cargo_command": normalize_command(command, temporary, None), "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}, "passed_test_count": passed, "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}, "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}, "trace": trace}


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="C retired-prepass trace"); validate_trace(rust_trace, description="Rust retired-prepass trace")
    mismatch = [key for key in EXPECTED_TRACE_VALUES if c_trace[key] != rust_trace[key]]
    if mismatch: raise EvidenceError("C/Rust retired-prepass mismatch: " + ", ".join(mismatch))
    return {"compared_value_count": 21, "status": "matched"}


def report_from_results(schema: Mapping[str, Any], provenance: Mapping[str, str], archive_sha256: str, anchors: Sequence[Mapping[str, Any]], c_probe: Mapping[str, Any], rust_probe: Mapping[str, Any]) -> dict[str, Any]:
    return {"c_probe": dict(c_probe), "comparison": compare_traces(c_probe["trace"], rust_probe["trace"]), "format": 1, "kind": "mimalloc-x86_64-retired-prepass-differential-evidence", "profile": schema["profile"], "provenance": dict(provenance), "rust_probe": dict(rust_probe), "scope": schema["scope"], "source": {"archive_sha256": archive_sha256, "anchors": [dict(a) for a in anchors], "release_flags": list(schema["release_flags"]), "release_source_set": list(schema["release_source_set"])}, "status": "passed", "target": schema["target"], "trace": schema["trace"], "upstream": schema["upstream"]}


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required or report["format"] != 1 or report["status"] != "passed": raise EvidenceError("retired-prepass report shape/status drifted")
    if report["kind"] != "mimalloc-x86_64-retired-prepass-differential-evidence" or report["profile"] != EXPECTED_PROFILE: raise EvidenceError("retired-prepass report identity drifted")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE): raise EvidenceError("retired-prepass report boundary drifted")
    if report["provenance"] not in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"}): raise EvidenceError("retired-prepass report lacks native provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]): raise EvidenceError("retired-prepass report trace drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"} or source["archive_sha256"] != run.load_pin()["sha256"] or not exactly_matches(source["anchors"], schema["source_anchors"]) or not exactly_matches(source["release_flags"], schema["release_flags"]) or not exactly_matches(source["release_source_set"], schema["release_source_set"]): raise EvidenceError("retired-prepass source drifted")
    c, rust = report["c_probe"], report["rust_probe"]
    if not isinstance(c, dict) or set(c) != {"build_command", "elf", "run_command", "source_sha256", "trace"} or not isinstance(rust, dict) or set(rust) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}: raise EvidenceError("retired-prepass probe shape drifted")
    if not exactly_matches(c["elf"], EXPECTED_C_ELF) or c["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/retired-prepass-c"] or c["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode()): raise EvidenceError("retired-prepass C probe drifted")
    validate_normalized_c_command(c["build_command"], schema); validate_normalized_rust_command(rust["cargo_command"])
    if rust["passed_test_count"] != 1 or not exactly_matches(rust["target_dir"], {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}): raise EvidenceError("retired-prepass Rust result drifted")
    if not exactly_matches(rust["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}) or not exactly_matches(rust["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}): raise EvidenceError("retired-prepass Rust provenance drifted")
    if not exactly_matches(report["comparison"], compare_traces(c["trace"], rust["trace"])): raise EvidenceError("retired-prepass comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64(); schema = load_schema(); before_lock = sha256_file(LOCKFILE)
    try: pin = run.load_pin(); archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error: raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-retired-prepass-") as name:
        temporary = Path(name)
        try: source = run.safe_extract(archive, temporary / "source", pin["archive_root"]); compiler = run.require_tool("musl-gcc"); readelf = run.require_tool("readelf"); cargo = run.require_tool("cargo")
        except run.HarnessError as error: raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source); c_probe = build_c_trace(compiler, readelf, source, temporary, schema); rust_probe = build_rust_trace(cargo, temporary); report = report_from_results(schema, provenance, sha256_file(archive), anchors, c_probe, rust_probe)
    if sha256_file(LOCKFILE) != before_lock: raise EvidenceError("Cargo.lock changed")
    validate_report(report); run.write_json(report_path, report); return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try: report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error: print(f"allocator x86-64 retired-prepass differential: FAIL: {error}", file=os.sys.stderr); return 1
    print(f"allocator x86-64 retired-prepass differential: PASS ({report['comparison']['compared_value_count']} logical values; report: {relative(arguments.report)})"); return 0


if __name__ == "__main__":
    raise SystemExit(main())
