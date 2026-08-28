#!/usr/bin/env python3
"""Differentially prove one regular-small retired-page reuse on native x86-64.

The pinned mimalloc v3.5.0 C fixture and one crate-private Rust test both use
one 1025-byte ordinary regular small arena page. They fill it, return every
block locally so it becomes retired, let the next generic allocation
quick-collect and reuse a prior block, then force-collect the second retired
state. The resulting record contains only fixed integers and booleans; source
anchors establish the C mutation order.

This is private native Linux/x86-64 allocator-engine evidence. It does not
claim general retirement, lifecycle, concurrent/remote collection, public
``mi_*`` behavior, public x86 runtime support, libc integration, backend
promotion, or AArch64 evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-regular-small-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/regular-small.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/single_thread.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = (
    "single_thread::tests::"
    "x86_64_regular_small_retire_quick_collect_reuse_and_force_release_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_REGULAR_SMALL_TRACE_BEGIN"
TRACE_END = "CRABC_MI_REGULAR_SMALL_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded regular-small differential could not establish its claim."""


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
EXPECTED_PROFILE = "linux-x86_64-private-regular-small-retire-quick-collect-force-release"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "forced_retired_release_only": True,
    "general_lifecycle_claimed": False,
    "general_retirement_claimed": False,
    "native_linux_x86_64_required": True,
    "ordinary_regular_small_page_only": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "quick_collect_reuse_only": True,
    "single_theap_same_thread_only": True,
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
    ("include/mimalloc.h", 122, 123, "254ce29a1c8187dae3f5cccd5f98bbf7f71f448f68cbb5e822dd6f74f291778c"),
    ("include/mimalloc/types.h", 430, 449, "9befd05f3264611334cec9745bbd1de88fe83f01b4a1c7f2b9beadb3e6badb5f"),
    ("include/mimalloc/types.h", 731, 740, "d898791180decb2ddb76eca0a7373a68e2437cce514c35d10b674fbb3d6e4988"),
    ("src/alloc.c", 204, 240, "d9e591aba82a335db52a1a97e3a5fe8ba080d1bc29ea2b91960cb07f33306164"),
    ("src/arena.c", 980, 998, "4d66fd65bb721890af00061539085a8a10b6c8226c4da8fcf21d874ac084aa74"),
    ("src/arena.c", 1053, 1064, "e2063beb8a77f1bf35554b3ad7fb761362d2c430434867c68a67b7f7315c2371"),
    ("src/arena.c", 1183, 1204, "09e82c9f0473e73a9fad065943d41fdab4b85faf570274bddbac77aee3b6860a"),
    ("src/free.c", 44, 56, "de6d94667e1d6b127947a347660b35b4eaf1480751da492154de4a1e48f43e13"),
    ("src/page.c", 203, 212, "eeb1ec81e87ae341ec1828f2d56c033b4fa0d60c707da4ca10d4c3a4b27d706c"),
    ("src/page.c", 424, 457, "70a97877d51e5ca85aee8e74e61e293ebddd7676e214035abb83f5a30608078c"),
    ("src/page.c", 481, 518, "a9b7636f8fbec09a0fe97d482c7d66f89bb1be0a1c0118047b8b5ac5dcb1f0a7"),
    ("src/page.c", 879, 917, "b9a8d102ea3285c4f0283e7379d621f36dde91728a5daa3306e764e979a949b6"),
    ("src/theap.c", 123, 165, "a84d17ad1b74eb93e79bb3b756f099fd60fe611eda6279c17db283c44cccc1bb"),
    ("src/page-map.c", 460, 515, "c752c966d40e6ebd16795295a1a87d3b8a762cdfc4ba752aa3a043df44dfb495"),
)
EXPECTED_TRACE_VALUES = {
    "trace.regular_small.request": 1025,
    "trace.regular_small.block_size": 1280,
    "trace.regular_small.capacity": 51,
    "trace.regular_small.slice_count": 1,
    "trace.regular_small.arena_backed": 1,
    "trace.regular_small.filled.used": 51,
    "trace.regular_small.filled.free_empty": 1,
    "trace.regular_small.filled.local_empty": 1,
    "trace.regular_small.filled.remote_empty": 1,
    "trace.regular_small.filled.queue_count": 1,
    "trace.regular_small.filled.page_count": 1,
    "trace.regular_small.retired.queue_count": 1,
    "trace.regular_small.retired.page_count": 1,
    "trace.regular_small.retired.used": 0,
    "trace.regular_small.retired.expire": 16,
    "trace.regular_small.retired.free_empty": 1,
    "trace.regular_small.retired.local_nonempty": 1,
    "trace.regular_small.retired.remote_empty": 1,
    "trace.regular_small.retired.map_published": 1,
    "trace.regular_small.retired.arena_page_set": 1,
    "trace.regular_small.retired.slices_unreleased": 1,
    "trace.regular_small.reuse.same_page": 1,
    "trace.regular_small.reuse.from_freed_set": 1,
    "trace.regular_small.reuse.used": 1,
    "trace.regular_small.reuse.expire": 0,
    "trace.regular_small.reuse.free_nonempty": 1,
    "trace.regular_small.reuse.local_empty": 1,
    "trace.regular_small.reuse.remote_empty": 1,
    "trace.regular_small.reuse.queue_count": 1,
    "trace.regular_small.second_retire.used": 0,
    "trace.regular_small.second_retire.expire": 16,
    "trace.regular_small.second_retire.free_nonempty": 1,
    "trace.regular_small.second_retire.local_nonempty": 1,
    "trace.regular_small.release.queue_count": 0,
    "trace.regular_small.release.page_count": 0,
    "trace.regular_small.release.map_clear": 1,
    "trace.regular_small.release.span_map_clear": 1,
    "trace.regular_small.release.arena_page_clear": 1,
    "trace.regular_small.release.slices_free": 1,
    "trace.regular_small.valid": 1,
}


C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private regular-small fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0
#error this fixture requires the native x86-64 two-level PageMap branch
#endif
#if MI_ENCODE_FREELIST != 0
#error this fixture requires the pinned unencoded release freelist
#endif

int main(void) {
  const size_t request = MI_SMALL_SIZE_MAX + 1;
  void* blocks[MI_SMALL_PAGE_SIZE / sizeof(void*)] = { 0 };
  size_t block_count = 0;
  size_t freed_count = 0;
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_queue_t* queue = NULL;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  void* reused = NULL;
  uintptr_t saved_address = 0;
  size_t slice_index = 0;
  size_t slice_count = 0;
  size_t block_size = 0;
  size_t capacity = 0;
  bool valid = false;

  int arena_backed = 0;
  size_t filled_used = 0, filled_queue_count = 0, filled_page_count = 0;
  int filled_free_empty = 0, filled_local_empty = 0, filled_remote_empty = 0;
  size_t retired_queue_count = 0, retired_page_count = 0, retired_used = 0, retired_expire = 0;
  int retired_free_empty = 0, retired_local_nonempty = 0, retired_remote_empty = 0;
  int retired_map_published = 0, retired_arena_page_set = 0, retired_slices_unreleased = 0;
  int reuse_same_page = 0, reuse_from_freed_set = 0, reuse_free_nonempty = 0;
  int reuse_local_empty = 0, reuse_remote_empty = 0;
  size_t reuse_used = 0, reuse_expire = 0, reuse_queue_count = 0;
  size_t second_retire_used = 0, second_retire_expire = 0;
  int second_retire_free_nonempty = 0, second_retire_local_nonempty = 0;
  size_t release_queue_count = 0, release_page_count = 0;
  int release_map_clear = 0, release_span_map_clear = 0;
  int release_arena_page_clear = 0, release_slices_free = 0;

  mi_thread_init();
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto output;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto output;
  blocks[block_count] = mi_heap_malloc(heap, request);
  if (blocks[block_count] == NULL) goto output;
  block_count++;
  page = _mi_ptr_page(blocks[0]);
  theap = _mi_heap_theap(heap);
  if (page == NULL || theap == NULL || page->memid.memkind != MI_MEM_ARENA
      || page->block_size <= MI_SMALL_SIZE_MAX || page->block_size > MI_SMALL_MAX_OBJ_SIZE
      || page->reserved == 0 || page->reserved > MI_SMALL_PAGE_SIZE / sizeof(void*)) goto output;
  arena_backed = (page->memid.memkind == MI_MEM_ARENA);
  arena = mi_memid_arena(page->memid);
  if (arena == NULL || arena->arena_idx >= MI_MAX_ARENAS) goto output;
  arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  if (arena_pages == NULL) goto output;
  queue = mi_page_queue(theap, page->block_size);
  if (queue == NULL || queue->first != page || queue->count != 1) goto output;
  slice_index = page->memid.mem.arena.slice_index;
  slice_count = page->memid.mem.arena.slice_count;
  block_size = page->block_size;
  capacity = page->reserved;
  if (slice_count == 0) goto output;

  while (page->used < page->reserved) {
    if (block_count == MI_SMALL_PAGE_SIZE / sizeof(void*)) goto output;
    blocks[block_count] = mi_heap_malloc(heap, request);
    if (blocks[block_count] == NULL || _mi_ptr_page(blocks[block_count]) != page) goto output;
    block_count++;
  }
  filled_used = page->used;
  filled_free_empty = (page->free == NULL);
  filled_local_empty = (page->local_free == NULL);
  filled_remote_empty = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  filled_queue_count = queue->count;
  filled_page_count = theap->page_count;
  if (block_count != capacity || page->capacity != page->reserved
      || filled_used != capacity || !filled_free_empty || !filled_local_empty
      || !filled_remote_empty || filled_queue_count != 1 || filled_page_count != 1) goto output;

  for (size_t index = 0; index < block_count; index++) {
    mi_free(blocks[index]);
    freed_count++;
  }
  saved_address = (uintptr_t)blocks[0];
  retired_queue_count = queue->count;
  retired_page_count = theap->page_count;
  retired_used = page->used;
  retired_expire = page->retire_expire;
  retired_free_empty = (page->free == NULL);
  retired_local_nonempty = (page->local_free != NULL);
  retired_remote_empty = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  retired_map_published = (_mi_safe_ptr_page((const void*)saved_address) == page);
  retired_arena_page_set = mi_bitmap_is_setN(arena_pages->pages, slice_index, slice_count);
  retired_slices_unreleased = mi_bbitmap_is_clearN(arena->slices_free, slice_index, slice_count);
  if (retired_queue_count != 1 || retired_page_count != 1 || retired_used != 0
      || retired_expire != 16 || !retired_free_empty || !retired_local_nonempty
      || !retired_remote_empty || !retired_map_published || !retired_arena_page_set
      || !retired_slices_unreleased) goto output;

  reused = mi_heap_malloc(heap, request);
  if (reused == NULL) goto output;
  reuse_same_page = (_mi_ptr_page(reused) == page);
  reuse_from_freed_set = (reused == blocks[block_count - 1]);
  reuse_used = page->used;
  reuse_expire = page->retire_expire;
  reuse_free_nonempty = (page->free != NULL);
  reuse_local_empty = (page->local_free == NULL);
  reuse_remote_empty = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  reuse_queue_count = queue->count;
  if (!reuse_same_page || !reuse_from_freed_set || reuse_used != 1 || reuse_expire != 0
      || !reuse_free_nonempty || !reuse_local_empty || !reuse_remote_empty
      || reuse_queue_count != 1) goto output;

  mi_free(reused);
  reused = NULL;
  second_retire_used = page->used;
  second_retire_expire = page->retire_expire;
  second_retire_free_nonempty = (page->free != NULL);
  second_retire_local_nonempty = (page->local_free != NULL);
  if (second_retire_used != 0 || second_retire_expire != 16
      || !second_retire_free_nonempty || !second_retire_local_nonempty) goto output;

  mi_heap_collect(heap, true);
  release_queue_count = queue->count;
  release_page_count = theap->page_count;
  release_map_clear = (_mi_safe_ptr_page((const void*)saved_address) == NULL);
  release_span_map_clear = true;
  for (size_t index = 0; index < slice_count; index++) {
    const uint8_t* const start = (const uint8_t*)arena->start
        + (slice_index + index) * MI_ARENA_SLICE_SIZE;
    if (_mi_safe_ptr_page(start) != NULL) {
      release_span_map_clear = false;
    }
  }
  release_arena_page_clear = mi_bitmap_is_clearN(arena_pages->pages, slice_index, slice_count);
  release_slices_free = mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count);
  valid = (request == 1025 && block_size == 1280 && capacity == 51 && slice_count == 1
           && arena_backed && filled_used == 51
           && filled_free_empty && filled_local_empty && filled_remote_empty
           && filled_queue_count == 1 && filled_page_count == 1
           && retired_queue_count == 1 && retired_page_count == 1 && retired_used == 0
           && retired_expire == 16 && retired_free_empty && retired_local_nonempty
           && retired_remote_empty && retired_map_published && retired_arena_page_set
           && retired_slices_unreleased && reuse_same_page && reuse_from_freed_set
           && reuse_used == 1 && reuse_expire == 0 && reuse_free_nonempty
           && reuse_local_empty && reuse_remote_empty && reuse_queue_count == 1
           && second_retire_used == 0 && second_retire_expire == 16
           && second_retire_free_nonempty && second_retire_local_nonempty
           && release_queue_count == 0 && release_page_count == 0 && release_map_clear
           && release_span_map_clear && release_arena_page_clear && release_slices_free);

output:
  printf("CRABC_MI_REGULAR_SMALL_TRACE_BEGIN\n");
  printf("trace.regular_small.request=%zu\n", request);
  printf("trace.regular_small.block_size=%zu\n", block_size);
  printf("trace.regular_small.capacity=%zu\n", capacity);
  printf("trace.regular_small.slice_count=%zu\n", slice_count);
  printf("trace.regular_small.arena_backed=%d\n", arena_backed);
  printf("trace.regular_small.filled.used=%zu\n", filled_used);
  printf("trace.regular_small.filled.free_empty=%d\n", filled_free_empty);
  printf("trace.regular_small.filled.local_empty=%d\n", filled_local_empty);
  printf("trace.regular_small.filled.remote_empty=%d\n", filled_remote_empty);
  printf("trace.regular_small.filled.queue_count=%zu\n", filled_queue_count);
  printf("trace.regular_small.filled.page_count=%zu\n", filled_page_count);
  printf("trace.regular_small.retired.queue_count=%zu\n", retired_queue_count);
  printf("trace.regular_small.retired.page_count=%zu\n", retired_page_count);
  printf("trace.regular_small.retired.used=%zu\n", retired_used);
  printf("trace.regular_small.retired.expire=%zu\n", retired_expire);
  printf("trace.regular_small.retired.free_empty=%d\n", retired_free_empty);
  printf("trace.regular_small.retired.local_nonempty=%d\n", retired_local_nonempty);
  printf("trace.regular_small.retired.remote_empty=%d\n", retired_remote_empty);
  printf("trace.regular_small.retired.map_published=%d\n", retired_map_published);
  printf("trace.regular_small.retired.arena_page_set=%d\n", retired_arena_page_set);
  printf("trace.regular_small.retired.slices_unreleased=%d\n", retired_slices_unreleased);
  printf("trace.regular_small.reuse.same_page=%d\n", reuse_same_page);
  printf("trace.regular_small.reuse.from_freed_set=%d\n", reuse_from_freed_set);
  printf("trace.regular_small.reuse.used=%zu\n", reuse_used);
  printf("trace.regular_small.reuse.expire=%zu\n", reuse_expire);
  printf("trace.regular_small.reuse.free_nonempty=%d\n", reuse_free_nonempty);
  printf("trace.regular_small.reuse.local_empty=%d\n", reuse_local_empty);
  printf("trace.regular_small.reuse.remote_empty=%d\n", reuse_remote_empty);
  printf("trace.regular_small.reuse.queue_count=%zu\n", reuse_queue_count);
  printf("trace.regular_small.second_retire.used=%zu\n", second_retire_used);
  printf("trace.regular_small.second_retire.expire=%zu\n", second_retire_expire);
  printf("trace.regular_small.second_retire.free_nonempty=%d\n", second_retire_free_nonempty);
  printf("trace.regular_small.second_retire.local_nonempty=%d\n", second_retire_local_nonempty);
  printf("trace.regular_small.release.queue_count=%zu\n", release_queue_count);
  printf("trace.regular_small.release.page_count=%zu\n", release_page_count);
  printf("trace.regular_small.release.map_clear=%d\n", release_map_clear);
  printf("trace.regular_small.release.span_map_clear=%d\n", release_span_map_clear);
  printf("trace.regular_small.release.arena_page_clear=%d\n", release_arena_page_clear);
  printf("trace.regular_small.release.slices_free=%d\n", release_slices_free);
  printf("trace.regular_small.valid=%d\n", valid);
  printf("CRABC_MI_REGULAR_SMALL_TRACE_END\n");

  if (reused != NULL) mi_free(reused);
  for (size_t index = freed_count; index < block_count; index++) {
    if (blocks[index] != NULL) mi_free(blocks[index]);
  }
  if (heap != NULL) mi_heap_destroy(heap);
  return valid ? 0 : 2;
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
            exactly_matches(left, right) for left, right in zip(observed, expected)
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
        raise EvidenceError("regular-small source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def _schema_template() -> dict[str, Any]:
    return {
        "format": 1,
        "schema": "crabc-mimalloc-x86_64-regular-small-evidence",
        "profile": EXPECTED_PROFILE,
        "target": copy.deepcopy(EXPECTED_TARGET),
        "upstream": copy.deepcopy(EXPECTED_UPSTREAM),
        "scope": copy.deepcopy(EXPECTED_SCOPE),
        "compile_definitions": list(EXPECTED_COMPILE_DEFINITIONS),
        "release_flags": list(run.CONFIGURATION_PROFILES["release"]),
        "release_source_set": list(run.ORACLE_SOURCES),
        "source_anchors": [
            {"member": member, "start_line": start, "end_line": end, "sha256": digest}
            for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
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
    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 regular-small evidence schema") from error
    if not exactly_matches(schema, _schema_template()):
        raise EvidenceError("regular-small checked-in schema drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate the pinned regular-small upstream identity") from error
    observed_pin = {
        "archive_root": pin["archive_root"],
        "revision": pin["revision"],
        "version": pin["version"],
    }
    if not exactly_matches(observed_pin, EXPECTED_UPSTREAM) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("regular-small upstream archive pin drifted")
    return schema


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    anchors = schema["source_anchors"]
    assert isinstance(anchors, list)
    validated: list[dict[str, Any]] = []
    for anchor in anchors:
        assert isinstance(anchor, dict)
        member = str(anchor["member"])
        contents = (source / member).read_bytes()
        observed = sha256_bytes(
            source_range(contents, int(anchor["start_line"]), int(anchor["end_line"]))
        )
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned regular-small source anchor drifted: {member}")
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(
            output, begin=TRACE_BEGIN, end=TRACE_END, description=description
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    non_integer = sorted(key for key, value in trace.items() if type(value) is not int)
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
        raise EvidenceError(f"{description} differs from the fixed regular-small trace: " + "; ".join(details))


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C regular-small trace")
    validate_trace(rust_trace, description="Rust regular-small trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise EvidenceError("Rust regular-small trace differs from pinned C: " + ", ".join(mismatches))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized: list[str] = []
    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            normalized.append(NORMALIZED_PINNED_SOURCE + part[len(source_text) :])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text) :])
        else:
            normalized.append(part)
    return normalized


def c_trace_command(
    compiler: str, source: Path, probe_source: Path, probe_binary: Path, schema: Mapping[str, Any]
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


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(EXPECTED_COMPILE_DEFINITIONS) or definitions != list(schema["compile_definitions"]):
        raise EvidenceError("regular-small C command compile definitions drifted")
    if flags != list(schema["release_flags"]) or "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("regular-small C command release pthread/TLS selection drifted")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("regular-small report C command is malformed")
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
        f"{NORMALIZED_EVIDENCE_ROOT}/regular-small.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/regular-small-c",
    ]
    if Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise EvidenceError("regular-small report C command drifted")


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
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("regular-small report Rust command is malformed")
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
        raise EvidenceError("regular-small report Rust command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]
) -> dict[str, Any]:
    probe_source = temporary / "regular-small.c"
    probe_binary = temporary / "regular-small-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C regular-small fixture build")
        header = run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        run.require_success(header, "pinned C regular-small fixture ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(probe_binary),), cwd=source)
        run.require_success(execution, "pinned C regular-small fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C regular-small trace")
    validate_trace(trace, description="pinned C regular-small trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/regular-small-c"],
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
        run.require_success(execution, "Rust regular-small fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust regular-small fixture passed {passed} tests, expected one")
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust regular-small trace",
    )
    validate_trace(trace, description="Rust regular-small trace")
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
        raise EvidenceError("regular-small report inputs lack trace records")
    report: dict[str, Any] = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": "mimalloc-x86_64-regular-small-retire-quick-collect-differential-evidence",
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


def validate_report(report: Mapping[str, Any]) -> None:
    required = {
        "c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe",
        "scope", "source", "status", "target", "trace", "upstream",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("regular-small report schema drifted")
    if report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("regular-small report format/status drifted")
    if report["kind"] != "mimalloc-x86_64-regular-small-retire-quick-collect-differential-evidence":
        raise EvidenceError("regular-small report kind drifted")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("regular-small report target/upstream drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("regular-small report private boundary drifted")
    if not any(
        exactly_matches(report["provenance"], candidate)
        for candidate in (
            {"execution_mode": "native", "host_architecture": "x86_64"},
            {"execution_mode": "native", "host_architecture": "amd64"},
        )
    ):
        raise EvidenceError("regular-small report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("regular-small report trace contract drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {
        "archive_sha256", "anchors", "release_flags", "release_source_set"
    }:
        raise EvidenceError("regular-small report source record is malformed")
    if source["archive_sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("regular-small report archive identity drifted")
    if not exactly_matches(source["anchors"], schema["source_anchors"]):
        raise EvidenceError("regular-small report source anchors drifted")
    if not exactly_matches(source["release_flags"], schema["release_flags"]):
        raise EvidenceError("regular-small report release flags drifted")
    if not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("regular-small report source set drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {
        "build_command", "elf", "run_command", "source_sha256", "trace"
    }:
        raise EvidenceError("regular-small report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {
        "cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"
    }:
        raise EvidenceError("regular-small report Rust probe record drifted")
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF):
        raise EvidenceError("regular-small report C ELF identity drifted")
    if c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/regular-small-c"]:
        raise EvidenceError("regular-small report C run command drifted")
    if c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("regular-small report C source hash drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if type(rust_probe["passed_test_count"]) is not int or rust_probe["passed_test_count"] != 1:
        raise EvidenceError("regular-small report Rust test selection drifted")
    if not exactly_matches(
        rust_probe["target_dir"],
        {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"},
    ):
        raise EvidenceError("regular-small report Rust target directory drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(
        rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}
    ):
        raise EvidenceError("regular-small report Rust lockfile identity drifted")
    if not exactly_matches(
        rust_probe["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}
    ):
        raise EvidenceError("regular-small report Rust source identity drifted")
    if not isinstance(c_probe["trace"], Mapping) or not isinstance(rust_probe["trace"], Mapping):
        raise EvidenceError("regular-small report lacks C/Rust traces")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise EvidenceError("regular-small report comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-regular-small-") as temporary_name:
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
            schema=schema,
            provenance=provenance,
            archive_sha256=sha256_file(archive),
            anchors=anchors,
            c_probe=c_probe,
            rust_probe=rust_probe,
        )
    if sha256_file(LOCKFILE) != before_lockfile:
        raise EvidenceError("Cargo.lock changed despite the required --locked Rust trace command")
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
        print(f"allocator x86-64 regular-small differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 regular-small differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
