#!/usr/bin/env python3
"""Differentially prove one owner-local direct-small full/retire/release trace.

The fixed C oracle fills one arena-backed 1024-byte direct-small page without
performing the later generic queue scan that can move an exhausted small page
to the full queue. It therefore remains the ordinary regular-bin direct-cache
head while full, locally retires as that bin's sole page, and is then
force-collected through its direct-cache, PageMap, arena bitmap, and slice
release boundary.

This is private native Linux/x86-64 fixed-mimalloc evidence only. It does not
claim public x86 support, a general retirement/lifecycle behavior, remote
routing, thread exit, abandonment/adoption, or an AArch64 result.
"""

from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
_spec = importlib.util.spec_from_file_location("regular_small_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)

SCHEMA_PATH = ROOT / "compat/allocator/x86_64-direct-small-full-retire-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/direct-small-full-retire.json"
EXPECTED_PROFILE = "linux-x86_64-private-direct-small-full-regular-retire-force-release"
RUST_TEST_FILTER = (
    "single_thread::tests::"
    "x86_64_direct_small_full_regular_retire_force_release_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_DIRECT_SMALL_FULL_RETIRE_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DIRECT_SMALL_FULL_RETIRE_TRACE_END"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "forced_retired_release_only": True,
    "full_direct_small_regular_bin_only": True,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_remote_free_routing_claimed": False,
    "general_retirement_claimed": False,
    "native_linux_x86_64_required": True,
    "owner_local_retire_only": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "single_theap_same_thread_only": True,
    "thread_exit_claimed": False,
}
EXPECTED_SOURCE_ANCHORS = (
    ("include/mimalloc.h", 122, 123, "254ce29a1c8187dae3f5cccd5f98bbf7f71f448f68cbb5e822dd6f74f291778c"),
    ("include/mimalloc/types.h", 430, 449, "9befd05f3264611334cec9745bbd1de88fe83f01b4a1c7f2b9beadb3e6badb5f"),
    ("src/alloc.c", 29, 58, "ebecab0a27c74739c146a986504e36e8361dbac617a78071cc97ef8d3e67602a"),
    ("src/arena.c", 980, 998, "4d66fd65bb721890af00061539085a8a10b6c8226c4da8fcf21d874ac084aa74"),
    ("src/arena.c", 1053, 1064, "e2063beb8a77f1bf35554b3ad7fb761362d2c430434867c68a67b7f7315c2371"),
    ("src/arena.c", 1183, 1204, "09e82c9f0473e73a9fad065943d41fdab4b85faf570274bddbac77aee3b6860a"),
    ("src/arena.c", 1216, 1298, "f03933764ea1a18dd674a80738205efcd294b87e15fbdaa5f2f7add5c3263645"),
    ("src/free.c", 26, 56, "14991fee0050592f4648ce329c4af35486aa8478d526ff1cd3590e9e1c1355be"),
    ("src/page-map.c", 460, 515, "c752c966d40e6ebd16795295a1a87d3b8a762cdfc4ba752aa3a043df44dfb495"),
    ("src/page-queue.c", 204, 244, "4216ce3f998d0a8c3891e0c89e1feaa34aff407d10e14135e68334ce833d6e6b"),
    ("src/page.c", 214, 243, "35148cff687e602b8de307ca1abad524655f48bf4410b2c64a7e44af8909203b"),
    ("src/page.c", 308, 350, "3c21436fc5bc43fac8847d62af99f10ca3624885da75e11d3b03490fa930f9ac"),
    ("src/page.c", 392, 457, "34a443fb93957c79000cb4e3fa9277077a18824a23bcca675bb41b0f21a7695d"),
    ("src/page.c", 481, 518, "a9b7636f8fbec09a0fe97d482c7d66f89bb1be0a1c0118047b8b5ac5dcb1f0a7"),
    ("src/theap.c", 23, 48, "4df1e18388900637745d7867bb5a4b6e1bac86679b550bb8ff77ac6ff9a68679"),
    ("src/theap.c", 97, 114, "9c66a394ded8185fc4af733ddcf4fd2f60db3922fc8c547400bc612def40f2d5"),
)
EXPECTED_TRACE_VALUES = {
    "trace.direct_small_full.request": 1024,
    "trace.direct_small_full.block_size": 1024,
    "trace.direct_small_full.capacity": 64,
    "trace.direct_small_full.slice_count": 1,
    "trace.direct_small_full.arena_backed": 1,
    "trace.direct_small_full.direct_range_start": 113,
    "trace.direct_small_full.direct_range_end": 128,
    "trace.direct_small_full.filled.used": 64,
    "trace.direct_small_full.filled.regular_queue": 1,
    "trace.direct_small_full.filled.full_queue": 0,
    "trace.direct_small_full.filled.page_count": 1,
    "trace.direct_small_full.filled.not_in_full": 1,
    "trace.direct_small_full.filled.free_empty": 1,
    "trace.direct_small_full.filled.local_empty": 1,
    "trace.direct_small_full.filled.remote_empty": 1,
    "trace.direct_small_full.filled.direct_range_matches": 1,
    "trace.direct_small_full.retired.used": 0,
    "trace.direct_small_full.retired.expire": 16,
    "trace.direct_small_full.retired.regular_queue": 1,
    "trace.direct_small_full.retired.full_queue": 0,
    "trace.direct_small_full.retired.page_count": 1,
    "trace.direct_small_full.retired.not_in_full": 1,
    "trace.direct_small_full.retired.free_empty": 1,
    "trace.direct_small_full.retired.local_nonempty": 1,
    "trace.direct_small_full.retired.remote_empty": 1,
    "trace.direct_small_full.retired.direct_range_matches": 1,
    "trace.direct_small_full.retired.map_published": 1,
    "trace.direct_small_full.retired.arena_page_set": 1,
    "trace.direct_small_full.retired.slices_unreleased": 1,
    "trace.direct_small_full.release.regular_queue": 0,
    "trace.direct_small_full.release.full_queue": 0,
    "trace.direct_small_full.release.page_count": 0,
    "trace.direct_small_full.release.direct_range_empty": 1,
    "trace.direct_small_full.release.map_clear": 1,
    "trace.direct_small_full.release.span_map_clear": 1,
    "trace.direct_small_full.release.arena_page_clear": 1,
    "trace.direct_small_full.release.slices_free": 1,
    "trace.direct_small_full.valid": 1,
}

C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private direct-small fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0 || MI_PADDING != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native two-level map and unencoded release freelist
#endif

#define CRABC_DIRECT_SMALL_MAX_BLOCKS 128

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
  void* blocks[CRABC_DIRECT_SMALL_MAX_BLOCKS] = { 0 };
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_queue_t* regular = NULL;
  mi_page_queue_t* full = NULL;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  uintptr_t saved_address = 0;
  uintptr_t saved_slice_start = 0;
  size_t block_count = 0;
  size_t block_size = 0;
  size_t capacity = 0;
  size_t slice_index = 0;
  size_t slice_count = 0;
  size_t direct_start = 0;
  size_t direct_end = 0;
  bool released = false;
  bool valid = false;

  int arena_backed = 0;
  size_t filled_used = 0, filled_regular = 0, filled_full = 0, filled_pages = 0;
  int filled_not_in_full = 0, filled_free = 0, filled_local = 0, filled_remote = 0;
  int filled_direct = 0;
  size_t retired_used = 0, retired_expire = 0, retired_regular = 0, retired_full = 0, retired_pages = 0;
  int retired_not_in_full = 0, retired_free = 0, retired_local = 0, retired_remote = 0;
  int retired_direct = 0, retired_map = 0, retired_arena_page = 0, retired_slices = 0;
  size_t release_regular = 0, release_full = 0, release_pages = 0;
  int release_direct = 0, release_map = 0, release_span = 0, release_arena_page = 0, release_slices = 0;

  mi_thread_init();
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto output;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto output;
  theap = _mi_heap_theap(heap);
  blocks[0] = mi_heap_malloc_small(heap, request);
  if (blocks[0] == NULL || theap == NULL) goto output;
  block_count = 1;
  page = _mi_ptr_page(blocks[0]);
  if (page == NULL || page->memid.memkind != MI_MEM_ARENA
      || page->block_size > MI_SMALL_SIZE_MAX || page->reserved == 0
      || page->reserved > CRABC_DIRECT_SMALL_MAX_BLOCKS) goto output;
  arena = mi_memid_arena(page->memid);
  if (arena == NULL || arena->arena_idx >= MI_MAX_ARENAS) goto output;
  arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  regular = mi_page_queue(theap, page->block_size);
  full = &theap->pages[MI_BIN_FULL];
  if (arena_pages == NULL || regular == NULL || full == NULL || regular->first != page
      || regular->count != 1 || mi_page_is_in_full(page)) goto output;

  block_size = page->block_size;
  capacity = page->reserved;
  slice_index = page->memid.mem.arena.slice_index;
  slice_count = page->memid.mem.arena.slice_count;
  saved_address = (uintptr_t)blocks[0];
  saved_slice_start = (uintptr_t)((uint8_t*)arena->start + slice_index * MI_ARENA_SLICE_SIZE);
  arena_backed = (page->memid.memkind == MI_MEM_ARENA);
  if (slice_count == 0 || !direct_cache_image(theap, regular, page, &direct_start, &direct_end)) goto output;

  while (page->used < page->reserved) {
    if (block_count >= CRABC_DIRECT_SMALL_MAX_BLOCKS) goto output;
    blocks[block_count] = mi_heap_malloc_small(heap, request);
    if (blocks[block_count] == NULL || _mi_ptr_page(blocks[block_count]) != page) goto output;
    block_count++;
  }

  filled_used = page->used;
  filled_regular = regular->count;
  filled_full = full->count;
  filled_pages = theap->page_count;
  filled_not_in_full = !mi_page_is_in_full(page);
  filled_free = (page->free == NULL);
  filled_local = (page->local_free == NULL);
  filled_remote = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  filled_direct = direct_cache_image(theap, regular, page, NULL, NULL);
  if (block_count != capacity || page->capacity != page->reserved || !mi_page_is_full(page)
      || filled_used != capacity || filled_regular != 1 || filled_full != 0 || filled_pages != 1
      || !filled_not_in_full || !filled_free || !filled_local || !filled_remote || !filled_direct) goto output;

  for (size_t index = 0; index < block_count; index++) {
    mi_free(blocks[index]);
    blocks[index] = NULL;
  }

  retired_used = page->used;
  retired_expire = page->retire_expire;
  retired_regular = regular->count;
  retired_full = full->count;
  retired_pages = theap->page_count;
  retired_not_in_full = !mi_page_is_in_full(page);
  retired_free = (page->free == NULL);
  retired_local = (page->local_free != NULL);
  retired_remote = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  retired_direct = direct_cache_image(theap, regular, page, NULL, NULL);
  retired_map = (_mi_safe_ptr_page((const void*)saved_address) == page);
  retired_arena_page = mi_bitmap_is_setN(arena_pages->pages, slice_index, 1);
  retired_slices = mi_bbitmap_is_clearN(arena->slices_free, slice_index, slice_count);
  if (retired_used != 0 || retired_expire != 16 || retired_regular != 1 || retired_full != 0
      || retired_pages != 1 || !retired_not_in_full || !retired_free || !retired_local
      || !retired_remote || !retired_direct || !retired_map || !retired_arena_page
      || !retired_slices) goto output;

  mi_heap_collect(heap, true);
  released = true;
  release_regular = regular->count;
  release_full = full->count;
  release_pages = theap->page_count;
  release_direct = direct_cache_image(theap, regular, NULL, NULL, NULL);
  release_map = (_mi_safe_ptr_page((const void*)saved_address) == NULL);
  release_span = 1;
  for (size_t index = 0; index < slice_count; index++) {
    if (_mi_safe_ptr_page((const void*)(saved_slice_start + index * MI_ARENA_SLICE_SIZE)) != NULL) {
      release_span = 0;
    }
  }
  release_arena_page = mi_bitmap_is_clearN(arena_pages->pages, slice_index, 1);
  release_slices = mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count);
  valid = (request == 1024 && block_size == 1024 && capacity == 64 && slice_count == 1
      && arena_backed && direct_start == 113 && direct_end == 128
      && filled_used == 64 && filled_regular == 1 && filled_full == 0 && filled_pages == 1
      && filled_not_in_full && filled_free && filled_local && filled_remote && filled_direct
      && retired_used == 0 && retired_expire == 16 && retired_regular == 1 && retired_full == 0
      && retired_pages == 1 && retired_not_in_full && retired_free && retired_local && retired_remote
      && retired_direct && retired_map && retired_arena_page && retired_slices
      && release_regular == 0 && release_full == 0 && release_pages == 0 && release_direct
      && release_map && release_span && release_arena_page && release_slices);

output:
  printf("CRABC_MI_DIRECT_SMALL_FULL_RETIRE_TRACE_BEGIN\n");
#define OUT_N(k,v) printf("trace.direct_small_full.%s=%zu\n", k, (size_t)(v))
#define OUT_B(k,v) printf("trace.direct_small_full.%s=%d\n", k, (v) ? 1 : 0)
  OUT_N("request", request); OUT_N("block_size", block_size); OUT_N("capacity", capacity);
  OUT_N("slice_count", slice_count); OUT_B("arena_backed", arena_backed);
  OUT_N("direct_range_start", direct_start); OUT_N("direct_range_end", direct_end);
  OUT_N("filled.used", filled_used); OUT_N("filled.regular_queue", filled_regular);
  OUT_N("filled.full_queue", filled_full); OUT_N("filled.page_count", filled_pages);
  OUT_B("filled.not_in_full", filled_not_in_full); OUT_B("filled.free_empty", filled_free);
  OUT_B("filled.local_empty", filled_local); OUT_B("filled.remote_empty", filled_remote);
  OUT_B("filled.direct_range_matches", filled_direct);
  OUT_N("retired.used", retired_used); OUT_N("retired.expire", retired_expire);
  OUT_N("retired.regular_queue", retired_regular); OUT_N("retired.full_queue", retired_full);
  OUT_N("retired.page_count", retired_pages); OUT_B("retired.not_in_full", retired_not_in_full);
  OUT_B("retired.free_empty", retired_free); OUT_B("retired.local_nonempty", retired_local);
  OUT_B("retired.remote_empty", retired_remote); OUT_B("retired.direct_range_matches", retired_direct);
  OUT_B("retired.map_published", retired_map); OUT_B("retired.arena_page_set", retired_arena_page);
  OUT_B("retired.slices_unreleased", retired_slices);
  OUT_N("release.regular_queue", release_regular); OUT_N("release.full_queue", release_full);
  OUT_N("release.page_count", release_pages); OUT_B("release.direct_range_empty", release_direct);
  OUT_B("release.map_clear", release_map); OUT_B("release.span_map_clear", release_span);
  OUT_B("release.arena_page_clear", release_arena_page); OUT_B("release.slices_free", release_slices);
  OUT_B("valid", valid);
  printf("CRABC_MI_DIRECT_SMALL_FULL_RETIRE_TRACE_END\n");

  if (!released && heap != NULL) {
    for (size_t index = 0; index < block_count; index++) {
      if (blocks[index] != NULL) mi_free(blocks[index]);
    }
    mi_heap_collect(heap, true);
  }
  if (heap != NULL) mi_heap_destroy(heap);
  return valid ? 0 : 2;
}
'''

DIRECT_SMALL_FULL_RETIRE_KIND = (
    "mimalloc-x86_64-direct-small-full-regular-retire-force-release-differential-evidence"
)
_BASE_SCHEMA_TEMPLATE = _base._schema_template
_BASE_REPORT_FROM_RESULTS = _base.report_from_results
_BASE_VALIDATE_REPORT = _base.validate_report
_BASE_VALIDATE_NORMALIZED_C_COMMAND = _base.validate_normalized_c_command


def _schema_template() -> dict:
    value = _BASE_SCHEMA_TEMPLATE()
    value["schema"] = "crabc-mimalloc-x86_64-direct-small-full-regular-retire-evidence"
    value["profile"] = EXPECTED_PROFILE
    # This lane intentionally reuses only the private evidence mechanics. The
    # dependency hash makes that reuse explicit rather than silently inheriting
    # a changed parser, native-provenance check, or report validator.
    value["harness_dependency"] = {
        "path": relative(BASE_PATH),
        "sha256": sha256_file(BASE_PATH),
    }
    value["scope"] = dict(EXPECTED_SCOPE)
    value["source_anchors"] = [
        {"member": member, "start_line": start, "end_line": end, "sha256": digest}
        for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
    ]
    value["c_probe_sha256"] = sha256_bytes(C_TRACE_PROBE.encode("utf-8"))
    value["rust_test"] = {
        "path": "crabc-mimalloc/src/single_thread.rs",
        "target_arch": "x86_64",
        "test_filter": RUST_TEST_FILTER,
    }
    value["trace"] = {
        "begin": TRACE_BEGIN,
        "end": TRACE_END,
        "expected_values": dict(EXPECTED_TRACE_VALUES),
    }
    return value


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
    flags = [part for part in command if part in _base.run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(EXPECTED_COMPILE_DEFINITIONS) or definitions != list(schema["compile_definitions"]):
        raise EvidenceError("direct-small-full-retire C command compile definitions drifted")
    if (
        flags != list(schema["release_flags"])
        or "-pthread" not in command
        or "-ftls-model=initial-exec" not in command
    ):
        raise EvidenceError("direct-small-full-retire C command release pthread/TLS selection drifted")


def validate_normalized_c_command(command: object, schema: dict) -> None:
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
        f"{NORMALIZED_EVIDENCE_ROOT}/direct-small-full-retire.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/direct-small-full-retire-c",
    ]
    if (
        not isinstance(command, list)
        or not command
        or Path(command[0]).name != "musl-gcc"
        or command[1:] != expected
    ):
        raise EvidenceError("direct-small-full-retire report C command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: dict
) -> dict:
    probe_source = temporary / "direct-small-full-retire.c"
    probe_binary = temporary / "direct-small-full-retire-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        _base.run.require_success(
            _base.run.command_record(command, cwd=source),
            "pinned C direct-small-full-retire fixture build",
        )
        header = _base.run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        _base.run.require_success(
            header, "pinned C direct-small-full-retire fixture ELF identity"
        )
        elf = _base.run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = _base.run.command_record((str(probe_binary),), cwd=source)
        _base.run.require_success(
            execution, "pinned C direct-small-full-retire fixture execution"
        )
    except _base.run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(
        str(execution["stdout"]), description="pinned C direct-small-full-retire trace"
    )
    validate_trace(trace, description="pinned C direct-small-full-retire trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/direct-small-full-retire-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def report_from_results(**kwargs):
    checker = _base.validate_report
    _base.validate_report = lambda _report: None
    try:
        report = _BASE_REPORT_FROM_RESULTS(**kwargs)
    finally:
        _base.validate_report = checker
    report["kind"] = DIRECT_SMALL_FULL_RETIRE_KIND
    validate_report(report)
    return report


def validate_report(report: dict) -> None:
    if report.get("kind") != DIRECT_SMALL_FULL_RETIRE_KIND:
        raise EvidenceError("direct-small-full-retire report kind drifted")
    c_probe = report.get("c_probe")
    if (
        not isinstance(c_probe, dict)
        or c_probe.get("run_command")
        != [f"{NORMALIZED_EVIDENCE_ROOT}/direct-small-full-retire-c"]
    ):
        raise EvidenceError("direct-small-full-retire report C command drifted")
    if c_probe.get("source_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("direct-small-full-retire report C source hash drifted")
    validate_normalized_c_command(c_probe.get("build_command"), load_schema())
    compatible = copy.deepcopy(report)
    compatible["kind"] = "mimalloc-x86_64-regular-small-retire-quick-collect-differential-evidence"
    compatible["c_probe"]["run_command"] = [f"{NORMALIZED_EVIDENCE_ROOT}/regular-small-c"]
    compatible["c_probe"]["build_command"] = [
        part.replace("direct-small-full-retire", "regular-small")
        for part in compatible["c_probe"]["build_command"]
    ]
    try:
        _base.validate_normalized_c_command = _BASE_VALIDATE_NORMALIZED_C_COMMAND
        _BASE_VALIDATE_REPORT(compatible)
    finally:
        _base.validate_normalized_c_command = validate_normalized_c_command


# Reuse the audited regular-small evidence mechanics while binding every value
# to this direct-cache-specific fixture. This is a private implementation
# dependency, not a public allocator API or a fallback.
for _name in (
    "SCHEMA_PATH",
    "REPORT_DEFAULT",
    "EXPECTED_PROFILE",
    "RUST_TEST_FILTER",
    "TRACE_BEGIN",
    "TRACE_END",
    "EXPECTED_SCOPE",
    "EXPECTED_SOURCE_ANCHORS",
    "EXPECTED_TRACE_VALUES",
    "C_TRACE_PROBE",
):
    setattr(_base, _name, globals()[_name])

_base._schema_template = _schema_template
_base.c_trace_command = c_trace_command
_base.validate_c_command = validate_c_command
_base.validate_normalized_c_command = validate_normalized_c_command
_base.build_c_trace = build_c_trace
_base.report_from_results = report_from_results
_base.validate_report = validate_report

for _name in (
    "EvidenceError",
    "sha256_bytes",
    "sha256_file",
    "relative",
    "load_schema",
    "validate_source_anchors",
    "parse_trace",
    "validate_trace",
    "compare_traces",
    "normalize_command",
    "c_trace_command",
    "validate_c_command",
    "validate_normalized_c_command",
    "rust_trace_command",
    "validate_normalized_rust_command",
    "run_evidence",
    "EXPECTED_TARGET",
    "EXPECTED_UPSTREAM",
    "EXPECTED_ARCHIVE_SHA256",
    "EXPECTED_COMPILE_DEFINITIONS",
    "EXPECTED_C_ELF",
    "LOCKFILE",
    "RUST_TEST_SOURCE",
    "TARGET",
    "NORMALIZED_EVIDENCE_ROOT",
    "NORMALIZED_PINNED_SOURCE",
):
    globals()[_name] = getattr(_base, _name)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, ValueError) as error:
        print(
            f"allocator x86-64 direct-small-full-retire differential: FAIL: {error}",
            file=os.sys.stderr,
        )
        return 1
    print(
        "allocator x86-64 direct-small-full-retire differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
