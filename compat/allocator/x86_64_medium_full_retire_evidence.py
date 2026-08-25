#!/usr/bin/env python3
"""Differentially prove one private owner-local medium full/unfull/retire trace."""

from __future__ import annotations

import importlib.util
import os
import copy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
_spec = importlib.util.spec_from_file_location("regular_small_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)

SCHEMA_PATH = ROOT / "compat/allocator/x86_64-medium-full-retire-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/medium-full-retire.json"
EXPECTED_PROFILE = "linux-x86_64-private-medium-full-regular-retire-force-release"
RUST_TEST_FILTER = (
    "single_thread::tests::"
    "x86_64_medium_full_unfull_retire_force_release_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_MEDIUM_FULL_TRACE_BEGIN"
TRACE_END = "CRABC_MI_MEDIUM_FULL_TRACE_END"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "abandonment_disabled_only": True,
    "emulation_accepted": False,
    "forced_retired_release_only": True,
    "general_lifecycle_claimed": False,
    "general_retirement_claimed": False,
    "native_linux_x86_64_required": True,
    "ordinary_medium_page_only": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "single_theap_same_thread_only": True,
}
EXPECTED_SOURCE_ANCHORS = (
    ("include/mimalloc.h", 122, 123, "254ce29a1c8187dae3f5cccd5f98bbf7f71f448f68cbb5e822dd6f74f291778c"),
    ("include/mimalloc/types.h", 228, 238, "7a29585d14970109c4c0ecff95c918e90d43c57eb8de4fcd9495ef8cb277d907"),
    ("include/mimalloc/types.h", 430, 449, "9befd05f3264611334cec9745bbd1de88fe83f01b4a1c7f2b9beadb3e6badb5f"),
    ("include/mimalloc/types.h", 731, 740, "d898791180decb2ddb76eca0a7373a68e2437cce514c35d10b674fbb3d6e4988"),
    ("src/page-queue.c", 92, 116, "bfbc65c903825cf36ec379c52ba6ee7857a8965861b69b2486d05c05913cf011"),
    ("src/arena.c", 980, 998, "4d66fd65bb721890af00061539085a8a10b6c8226c4da8fcf21d874ac084aa74"),
    ("src/arena.c", 1053, 1064, "e2063beb8a77f1bf35554b3ad7fb761362d2c430434867c68a67b7f7315c2371"),
    ("src/arena.c", 1183, 1204, "09e82c9f0473e73a9fad065943d41fdab4b85faf570274bddbac77aee3b6860a"),
    ("src/arena.c", 1285, 1308, "d6649da0e0a6903b0e0bde04d12df78a99159d8c64b2acfb4c51a1827af9f3d1"),
    ("src/free.c", 44, 56, "de6d94667e1d6b127947a347660b35b4eaf1480751da492154de4a1e48f43e13"),
    ("src/page.c", 350, 413, "5b409a75471fbfec55eca726ffaeda2748f1ca0fd919d157dea9a04be01fbde6"),
    ("src/page.c", 414, 457, "2c58d5b8b71c68e9dc1794c63a218f41f374b85f822abc60ba920d65efe5a30a"),
    ("src/page.c", 460, 518, "9e0c373ed5a817f9e9998319442aaf7b5870509e4821a57686179b54ff6428af"),
    ("src/page.c", 1068, 1081, "af1dea54316ebd65ce020d39dd30dd4ed97fb1908533a952fc4eb0ebee2ecd31"),
    ("src/theap.c", 123, 165, "a84d17ad1b74eb93e79bb3b756f099fd60fe611eda6279c17db283c44cccc1bb"),
    ("src/theap.c", 228, 232, "16c0e73a20b9a94bf994c4e83836c976f5683e3c6e8b18935782a934405adba0"),
    ("src/page-map.c", 460, 515, "c752c966d40e6ebd16795295a1a87d3b8a762cdfc4ba752aa3a043df44dfb495"),
)

EXPECTED_TRACE_VALUES = {
    "trace.medium_full.request": 10241,
    "trace.medium_full.block_size": 12288,
    "trace.medium_full.capacity": 42,
    "trace.medium_full.slice_count": 8,
    "trace.medium_full.arena_backed": 1,
    "trace.medium_full.filled.used": 42,
    "trace.medium_full.filled.regular_queue": 0,
    "trace.medium_full.filled.full_queue": 1,
    "trace.medium_full.filled.page_count": 1,
    "trace.medium_full.filled.free_empty": 1,
    "trace.medium_full.filled.local_empty": 1,
    "trace.medium_full.filled.remote_empty": 1,
    "trace.medium_full.unfull.used": 41,
    "trace.medium_full.unfull.regular_queue": 1,
    "trace.medium_full.unfull.full_queue": 0,
    "trace.medium_full.unfull.in_full": 0,
    "trace.medium_full.unfull.free_empty": 1,
    "trace.medium_full.unfull.local_nonempty": 1,
    "trace.medium_full.unfull.remote_empty": 1,
    "trace.medium_full.retired.used": 0,
    "trace.medium_full.retired.expire": 4,
    "trace.medium_full.retired.regular_queue": 1,
    "trace.medium_full.retired.full_queue": 0,
    "trace.medium_full.retired.free_empty": 1,
    "trace.medium_full.retired.local_nonempty": 1,
    "trace.medium_full.retired.remote_empty": 1,
    "trace.medium_full.retired.map_published": 1,
    "trace.medium_full.retired.arena_page_set": 1,
    "trace.medium_full.retired.slices_unreleased": 1,
    "trace.medium_full.release.regular_queue": 0,
    "trace.medium_full.release.full_queue": 0,
    "trace.medium_full.release.page_count": 0,
    "trace.medium_full.release.map_clear": 1,
    "trace.medium_full.release.span_map_clear": 1,
    "trace.medium_full.release.arena_page_clear": 1,
    "trace.medium_full.release.slices_free": 1,
    "trace.medium_full.valid": 1,
}

C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private medium fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0 || MI_PADDING != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native two-level map and unencoded release freelist
#endif

int main(void) {
  const size_t request = MI_SMALL_MAX_OBJ_SIZE + 1;
  void* blocks[64] = { 0 };
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_queue_t* regular = NULL;
  mi_page_queue_t* full = NULL;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  uintptr_t saved_address = 0, saved_slice_start = 0;
  size_t block_count = 0, slice_index = 0, slice_count = 0;
  size_t block_size = 0, capacity = 0;
  long old_full_retain = 0;
  bool options_changed = false, released = false, valid = false;
  size_t filled_used = 0, filled_regular = 0, filled_full = 0, filled_pages = 0;
  int filled_free = 0, filled_local = 0, filled_remote = 0;
  size_t unfull_used = 0, unfull_regular = 0, unfull_full = 0;
  int unfull_in_full = 0, unfull_free = 0, unfull_local = 0, unfull_remote = 0;
  size_t retired_used = 0, retired_expire = 0, retired_regular = 0, retired_full = 0;
  int retired_free = 0, retired_local = 0, retired_remote = 0;
  int retired_map = 0, retired_pages = 0, retired_slices = 0;
  size_t release_regular = 0, release_full = 0, release_pages = 0;
  int release_map = 0, release_span = 0, release_arena = 0, release_slices = 0;

  mi_thread_init();
  old_full_retain = mi_option_get(mi_option_page_full_retain);
  mi_option_set(mi_option_page_full_retain, -1);
  options_changed = true;
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto output;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto output;
  theap = _mi_heap_theap(heap);
  blocks[0] = mi_heap_malloc(heap, request);
  if (blocks[0] == NULL || theap == NULL) goto output;
  block_count = 1;
  page = _mi_ptr_page(blocks[0]);
  if (page == NULL || page->memid.memkind != MI_MEM_ARENA
      || page->block_size <= MI_SMALL_MAX_OBJ_SIZE
      || page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || page->reserved == 0 || page->reserved > 64) goto output;
  arena = mi_memid_arena(page->memid);
  if (arena == NULL || arena->arena_idx >= MI_MAX_ARENAS) goto output;
  arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  regular = mi_page_queue(theap, page->block_size);
  full = &theap->pages[MI_BIN_FULL];
  if (arena_pages == NULL || regular == NULL || full == NULL || regular->first != page) goto output;
  slice_index = page->memid.mem.arena.slice_index;
  slice_count = page->memid.mem.arena.slice_count;
  block_size = page->block_size;
  capacity = page->reserved;
  saved_address = (uintptr_t)blocks[0];
  saved_slice_start = (uintptr_t)((uint8_t*)arena->start + slice_index * MI_ARENA_SLICE_SIZE);
  while (page->used < page->reserved) {
    if (block_count >= 64) goto output;
    blocks[block_count] = mi_heap_malloc(heap, request);
    if (blocks[block_count] == NULL || _mi_ptr_page(blocks[block_count]) != page) goto output;
    block_count++;
  }
  filled_used = page->used;
  filled_regular = regular->count;
  filled_full = full->count;
  filled_pages = theap->page_count;
  filled_free = (page->free == NULL);
  filled_local = (page->local_free == NULL);
  filled_remote = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  if (block_count != capacity || page->capacity != page->reserved || filled_used != capacity
      || filled_regular != 0 || filled_full != 1 || filled_pages != 1
      || !filled_free || !filled_local || !filled_remote) goto output;

  mi_free(blocks[0]);
  blocks[0] = NULL;
  unfull_used = page->used;
  unfull_regular = regular->count;
  unfull_full = full->count;
  unfull_in_full = mi_page_is_in_full(page);
  unfull_free = (page->free == NULL);
  unfull_local = (page->local_free != NULL);
  unfull_remote = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  if (unfull_used != capacity - 1 || unfull_regular != 1 || unfull_full != 0
      || unfull_in_full || !unfull_free || !unfull_local || !unfull_remote) goto output;
  for (size_t i = 1; i < block_count; i++) { mi_free(blocks[i]); blocks[i] = NULL; }
  retired_used = page->used;
  retired_expire = page->retire_expire;
  retired_regular = regular->count;
  retired_full = full->count;
  retired_free = (page->free == NULL);
  retired_local = (page->local_free != NULL);
  retired_remote = (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) == NULL);
  retired_map = (_mi_safe_ptr_page((const void*)saved_address) == page);
  /* The arena-pages bitmap records the first slice of a multi-slice page. */
  retired_pages = mi_bitmap_is_setN(arena_pages->pages, slice_index, 1);
  retired_slices = mi_bbitmap_is_clearN(arena->slices_free, slice_index, slice_count);
  if (retired_used != 0 || retired_expire != 4 || retired_regular != 1 || retired_full != 0
      || !retired_free || !retired_local || !retired_remote || !retired_map
      || !retired_pages || !retired_slices) goto output;

  mi_heap_collect(heap, true);
  released = true;
  release_regular = regular->count;
  release_full = full->count;
  release_pages = theap->page_count;
  release_map = (_mi_safe_ptr_page((const void*)saved_address) == NULL);
  release_span = 1;
  for (size_t i = 0; i < slice_count; i++) {
    if (_mi_safe_ptr_page((const void*)(saved_slice_start + i * MI_ARENA_SLICE_SIZE)) != NULL)
      release_span = 0;
  }
  release_arena = mi_bitmap_is_clearN(arena_pages->pages, slice_index, 1);
  release_slices = mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count);
  valid = (request == 10241 && block_size == 12288 && capacity == 42 && slice_count == 8
      && filled_used == 42 && filled_regular == 0 && filled_full == 1 && filled_pages == 1
      && filled_free && filled_local && filled_remote && unfull_used == 41
      && unfull_regular == 1 && unfull_full == 0 && !unfull_in_full && unfull_free
      && unfull_local && unfull_remote && retired_used == 0 && retired_expire == 4
      && retired_regular == 1 && retired_full == 0 && retired_free && retired_local
      && retired_remote && retired_map && retired_pages && retired_slices && release_regular == 0
      && release_full == 0 && release_pages == 0 && release_map && release_span
      && release_arena && release_slices);
output:
  printf("CRABC_MI_MEDIUM_FULL_TRACE_BEGIN\n");
#define OUT_N(k,v) printf("trace.medium_full.%s=%zu\n", k, (size_t)(v))
#define OUT_B(k,v) printf("trace.medium_full.%s=%d\n", k, (v) ? 1 : 0)
  OUT_N("request", request); OUT_N("block_size", block_size); OUT_N("capacity", capacity);
  OUT_N("slice_count", slice_count); OUT_B("arena_backed", arena != NULL);
  OUT_N("filled.used", filled_used); OUT_N("filled.regular_queue", filled_regular);
  OUT_N("filled.full_queue", filled_full); OUT_N("filled.page_count", filled_pages);
  OUT_B("filled.free_empty", filled_free); OUT_B("filled.local_empty", filled_local); OUT_B("filled.remote_empty", filled_remote);
  OUT_N("unfull.used", unfull_used); OUT_N("unfull.regular_queue", unfull_regular); OUT_N("unfull.full_queue", unfull_full);
  OUT_B("unfull.in_full", unfull_in_full); OUT_B("unfull.free_empty", unfull_free); OUT_B("unfull.local_nonempty", unfull_local); OUT_B("unfull.remote_empty", unfull_remote);
  OUT_N("retired.used", retired_used); OUT_N("retired.expire", retired_expire); OUT_N("retired.regular_queue", retired_regular); OUT_N("retired.full_queue", retired_full);
  OUT_B("retired.free_empty", retired_free); OUT_B("retired.local_nonempty", retired_local); OUT_B("retired.remote_empty", retired_remote); OUT_B("retired.map_published", retired_map); OUT_B("retired.arena_page_set", retired_pages); OUT_B("retired.slices_unreleased", retired_slices);
  OUT_N("release.regular_queue", release_regular); OUT_N("release.full_queue", release_full); OUT_N("release.page_count", release_pages); OUT_B("release.map_clear", release_map); OUT_B("release.span_map_clear", release_span); OUT_B("release.arena_page_clear", release_arena); OUT_B("release.slices_free", release_slices);
  OUT_B("valid", valid);
  printf("CRABC_MI_MEDIUM_FULL_TRACE_END\n");
  if (!released && heap != NULL) {
    for (size_t i = 0; i < block_count; i++) if (blocks[i] != NULL) mi_free(blocks[i]);
  }
  if (heap != NULL) mi_heap_destroy(heap);
  if (options_changed) mi_option_set(mi_option_page_full_retain, old_full_retain);
  return valid ? 0 : 2;
}
'''

MEDIUM_KIND = "mimalloc-x86_64-medium-full-regular-retire-force-release-differential-evidence"
_BASE_SCHEMA_TEMPLATE = _base._schema_template
_BASE_REPORT_FROM_RESULTS = _base.report_from_results
_BASE_VALIDATE_REPORT = _base.validate_report
_BASE_VALIDATE_NORMALIZED_C_COMMAND = _base.validate_normalized_c_command


def _schema_template() -> dict:
    value = _BASE_SCHEMA_TEMPLATE()
    value["schema"] = "crabc-mimalloc-x86_64-medium-full-retire-evidence"
    value["profile"] = EXPECTED_PROFILE
    # The private shared mechanics are an intentional dependency, not an
    # implicit fallback: pin their exact checked-in image so this lane cannot
    # silently inherit a changed parser, native-provenance check, or report
    # validator from the regular-small differential.
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


def c_trace_command(compiler: str, source: Path, probe_source: Path, probe_binary: Path, schema: dict) -> list[str]:
    return [
        compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"),
        *schema["release_flags"], str(probe_source),
        *(str(source / member) for member in schema["release_source_set"]),
        "-pthread", "-o", str(probe_binary),
    ]


def validate_c_command(command: list[str], schema: dict) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in _base.run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(EXPECTED_COMPILE_DEFINITIONS) or definitions != list(schema["compile_definitions"]):
        raise EvidenceError("medium-full C command compile definitions drifted")
    if flags != list(schema["release_flags"]) or "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("medium-full C command release pthread/TLS selection drifted")


def validate_normalized_c_command(command: object, schema: dict) -> None:
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/medium-full-retire.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/medium-full-retire-c",
    ]
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise EvidenceError("medium-full report C command drifted")


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: dict) -> dict:
    probe_source = temporary / "medium-full-retire.c"
    probe_binary = temporary / "medium-full-retire-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        _base.run.require_success(_base.run.command_record(command, cwd=source), "pinned C medium-full fixture build")
        header = _base.run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        _base.run.require_success(header, "pinned C medium-full fixture ELF identity")
        elf = _base.run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = _base.run.command_record((str(probe_binary),), cwd=source)
        _base.run.require_success(execution, "pinned C medium-full fixture execution")
    except _base.run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C medium-full trace")
    validate_trace(trace, description="pinned C medium-full trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/medium-full-retire-c"],
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
    report["kind"] = MEDIUM_KIND
    validate_report(report)
    return report


def validate_report(report: dict) -> None:
    if report.get("kind") != MEDIUM_KIND:
        raise EvidenceError("medium-full report kind drifted")
    c_probe = report.get("c_probe")
    if not isinstance(c_probe, dict) or c_probe.get("run_command") != [f"{NORMALIZED_EVIDENCE_ROOT}/medium-full-retire-c"]:
        raise EvidenceError("medium-full report C command drifted")
    if c_probe.get("source_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("medium-full report C source hash drifted")
    validate_normalized_c_command(c_probe.get("build_command"), load_schema())
    compatible = copy.deepcopy(report)
    compatible["kind"] = "mimalloc-x86_64-regular-small-retire-quick-collect-differential-evidence"
    compatible["c_probe"]["run_command"] = [f"{NORMALIZED_EVIDENCE_ROOT}/regular-small-c"]
    compatible["c_probe"]["build_command"] = [
        part.replace("medium-full-retire", "regular-small")
        for part in compatible["c_probe"]["build_command"]
    ]
    try:
        _base.validate_normalized_c_command = _BASE_VALIDATE_NORMALIZED_C_COMMAND
        _BASE_VALIDATE_REPORT(compatible)
    finally:
        _base.validate_normalized_c_command = validate_normalized_c_command

# Reuse the audited regular-small mechanics while binding every contract value
# to this medium-only fixture. This is an explicit private implementation
# dependency pinned by the checked-in schema, not a public API or fallback.
for _name in (
    "SCHEMA_PATH", "REPORT_DEFAULT", "EXPECTED_PROFILE", "RUST_TEST_FILTER",
    "TRACE_BEGIN", "TRACE_END", "EXPECTED_SCOPE", "EXPECTED_SOURCE_ANCHORS",
    "EXPECTED_TRACE_VALUES", "C_TRACE_PROBE",
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
    "EvidenceError", "sha256_bytes", "sha256_file", "relative", "load_schema",
    "validate_source_anchors", "parse_trace", "validate_trace",
    "compare_traces", "normalize_command", "c_trace_command", "validate_c_command",
    "validate_normalized_c_command", "rust_trace_command", "validate_normalized_rust_command",
    "run_evidence", "EXPECTED_TARGET",
    "EXPECTED_UPSTREAM", "EXPECTED_ARCHIVE_SHA256", "EXPECTED_COMPILE_DEFINITIONS",
    "EXPECTED_C_ELF", "LOCKFILE", "RUST_TEST_SOURCE", "TARGET", "NORMALIZED_EVIDENCE_ROOT",
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
        print(f"allocator x86-64 medium-full differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 medium-full differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
