#!/usr/bin/env python3
"""Prove one native x86-64 allocation-time mapped-page adoption differential.

The private pinned-C fixture abandons one nonempty arena-backed medium page,
then lets the next allocation claim, reassociate, and requeue that exact page.
The C half reaches the claim through its next same-heap allocation. The Rust
half explicitly consumes the existing test-only mapped-page handoff with
`adopt()` before allocating from the returned engine; it does not make generic
Rust allocation scan abandoned pages. Only this same-origin, one-page,
one-thread adapter mapping is claimed.
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-mapped-adoption-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/mapped-adoption.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/dynamic_theap.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "dynamic_theap::tests::x86_64_mapped_allocation_adoption_trace_matches_pinned_c_protocol"
TRACE_BEGIN = "CRABC_MI_MAPPED_ADOPTION_TRACE_BEGIN"
TRACE_END = "CRABC_MI_MAPPED_ADOPTION_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"
EVIDENCE_SCHEMA = "crabc-mimalloc-x86_64-mapped-adoption-evidence"
EVIDENCE_KIND = "mimalloc-x86_64-mapped-arena-allocation-time-adoption-differential-evidence"
EVIDENCE_LABEL = "mapped-adoption"
PROBE_STEM = "mapped-adoption"
TEMPORARY_PREFIX = "crabc-mimalloc-x86-mapped-adoption-"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded mapped-adoption differential could not establish its claim."""


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
EXPECTED_PROFILE = "linux-x86_64-private-mapped-arena-allocation-time-adoption"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "allocation_time_same_origin_adoption_only": True,
    "arena_backed_only": True,
    "cross_thread_adoption_claimed": False,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "rust_test_adapter_adopt_before_third_allocation_only": True,
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
    ("src/arena.c", 655, 671, "b3f4d4f3397c726f6de0f86b4f989cc5376ffaa597d4b852407b60e6219e58cc"),
    ("src/arena.c", 725, 775, "bb3a4ff85331df5b441fab7ad8b957afe7b9493a095e6591a046eeedfa2281e5"),
    ("src/arena.c", 1130, 1136, "01f8af8a775c7cd2d243ea9ef0a18b5364c175de5475de31c812646c7ef63f02"),
    ("src/arena.c", 1304, 1409, "6a6d08e7cb4a45803619ce1c9d7efab31808068a756a727a4d3fd3d48d30413f"),
    ("src/page.c", 277, 289, "fcf1bbb7f05a126878a5d82df3680532710c9a7e457a628e355a716c75c157d1"),
    ("src/page.c", 291, 303, "d363079d5e484919082b5602cc3757a3e3a357e68594fc040d902232c7458bbf"),
    ("src/page.c", 308, 340, "f4494b356b497a4f2b4a78c58c0da8b70db59769db2cdb25bc667f7d6372ff3d"),
    ("src/page-queue.c", 306, 333, "6b5a60833882d0bf4ac260aca5e21e9c2e63ae773ba356774686df6061e8cb3a"),
    ("include/mimalloc/prim-tls.h", 412, 421, "466e1c5ef5f6fcddae9a518965638676a61bd41b8cbde85a5c0bcba76e2710dd"),
)
EXPECTED_TRACE_VALUES = {
    "trace.mapped_adoption.arena_backed": 1,
    "trace.mapped_adoption.medium_page": 1,
    "trace.mapped_adoption.two_blocks_same_page": 1,
    "trace.mapped_adoption.abandoned_bitmap_before_allocation": 1,
    "trace.mapped_adoption.abandoned_count_before_allocation": 1,
    "trace.mapped_adoption.queue_empty_before_allocation": 1,
    "trace.mapped_adoption.page_count_zero_before_allocation": 1,
    "trace.mapped_adoption.page_map_and_arena_bitmap_preserved": 1,
    "trace.mapped_adoption.remote_list_empty_before_allocation": 1,
    "trace.mapped_adoption.allocation_is_same_page": 1,
    "trace.mapped_adoption.abandoned_bitmap_cleared": 1,
    "trace.mapped_adoption.abandoned_count_cleared": 1,
    "trace.mapped_adoption.original_theap_restored": 1,
    "trace.mapped_adoption.queue_tail_reassociated": 1,
    "trace.mapped_adoption.page_count_restored": 1,
    "trace.mapped_adoption.remote_list_empty": 1,
    "trace.mapped_adoption.used_after_allocation": 3,
    "trace.mapped_adoption.valid": 1,
}


C_TRACE_PROBE = r"""
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <stdbool.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private mapped-adoption fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private mapped-adoption fixture requires the fixed release profile
#endif

int main(void) {
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

  int arena_backed = 0;
  int medium_page = 0;
  int two_blocks_same_page = 0;
  int abandoned_bitmap_before_allocation = 0;
  int abandoned_count_before_allocation = 0;
  int queue_empty_before_allocation = 0;
  int page_count_zero_before_allocation = 0;
  int page_map_and_arena_bitmap_preserved = 0;
  int remote_list_empty_before_allocation = 0;
  int allocation_is_same_page = 0;
  int abandoned_bitmap_cleared = 0;
  int abandoned_count_cleared = 0;
  int original_theap_restored = 0;
  int queue_tail_reassociated = 0;
  int page_count_restored = 0;
  int remote_list_empty = 0;
  int used_after_allocation = -1;

  const size_t request = MI_SMALL_SIZE_MAX + 1024;

  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) {
    goto cleanup;
  }
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto cleanup;
  first = mi_heap_malloc(heap, request);
  survivor = mi_heap_malloc(heap, request);
  if (first == NULL || survivor == NULL) goto cleanup;

  page = _mi_ptr_page(first);
  theap = _mi_heap_theap(heap);
  if (page == NULL || theap == NULL || _mi_ptr_page(survivor) != page
      || page->block_size <= MI_SMALL_SIZE_MAX
      || page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || page->memid.memkind != MI_MEM_ARENA
      || mi_page_is_full(page)) {
    goto cleanup;
  }
  queue = mi_page_queue(theap, page->block_size);
  arena = page->memid.mem.arena.arena;
  if (queue == NULL || arena == NULL || queue->count != 1 || queue->first != page
      || queue->last != page) {
    goto cleanup;
  }
  const size_t bin = _mi_bin(page->block_size);
  const size_t slice_index = page->memid.mem.arena.slice_index;
  arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  if (arena_pages == NULL || arena_pages->pages == NULL
      || arena_pages->pages_abandoned[bin] == NULL
      || !mi_bitmap_is_set(arena_pages->pages, slice_index)) {
    goto cleanup;
  }

  // This retains the source's queue detach, abandoned identity, bitmap/count
  // publication, and owner release. Calling the arena helper directly would
  // skip required page state transitions.
  _mi_page_abandon(page, queue);
  arena_backed = (page->memid.memkind == MI_MEM_ARENA);
  medium_page = (page->block_size > MI_SMALL_SIZE_MAX
                 && page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE
                 && !mi_page_is_full(page));
  two_blocks_same_page = (_mi_ptr_page(first) == page && _mi_ptr_page(survivor) == page);
  abandoned_bitmap_before_allocation = (mi_page_is_abandoned(page)
      && mi_page_is_abandoned_mapped(page)
      && mi_bitmap_is_set(arena_pages->pages_abandoned[bin], slice_index));
  abandoned_count_before_allocation = (mi_atomic_load_relaxed(&heap->abandoned_count[bin]) == 1);
  queue_empty_before_allocation = (queue->count == 0 && queue->first == NULL && queue->last == NULL);
  page_count_zero_before_allocation = (theap->page_count == 0);
  // `_mi_checked_ptr_page` is the pinned PageMap lookup even in this
  // release configuration, where the ordinary pointer helper may use an
  // aligned metadata fast path.
  page_map_and_arena_bitmap_preserved = (_mi_checked_ptr_page(first) == page
      && _mi_checked_ptr_page(survivor) == page
      && mi_bitmap_is_set(arena_pages->pages, slice_index));
  remote_list_empty_before_allocation =
      (mi_tf_block(mi_atomic_load_relaxed(&page->xthread_free)) == NULL);
  if (!arena_backed || !medium_page || !two_blocks_same_page
      || !abandoned_bitmap_before_allocation || !abandoned_count_before_allocation
      || !queue_empty_before_allocation || !page_count_zero_before_allocation
      || !page_map_and_arena_bitmap_preserved
      || !remote_list_empty_before_allocation) {
    goto cleanup;
  }

  // The next same-heap allocation must travel `mi_arenas_page_try_find_abandoned`
  // -> `mi_page_fresh_alloc` -> `_mi_theap_page_reclaim`, not fresh allocation.
  adopted = mi_heap_malloc(heap, request);
  if (adopted == NULL) goto cleanup;

  allocation_is_same_page = (_mi_ptr_page(adopted) == page);
  abandoned_bitmap_cleared = (!mi_page_is_abandoned_mapped(page)
      && !mi_bitmap_is_set(arena_pages->pages_abandoned[bin], slice_index));
  abandoned_count_cleared = (mi_atomic_load_relaxed(&heap->abandoned_count[bin]) == 0);
  original_theap_restored = (!mi_page_is_abandoned(page)
      && page->theap == theap
      && _mi_page_associated_theap_peek(page) == theap);
  queue_tail_reassociated = (queue->count == 1 && queue->first == page
      && queue->last == page && page->next == NULL && page->prev == NULL);
  page_count_restored = (theap->page_count == 1);
  remote_list_empty = (mi_tf_block(mi_atomic_load_relaxed(&page->xthread_free)) == NULL);
  used_after_allocation = (int)page->used;
  valid = (allocation_is_same_page && abandoned_bitmap_cleared
      && abandoned_count_cleared && original_theap_restored
      && queue_tail_reassociated && page_count_restored && remote_list_empty
      && used_after_allocation == 3 && _mi_ptr_page(first) == page
      && _mi_ptr_page(survivor) == page && !mi_page_all_free(page));

  printf("CRABC_MI_MAPPED_ADOPTION_TRACE_BEGIN\n");
  printf("trace.mapped_adoption.arena_backed=%d\n", arena_backed);
  printf("trace.mapped_adoption.medium_page=%d\n", medium_page);
  printf("trace.mapped_adoption.two_blocks_same_page=%d\n", two_blocks_same_page);
  printf("trace.mapped_adoption.abandoned_bitmap_before_allocation=%d\n", abandoned_bitmap_before_allocation);
  printf("trace.mapped_adoption.abandoned_count_before_allocation=%d\n", abandoned_count_before_allocation);
  printf("trace.mapped_adoption.queue_empty_before_allocation=%d\n", queue_empty_before_allocation);
  printf("trace.mapped_adoption.page_count_zero_before_allocation=%d\n", page_count_zero_before_allocation);
  printf("trace.mapped_adoption.page_map_and_arena_bitmap_preserved=%d\n", page_map_and_arena_bitmap_preserved);
  printf("trace.mapped_adoption.remote_list_empty_before_allocation=%d\n", remote_list_empty_before_allocation);
  printf("trace.mapped_adoption.allocation_is_same_page=%d\n", allocation_is_same_page);
  printf("trace.mapped_adoption.abandoned_bitmap_cleared=%d\n", abandoned_bitmap_cleared);
  printf("trace.mapped_adoption.abandoned_count_cleared=%d\n", abandoned_count_cleared);
  printf("trace.mapped_adoption.original_theap_restored=%d\n", original_theap_restored);
  printf("trace.mapped_adoption.queue_tail_reassociated=%d\n", queue_tail_reassociated);
  printf("trace.mapped_adoption.page_count_restored=%d\n", page_count_restored);
  printf("trace.mapped_adoption.remote_list_empty=%d\n", remote_list_empty);
  printf("trace.mapped_adoption.used_after_allocation=%d\n", used_after_allocation);
  printf("trace.mapped_adoption.valid=%d\n", valid ? 1 : 0);
  printf("CRABC_MI_MAPPED_ADOPTION_TRACE_END\n");

cleanup:
  if (adopted != NULL) mi_free(adopted);
  if (first != NULL) mi_free(first);
  if (survivor != NULL) mi_free(survivor);
  if (heap != NULL) mi_heap_destroy(heap);
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
        raise EvidenceError("mapped-adoption source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 mapped-adoption schema") from error
    expected_fields = {
        "c_probe_sha256",
        "compile_definitions",
        "format",
        "profile",
        "release_flags",
        "release_source_set",
        "rust_test",
        "schema",
        "scope",
        "source_anchors",
        "target",
        "trace",
        "upstream",
    }
    if not isinstance(schema, dict) or set(schema) != expected_fields:
        raise EvidenceError("mapped-adoption schema fields drifted")
    if type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("unsupported x86-64 mapped-adoption schema format")
    if schema["schema"] != EVIDENCE_SCHEMA:
        raise EvidenceError("unsupported x86-64 mapped-adoption schema")
    if schema["profile"] != EXPECTED_PROFILE or not exactly_matches(schema["target"], EXPECTED_TARGET):
        raise EvidenceError("mapped-adoption schema target/profile drifted")
    if not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("mapped-adoption schema upstream drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate mapped-adoption upstream pin") from error
    if not exactly_matches(
        {"archive_root": pin["archive_root"], "revision": pin["revision"], "version": pin["version"]},
        EXPECTED_UPSTREAM,
    ) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("mapped-adoption upstream pin drifted")
    if not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("mapped-adoption schema private boundary drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("mapped-adoption C source set differs from the pinned oracle")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("mapped-adoption C release flags drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("mapped-adoption C compile definitions drifted")
    if not exactly_matches(
        schema["rust_test"],
        {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER},
    ):
        raise EvidenceError("mapped-adoption Rust test selection drifted")
    if not exactly_matches(
        schema["trace"],
        {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES},
    ):
        raise EvidenceError("mapped-adoption fixed trace schema drifted")
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("mapped-adoption C probe source hash drifted")
    anchors = schema["source_anchors"]
    observed: list[tuple[str, int, int, str]] = []
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("mapped-adoption source anchors drifted")
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("mapped-adoption source anchor shape drifted")
        member, start, end, digest = (
            anchor["member"], anchor["start_line"], anchor["end_line"], anchor["sha256"]
        )
        if (
            not isinstance(member, str)
            or type(start) is not int
            or type(end) is not int
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise EvidenceError("mapped-adoption source anchor values drifted")
        observed.append((member, start, end, digest))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("mapped-adoption source anchor contract drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    anchors = schema["source_anchors"]
    assert isinstance(anchors, list)
    for anchor in anchors:
        assert isinstance(anchor, dict)
        member = str(anchor["member"])
        path = source / member
        if not path.is_file():
            raise EvidenceError(f"pinned source lacks mapped-adoption anchor member: {member}")
        observed = sha256_bytes(
            source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))
        )
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned mapped-adoption source anchor drifted: {member}")
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
    missing = sorted(set(EXPECTED_TRACE_VALUES).difference(trace))
    unexpected = sorted(set(trace).difference(EXPECTED_TRACE_VALUES))
    non_integer = sorted(key for key, value in trace.items() if type(value) is not int)
    mismatches = [
        f"{key} (expected {EXPECTED_TRACE_VALUES[key]}, observed {trace[key]})"
        for key in sorted(set(trace).intersection(EXPECTED_TRACE_VALUES))
        if type(trace[key]) is int and trace[key] != EXPECTED_TRACE_VALUES[key]
    ]
    if missing or unexpected or non_integer or mismatches:
        parts: list[str] = []
        if missing:
            parts.append("missing: " + ", ".join(missing))
        if unexpected:
            parts.append("unexpected: " + ", ".join(unexpected))
        if non_integer:
            parts.append("non-integer values: " + ", ".join(non_integer))
        if mismatches:
            parts.append("value mismatches: " + ", ".join(mismatches))
        raise EvidenceError(f"{description} differs from the fixed mapped-adoption trace: " + "; ".join(parts))


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C mapped-adoption trace")
    validate_trace(rust_trace, description="Rust mapped-adoption trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise EvidenceError("Rust mapped-adoption trace differs from pinned C: " + ", ".join(mismatches))
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
    flags = schema["release_flags"]
    definitions = schema["compile_definitions"]
    sources = schema["release_source_set"]
    assert isinstance(flags, list) and isinstance(definitions, list) and isinstance(sources, list)
    return [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        *definitions,
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *flags,
        str(probe_source),
        *(str(source / member) for member in sources),
        "-pthread",
        "-o",
        str(probe_binary),
    ]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(schema["compile_definitions"]) or definitions != list(EXPECTED_COMPILE_DEFINITIONS):
        raise EvidenceError("mapped-adoption C command compile definitions drifted")
    if flags != list(schema["release_flags"]):
        raise EvidenceError("mapped-adoption C command release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("mapped-adoption C command lacks the fixed pthread/TLS mode")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("mapped-adoption report C command is malformed")
    if Path(command[0]).name != "musl-gcc":
        raise EvidenceError("mapped-adoption report C command compiler drifted")
    expected = [
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        *list(schema["compile_definitions"]),
        "-I",
        f"{NORMALIZED_PINNED_SOURCE}/include",
        "-I",
        f"{NORMALIZED_PINNED_SOURCE}/src",
        *list(schema["release_flags"]),
        f"{NORMALIZED_EVIDENCE_ROOT}/{PROBE_STEM}.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/{PROBE_STEM}-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("mapped-adoption report C command drifted")


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
        raise EvidenceError("mapped-adoption report Rust command is malformed")
    if Path(command[0]).name != "cargo":
        raise EvidenceError("mapped-adoption report Rust command compiler drifted")
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
    if command[1:] != expected:
        raise EvidenceError("mapped-adoption report Rust command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]
) -> dict[str, Any]:
    probe_source = temporary / f"{PROBE_STEM}.c"
    probe_binary = temporary / f"{PROBE_STEM}-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C mapped-adoption fixture build")
        header = run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        run.require_success(header, "pinned C mapped-adoption fixture ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(probe_binary),), cwd=source)
        run.require_success(execution, "pinned C mapped-adoption fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C mapped-adoption trace")
    validate_trace(trace, description="pinned C mapped-adoption trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/{PROBE_STEM}-c"],
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
        run.require_success(execution, "Rust mapped-adoption fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust mapped-adoption fixture passed {passed} tests, expected one")
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust mapped-adoption trace",
    )
    validate_trace(trace, description="Rust mapped-adoption trace")
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
        raise EvidenceError("mapped-adoption report inputs lack trace records")
    report: dict[str, Any] = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": EVIDENCE_KIND,
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
        raise EvidenceError("mapped-adoption report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("mapped-adoption report must record a passing format-1 result")
    if report["kind"] != EVIDENCE_KIND:
        raise EvidenceError("mapped-adoption report kind drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["target"], EXPECTED_TARGET):
        raise EvidenceError("mapped-adoption report target/profile drifted")
    if not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("mapped-adoption report source or private boundary drifted")
    if not exactly_matches(report["trace"], {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES}):
        raise EvidenceError("mapped-adoption report trace contract drifted")
    if not any(
        exactly_matches(report["provenance"], candidate)
        for candidate in (
            {"execution_mode": "native", "host_architecture": "x86_64"},
            {"execution_mode": "native", "host_architecture": "amd64"},
        )
    ):
        raise EvidenceError("mapped-adoption report lacks native x86-64 provenance")
    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("mapped-adoption report source record is malformed")
    if source["archive_sha256"] != run.load_pin()["sha256"]:
        raise EvidenceError("mapped-adoption report archive identity drifted")
    if not exactly_matches(source["anchors"], schema["source_anchors"]):
        raise EvidenceError("mapped-adoption report source anchors drifted")
    if not exactly_matches(source["release_flags"], schema["release_flags"]):
        raise EvidenceError("mapped-adoption report release flags drifted")
    if not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("mapped-adoption report source set drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("mapped-adoption report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("mapped-adoption report Rust probe record drifted")
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF):
        raise EvidenceError("mapped-adoption report C ELF identity drifted")
    if not exactly_matches(c_probe["run_command"], [f"{NORMALIZED_EVIDENCE_ROOT}/{PROBE_STEM}-c"]):
        raise EvidenceError("mapped-adoption report C run command drifted")
    if c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("mapped-adoption report C source hash drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    validate_trace(c_probe["trace"], description="mapped-adoption report C trace")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if type(rust_probe["passed_test_count"]) is not int or rust_probe["passed_test_count"] != 1:
        raise EvidenceError("mapped-adoption report Rust selection drifted")
    if not exactly_matches(
        rust_probe["lockfile"],
        {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
    ):
        raise EvidenceError("mapped-adoption report Rust lockfile identity drifted")
    if not exactly_matches(
        rust_probe["source"],
        {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)},
    ):
        raise EvidenceError("mapped-adoption report Rust source identity drifted")
    if not exactly_matches(
        rust_probe["target_dir"],
        {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"},
    ):
        raise EvidenceError("mapped-adoption report Rust target directory drifted")
    validate_trace(rust_probe["trace"], description="mapped-adoption report Rust trace")
    comparison = report["comparison"]
    if not exactly_matches(
        comparison,
        {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"},
    ):
        raise EvidenceError("mapped-adoption report comparison drifted")
    compare_traces(c_probe["trace"], rust_probe["trace"])


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    schema = load_schema()
    provenance = require_native_x86_64()
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
        compiler = run.require_tool("musl-gcc")
        cargo = run.require_tool("cargo")
        readelf = run.require_tool("readelf")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix=TEMPORARY_PREFIX) as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source)
        c_probe = build_c_trace(compiler, readelf, source, temporary, schema)
        rust_probe = build_rust_trace(cargo, temporary)
        report = report_from_results(
            schema=schema,
            provenance=provenance,
            archive_sha256=pin["sha256"],
            anchors=anchors,
            c_probe=c_probe,
            rust_probe=rust_probe,
        )
    run.write_json(report_path, report)
    return report


def report_path_display(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 {EVIDENCE_LABEL} evidence: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        f"allocator x86-64 {EVIDENCE_LABEL} evidence: PASS "
        f"({report['comparison']['compared_value_count']} values; report: "
        f"{report_path_display(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
