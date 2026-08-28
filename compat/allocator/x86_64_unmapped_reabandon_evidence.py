#!/usr/bin/env python3
"""Differentially prove one real unmapped-full-page route on native x86-64.

The pinned-C fixture forces a fresh arena Theap to disable reclaim-on-free and
full-page abandonment, fills one medium arena page, and source-abandons that
full-queue member. Public ``mi_free`` calls then take the pinned failed-reclaim
tail until the exact eighth threshold republishes the nonempty page as mapped.
The Rust side fills one real medium arena page, transfers its full queue entry
through the bounded post-Theap-teardown route, and consumes the same threshold
with sequential client frees. It remains one private linear route, not general
thread exit, free routing, or abandonment/adoption.

This is bounded private allocator-engine evidence only. It does not establish
general abandonment/adoption, general free routing, public ``mi_*`` behavior,
public x86 crabc support, or AArch64 evidence.
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-unmapped-reabandon-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/unmapped-reabandon.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/main_heap_page.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "main_heap_page::tests::later_thread_exit_full_medium_route_reabandons_after_mostly_used_frees"
TRACE_BEGIN = "CRABC_MI_UNMAPPED_REABANDON_TRACE_BEGIN"
TRACE_END = "CRABC_MI_UNMAPPED_REABANDON_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded unmapped-reabandon differential could not establish its claim."""


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
EXPECTED_PROFILE = "linux-x86_64-private-unmapped-full-medium-reabandon"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_free_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
    "rust_full_medium_routing_claimed": True,
    "unmapped_full_page_reabandon_only": True,
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
    ("src/page.c", 291, 303, "d363079d5e484919082b5602cc3757a3e3a357e68594fc040d902232c7458bbf"),
    ("src/page.c", 374, 388, "c2c25a5a4faef1258508e47e1697bc062d157ec72a19ac266be0156180c1d7f6"),
    ("src/arena.c", 1304, 1379, "04771bd2a839a5a07b308ada8b4ff9b3ec4e192b3ad9b94a300e30355f1d28fc"),
    ("src/theap.c", 228, 232, "16c0e73a20b9a94bf994c4e83836c976f5683e3c6e8b18935782a934405adba0"),
)
EXPECTED_TRACE_VALUES = {
    "trace.unmapped_reabandon.abandoned_after_free": 1,
    "trace.unmapped_reabandon.abandoned_before_free": 1,
    "trace.unmapped_reabandon.arena_backed": 1,
    "trace.unmapped_reabandon.bitmap_published_after": 1,
    "trace.unmapped_reabandon.initially_full": 1,
    "trace.unmapped_reabandon.initially_unmapped": 1,
    "trace.unmapped_reabandon.medium_page": 1,
    "trace.unmapped_reabandon.page_still_live": 1,
    "trace.unmapped_reabandon.pretransition_remained_unmapped": 1,
    "trace.unmapped_reabandon.reabandon_threshold_crossed": 1,
    "trace.unmapped_reabandon.reabandoned_mapped_after_free": 1,
    "trace.unmapped_reabandon.unowned_after_free": 1,
    "trace.unmapped_reabandon.valid": 1,
}


# The fixture configures its new Theap before it exists: -1 disables both
# reclaim-on-free and full-page immediate abandonment. A fully allocated medium
# page therefore enters MI_BIN_FULL, is explicitly source-abandoned while
# unmapped, and stays unowned/unmapped through the first `reserved / 8` public
# frees. The final free reaches `free.c:mi_abandoned_page_try_reabandon_to_mapped`.
# All post-unown page observations below are atomic identity/owner loads or the
# captured arena bitmap; the live survivor count is derived from fixture-owned
# client pointers rather than reading ordinary unowned page fields.
C_TRACE_PROBE = r"""
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <stdbool.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private unmapped-reabandon fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private unmapped-reabandon fixture requires the fixed release profile
#endif

#define CRABC_REABANDON_MAX_BLOCKS 1024

static bool crabc_arena_bitmap_has_page(
    mi_heap_t* heap, mi_arena_t* arena, size_t bin, size_t slice_index
) {
  if (heap == NULL || arena == NULL || bin >= MI_ARENA_BIN_COUNT) return false;
  mi_arena_pages_t* const pages = mi_atomic_load_ptr_acquire(
      mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  return pages != NULL && pages->pages_abandoned[bin] != NULL
      && mi_bitmap_is_set(pages->pages_abandoned[bin], slice_index);
}

int main(void) {
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_queue_t* full_queue = NULL;
  mi_arena_t* page_arena = NULL;
  void* blocks[CRABC_REABANDON_MAX_BLOCKS] = { NULL };
  size_t allocated_count = 0;
  size_t free_count_to_reabandon = 0;
  size_t slice_index = 0;
  size_t bin = 0;
  uint16_t reserved_before_free = 0;
  long old_reclaim_on_free = 0;
  long old_full_retain = 0;
  bool options_changed = false;
  bool valid = false;
  int stage = 0;

  int arena_backed = 0;
  int medium_page = 0;
  int initially_full = 0;
  int initially_unmapped = 0;
  int abandoned_before_free = 0;
  int pretransition_remained_unmapped = 0;
  int reabandon_threshold_crossed = 0;
  int reabandoned_mapped_after_free = 0;
  int abandoned_after_free = 0;
  int bitmap_published_after = 0;
  int page_still_live = 0;
  int unowned_after_free = 0;

  // The request exceeds the direct small route while remaining a regular
  // medium page. It is deliberately the same class used by the C/Rust
  // mapped-reclaim fixture, but this probe fills the page before abandonment.
  const size_t request = MI_SMALL_MAX_OBJ_SIZE + 1024;

  old_reclaim_on_free = mi_option_get(mi_option_page_reclaim_on_free);
  old_full_retain = mi_option_get(mi_option_page_full_retain);
  mi_option_set(mi_option_page_reclaim_on_free, -1);
  mi_option_set(mi_option_page_full_retain, -1);
  options_changed = true;
  stage = 1;

  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) {
    goto cleanup;
  }
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto cleanup;
  stage = 2;

  while (allocated_count < CRABC_REABANDON_MAX_BLOCKS) {
    void* const block = mi_heap_malloc(heap, request);
    if (block == NULL) goto cleanup;
    if (page == NULL) {
      page = _mi_ptr_page(block);
      if (page == NULL) {
        mi_free(block);
        goto cleanup;
      }
    }
    if (_mi_ptr_page(block) != page) {
      mi_free(block);
      goto cleanup;
    }
    blocks[allocated_count++] = block;
    if (mi_page_is_full(page)) break;
  }
  stage = 3;

  theap = _mi_heap_theap(heap);
  if (theap == NULL || page == NULL || !mi_page_is_full(page)
      || allocated_count != (size_t)page->reserved
      || page->block_size <= MI_SMALL_MAX_OBJ_SIZE
      || page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || page->memid.memkind != MI_MEM_ARENA
      || theap->allow_page_reclaim || theap->allow_page_abandon
      || !mi_page_is_in_full(page)) {
    fprintf(stderr,
      "unmapped-reabandon full setup: theap=%d page=%d full=%d allocated=%zu reserved=%u "
      "block=%zu kind=%d reclaim=%d abandon=%d in_full=%d\\n",
      theap != NULL, page != NULL, page != NULL && mi_page_is_full(page), allocated_count,
      page == NULL ? 0 : (unsigned)page->reserved, page == NULL ? 0 : page->block_size,
      page == NULL ? -1 : (int)page->memid.memkind,
      theap != NULL && theap->allow_page_reclaim,
      theap != NULL && theap->allow_page_abandon,
      page != NULL && mi_page_is_in_full(page));
    goto cleanup;
  }
  full_queue = &theap->pages[MI_BIN_FULL];
  if (full_queue->count != 1 || full_queue->first != page) goto cleanup;
  stage = 4;

  page_arena = page->memid.mem.arena.arena;
  slice_index = page->memid.mem.arena.slice_index;
  bin = _mi_bin(page->block_size);
  reserved_before_free = page->reserved;
  if (page_arena == NULL || bin >= MI_ARENA_BIN_COUNT
      || reserved_before_free == 0) {
    goto cleanup;
  }
  stage = 5;

  // This is the source queue-to-unmapped-abandoned transition for the forced
  // full-queue mode. The fixture has disabled source reclaim-on-free before
  // the Theap is constructed, so public frees continue to the reabandon tail.
  _mi_page_abandon(page, full_queue);
  arena_backed = (page->memid.memkind == MI_MEM_ARENA);
  medium_page = (page->block_size > MI_SMALL_MAX_OBJ_SIZE
                 && page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE);
  initially_full = (allocated_count == (size_t)reserved_before_free);
  initially_unmapped = (mi_page_is_abandoned(page) && !mi_page_is_abandoned_mapped(page));
  abandoned_before_free = mi_page_is_abandoned(page);
  if (!arena_backed || !medium_page || !initially_full || !initially_unmapped
      || !abandoned_before_free
      || full_queue->count != 0 || page->next != NULL || page->prev != NULL) {
    goto cleanup;
  }
  stage = 6;

  free_count_to_reabandon = (size_t)reserved_before_free / 8 + 1;
  if (free_count_to_reabandon >= allocated_count) goto cleanup;
  for (size_t index = 0; index + 1 < free_count_to_reabandon; index++) {
    mi_free(blocks[index]);
    blocks[index] = NULL;
  }
  pretransition_remained_unmapped = (mi_page_is_abandoned(page)
                                     && !mi_page_is_abandoned_mapped(page)
                                     && !mi_page_is_owned(page));
  if (!pretransition_remained_unmapped) goto cleanup;
  stage = 7;

  mi_free(blocks[free_count_to_reabandon - 1]);
  blocks[free_count_to_reabandon - 1] = NULL;
  reabandon_threshold_crossed = (free_count_to_reabandon > (size_t)reserved_before_free / 8);
  reabandoned_mapped_after_free = mi_page_is_abandoned_mapped(page);
  abandoned_after_free = mi_page_is_abandoned(page);
  bitmap_published_after = crabc_arena_bitmap_has_page(heap, page_arena, bin, slice_index);
  page_still_live = (allocated_count > free_count_to_reabandon);
  unowned_after_free = !mi_page_is_owned(page);
  valid = (arena_backed && medium_page && initially_full && initially_unmapped
           && abandoned_before_free
           && pretransition_remained_unmapped && reabandon_threshold_crossed
           && reabandoned_mapped_after_free && abandoned_after_free
           && bitmap_published_after && page_still_live && unowned_after_free);
  stage = 8;

  printf("CRABC_MI_UNMAPPED_REABANDON_TRACE_BEGIN\n");
  printf("trace.unmapped_reabandon.arena_backed=%d\n", arena_backed);
  printf("trace.unmapped_reabandon.medium_page=%d\n", medium_page);
  printf("trace.unmapped_reabandon.initially_full=%d\n", initially_full);
  printf("trace.unmapped_reabandon.initially_unmapped=%d\n", initially_unmapped);
  printf("trace.unmapped_reabandon.abandoned_before_free=%d\n", abandoned_before_free);
  printf("trace.unmapped_reabandon.pretransition_remained_unmapped=%d\n", pretransition_remained_unmapped);
  printf("trace.unmapped_reabandon.reabandon_threshold_crossed=%d\n", reabandon_threshold_crossed);
  printf("trace.unmapped_reabandon.reabandoned_mapped_after_free=%d\n", reabandoned_mapped_after_free);
  printf("trace.unmapped_reabandon.abandoned_after_free=%d\n", abandoned_after_free);
  printf("trace.unmapped_reabandon.bitmap_published_after=%d\n", bitmap_published_after);
  printf("trace.unmapped_reabandon.page_still_live=%d\n", page_still_live);
  printf("trace.unmapped_reabandon.unowned_after_free=%d\n", unowned_after_free);
  printf("trace.unmapped_reabandon.valid=%d\n", valid);
  printf("CRABC_MI_UNMAPPED_REABANDON_TRACE_END\n");

cleanup:
  if (!valid) {
    fprintf(stderr, "unmapped-reabandon fixture stopped at stage %d\n", stage);
  }
  for (size_t index = 0; index < allocated_count; index++) {
    if (blocks[index] != NULL) mi_free(blocks[index]);
  }
  if (heap != NULL) mi_heap_destroy(heap);
  if (options_changed) {
    mi_option_set(mi_option_page_reclaim_on_free, old_reclaim_on_free);
    mi_option_set(mi_option_page_full_retain, old_full_retain);
  }
  return (valid ? 0 : 2);
}
"""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"required evidence input is missing: {relative(path)}")
    return sha256_bytes(path.read_bytes())


def exactly_matches(observed: object, expected: object) -> bool:
    """Compare JSON-shaped values without Python's bool/int coercion."""

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
        raise EvidenceError("unmapped-reabandon source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    """Read and fail-closed validate the checked-in native-only contract."""

    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 unmapped-reabandon schema") from error
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
        raise EvidenceError("x86-64 unmapped-reabandon schema fields drifted")
    if (
        type(schema.get("format")) is not int
        or schema.get("format") != 1
        or schema.get("schema") != "crabc-mimalloc-x86_64-unmapped-reabandon-evidence"
    ):
        raise EvidenceError("unsupported x86-64 unmapped-reabandon schema")
    if not exactly_matches(schema.get("target"), EXPECTED_TARGET):
        raise EvidenceError("unmapped-reabandon schema target is not native Linux/x86-64")
    if not exactly_matches(schema.get("upstream"), EXPECTED_UPSTREAM):
        raise EvidenceError("unmapped-reabandon schema upstream is not pinned mimalloc 3.5.0")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate the pinned unmapped-reabandon upstream identity") from error
    if not exactly_matches(
        {"archive_root": pin["archive_root"], "revision": pin["revision"], "version": pin["version"]},
        EXPECTED_UPSTREAM,
    ) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("unmapped-reabandon upstream pin drifted")
    if schema.get("profile") != EXPECTED_PROFILE:
        raise EvidenceError("unmapped-reabandon schema profile drifted")
    if not exactly_matches(schema.get("scope"), EXPECTED_SCOPE):
        raise EvidenceError("unmapped-reabandon schema private boundary drifted")
    if not exactly_matches(schema.get("release_source_set"), list(run.ORACLE_SOURCES)):
        raise EvidenceError("unmapped-reabandon C source set differs from the pinned oracle")
    if not exactly_matches(schema.get("release_flags"), list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("unmapped-reabandon C release flags drifted")
    if not exactly_matches(schema.get("compile_definitions"), list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("unmapped-reabandon C compile definitions drifted")
    if not exactly_matches(
        schema.get("rust_test"),
        {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER},
    ):
        raise EvidenceError("unmapped-reabandon Rust test selection drifted")
    if not exactly_matches(
        schema.get("trace"),
        {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES},
    ):
        raise EvidenceError("unmapped-reabandon fixed trace schema drifted")
    if schema.get("c_probe_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("unmapped-reabandon C probe source hash drifted")

    anchors = schema.get("source_anchors")
    observed: list[tuple[str, int, int, str]] = []
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("unmapped-reabandon source anchors drifted")
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("unmapped-reabandon source anchor has an invalid shape")
        member = anchor.get("member")
        start_line = anchor.get("start_line")
        end_line = anchor.get("end_line")
        digest = anchor.get("sha256")
        if (
            not isinstance(member, str)
            or type(start_line) is not int
            or type(end_line) is not int
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise EvidenceError("unmapped-reabandon source anchor has invalid values")
        observed.append((member, start_line, end_line, digest))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("unmapped-reabandon source anchor contract drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    """Bind the C protocol to exact ranges in the extracted frozen source."""

    validated: list[dict[str, Any]] = []
    anchors = schema["source_anchors"]
    assert isinstance(anchors, list)
    for anchor in anchors:
        assert isinstance(anchor, dict)
        member = str(anchor["member"])
        path = source / member
        if not path.is_file():
            raise EvidenceError(f"pinned source lacks unmapped-reabandon anchor member: {member}")
        observed = sha256_bytes(
            source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))
        )
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned unmapped-reabandon source anchor drifted: {member}")
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
        failures: list[str] = []
        if missing:
            failures.append("missing: " + ", ".join(missing))
        if unexpected:
            failures.append("unexpected: " + ", ".join(unexpected))
        if non_integer:
            failures.append("non-integer values: " + ", ".join(non_integer))
        if mismatches:
            failures.append("value mismatches: " + ", ".join(mismatches))
        raise EvidenceError(
            f"{description} differs from the fixed unmapped-reabandon trace: " + "; ".join(failures)
        )


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C unmapped-reabandon trace")
    validate_trace(rust_trace, description="Rust unmapped-reabandon trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise EvidenceError("Rust unmapped-reabandon trace differs from pinned C: " + ", ".join(mismatches))
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
        raise EvidenceError("unmapped-reabandon C command compile definitions drifted")
    if flags != list(schema["release_flags"]):
        raise EvidenceError("unmapped-reabandon C command release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("unmapped-reabandon C command lacks the fixed pthread/TLS mode")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("unmapped-reabandon report C command is malformed")
    if Path(command[0]).name != "musl-gcc":
        raise EvidenceError("unmapped-reabandon report C command compiler drifted")
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
        f"{NORMALIZED_EVIDENCE_ROOT}/unmapped-reabandon.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/unmapped-reabandon-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("unmapped-reabandon report C command drifted")


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
        raise EvidenceError("unmapped-reabandon report Rust command is malformed")
    if Path(command[0]).name != "cargo":
        raise EvidenceError("unmapped-reabandon report Rust command compiler drifted")
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
        raise EvidenceError("unmapped-reabandon report Rust command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]
) -> dict[str, Any]:
    probe_source = temporary / "unmapped-reabandon.c"
    probe_binary = temporary / "unmapped-reabandon-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C unmapped-reabandon fixture build")
        header = run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        run.require_success(header, "pinned C unmapped-reabandon fixture ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(probe_binary),), cwd=source)
        run.require_success(execution, "pinned C unmapped-reabandon fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C unmapped-reabandon trace")
    validate_trace(trace, description="pinned C unmapped-reabandon trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/unmapped-reabandon-c"],
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
        run.require_success(execution, "Rust unmapped-reabandon fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust unmapped-reabandon fixture passed {passed} tests, expected one")
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust unmapped-reabandon trace",
    )
    validate_trace(trace, description="Rust unmapped-reabandon trace")
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
        raise EvidenceError("unmapped-reabandon report inputs lack trace records")
    report: dict[str, Any] = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": "mimalloc-x86_64-unmapped-full-medium-reabandon-differential-evidence",
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
        raise EvidenceError("unmapped-reabandon report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("unmapped-reabandon report must record a passing format-1 result")
    if report["kind"] != "mimalloc-x86_64-unmapped-full-medium-reabandon-differential-evidence":
        raise EvidenceError("unmapped-reabandon report kind drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["target"], EXPECTED_TARGET):
        raise EvidenceError("unmapped-reabandon report target/profile drifted")
    if not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("unmapped-reabandon report source or private boundary drifted")
    if not exactly_matches(
        report["trace"], {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES}
    ):
        raise EvidenceError("unmapped-reabandon report trace contract drifted")
    if not any(
        exactly_matches(report["provenance"], candidate)
        for candidate in (
            {"execution_mode": "native", "host_architecture": "x86_64"},
            {"execution_mode": "native", "host_architecture": "amd64"},
        )
    ):
        raise EvidenceError("unmapped-reabandon report lacks native x86-64 provenance")

    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("unmapped-reabandon report source record is malformed")
    if source.get("archive_sha256") != run.load_pin()["sha256"]:
        raise EvidenceError("unmapped-reabandon report archive identity drifted")
    if not exactly_matches(source.get("anchors"), schema["source_anchors"]):
        raise EvidenceError("unmapped-reabandon report source anchors drifted")
    if not exactly_matches(source.get("release_flags"), schema["release_flags"]):
        raise EvidenceError("unmapped-reabandon report release flags drifted")
    if not exactly_matches(source.get("release_source_set"), schema["release_source_set"]):
        raise EvidenceError("unmapped-reabandon report source set drifted")

    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("unmapped-reabandon report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("unmapped-reabandon report Rust probe record drifted")
    if not exactly_matches(c_probe.get("elf"), EXPECTED_C_ELF):
        raise EvidenceError("unmapped-reabandon report C ELF identity drifted")
    if not exactly_matches(c_probe.get("run_command"), [f"{NORMALIZED_EVIDENCE_ROOT}/unmapped-reabandon-c"]):
        raise EvidenceError("unmapped-reabandon report C run command drifted")
    if c_probe.get("source_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("unmapped-reabandon report C source hash drifted")
    validate_normalized_c_command(c_probe.get("build_command"), schema)
    if type(rust_probe.get("passed_test_count")) is not int or rust_probe["passed_test_count"] != 1:
        raise EvidenceError("unmapped-reabandon report Rust selection did not pass exactly one test")
    if not exactly_matches(
        rust_probe.get("target_dir"),
        {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"},
    ):
        raise EvidenceError("unmapped-reabandon report Rust target directory drifted")
    validate_normalized_rust_command(rust_probe.get("cargo_command"))
    if not exactly_matches(rust_probe.get("lockfile"), {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}):
        raise EvidenceError("unmapped-reabandon report Rust lockfile identity drifted")
    if not exactly_matches(rust_probe.get("source"), {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}):
        raise EvidenceError("unmapped-reabandon report Rust source identity drifted")
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("unmapped-reabandon report lacks C/Rust trace records")
    if not exactly_matches(report["comparison"], compare_traces(c_trace, rust_trace)):
        raise EvidenceError("unmapped-reabandon report comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-unmapped-reabandon-") as temporary_name:
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
        print(f"allocator x86-64 unmapped-reabandon differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    comparison = report["comparison"]
    print(
        "allocator x86-64 unmapped-reabandon differential: PASS "
        f"({comparison['compared_value_count']} logical values; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
