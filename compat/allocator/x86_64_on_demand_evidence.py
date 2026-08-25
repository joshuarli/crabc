#!/usr/bin/env python3
"""Differentially prove one ordinary reserved-medium on-demand extension.

This private native-x86-64 lane compiles the pinned mimalloc 3.5.0 C oracle
and compares one address-independent ordinary-allocation trace with the
crate-private Rust test
``main_heap_page::tests::ordinary_reserved_medium_on_demand_commit_before_reuse``.
Both sides allocate the first medium block from a reserved arena, exhaust its
initial prefix, and allocate a second block from that same page after the
source direct commit-before-extension order. The Rust test separately injects
and checks a failed direct commit before its successful retry; that failure
path is deliberately not claimed as C fault-injection parity. In particular,
the private Rust seam returns no allocation and requires an explicit retry of
the same selected page; it does not model the pinned C source's separate
retire/fresh-fallback behavior after a failed direct extension.

This is private allocator-engine evidence only. It does not establish a
production page-on-demand policy, fresh fallback, public x86 crabc support,
public ``mi_*`` behavior, or AArch64 evidence. The C option setup is oracle
configuration only; Rust retains no production option parser or API.
"""

from __future__ import annotations

import argparse
import copy
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-on-demand-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/on-demand.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/main_heap_page.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "main_heap_page::tests::ordinary_reserved_medium_on_demand_commit_before_reuse"
TRACE_BEGIN = "CRABC_MI_ON_DEMAND_TRACE_BEGIN"
TRACE_END = "CRABC_MI_ON_DEMAND_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded on-demand differential could not establish its claim."""


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
EXPECTED_PROFILE = "linux-x86_64-private-ordinary-reserved-medium-on-demand-commit-before-reuse"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "native_linux_x86_64_required": True,
    "oracle_option_setup_only": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "reserved_medium_on_demand_reuse_only": True,
    "failed_commit_recovery_claimed": False,
    "production_page_on_demand_policy_claimed": False,
    "fresh_fallback_claimed": False,
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

# These are fixed address-independent protocol values emitted by both probes.
# They contain no pointer, address, or allocator identity. The six numeric
# values pin the fixed native x86-64 geometry in addition to the transition
# predicates, so a changed page size or extension count cannot silently match.
TRACE_FIELDS = (
    "arena_backed",
    "reserved_mapping",
    "medium_page",
    "initial_prefix_present",
    "initial_free_empty",
    "initial_nonfull",
    "initial_used_equals_capacity",
    "initial_queue_registered",
    "commit_before_reuse",
    "committed_prefix_grew",
    "capacity_grew",
    "target_queue_registered",
    "reused_same_page",
    "used_increment_one",
    "payload_preserved",
    "final_page_released",
    "initial_capacity",
    "initial_used",
    "initial_slice_pcommitted",
    "post_capacity",
    "post_used",
    "post_slice_pcommitted",
    "valid",
)
EXPECTED_TRACE_VALUES = {
    **{
        f"trace.on_demand.{field}": 1
        for field in TRACE_FIELDS
        if field
        not in {
            "initial_capacity",
            "initial_used",
            "initial_slice_pcommitted",
            "post_capacity",
            "post_used",
            "post_slice_pcommitted",
        }
    },
    "trace.on_demand.initial_capacity": 1,
    "trace.on_demand.initial_used": 1,
    "trace.on_demand.initial_slice_pcommitted": 4,
    "trace.on_demand.post_capacity": 2,
    "trace.on_demand.post_used": 2,
    "trace.on_demand.post_slice_pcommitted": 8,
}

# The ranges bind the C protocol to the pinned source's reserved-arena setup,
# direct page-area extension, and ordinary queue-search/extension order. They
# are checked against the extracted archive before the fixture runs. Final
# release is observed as a fixture result; it is not misrepresented as an
# independently source-anchored abandon/reclaim protocol.
EXPECTED_SOURCE_ANCHORS = (
    ("src/arena.c", 951, 1069, "b1c4e4f4c2f7d18243066233baa3070a563c51b0d55a212aeea990f8a1289fcf"),
    ("src/arena.c", 1138, 1154, "4777f29be08991a04391029e1cd4daabcc00f2e53e9e6f36f20ad69093a142ed"),
    ("src/page.c", 630, 706, "c2fdd18ad991b45c8bf8f8a6441f66c1c2dbfe1f5f81e60688e8e66fd32865f3"),
    ("src/page.c", 765, 875, "3c8a1de257b88eb5c17b54da1cca31337fc9555aaca6a1cf167f3f0f4aaa7598"),
)


# The C side uses the pinned option only to select its own fixed source branch.
# It does not emulate the Rust test's injected commit failure. The two ordinary
# `mi_heap_malloc` calls exercise `mi_page_queue_find_free_ex` and its selected
# `mi_page_extend_free` direct commit branch without thread-exit/reclaim state.
C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "bitmap.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private on-demand fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private on-demand fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0
#error this private on-demand fixture requires the native x86-64 two-level PageMap branch
#endif

_Static_assert(sizeof(void*) == 8, "this private fixture requires 64-bit pointers");
_Static_assert(sizeof(size_t) == 8, "this private fixture requires 64-bit size_t");

int main(void) {
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_t* second_page = NULL;
  mi_page_queue_t* queue = NULL;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  void* first = NULL;
  void* second = NULL;
  size_t slice = 0;
  long old_page_commit_on_demand = 0;
  bool option_changed = false;
  size_t prefix_before = 0;
  size_t capacity_before = 0;
  size_t used_before = 0;
  size_t prefix_after = 0;
  size_t capacity_after = 0;
  size_t used_after = 0;
  bool valid = false;
  int stage = 0;

  int arena_backed = 0;
  int reserved_mapping = 0;
  int medium_page = 0;
  int initial_prefix_present = 0;
  int initial_free_empty = 0;
  int initial_nonfull = 0;
  int initial_used_equals_capacity = 0;
  int initial_queue_registered = 0;
  int commit_before_reuse = 0;
  int committed_prefix_grew = 0;
  int capacity_grew = 0;
  int target_queue_registered = 0;
  int reused_same_page = 0;
  int used_increment_one = 0;
  int payload_preserved = 0;
  int final_page_released = 0;

  const size_t request = MI_SMALL_MAX_OBJ_SIZE + 1;
  old_page_commit_on_demand = mi_option_get(mi_option_page_commit_on_demand);
  mi_option_set(mi_option_page_commit_on_demand, 1);
  option_changed = true;
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), false, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto cleanup;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto cleanup;
  first = mi_heap_malloc(heap, request);
  if (first == NULL) goto cleanup;
  stage = 1;

  page = _mi_ptr_page(first);
  theap = mi_heap_theap(heap);
  if (page == NULL || theap == NULL) goto cleanup;
  arena = page->memid.mem.arena.arena;
  if (arena == NULL) goto cleanup;
  slice = page->memid.mem.arena.slice_index;
  queue = mi_page_queue(theap, page->block_size);
  arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  arena_backed = page->memid.memkind == MI_MEM_ARENA;
  reserved_mapping = !page->memid.initially_committed;
  medium_page = (page->block_size > MI_SMALL_MAX_OBJ_SIZE
                 && page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE);
  initial_prefix_present = page->slice_pcommitted > 0;
  initial_free_empty = (page->free == NULL);
  initial_nonfull = (!mi_page_is_full(page) && page->used > 0);
  initial_used_equals_capacity = (page->used == page->capacity);
  initial_queue_registered = (queue != NULL && queue->count == 1 && queue->first == page);
  if (arena_pages == NULL || !mi_bitmap_is_set(arena_pages->pages, slice)) goto cleanup;
  stage = 2;
  prefix_before = page->slice_pcommitted;
  capacity_before = page->capacity;
  used_before = page->used;
  ((unsigned char*)first)[0] = 0xA5;

  second = mi_heap_malloc(heap, request);
  if (second == NULL) goto cleanup;
  second_page = _mi_ptr_page(second);
  if (second_page == NULL) goto cleanup;
  stage = 3;
  prefix_after = page->slice_pcommitted;
  capacity_after = page->capacity;
  used_after = page->used;
  reused_same_page = (second_page == page);
  committed_prefix_grew = (prefix_after > prefix_before);
  capacity_grew = (capacity_after > capacity_before);
  used_increment_one = (used_after == used_before + 1);
  target_queue_registered = (queue->count == 1 && queue->first == page);
  commit_before_reuse = (reused_same_page && committed_prefix_grew);
  payload_preserved = (((unsigned char*)first)[0] == 0xA5);
  if (!commit_before_reuse || !capacity_grew || !used_increment_one
      || !target_queue_registered || !payload_preserved) goto cleanup;
  stage = 4;

  mi_free(first);
  first = NULL;
  mi_free(second);
  second = NULL;
  // The pinned local-free path may retain this all-free page until its normal
  // forced collector. Rust's matching fixture calls `finish`, which performs
  // the same source collection before it observes terminal page release.
  mi_heap_collect(heap, true);
  // The page's arena bit is the stable post-release witness; the page object
  // itself is no longer dereferenced after the final client free.
  final_page_released = !mi_bitmap_is_set(arena_pages->pages, slice);
  stage = 5;
  valid = (arena_backed && reserved_mapping && medium_page && initial_prefix_present
           && initial_free_empty && initial_nonfull && initial_used_equals_capacity
           && initial_queue_registered && commit_before_reuse && committed_prefix_grew
           && capacity_grew && used_increment_one && target_queue_registered
           && reused_same_page && payload_preserved && final_page_released);

  printf("CRABC_MI_ON_DEMAND_TRACE_BEGIN\n");
  printf("trace.on_demand.arena_backed=%d\n", arena_backed);
  printf("trace.on_demand.reserved_mapping=%d\n", reserved_mapping);
  printf("trace.on_demand.medium_page=%d\n", medium_page);
  printf("trace.on_demand.initial_prefix_present=%d\n", initial_prefix_present);
  printf("trace.on_demand.initial_free_empty=%d\n", initial_free_empty);
  printf("trace.on_demand.initial_nonfull=%d\n", initial_nonfull);
  printf("trace.on_demand.initial_used_equals_capacity=%d\n", initial_used_equals_capacity);
  printf("trace.on_demand.initial_queue_registered=%d\n", initial_queue_registered);
  printf("trace.on_demand.commit_before_reuse=%d\n", commit_before_reuse);
  printf("trace.on_demand.committed_prefix_grew=%d\n", committed_prefix_grew);
  printf("trace.on_demand.capacity_grew=%d\n", capacity_grew);
  printf("trace.on_demand.target_queue_registered=%d\n", target_queue_registered);
  printf("trace.on_demand.reused_same_page=%d\n", reused_same_page);
  printf("trace.on_demand.used_increment_one=%d\n", used_increment_one);
  printf("trace.on_demand.payload_preserved=%d\n", payload_preserved);
  printf("trace.on_demand.final_page_released=%d\n", final_page_released);
  printf("trace.on_demand.initial_capacity=%zu\n", capacity_before);
  printf("trace.on_demand.initial_used=%zu\n", used_before);
  printf("trace.on_demand.initial_slice_pcommitted=%zu\n", prefix_before);
  printf("trace.on_demand.post_capacity=%zu\n", capacity_after);
  printf("trace.on_demand.post_used=%zu\n", used_after);
  printf("trace.on_demand.post_slice_pcommitted=%zu\n", prefix_after);
  printf("trace.on_demand.valid=%d\n", valid);
  printf("CRABC_MI_ON_DEMAND_TRACE_END\n");

cleanup:
  if (!valid) {
    fprintf(stderr, "private on-demand fixture failed at stage %d\n", stage);
    fprintf(stderr,
            "flags arena=%d reserved=%d medium=%d prefix=%d free=%d nonfull=%d usedcap=%d queue=%d commit=%d prefixgrow=%d capgrow=%d usedgrow=%d targetqueue=%d same=%d payload=%d released=%d\n",
            arena_backed, reserved_mapping, medium_page, initial_prefix_present,
            initial_free_empty, initial_nonfull, initial_used_equals_capacity,
            initial_queue_registered, commit_before_reuse, committed_prefix_grew,
            capacity_grew, used_increment_one, target_queue_registered,
            reused_same_page, payload_preserved, final_page_released);
  }
  if (first != NULL) mi_free(first);
  if (second != NULL) mi_free(second);
  if (heap != NULL) mi_heap_destroy(heap);
  if (option_changed) mi_option_set(mi_option_page_commit_on_demand, old_page_commit_on_demand);
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


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise EvidenceError("on-demand source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def _schema_template() -> dict[str, Any]:
    return {
        "format": 1,
        "schema": "crabc-mimalloc-x86_64-on-demand-evidence",
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
        "rust_test": {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER},
        "trace": {
            "begin": TRACE_BEGIN,
            "end": TRACE_END,
            "expected_values": dict(EXPECTED_TRACE_VALUES),
        },
    }


def load_schema(path: Path | None = None) -> dict[str, Any]:
    """Load and fail-closed validate the serialized on-demand contract."""

    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 on-demand evidence schema") from error
    if not isinstance(schema, dict):
        raise EvidenceError("x86-64 on-demand evidence schema is not an object")
    expected_fields = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "rust_test", "schema", "scope", "source_anchors", "target",
        "trace", "upstream",
    }
    if set(schema) != expected_fields:
        raise EvidenceError("x86-64 on-demand schema fields drifted")
    if type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("unsupported x86-64 on-demand evidence schema")
    if schema["schema"] != "crabc-mimalloc-x86_64-on-demand-evidence":
        raise EvidenceError("unsupported x86-64 on-demand evidence schema")
    if not exactly_matches(schema["target"], EXPECTED_TARGET) or schema["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("on-demand target or profile drifted")
    if not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("on-demand upstream pin drifted")
    if not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("on-demand private boundary drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("on-demand compile definitions drifted")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("on-demand release flags drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("on-demand C source set differs from the pinned oracle")
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("on-demand C probe source hash drifted")
    if not exactly_matches(schema["rust_test"], _schema_template()["rust_test"]):
        raise EvidenceError("on-demand Rust test selection drifted")
    if not exactly_matches(schema["trace"], _schema_template()["trace"]):
        raise EvidenceError("on-demand fixed trace schema drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("on-demand source anchors drifted")
    observed: list[tuple[str, int, int, str]] = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("on-demand source anchor has an invalid shape")
        member, start, end, digest = anchor.get("member"), anchor.get("start_line"), anchor.get("end_line"), anchor.get("sha256")
        if not isinstance(member, str) or type(start) is not int or type(end) is not int or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise EvidenceError("on-demand source anchor has invalid values")
        observed.append((member, start, end, digest))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("on-demand source anchor contract drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate the pinned on-demand upstream identity") from error
    if not exactly_matches({"archive_root": pin["archive_root"], "revision": pin["revision"], "version": pin["version"]}, EXPECTED_UPSTREAM) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("on-demand upstream archive pin drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    anchors = schema["source_anchors"]
    assert isinstance(anchors, list)
    for anchor in anchors:
        assert isinstance(anchor, dict)
        path = source / str(anchor["member"])
        if not path.is_file():
            raise EvidenceError(f"pinned source lacks on-demand anchor member: {anchor['member']}")
        observed = sha256_bytes(source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"])))
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned on-demand source anchor drifted: {anchor['member']}")
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
    mismatches = [
        f"{key} (expected {EXPECTED_TRACE_VALUES[key]}, observed {trace[key]})"
        for key in sorted(set(trace) & set(EXPECTED_TRACE_VALUES))
        if type(trace[key]) is int and trace[key] != EXPECTED_TRACE_VALUES[key]
    ]
    if missing or unexpected or non_integer or mismatches:
        details = []
        if missing: details.append("missing: " + ", ".join(missing))
        if unexpected: details.append("unexpected: " + ", ".join(unexpected))
        if non_integer: details.append("non-integer values: " + ", ".join(non_integer))
        if mismatches: details.append("value mismatches: " + ", ".join(mismatches))
        raise EvidenceError(f"{description} differs from the fixed on-demand trace: " + "; ".join(details))


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C on-demand trace")
    validate_trace(rust_trace, description="Rust on-demand trace")
    mismatches = [f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})" for key in sorted(EXPECTED_TRACE_VALUES) if c_trace[key] != rust_trace[key]]
    if mismatches:
        raise EvidenceError("Rust on-demand trace differs from pinned C: " + ", ".join(mismatches))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized: list[str] = []
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


def c_trace_command(compiler: str, source: Path, probe_source: Path, probe_binary: Path, schema: Mapping[str, Any]) -> list[str]:
    return [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"), *schema["release_flags"], str(probe_source), *(str(source / member) for member in schema["release_source_set"]), "-pthread", "-o", str(probe_binary)]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(EXPECTED_COMPILE_DEFINITIONS) or definitions != list(schema["compile_definitions"]):
        raise EvidenceError("on-demand C command compile definitions drifted")
    if flags != list(schema["release_flags"]):
        raise EvidenceError("on-demand C command release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("on-demand C command lacks the fixed pthread/TLS mode")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command) or Path(command[0]).name != "musl-gcc":
        raise EvidenceError("on-demand report C command is malformed")
    expected = ["-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src", *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/on-demand.c", *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]), "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/on-demand-c"]
    if command[1:] != expected:
        raise EvidenceError("on-demand report C command drifted")


def rust_trace_command(cargo: str, target_dir: Path) -> list[str]:
    return [cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir), "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]


def validate_normalized_rust_command(command: object) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command) or Path(command[0]).name != "cargo":
        raise EvidenceError("on-demand report Rust command is malformed")
    expected = ["test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target", "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]
    if command[1:] != expected:
        raise EvidenceError("on-demand report Rust command drifted")


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    probe_source = temporary / "on-demand.c"
    probe_binary = temporary / "on-demand-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C on-demand fixture build")
        header = run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        run.require_success(header, "pinned C on-demand fixture ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(probe_binary),), cwd=source)
        run.require_success(execution, "pinned C on-demand fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C on-demand trace")
    validate_trace(trace, description="pinned C on-demand trace")
    return {"build_command": normalize_command(command, temporary, source), "elf": elf, "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/on-demand-c"], "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")), "trace": trace}


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, environment=environment)
        run.require_success(execution, "Rust on-demand fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust on-demand fixture passed {passed} tests, expected one")
    trace = parse_trace(str(execution["stdout"]) + "\n" + str(execution["stderr"]), description="Rust on-demand trace")
    validate_trace(trace, description="Rust on-demand trace")
    return {"cargo_command": normalize_command(command, temporary, None), "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}, "passed_test_count": passed, "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}, "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}, "trace": trace}


def report_from_results(*, schema: Mapping[str, Any], provenance: Mapping[str, str], archive_sha256: str, anchors: Sequence[Mapping[str, Any]], c_probe: Mapping[str, Any], rust_probe: Mapping[str, Any]) -> dict[str, Any]:
    c_trace, rust_trace = c_probe.get("trace"), rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("on-demand report inputs lack trace records")
    report: dict[str, Any] = {
        "c_probe": dict(c_probe), "comparison": compare_traces(c_trace, rust_trace), "format": 1,
        "kind": "mimalloc-x86_64-reserved-medium-on-demand-differential-evidence", "profile": schema["profile"],
        "provenance": dict(provenance), "rust_probe": dict(rust_probe), "scope": schema["scope"],
        "source": {"archive_sha256": archive_sha256, "anchors": [dict(anchor) for anchor in anchors], "release_flags": list(schema["release_flags"]), "release_source_set": list(schema["release_source_set"])},
        "status": "passed", "target": schema["target"], "trace": schema["trace"], "upstream": schema["upstream"],
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("on-demand report schema drifted")
    if report["format"] != 1 or report["status"] != "passed" or report["kind"] != "mimalloc-x86_64-reserved-medium-on-demand-differential-evidence":
        raise EvidenceError("on-demand report format/status/kind drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("on-demand report target/profile/source boundary drifted")
    if not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("on-demand report source or private boundary drifted")
    if not exactly_matches(report["trace"], _schema_template()["trace"]):
        raise EvidenceError("on-demand report trace contract drifted")
    if report["provenance"] not in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"}):
        raise EvidenceError("on-demand report lacks native x86-64 provenance")
    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("on-demand report source record is malformed")
    if source["archive_sha256"] != run.load_pin()["sha256"] or not exactly_matches(source["anchors"], schema["source_anchors"]) or not exactly_matches(source["release_flags"], schema["release_flags"]) or not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("on-demand report source identity drifted")
    c_probe, rust_probe = report["c_probe"], report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("on-demand report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("on-demand report Rust probe record drifted")
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF):
        raise EvidenceError("on-demand report C ELF identity drifted")
    if c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/on-demand-c"] or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("on-demand report C probe identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if type(rust_probe["passed_test_count"]) is not int or rust_probe["passed_test_count"] != 1 or not exactly_matches(rust_probe["target_dir"], {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}):
        raise EvidenceError("on-demand report Rust selection/target directory drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}) or not exactly_matches(rust_probe["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}):
        raise EvidenceError("on-demand report Rust source identity drifted")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise EvidenceError("on-demand report comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-on-demand-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
            compiler, readelf, cargo = run.require_tool("musl-gcc"), run.require_tool("readelf"), run.require_tool("cargo")
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source)
        c_probe = build_c_trace(compiler, readelf, source, temporary, schema)
        rust_probe = build_rust_trace(cargo, temporary)
        report = report_from_results(schema=schema, provenance=provenance, archive_sha256=sha256_file(archive), anchors=anchors, c_probe=c_probe, rust_probe=rust_probe)
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
        print(f"allocator x86-64 on-demand differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(f"allocator x86-64 on-demand differential: PASS ({report['comparison']['compared_value_count']} logical values; report: {relative(arguments.report)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
