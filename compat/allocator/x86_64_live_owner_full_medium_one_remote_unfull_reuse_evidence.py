#!/usr/bin/env python3
"""Differentially prove one live-owner full-medium remote unfull/reuse step.

This is a private native Linux/x86-64 oracle lane.  It keeps the pinned
mimalloc v3.5.0 release build and source-selection machinery identical to the
adjacent live-owner release lane, but changes the fixture to one joined remote
free.  The owner false-collects that publication, observes the full page
appended after its regular successor, consumes the successor's remaining
capacity, and requires the next ordinary allocation to return the exact
remotely freed block.  No teardown, abandonment, or public API claim is made.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_live_owner_full_medium_remote_release_evidence.py"
spec = importlib.util.spec_from_file_location("crabc_live_owner_release_base", BASE_PATH)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

RUNNER_PATH = base.RUNNER_PATH
LOCKFILE = base.LOCKFILE
RUST_TEST_SOURCE = base.RUST_TEST_SOURCE
TARGET = base.TARGET
NORMALIZED_EVIDENCE_ROOT = base.NORMALIZED_EVIDENCE_ROOT
NORMALIZED_PINNED_SOURCE = base.NORMALIZED_PINNED_SOURCE
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-live-owner-full-medium-one-remote-unfull-reuse-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/live-owner-full-medium-one-remote-unfull-reuse.json"
STEM = "live-owner-full-medium-one-remote-unfull-reuse"
RUST_TEST_FILTER = "single_thread::tests::x86_64_live_owner_full_medium_one_remote_unfull_reuse_trace_matches_pinned_c"
TRACE_BEGIN = "CRABC_MI_LIVE_OWNER_FULL_MEDIUM_ONE_REMOTE_UNFULL_REUSE_TRACE_BEGIN"
TRACE_END = "CRABC_MI_LIVE_OWNER_FULL_MEDIUM_ONE_REMOTE_UNFULL_REUSE_TRACE_END"
PREFIX = "trace.live_owner_full_medium_one_remote_unfull_reuse."

EXPECTED_TARGET = dict(base.EXPECTED_TARGET)
EXPECTED_UPSTREAM = dict(base.EXPECTED_UPSTREAM)
EXPECTED_ARCHIVE_SHA256 = base.EXPECTED_ARCHIVE_SHA256
EXPECTED_C_ELF = dict(base.EXPECTED_C_ELF)
EXPECTED_PROFILE = "linux-x86_64-private-live-owner-full-medium-one-remote-unfull-reuse"
EXPECTED_COMPILE_DEFINITIONS = tuple(base.EXPECTED_COMPILE_DEFINITIONS)
EXPECTED_SOURCE_ANCHORS = tuple(base.EXPECTED_SOURCE_ANCHORS)
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "c_oracle_one_full_page_remote_free_required": True,
    "c_oracle_join_before_non_atomic_owner_observation_required": True,
    "c_oracle_live_owner_only": True,
    "c_oracle_no_thread_teardown": True,
    "c_oracle_non_abandoning_full_queue_only": True,
    "c_oracle_real_pthread_required": True,
    "c_oracle_successor_capacity_precedes_reuse": True,
    "c_oracle_both_live_page_metadata_preserved": True,
    "c_rust_common_trace_facts_only": True,
    "emulation_accepted": False,
    "general_allocation_routing_claimed": False,
    "general_lifecycle_claimed": False,
    "general_remote_free_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
    "rust_scoped_joined_remote_producers_only": True,
}


def _expected(name: str) -> str:
    return PREFIX + name


_NAMES = (
    "request block_size capacity reserved slice_count arena_backed ordinary_medium non_abandoning_theap "
    "first_full_member_before_remote successor_regular_member_before_remote "
    "first_page_map_all_slices_before_remote successor_page_map_all_slices_before_remote "
    "first_arena_page_bitmap_set_before_remote first_slices_unreleased_before_remote initial_used "
    "initial_remote_head_owned initial_remote_empty joined_remote_free_count worker_joined_before_owner_collect "
    "published_used_unchanged published_remote_head_owned published_remote_count published_list_acyclic "
    "owner_false_collect_called full_queue_empty_after_collect first_used_after_collect "
    "first_regular_after_collect first_reusable_after_collect first_remote_empty_after_collect "
    "regular_queue_count_after_collect page_count_after_collect regular_queue_order_after_collect "
    "successor_regular_member_after_collect first_page_map_all_slices_after_collect "
    "successor_page_map_all_slices_after_collect first_arena_page_bitmap_set_after_collect "
    "first_slices_unreleased_after_collect predecessor_exhausted_before_reuse reused_exact_remote_block "
    "successor_full_after_predecessor_exhaustion regular_queue_count_before_exact_reuse "
    "full_queue_count_before_exact_reuse valid"
).split()
EXPECTED_TRACE_VALUES: dict[str, int] = {_expected(name): 1 for name in _NAMES}
EXPECTED_TRACE_VALUES.update(
    {
        _expected("request"): 10248,
        _expected("block_size"): 12288,
        _expected("capacity"): 42,
        _expected("reserved"): 42,
        _expected("slice_count"): 8,
        _expected("initial_used"): 42,
        _expected("joined_remote_free_count"): 1,
        _expected("published_remote_count"): 1,
        _expected("regular_queue_count_after_collect"): 2,
        _expected("page_count_after_collect"): 2,
        _expected("first_used_after_collect"): 41,
        _expected("predecessor_exhausted_before_reuse"): 1,
        _expected("regular_queue_count_before_exact_reuse"): 1,
        _expected("full_queue_count_before_exact_reuse"): 1,
    }
)


def _make_probe() -> str:
    """Specialize the adjacent C fixture without changing its pinned source set."""

    probe = base.C_TRACE_PROBE
    probe = probe.replace(
        "  void* successor = NULL;",
        "  void* successor = NULL;\n  void* remote_block = NULL;",
        1,
    )
    probe = probe.replace(
        "  worker_joined = true;\n  worker_joined_before_owner_collect",
        "  worker_joined = true;\n  remote_block = fixture.blocks[0];\n  fixture.blocks[0] = NULL;\n  worker_joined_before_owner_collect",
        1,
    )
    probe = probe.replace(
        "for (size_t index = 0; index < fixture->first_count; index++) {\n    void* const block = fixture->blocks[index];\n    if (block == NULL) return (void*)1;\n    mi_free(block);\n    fixture->blocks[index] = NULL;\n  }",
        "void* const block = fixture->blocks[0];\n  if (block == NULL) return (void*)1;\n  mi_free(block);",
        1,
    )
    probe = probe.replace("joined_remote_free_count = reserved;", "joined_remote_free_count = 1;", 1)
    probe = probe.replace("published_remote_count != reserved", "published_remote_count != 1", 1)
    probe = probe.replace("published_remote_count == 42", "published_remote_count == 1", 1)
    probe = probe.replace("joined_remote_free_count == 42", "joined_remote_free_count == 1", 1)
    probe = probe.replace(
        "  int first_slices_free_after_collect = 0;",
        """  int first_slices_free_after_collect = 0;
  size_t full_queue_count_after_collect = 0;
  size_t first_used_after_collect = 0;
  size_t first_used_after_reuse = 0;
  size_t full_queue_count_after_reuse = 0;
  size_t regular_queue_count_after_reuse = 0;
  size_t regular_queue_count_before_exact_reuse = 0;
  size_t full_queue_count_before_exact_reuse = 0;
  int first_regular_after_collect = 0;
  int regular_queue_first_is_successor_after_collect = 0;
  int regular_queue_last_is_first_after_collect = 0;
  int successor_next_is_first_after_collect = 0;
  int first_prev_is_successor_after_collect = 0;
  int successor_prev_is_null_after_collect = 0;
  int regular_queue_order_after_collect = 0;
  int first_in_full_after_collect = 0;
  int first_reusable_after_collect = 0;
  int first_free_exact_remote_internal = 0;
  int first_local_free_empty_internal = 0;
  int first_remote_empty_after_collect = 0;
  int first_page_map_all_slices_after_collect = 0;
  int successor_page_map_all_slices_before_remote = 0;
  int first_arena_page_bitmap_set_after_collect = 0;
  int successor_arena_page_bitmap_set_after_collect = 0;
  int first_slices_unreleased_after_collect = 0;
  int successor_slices_unreleased_after_collect = 0;
  int predecessor_exhausted_before_reuse = 0;
  int reused_exact_remote_block = 0;
  int successor_full_after_predecessor_exhaustion = 0;
  int first_full_member_after_reuse = 0;
  int successor_full_member_after_reuse = 0;
  int first_page_map_all_slices_after_reuse = 0;
  int successor_page_map_all_slices_after_reuse = 0;
  int first_arena_page_bitmap_set_after_reuse = 0;
  int successor_arena_page_bitmap_set_after_reuse = 0;
  int first_slices_unreleased_after_reuse = 0;
  int successor_slices_unreleased_after_reuse = 0;""",
        1,
    )
    old_block = """  mi_heap_collect(heap, false);
  owner_false_collect_called = 1;
  full_queue_empty_after_collect = (
      full != NULL && full->count == 0 && full->first == NULL
      && full->last == NULL);
  regular_queue_count_after_collect = (regular == NULL ? 0 : regular->count);
  page_count_after_collect = theap->page_count;
  successor_regular_member_after_collect = queue_has_only_member(
      regular, successor_page);
  successor_page_map_all_slices_after_collect = map_span_is_page(
      successor_page, successor_span_start, successor_slice_count);
  first_page_map_all_slices_clear_after_collect = map_span_is_clear(
      first_span_start, first_slice_count);
  first_arena_page_bitmap_clear_after_collect = mi_bitmap_is_clearN(
      arena_pages->pages, first_slice_index, 1);
  first_slices_free_after_collect = mi_bbitmap_is_setN(
      arena->slices_free, first_slice_index, first_slice_count);
  valid = (request == 10248 && block_size == 12288
      && capacity == 42 && reserved == 42 && first_slice_count == 8
      && arena_backed && ordinary_medium && non_abandoning_theap
      && first_full_member_before_remote
      && successor_regular_member_before_remote
      && full_queue_count_before_remote == 1
      && regular_queue_count_before_remote == 1
      && page_count_before_remote == 2
      && first_page_map_all_slices_before_remote
      && first_arena_page_bitmap_set_before_remote
      && first_slices_unreleased_before_remote
      && initial_used == 42 && initial_remote_head_owned && initial_remote_empty
      && joined_remote_free_count == 1 && worker_joined_before_owner_collect
      && published_used_unchanged && published_remote_head_owned
      && published_remote_count == 1 && published_list_acyclic
      && owner_false_collect_called && full_queue_empty_after_collect
      && regular_queue_count_after_collect == 1 && page_count_after_collect == 1
      && successor_regular_member_after_collect
      && successor_page_map_all_slices_after_collect
      && first_page_map_all_slices_clear_after_collect
      && first_arena_page_bitmap_clear_after_collect
      && first_slices_free_after_collect);"""
    new_block = r'''  mi_heap_collect(heap, false);
  owner_false_collect_called = 1;
  full_queue_count_after_collect = (full == NULL ? 0 : full->count);
  regular_queue_count_after_collect = (regular == NULL ? 0 : regular->count);
  page_count_after_collect = theap->page_count;
  first_used_after_collect = first_page->used;
  full_queue_empty_after_collect = (full != NULL && full->count == 0
      && full->first == NULL && full->last == NULL);
  first_regular_after_collect = !mi_page_is_in_full(first_page)
      && queue_contains_member(regular, first_page);
  successor_regular_member_after_collect = !mi_page_is_in_full(successor_page)
      && queue_contains_member(regular, successor_page);
  regular_queue_first_is_successor_after_collect = regular->first == successor_page;
  regular_queue_last_is_first_after_collect = regular->last == first_page;
  successor_next_is_first_after_collect = successor_page->next == first_page;
  first_prev_is_successor_after_collect = first_page->prev == successor_page;
  successor_prev_is_null_after_collect = successor_page->prev == NULL;
  regular_queue_order_after_collect = regular_queue_first_is_successor_after_collect
      && regular_queue_last_is_first_after_collect
      && successor_next_is_first_after_collect
      && first_prev_is_successor_after_collect
      && successor_prev_is_null_after_collect;
  first_in_full_after_collect = mi_page_is_in_full(first_page);
  first_reusable_after_collect = (first_page->free != NULL || first_page->local_free != NULL);
  first_free_exact_remote_internal = (first_page->free == remote_block);
  first_local_free_empty_internal = (first_page->local_free == NULL);
  first_remote_empty_after_collect = (mi_tf_block(mi_atomic_load_acquire(
      &first_page->xthread_free)) == NULL);
  first_page_map_all_slices_after_collect = map_span_is_page(
      first_page, first_span_start, first_slice_count);
  successor_page_map_all_slices_after_collect = map_span_is_page(
      successor_page, successor_span_start, successor_slice_count);
  first_arena_page_bitmap_set_after_collect = mi_bitmap_is_setN(
      arena_pages->pages, first_slice_index, 1);
  first_slices_unreleased_after_collect = mi_bbitmap_is_clearN(
      arena->slices_free, first_slice_index, first_slice_count);
  const size_t successor_slice_index = successor_page->memid.mem.arena.slice_index;
  successor_arena_page_bitmap_set_after_collect = mi_bitmap_is_setN(
      arena_pages->pages, successor_slice_index, 1);
  successor_slices_unreleased_after_collect = mi_bbitmap_is_clearN(
      arena->slices_free, successor_slice_index, successor_slice_count);
  if (!first_regular_after_collect || !successor_regular_member_after_collect
      || !regular_queue_first_is_successor_after_collect
      || !regular_queue_last_is_first_after_collect
      || !successor_next_is_first_after_collect
      || !first_prev_is_successor_after_collect
      || !successor_prev_is_null_after_collect) goto output;

  void* predecessor_blocks[MAX_FIRST_PAGE_BLOCKS] = { 0 };
  size_t predecessor_count = 0;
  while (successor_page->used < successor_page->reserved) {
    void* const filler = mi_heap_malloc(heap, request);
    if (filler == NULL || _mi_ptr_page(filler) != successor_page
        || predecessor_count >= MAX_FIRST_PAGE_BLOCKS) goto output;
    predecessor_blocks[predecessor_count++] = filler;
  }
  predecessor_exhausted_before_reuse = (predecessor_count == 41);
  successor_full_after_predecessor_exhaustion = mi_page_is_in_full(successor_page);
  regular_queue_count_before_exact_reuse = regular->count;
  full_queue_count_before_exact_reuse = full->count;
  successor_page = _mi_ptr_page(successor);
  void* const reused = mi_heap_malloc(heap, request);
  reused_exact_remote_block = (reused == remote_block);
  if (!reused_exact_remote_block) goto output;
  first_used_after_reuse = first_page->used;
  full_queue_count_after_reuse = full->count;
  regular_queue_count_after_reuse = regular->count;
  first_full_member_after_reuse = mi_page_is_in_full(first_page);
  successor_full_member_after_reuse = mi_page_is_in_full(successor_page);
  first_page_map_all_slices_after_reuse = map_span_is_page(
      first_page, first_span_start, first_slice_count);
  successor_page_map_all_slices_after_reuse = map_span_is_page(
      successor_page, successor_span_start, successor_slice_count);
  first_arena_page_bitmap_set_after_reuse = mi_bitmap_is_setN(
      arena_pages->pages, first_slice_index, 1);
  successor_arena_page_bitmap_set_after_reuse = mi_bitmap_is_setN(
      arena_pages->pages, successor_slice_index, 1);
  first_slices_unreleased_after_reuse = mi_bbitmap_is_clearN(
      arena->slices_free, first_slice_index, first_slice_count);
  successor_slices_unreleased_after_reuse = mi_bbitmap_is_clearN(
      arena->slices_free, successor_slice_index, successor_slice_count);
  valid = (request == 10248 && block_size == 12288 && capacity == 42
      && reserved == 42 && first_slice_count == 8 && arena_backed && ordinary_medium
      && non_abandoning_theap && first_full_member_before_remote
      && successor_regular_member_before_remote && full_queue_count_before_remote == 1
      && regular_queue_count_before_remote == 1 && page_count_before_remote == 2
      && first_page_map_all_slices_before_remote && first_arena_page_bitmap_set_before_remote
      && first_slices_unreleased_before_remote && initial_used == 42
      && initial_remote_head_owned && initial_remote_empty && joined_remote_free_count == 1
      && worker_joined_before_owner_collect && published_used_unchanged
      && published_remote_head_owned && published_remote_count == 1 && published_list_acyclic
      && owner_false_collect_called && full_queue_count_after_collect == 0
      && regular_queue_count_after_collect == 2 && page_count_after_collect == 2
      && first_regular_after_collect && successor_regular_member_after_collect
      && regular_queue_first_is_successor_after_collect
      && regular_queue_last_is_first_after_collect && successor_next_is_first_after_collect
      && first_prev_is_successor_after_collect && successor_prev_is_null_after_collect
      && !first_in_full_after_collect && first_used_after_collect == 41
      && first_reusable_after_collect && first_free_exact_remote_internal
      && first_local_free_empty_internal
      && first_remote_empty_after_collect && first_page_map_all_slices_after_collect
      && successor_page_map_all_slices_after_collect && first_arena_page_bitmap_set_after_collect
      && successor_arena_page_bitmap_set_after_collect && first_slices_unreleased_after_collect
      && successor_slices_unreleased_after_collect && predecessor_exhausted_before_reuse
      && reused_exact_remote_block && first_used_after_reuse == 42
      && first_full_member_after_reuse && successor_full_member_after_reuse
      && full_queue_count_after_reuse == 2 && regular_queue_count_after_reuse == 0
      && first_page_map_all_slices_after_reuse && successor_page_map_all_slices_after_reuse
      && first_arena_page_bitmap_set_after_reuse && successor_arena_page_bitmap_set_after_reuse
      && first_slices_unreleased_after_reuse && successor_slices_unreleased_after_reuse);'''
    if old_block not in probe:
        raise RuntimeError("adjacent live-owner probe changed its replacement boundary")
    probe = probe.replace(old_block, new_block, 1)
    probe = probe.replace(
        "  first_arena_page_bitmap_set_before_remote = mi_bitmap_is_setN(",
        """  successor_page_map_all_slices_before_remote = map_span_is_page(
      successor_page, successor_span_start, successor_slice_count);
  first_arena_page_bitmap_set_before_remote = mi_bitmap_is_setN(""",
        1,
    )
    probe = probe.replace(
        "&& first_page_map_all_slices_before_remote\n      && first_arena_page_bitmap_set_before_remote",
        "&& first_page_map_all_slices_before_remote\n      && successor_page_map_all_slices_before_remote\n      && first_arena_page_bitmap_set_before_remote",
    )
    # Add all new address-independent output fields immediately before the
    # old release-lane output section and replace its field names.
    output_start = probe.index('  printf("CRABC_MI_LIVE_OWNER_FULL_MEDIUM_REMOTE_RELEASE_TRACE_BEGIN\\n");')
    output_end = probe.index('  printf("CRABC_MI_LIVE_OWNER_FULL_MEDIUM_REMOTE_RELEASE_TRACE_END\\n");', output_start)
    output = (
        '  printf("' + TRACE_BEGIN + '\\n");\n'
        '#define OUT_N(name, value) printf("' + PREFIX + '%s=%zu\\n", name, (size_t)(value))\n'
        '#define OUT_B(name, value) printf("' + PREFIX + '%s=%d\\n", name, (value) ? 1 : 0)\n'
    )
    for name in _NAMES:
        macro = "OUT_N" if name in {"request", "block_size", "capacity", "reserved", "slice_count", "initial_used", "joined_remote_free_count", "published_remote_count", "first_used_after_collect", "regular_queue_count_after_collect", "page_count_after_collect", "regular_queue_count_before_exact_reuse", "full_queue_count_before_exact_reuse"} else "OUT_B"
        output += f'  {macro}("{name}", {name});\n'
    output += '  printf("' + TRACE_END + '\\n");\n'
    probe = probe[:output_start] + output + probe[output_end + len('  printf("CRABC_MI_LIVE_OWNER_FULL_MEDIUM_REMOTE_RELEASE_TRACE_END\\n");\n'):]
    probe = probe.replace('OUT_N("slice_count", slice_count);', 'OUT_N("slice_count", first_slice_count);')
    return probe


C_TRACE_PROBE = _make_probe()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return base.sha256_file(path)


def exactly_matches(observed: object, expected: object) -> bool:
    return base.exactly_matches(observed, expected)


def relative(path: Path) -> str:
    return base.relative(path)


def _schema_template() -> dict[str, Any]:
    return {
        "format": 1,
        "schema": "crabc-mimalloc-x86_64-live-owner-full-medium-one-remote-unfull-reuse-evidence",
        "profile": EXPECTED_PROFILE,
        "harness_dependency": {
            "path": relative(BASE_PATH),
            "sha256": sha256_file(BASE_PATH),
        },
        "target": copy.deepcopy(EXPECTED_TARGET),
        "upstream": copy.deepcopy(EXPECTED_UPSTREAM),
        "scope": copy.deepcopy(EXPECTED_SCOPE),
        "compile_definitions": list(EXPECTED_COMPILE_DEFINITIONS),
        "release_flags": list(base.run.CONFIGURATION_PROFILES["release"]),
        "release_source_set": list(base.run.ORACLE_SOURCES),
        "source_anchors": [
            {"member": member, "start_line": start, "end_line": end, "sha256": digest}
            for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
        ],
        "c_probe_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "rust_test": {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER},
        "trace": {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": copy.deepcopy(EXPECTED_TRACE_VALUES)},
    }


class EvidenceError(RuntimeError):
    pass


def load_schema(path: Path | None = None) -> dict[str, Any]:
    target = SCHEMA_PATH if path is None else Path(path)
    try:
        schema = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read live-owner full-medium one-remote schema") from error
    if not exactly_matches(schema, _schema_template()):
        raise EvidenceError("live-owner full-medium one-remote checked-in schema drifted")
    pin = base.run.load_pin()
    if {k: pin[k] for k in ("archive_root", "revision", "version")} != EXPECTED_UPSTREAM or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("live-owner full-medium one-remote upstream pin drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    return base.validate_source_anchors(schema, source)


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return base.run.parse_address_independent_trace(output, begin=TRACE_BEGIN, end=TRACE_END, description=description)
    except base.run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, object], *, description: str) -> None:
    if not isinstance(trace, Mapping):
        raise EvidenceError(f"{description} is not a trace mapping")
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    non_integer = sorted(key for key, value in trace.items() if type(value) is not int)
    mismatches = [f"{key} (expected {EXPECTED_TRACE_VALUES[key]}, observed {trace[key]})" for key in sorted(set(trace) & set(EXPECTED_TRACE_VALUES)) if type(trace[key]) is int and trace[key] != EXPECTED_TRACE_VALUES[key]]
    if missing or unexpected or non_integer or mismatches:
        details = []
        if missing: details.append("missing: " + ", ".join(missing))
        if unexpected: details.append("unexpected: " + ", ".join(unexpected))
        if non_integer: details.append("non-integer values: " + ", ".join(non_integer))
        if mismatches: details.append("value mismatches: " + ", ".join(mismatches))
        raise EvidenceError(f"{description} differs from the fixed one-remote unfull trace: " + "; ".join(details))


def compare_traces(c_trace: Mapping[str, object], rust_trace: Mapping[str, object]) -> dict[str, int | str]:
    validate_trace(c_trace, description="pinned C one-remote unfull trace")
    validate_trace(rust_trace, description="Rust one-remote unfull trace")
    if any(c_trace[key] != rust_trace[key] for key in EXPECTED_TRACE_VALUES):
        raise EvidenceError("Rust one-remote unfull trace differs from pinned C")
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def validate_c_probe_contract(probe: str) -> None:
    """Keep the one joined producer, owner boundary, and exact reuse proof."""

    create = "if (pthread_create(&worker, NULL, remote_worker, &fixture) != 0) goto output;"
    join = "if (pthread_join(worker, &worker_result) != 0) goto output;"
    if probe.count(create) != 1 or probe.count(join) != 1:
        raise EvidenceError("one-remote C probe must create and join exactly one real worker pthread")
    if probe.count("mi_free(block);") != 1:
        raise EvidenceError("one-remote C worker must perform exactly one real mi_free")
    if "mi_thread_done" in probe:
        raise EvidenceError("one-remote C probe must not perform thread teardown")
    if "mi_heap_collect(heap, false);" not in probe:
        raise EvidenceError("one-remote C probe must invoke the owner false collector")
    if probe.index(create) > probe.index(join) or probe.index(join) > probe.index("published_head"):
        raise EvidenceError("one-remote C probe must join before owner observation")
    if "mi_option_set(mi_option_page_full_retain, -1);" not in probe:
        raise EvidenceError("one-remote C probe must select page_full_retain=-1")
    required = (
        "full_queue_empty_after_collect",
        "regular_queue_first_is_successor_after_collect",
        "successor_next_is_first_after_collect",
        "first_used_after_collect",
        "first_reusable_after_collect = (first_page->free != NULL || first_page->local_free != NULL);",
        "first_free_exact_remote_internal = (first_page->free == remote_block);",
        "first_local_free_empty_internal = (first_page->local_free == NULL);",
        "first_remote_empty_after_collect",
        "first_page_map_all_slices_after_collect",
        "successor_page_map_all_slices_after_collect",
        "first_arena_page_bitmap_set_after_collect",
        "successor_arena_page_bitmap_set_after_collect",
        "first_slices_unreleased_after_collect",
        "successor_slices_unreleased_after_collect",
        "predecessor_exhausted_before_reuse",
        "reused_exact_remote_block",
        "first_page_map_all_slices_after_reuse",
        "successor_page_map_all_slices_after_reuse",
        "mi_bbitmap_is_clearN(",
        "mi_bitmap_is_setN(",
        "queue_contains_member(regular, first_page)",
    )
    missing = [token for token in required if token not in probe]
    if missing:
        raise EvidenceError("one-remote C probe lacks required oracle contract: " + ", ".join(missing))
    if "reused_exact_remote_block = (reused == fixture.blocks[0]);" not in probe:
        if "reused_exact_remote_block = (reused == remote_block);" not in probe:
            raise EvidenceError("one-remote C probe must compare ordinary reuse with the preserved remote block")
    filler = "while (successor_page->used < successor_page->reserved) {"
    reuse_site = probe.index("void* const reused")
    if filler not in probe or probe.index(filler) > probe.index("reused_exact_remote_block", reuse_site):
        raise EvidenceError("one-remote C probe must consume successor capacity before reuse")


def _configure_base() -> None:
    """Reuse the release runner's command/report mechanics with this contract."""

    for name, value in {
        "SCHEMA_PATH": SCHEMA_PATH,
        "STEM": STEM,
        "RUST_TEST_FILTER": RUST_TEST_FILTER,
        "TRACE_BEGIN": TRACE_BEGIN,
        "TRACE_END": TRACE_END,
        "PREFIX": PREFIX,
        "C_TRACE_PROBE": C_TRACE_PROBE,
        "EXPECTED_TARGET": EXPECTED_TARGET,
        "EXPECTED_UPSTREAM": EXPECTED_UPSTREAM,
        "EXPECTED_ARCHIVE_SHA256": EXPECTED_ARCHIVE_SHA256,
        "EXPECTED_PROFILE": EXPECTED_PROFILE,
        "EXPECTED_COMPILE_DEFINITIONS": EXPECTED_COMPILE_DEFINITIONS,
        "EXPECTED_SCOPE": EXPECTED_SCOPE,
        "EXPECTED_SOURCE_ANCHORS": EXPECTED_SOURCE_ANCHORS,
        "EXPECTED_TRACE_VALUES": EXPECTED_TRACE_VALUES,
        "EXPECTED_C_ELF": EXPECTED_C_ELF,
        "NORMALIZED_EVIDENCE_ROOT": NORMALIZED_EVIDENCE_ROOT,
        "NORMALIZED_PINNED_SOURCE": NORMALIZED_PINNED_SOURCE,
    }.items():
        setattr(base, name, value)
    base.validate_c_probe_contract = validate_c_probe_contract
    base.parse_trace = parse_trace
    base.validate_trace = validate_trace
    base.compare_traces = compare_traces


def c_trace_command(compiler: str, source: Path, probe_source: Path, probe_binary: Path, schema: Mapping[str, Any]) -> list[str]:
    _configure_base()
    return base.c_trace_command(compiler, source, probe_source, probe_binary, schema)


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    _configure_base()
    return base.validate_c_command(command, schema)


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    _configure_base()
    return base.normalize_command(command, temporary, source)


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    _configure_base()
    return base.validate_normalized_c_command(command, schema)


def rust_trace_command(cargo: str, target_dir: Path) -> list[str]:
    _configure_base()
    return base.rust_trace_command(cargo, target_dir)


def validate_normalized_rust_command(command: object) -> None:
    _configure_base()
    return base.validate_normalized_rust_command(command)


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    _configure_base()
    return base.build_c_trace(compiler, readelf, source, temporary, schema)


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    _configure_base()
    return base.build_rust_trace(cargo, temporary)


def report_from_results(*, schema: Mapping[str, Any], provenance: Mapping[str, str], archive_sha256: str, anchors: Sequence[Mapping[str, Any]], c_probe: Mapping[str, Any], rust_probe: Mapping[str, Any]) -> dict[str, Any]:
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("one-remote report inputs lack C/Rust traces")
    report: dict[str, Any] = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": "mimalloc-x86_64-live-owner-full-medium-one-remote-unfull-reuse-differential-evidence",
        "profile": EXPECTED_PROFILE,
        "provenance": dict(provenance),
        "rust_probe": dict(rust_probe),
        "scope": copy.deepcopy(EXPECTED_SCOPE),
        "source": {"archive_sha256": archive_sha256, "anchors": [dict(anchor) for anchor in anchors], "release_flags": list(schema["release_flags"]), "release_source_set": list(schema["release_source_set"])},
        "status": "passed",
        "target": copy.deepcopy(EXPECTED_TARGET),
        "trace": copy.deepcopy(schema["trace"]),
        "upstream": copy.deepcopy(EXPECTED_UPSTREAM),
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("one-remote report schema drifted")
    if report["kind"] != "mimalloc-x86_64-live-owner-full-medium-one-remote-unfull-reuse-differential-evidence" or report["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("one-remote report identity drifted")
    if not exactly_matches(report["comparison"], {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}):
        raise EvidenceError("one-remote report comparison drifted")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("one-remote report target, upstream, or scope drifted")
    provenance = report["provenance"]
    if not exactly_matches(provenance, {"execution_mode": "native", "host_architecture": "x86_64"}) and not exactly_matches(provenance, {"execution_mode": "native", "host_architecture": "amd64"}):
        raise EvidenceError("one-remote report lacks native x86-64 provenance")
    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"} or source["archive_sha256"] != EXPECTED_ARCHIVE_SHA256 or not exactly_matches(source["anchors"], schema["source_anchors"]) or not exactly_matches(source["release_flags"], schema["release_flags"]) or not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("one-remote report source record drifted")
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("one-remote report trace schema drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"} or not exactly_matches(c_probe["elf"], EXPECTED_C_ELF) or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")) or not exactly_matches(c_probe["run_command"], [f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"]):
        raise EvidenceError("one-remote C probe record drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"} or rust_probe["passed_test_count"] != 1:
        raise EvidenceError("one-remote Rust probe record drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}) or not exactly_matches(rust_probe["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}) or not exactly_matches(rust_probe["target_dir"], {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}):
        raise EvidenceError("one-remote Rust identity drifted")
    compare_traces(c_probe["trace"], rust_probe["trace"])


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    _configure_base()
    try:
        provenance = base.run.require_native_x86_64()
        schema = load_schema()
        before_lockfile = sha256_file(LOCKFILE)
        pin = base.run.load_pin()
        archive = base.run.fetch_archive(pin, offline)
    except base.run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-live-owner-full-medium-one-remote-") as temporary_name:
        temporary = Path(temporary_name)
        source = base.run.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = base.run.require_tool("musl-gcc")
        readelf = base.run.require_tool("readelf")
        cargo = base.run.require_tool("cargo")
        anchors = validate_source_anchors(schema, source)
        c_probe = build_c_trace(compiler, readelf, source, temporary, schema)
        rust_probe = build_rust_trace(cargo, temporary)
        report = report_from_results(schema=schema, provenance=provenance, archive_sha256=sha256_file(archive), anchors=anchors, c_probe=c_probe, rust_probe=rust_probe)
    if sha256_file(LOCKFILE) != before_lockfile:
        raise EvidenceError("Cargo.lock changed despite the required --locked Rust trace command")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    base.run.write_json(report_path, report)
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
        print(f"allocator x86-64 live-owner full-medium one-remote unfull/reuse differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(f"allocator x86-64 live-owner full-medium one-remote unfull/reuse differential: PASS ({report['comparison']['compared_value_count']} logical values; report: {relative(arguments.report)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
