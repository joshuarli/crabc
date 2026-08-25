#!/usr/bin/env python3
"""Differentially prove one bounded live-owner remote-free protocol on x86-64.

This native-only judge compiles a private pinned-C fixture that routes two
ordinary small allocations through ``mi_free`` from one quiescent pthread,
then calls the exact owner-side private collector.  It compares that fixed
address-independent record with one crate-private Rust test of the same
live-owner publication/detach/list-merge substrate.

It is deliberately not public ``mi_*`` API, general allocation routing,
abandoned-page, thread-teardown, libc, loader, or backend evidence.  The C
fixture includes ``mimalloc/internal.h`` precisely so that its structural
observations remain a source-specific private protocol probe.
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-remote-free-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/live-owner-remote-free.json"
LOCKFILE = ROOT / "Cargo.lock"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = (
    "remote_free::tests::x86_64_live_owner_remote_free_trace_matches_pinned_c_protocol"
)
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/remote_free.rs"
TRACE_BEGIN = "CRABC_MI_LIVE_OWNER_REMOTE_FREE_TRACE_BEGIN"
TRACE_END = "CRABC_MI_LIVE_OWNER_REMOTE_FREE_TRACE_END"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded native differential could not establish its contract."""


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
EXPECTED_PROFILE = "linux-x86_64-private-live-owner-remote-free-differential"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "abandoned_or_thread_teardown_claimed": False,
    "emulation_accepted": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
}
EXPECTED_COMPILE_DEFINITIONS = (
    "-DMI_SHARED_LIB",
    "-DMI_SHARED_LIB_EXPORT",
    "-DMI_LIBC_MUSL=1",
)
EXPECTED_SOURCE_ANCHORS = (
    ("src/free.c", 62, 97, "6dc25419bcef550d5626841cfc8d3121526ceaaa3698bf215c16bfa5de665bd6"),
    ("src/free.c", 223, 249, "e755fc43b602a94ee89305924c28fcdbea5901bbccc2927c6cf5aa77f9e43942"),
    ("src/page.c", 150, 201, "01d8f3f6a09d7d7b30e9e4f90f59c6738954fe5231d8fe9dac1ef5d0f96b967a"),
    (
        "include/mimalloc/types.h",
        388,
        418,
        "efa7121eecd1146792f7eff5fd7b730daac15e124fe6a3d94457d81644d460cd",
    ),
)
EXPECTED_TRACE_VALUES = {
    "trace.live_owner_remote.producer_count": 2,
    "trace.live_owner_remote.same_page": 1,
    "trace.live_owner_remote.initial_live_owner_associated": 1,
    "trace.live_owner_remote.initial_used": 2,
    "trace.live_owner_remote.initial_capacity_ge_used": 1,
    "trace.live_owner_remote.initial_head_owned": 1,
    "trace.live_owner_remote.initial_head_empty": 1,
    "trace.live_owner_remote.initial_remote_count": 0,
    "trace.live_owner_remote.published_used_unchanged": 1,
    "trace.live_owner_remote.published_head_owned": 1,
    "trace.live_owner_remote.published_head_is_latest": 1,
    "trace.live_owner_remote.published_latest_predecessor_is_first": 1,
    "trace.live_owner_remote.published_nonempty": 1,
    "trace.live_owner_remote.published_remote_count": 2,
    "trace.live_owner_remote.post_join_remote_count": 2,
    "trace.live_owner_remote.published_actual_live_count": 0,
    "trace.live_owner_remote.collected_count": 2,
    "trace.live_owner_remote.collected_used": 0,
    "trace.live_owner_remote.post_collect_remote_count": 0,
    "trace.live_owner_remote.collected_head_owned": 1,
    "trace.live_owner_remote.collected_head_empty": 1,
    "trace.live_owner_remote.collected_local_count": 2,
    "trace.live_owner_remote.collected_lifo": 1,
    "trace.live_owner_remote.list_cycle_free": 1,
    "trace.live_owner_remote.valid": 1,
}
EXPECTED_C_ELF = {
    "class": "ELF64",
    "endianness": "little",
    "machine": "Advanced Micro Devices X86-64",
}
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

# This source intentionally calls the C public free entry only to select the
# frozen source's cross-thread route.  All page-head and collection inspection
# remains private pinned-C evidence.  The worker is released and joined before
# the owner reads any non-atomic page field or list link.
C_TRACE_PROBE = r"""
#define _POSIX_C_SOURCE 200809L
#include "mimalloc/internal.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private live-owner fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private live-owner fixture requires the fixed release profile
#endif
#if MI_ENCODE_FREELIST != 0
#error this fixture models the fixed unencoded normal-release freelist
#endif

typedef struct remote_fixture_s {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  unsigned stage;
  void* first;
  void* second;
} remote_fixture_t;

static bool fixture_advance(remote_fixture_t* fixture, unsigned stage) {
  if (pthread_mutex_lock(&fixture->mutex) != 0) return false;
  if (fixture->stage < stage) fixture->stage = stage;
  const int signal_result = pthread_cond_broadcast(&fixture->condition);
  const int unlock_result = pthread_mutex_unlock(&fixture->mutex);
  return signal_result == 0 && unlock_result == 0;
}

static bool fixture_wait_for(remote_fixture_t* fixture, unsigned expected_stage) {
  if (pthread_mutex_lock(&fixture->mutex) != 0) return false;
  struct timespec deadline;
  int result = 0;
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
    result = EINVAL;
  } else {
    deadline.tv_sec += 5;
    while (fixture->stage < expected_stage && result == 0) {
      result = pthread_cond_timedwait(&fixture->condition, &fixture->mutex, &deadline);
    }
  }
  const int unlock_result = pthread_mutex_unlock(&fixture->mutex);
  return result == 0 && unlock_result == 0;
}

static void* remote_worker(void* context) {
  remote_fixture_t* const fixture = (remote_fixture_t*)context;
  if (!fixture_wait_for(fixture, 1)) return (void*)1;
  mi_free(fixture->first);
  if (!fixture_advance(fixture, 2)) return (void*)1;
  if (!fixture_wait_for(fixture, 3)) return (void*)1;
  mi_free(fixture->second);
  if (!fixture_advance(fixture, 4)) return (void*)1;
  if (!fixture_wait_for(fixture, 5)) return (void*)1;
  return NULL;
}

static size_t bounded_list_count(mi_page_t* page, mi_block_t* head, size_t maximum) {
  size_t count = 0;
  while (head != NULL && count < maximum) {
    count++;
    head = mi_block_next(page, head);
  }
  return count;
}

int main(void) {
  const size_t producer_count = 2;
  remote_fixture_t fixture = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL, NULL };
  pthread_t worker;
  bool worker_started = false;
  bool worker_joined = false;
  void* worker_result = (void*)1;
  mi_heap_t* heap = NULL;
  bool valid = false;

  heap = mi_heap_new();
  if (heap == NULL) goto cleanup;
  fixture.first = mi_heap_malloc_small(heap, 16);
  fixture.second = mi_heap_malloc_small(heap, 16);
  if (fixture.first == NULL || fixture.second == NULL) goto cleanup;

  mi_page_t* const page = _mi_ptr_page(fixture.first);
  mi_page_t* const second_page = _mi_ptr_page(fixture.second);
  if (page == NULL || second_page == NULL || page != second_page) goto cleanup;
  if (mi_page_block_size(page) != 16) goto cleanup;

  const mi_thread_free_t initial_head = mi_atomic_load_acquire(&page->xthread_free);
  const size_t initial_used = page->used;
  const bool same_page = (page == second_page);
  const bool initial_live_owner_associated = !mi_page_is_abandoned(page) && mi_page_is_owned(page);
  const bool initial_capacity_ge_used = (page->capacity >= initial_used);
  const bool initial_head_owned = mi_tf_is_owned(initial_head);
  const bool initial_head_empty = (mi_tf_block(initial_head) == NULL);
  if (!same_page || !initial_live_owner_associated || !initial_capacity_ge_used || !initial_head_owned || !initial_head_empty || initial_used != producer_count) goto cleanup;

  if (pthread_create(&worker, NULL, &remote_worker, &fixture) != 0) goto cleanup;
  worker_started = true;
  if (!fixture_advance(&fixture, 1) || !fixture_wait_for(&fixture, 2)) goto cleanup;

  // The live worker is quiescent here.  Until it has joined, inspect only the
  // atomic source head and never traverse links or ordinary page metadata.
  const mi_thread_free_t first_head = mi_atomic_load_acquire(&page->xthread_free);
  if (!mi_tf_is_owned(first_head) || mi_tf_block(first_head) != (mi_block_t*)fixture.first) goto cleanup;

  if (!fixture_advance(&fixture, 3) || !fixture_wait_for(&fixture, 4)) goto cleanup;
  const mi_thread_free_t published_head_atomic = mi_atomic_load_acquire(&page->xthread_free);
  if (!mi_tf_is_owned(published_head_atomic) || mi_tf_block(published_head_atomic) != (mi_block_t*)fixture.second) goto cleanup;

  if (!fixture_advance(&fixture, 5)) goto cleanup;
  if (pthread_join(worker, &worker_result) != 0) goto cleanup;
  worker_joined = true;
  if (worker_result != NULL) goto cleanup;

  // The worker can no longer retain or access the page.  The owning thread
  // may now inspect the frozen linked list and source ordinary fields.
  const mi_thread_free_t published_head = mi_atomic_load_acquire(&page->xthread_free);
  mi_block_t* const published_block = mi_tf_block(published_head);
  mi_block_t* const published_predecessor = (published_block == NULL ? NULL : mi_block_next(page, published_block));
  mi_block_t* const published_tail = (published_predecessor == NULL ? NULL : mi_block_next(page, published_predecessor));
  const size_t published_remote_count = bounded_list_count(page, published_block, producer_count + 1);
  const size_t used_before = page->used;
  const bool published_used_unchanged = (used_before == initial_used);
  const bool published_head_owned = mi_tf_is_owned(published_head);
  const bool published_head_is_latest = (published_block == (mi_block_t*)fixture.second);
  const bool published_latest_predecessor_is_first = (published_predecessor == (mi_block_t*)fixture.first);
  const bool published_nonempty = (published_block != NULL);
  const bool list_cycle_free = (published_tail == NULL);
  if (published_remote_count > used_before) goto cleanup;
  const size_t published_actual_live_count = used_before - published_remote_count;

  _mi_page_free_collect(page, false);

  const mi_thread_free_t collected_head = mi_atomic_load_acquire(&page->xthread_free);
  mi_block_t* const collected_local = page->local_free;
  mi_block_t* const collected_predecessor = (collected_local == NULL ? NULL : mi_block_next(page, collected_local));
  mi_block_t* const collected_tail = (collected_predecessor == NULL ? NULL : mi_block_next(page, collected_predecessor));
  const size_t collected_local_count = bounded_list_count(page, collected_local, producer_count + 1);
  const size_t collected_used = page->used;
  const size_t post_collect_remote_count = bounded_list_count(page, mi_tf_block(collected_head), producer_count + 1);
  const size_t collected_count = used_before - collected_used;
  const bool collected_head_owned = mi_tf_is_owned(collected_head);
  const bool collected_head_empty = (mi_tf_block(collected_head) == NULL);
  const bool collected_lifo = (collected_local == (mi_block_t*)fixture.second
      && collected_predecessor == (mi_block_t*)fixture.first && collected_tail == NULL);
  const bool all_valid = same_page && initial_live_owner_associated && initial_capacity_ge_used
      && initial_head_owned && initial_head_empty && initial_used == producer_count
      && published_used_unchanged && published_head_owned && published_head_is_latest
      && published_latest_predecessor_is_first && published_nonempty
      && published_remote_count == producer_count && published_actual_live_count == 0
      && list_cycle_free && collected_count == producer_count && collected_used == 0
      && post_collect_remote_count == 0 && collected_head_owned && collected_head_empty
      && collected_local_count == producer_count && collected_lifo;

  printf("CRABC_MI_LIVE_OWNER_REMOTE_FREE_TRACE_BEGIN\n");
  printf("trace.live_owner_remote.producer_count=%zu\n", producer_count);
  printf("trace.live_owner_remote.same_page=%u\n", (unsigned)same_page);
  printf("trace.live_owner_remote.initial_live_owner_associated=%u\n", (unsigned)initial_live_owner_associated);
  printf("trace.live_owner_remote.initial_used=%zu\n", initial_used);
  printf("trace.live_owner_remote.initial_capacity_ge_used=%u\n", (unsigned)initial_capacity_ge_used);
  printf("trace.live_owner_remote.initial_head_owned=%u\n", (unsigned)initial_head_owned);
  printf("trace.live_owner_remote.initial_head_empty=%u\n", (unsigned)initial_head_empty);
  printf("trace.live_owner_remote.initial_remote_count=0\n");
  printf("trace.live_owner_remote.published_used_unchanged=%u\n", (unsigned)published_used_unchanged);
  printf("trace.live_owner_remote.published_head_owned=%u\n", (unsigned)published_head_owned);
  printf("trace.live_owner_remote.published_head_is_latest=%u\n", (unsigned)published_head_is_latest);
  printf("trace.live_owner_remote.published_latest_predecessor_is_first=%u\n", (unsigned)published_latest_predecessor_is_first);
  printf("trace.live_owner_remote.published_nonempty=%u\n", (unsigned)published_nonempty);
  printf("trace.live_owner_remote.published_remote_count=%zu\n", published_remote_count);
  printf("trace.live_owner_remote.post_join_remote_count=%zu\n", published_remote_count);
  printf("trace.live_owner_remote.published_actual_live_count=%zu\n", published_actual_live_count);
  printf("trace.live_owner_remote.collected_count=%zu\n", collected_count);
  printf("trace.live_owner_remote.collected_used=%zu\n", collected_used);
  printf("trace.live_owner_remote.post_collect_remote_count=%zu\n", post_collect_remote_count);
  printf("trace.live_owner_remote.collected_head_owned=%u\n", (unsigned)collected_head_owned);
  printf("trace.live_owner_remote.collected_head_empty=%u\n", (unsigned)collected_head_empty);
  printf("trace.live_owner_remote.collected_local_count=%zu\n", collected_local_count);
  printf("trace.live_owner_remote.collected_lifo=%u\n", (unsigned)collected_lifo);
  printf("trace.live_owner_remote.list_cycle_free=%u\n", (unsigned)list_cycle_free);
  printf("trace.live_owner_remote.valid=%u\n", (unsigned)all_valid);
  printf("CRABC_MI_LIVE_OWNER_REMOTE_FREE_TRACE_END\n");
  valid = all_valid;

cleanup:
  if (worker_started && !worker_joined) {
    (void)fixture_advance(&fixture, 5);
    if (pthread_join(worker, &worker_result) == 0) worker_joined = true;
  }
  // A failed join leaves the worker's lifetime unknowable.  Do not destroy
  // its heap or synchronization state on that failure path; process exit
  // reclaims this failed one-shot probe instead.
  if (!worker_started || worker_joined) {
    if (heap != NULL) mi_heap_destroy(heap);
    if (pthread_cond_destroy(&fixture.condition) != 0) valid = false;
    if (pthread_mutex_destroy(&fixture.mutex) != 0) valid = false;
  }
  return (valid && worker_joined && worker_result == NULL ? 0 : 1);
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
    """Use the shared canonical native-provenance predicate."""

    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise EvidenceError("private remote-free source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    """Read and rigidly validate the checked-in native-only contract."""

    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 live-owner remote-free schema") from error
    if not isinstance(schema, dict):
        raise EvidenceError("x86-64 live-owner remote-free schema is not an object")
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
    if set(schema) != expected_fields:
        raise EvidenceError("x86-64 live-owner remote-free schema fields drifted")
    if (
        type(schema.get("format")) is not int
        or schema.get("format") != 1
        or schema.get("schema") != "crabc-mimalloc-x86_64-live-owner-remote-free-evidence"
    ):
        raise EvidenceError("unsupported x86-64 live-owner remote-free schema")
    if not exactly_matches(schema.get("target"), EXPECTED_TARGET):
        raise EvidenceError("live-owner remote-free schema target is not native Linux/x86_64")
    if not exactly_matches(schema.get("upstream"), EXPECTED_UPSTREAM):
        raise EvidenceError("live-owner remote-free schema upstream is not pinned mimalloc 3.5.0")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate the pinned remote-free upstream identity") from error
    if not exactly_matches(
        {
            "archive_root": pin["archive_root"],
            "revision": pin["revision"],
            "version": pin["version"],
        },
        EXPECTED_UPSTREAM,
    ) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("live-owner remote-free upstream pin drifted")
    if schema.get("profile") != EXPECTED_PROFILE:
        raise EvidenceError("live-owner remote-free schema profile drifted")
    if not exactly_matches(schema.get("scope"), EXPECTED_SCOPE):
        raise EvidenceError("live-owner remote-free schema private boundary drifted")
    if not exactly_matches(schema.get("release_source_set"), list(run.ORACLE_SOURCES)):
        raise EvidenceError("live-owner remote-free C source set differs from the pinned oracle")
    if not exactly_matches(schema.get("release_flags"), list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("live-owner remote-free C release flags drifted")
    if not exactly_matches(schema.get("compile_definitions"), list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("live-owner remote-free C compile definitions drifted")
    expected_rust_test = {
        "path": relative(RUST_TEST_SOURCE),
        "target_arch": "x86_64",
        "test_filter": RUST_TEST_FILTER,
    }
    if not exactly_matches(schema.get("rust_test"), expected_rust_test):
        raise EvidenceError("live-owner remote-free Rust test selection drifted")
    expected_trace = {
        "begin": TRACE_BEGIN,
        "end": TRACE_END,
        "expected_values": EXPECTED_TRACE_VALUES,
    }
    if not exactly_matches(schema.get("trace"), expected_trace):
        raise EvidenceError("live-owner remote-free fixed trace schema drifted")
    if schema.get("c_probe_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("live-owner remote-free C probe source hash drifted")

    anchors = schema.get("source_anchors")
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("live-owner remote-free source anchors drifted")
    observed_anchor_specs: list[tuple[str, int, int, str]] = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("live-owner remote-free source anchor has an invalid shape")
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
            raise EvidenceError("live-owner remote-free source anchor has invalid values")
        observed_anchor_specs.append((member, start_line, end_line, digest))
    if tuple(observed_anchor_specs) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("live-owner remote-free source anchor contract drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    """Tie every recorded C protocol claim to bytes in the extracted pin."""

    anchors = schema["source_anchors"]
    assert isinstance(anchors, list)
    validated: list[dict[str, Any]] = []
    for anchor in anchors:
        assert isinstance(anchor, dict)
        member = str(anchor["member"])
        path = source / member
        if not path.is_file():
            raise EvidenceError(f"pinned source lacks remote-free anchor member: {member}")
        observed = sha256_bytes(
            source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))
        )
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned remote-free source anchor drifted: {member}")
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(
            output,
            begin=TRACE_BEGIN,
            end=TRACE_END,
            description=description,
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    """Reject missing, extra, or altered logical protocol observations."""

    missing = sorted(set(EXPECTED_TRACE_VALUES).difference(trace))
    unexpected = sorted(set(trace).difference(EXPECTED_TRACE_VALUES))
    non_integer_values = sorted(
        key for key, value in trace.items() if type(value) is not int
    )
    mismatches = [
        f"{key} (expected {EXPECTED_TRACE_VALUES[key]}, observed {trace[key]})"
        for key in sorted(set(trace).intersection(EXPECTED_TRACE_VALUES))
        if type(trace[key]) is int and trace[key] != EXPECTED_TRACE_VALUES[key]
    ]
    if missing or unexpected or non_integer_values or mismatches:
        problems: list[str] = []
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if unexpected:
            problems.append("unexpected: " + ", ".join(unexpected))
        if non_integer_values:
            problems.append("non-integer values: " + ", ".join(non_integer_values))
        if mismatches:
            problems.append("value mismatches: " + ", ".join(mismatches))
        raise EvidenceError(f"{description} differs from the fixed live-owner trace: " + "; ".join(problems))


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    """Require both independently checked records to match each other."""

    validate_trace(c_trace, description="pinned C live-owner remote-free trace")
    validate_trace(rust_trace, description="Rust live-owner remote-free trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise EvidenceError("Rust live-owner remote-free trace differs from pinned C: " + ", ".join(mismatches))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def normalize_command(
    command: Sequence[str], temporary: Path, source: Path | None
) -> list[str]:
    """Keep reports stable without concealing the command's exact structure."""

    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    normalized: list[str] = []
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            normalized.append("<temporary-pinned-mimalloc-source>" + part[len(source_text) :])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append("<temporary-evidence-root>" + part[len(temporary_text) :])
        else:
            normalized.append(part)
    return normalized


def c_trace_command(
    compiler: str,
    source: Path,
    probe_source: Path,
    probe_binary: Path,
    schema: Mapping[str, Any],
) -> list[str]:
    """Build the fixture with the exact selected pinned release inputs."""

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
    """Ensure the C fixture did not silently select another profile."""

    expected_definitions = list(schema["compile_definitions"])
    observed_definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    if observed_definitions != expected_definitions or observed_definitions != list(EXPECTED_COMPILE_DEFINITIONS):
        raise EvidenceError("live-owner remote-free C command compile definitions drifted")
    expected_flags = list(schema["release_flags"])
    observed_flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if observed_flags != expected_flags:
        raise EvidenceError("live-owner remote-free C command release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("live-owner remote-free C command lacks the fixed pthread/TLS mode")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    """Require the report to retain the exact private C release invocation."""

    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("live-owner remote-free report C command is malformed")
    if Path(command[0]).name != "musl-gcc":
        raise EvidenceError("live-owner remote-free report C command compiler drifted")
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
        f"{NORMALIZED_EVIDENCE_ROOT}/live-owner-remote-free.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/live-owner-remote-free-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("live-owner remote-free report C command drifted")


def validate_normalized_rust_command(command: object) -> None:
    """Require the report to retain the one isolated, locked Rust selection."""

    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("live-owner remote-free report Rust command is malformed")
    if Path(command[0]).name != "cargo":
        raise EvidenceError("live-owner remote-free report Rust command compiler drifted")
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
        raise EvidenceError("live-owner remote-free report Rust command drifted")


def build_c_trace(
    compiler: str,
    readelf: str,
    source: Path,
    temporary: Path,
    schema: Mapping[str, Any],
) -> dict[str, Any]:
    """Build, identify, and run one fresh pinned C private protocol probe."""

    probe_source = temporary / "live-owner-remote-free.c"
    probe_binary = temporary / "live-owner-remote-free-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    build = run.command_record(command, cwd=source)
    try:
        run.require_success(build, "pinned C live-owner remote-free fixture build")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    header = run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
    try:
        run.require_success(header, "pinned C live-owner remote-free fixture ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    execution = run.command_record((str(probe_binary),), cwd=source)
    try:
        run.require_success(execution, "pinned C live-owner remote-free fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C live-owner remote-free trace")
    validate_trace(trace, description="pinned C live-owner remote-free trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": ["<temporary-evidence-root>/live-owner-remote-free-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def rust_trace_command(cargo: str, target_dir: Path) -> list[str]:
    """Run only the fixed crate-private Rust counterpart in isolation."""

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


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    """Run and parse the one matching Rust source-level protocol trace."""

    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    execution = run.command_record(command, cwd=ROOT, environment=environment)
    try:
        run.require_success(execution, "Rust live-owner remote-free fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust live-owner remote-free fixture passed {passed} tests, expected one")
    output = str(execution["stdout"]) + "\n" + str(execution["stderr"])
    trace = parse_trace(output, description="Rust live-owner remote-free trace")
    validate_trace(trace, description="Rust live-owner remote-free trace")
    return {
        "cargo_command": normalize_command(command, temporary, None),
        "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
        "passed_test_count": passed,
        "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)},
        "target_dir": {
            "isolated": True,
            "retained": False,
            "value": "<temporary-evidence-root>/rust-target",
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
    """Construct a deliberately narrow native C/Rust differential report."""

    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("live-owner remote-free report inputs lack trace records")
    comparison = compare_traces(c_trace, rust_trace)
    report: dict[str, Any] = {
        "c_probe": dict(c_probe),
        "comparison": comparison,
        "format": 1,
        "kind": "mimalloc-x86_64-live-owner-remote-free-differential-evidence",
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
    """Fail closed if a result tries to broaden or weaken this evidence lane."""

    required_fields = {
        "c_probe",
        "comparison",
        "format",
        "kind",
        "profile",
        "provenance",
        "rust_probe",
        "scope",
        "source",
        "status",
        "target",
        "trace",
        "upstream",
    }
    if not isinstance(report, dict) or set(report) != required_fields:
        raise EvidenceError("live-owner remote-free report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("live-owner remote-free report must record a passing format-1 result")
    if report["kind"] != "mimalloc-x86_64-live-owner-remote-free-differential-evidence":
        raise EvidenceError("live-owner remote-free report kind drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["target"], EXPECTED_TARGET):
        raise EvidenceError("live-owner remote-free report target/profile drifted")
    if not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(
        report["scope"], EXPECTED_SCOPE
    ):
        raise EvidenceError("live-owner remote-free report source or private boundary drifted")
    if not exactly_matches(
        report["trace"],
        {
            "begin": TRACE_BEGIN,
            "end": TRACE_END,
            "expected_values": EXPECTED_TRACE_VALUES,
        },
    ):
        raise EvidenceError("live-owner remote-free report trace contract drifted")
    if not any(
        exactly_matches(report["provenance"], candidate)
        for candidate in (
            {"execution_mode": "native", "host_architecture": "x86_64"},
            {"execution_mode": "native", "host_architecture": "amd64"},
        )
    ):
        raise EvidenceError("live-owner remote-free report lacks native x86-64 provenance")
    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {
        "archive_sha256",
        "anchors",
        "release_flags",
        "release_source_set",
    }:
        raise EvidenceError("live-owner remote-free report source record is malformed")
    try:
        archive_sha256 = run.load_pin()["sha256"]
    except run.HarnessError as error:
        raise EvidenceError("cannot validate the pinned remote-free archive identity") from error
    if source.get("archive_sha256") != archive_sha256:
        raise EvidenceError("live-owner remote-free report archive identity drifted")
    if not exactly_matches(source.get("anchors"), schema["source_anchors"]):
        raise EvidenceError("live-owner remote-free report source anchors drifted")
    if not exactly_matches(source.get("release_flags"), schema["release_flags"]):
        raise EvidenceError("live-owner remote-free report release flags drifted")
    if not exactly_matches(source.get("release_source_set"), schema["release_source_set"]):
        raise EvidenceError("live-owner remote-free report source set drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or not isinstance(rust_probe, dict):
        raise EvidenceError("live-owner remote-free report probe records are malformed")
    if set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("live-owner remote-free report C probe record drifted")
    if not exactly_matches(c_probe.get("elf"), EXPECTED_C_ELF):
        raise EvidenceError("live-owner remote-free report C ELF identity drifted")
    if not exactly_matches(
        c_probe.get("run_command"),
        [f"{NORMALIZED_EVIDENCE_ROOT}/live-owner-remote-free-c"],
    ):
        raise EvidenceError("live-owner remote-free report C run command drifted")
    if c_probe.get("source_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("live-owner remote-free report C source hash drifted")
    validate_normalized_c_command(c_probe.get("build_command"), schema)
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("live-owner remote-free report lacks C/Rust trace records")
    comparison = compare_traces(c_trace, rust_trace)
    if not exactly_matches(report["comparison"], comparison):
        raise EvidenceError("live-owner remote-free report comparison drifted")
    if type(rust_probe.get("passed_test_count")) is not int or rust_probe.get("passed_test_count") != 1:
        raise EvidenceError("live-owner remote-free report Rust selection did not pass exactly one test")
    if set(rust_probe) != {
        "cargo_command",
        "lockfile",
        "passed_test_count",
        "source",
        "target_dir",
        "trace",
    }:
        raise EvidenceError("live-owner remote-free report Rust probe record drifted")
    target_dir = rust_probe.get("target_dir")
    if not exactly_matches(
        target_dir,
        {
            "isolated": True,
            "retained": False,
            "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        },
    ):
        raise EvidenceError("live-owner remote-free report Rust target directory drifted")
    cargo_command = rust_probe.get("cargo_command")
    validate_normalized_rust_command(cargo_command)
    if not exactly_matches(
        rust_probe.get("lockfile"),
        {
            "path": relative(LOCKFILE),
            "sha256": sha256_file(LOCKFILE),
        },
    ):
        raise EvidenceError("live-owner remote-free report Rust lockfile identity drifted")
    if not exactly_matches(
        rust_probe.get("source"),
        {
            "path": relative(RUST_TEST_SOURCE),
            "sha256": sha256_file(RUST_TEST_SOURCE),
        },
    ):
        raise EvidenceError("live-owner remote-free report Rust source identity drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    """Execute the fixed native C/Rust protocol differential once."""

    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    pin = run.load_pin()
    try:
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error

    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-live-owner-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
            compiler = run.require_tool("musl-gcc")
            readelf = run.require_tool("readelf")
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source)
        c_probe = build_c_trace(compiler, readelf, source, temporary, schema)
        rust_probe = build_rust_trace(run.require_tool("cargo"), temporary)
        report = report_from_results(
            schema=schema,
            provenance=provenance,
            archive_sha256=sha256_file(archive),
            anchors=anchors,
            c_probe=c_probe,
            rust_probe=rust_probe,
        )

    after_lockfile = sha256_file(LOCKFILE)
    if after_lockfile != before_lockfile:
        raise EvidenceError("Cargo.lock changed despite the required --locked Rust trace command")
    report_path.parent.mkdir(parents=True, exist_ok=True)
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
        print(f"allocator x86-64 live-owner remote-free differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    comparison = report["comparison"]
    print(
        "allocator x86-64 live-owner remote-free differential: PASS "
        f"({comparison['compared_value_count']} logical values; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
