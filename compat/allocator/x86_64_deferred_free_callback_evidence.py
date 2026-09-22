#!/usr/bin/env python3
"""Differential evidence for pinned mimalloc deferred-free callback timing.

This private native Linux/x86-64 fixture executes fixed v3.5.0 C code, not a
model: the C side registers one context, runs `_mi_malloc_generic` through its
1,000/10,000 administrative boundaries, and then exhausts a bounded arena so
`mi_malloc_generic_fallback` performs its single forced retry. The callback
makes a legal nested allocation and invokes `_mi_deferred_free` while its TLD
recursion marker is live. The Rust side drives the same selected phase through
the persistent owner cell; its callback re-enters through `with_owner`, so no
outer engine/TLD borrow survives user code.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-deferred-free-callback-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/deferred-free-callback.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/runtime_lifecycle.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "runtime_lifecycle::tests::native_deferred_free_callback_trace_matches_pinned_generic_timing"
TRACE_BEGIN = "CRABC_MI_DEFERRED_FREE_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DEFERRED_FREE_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded deferred-free C/Rust differential failed."""


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
EXPECTED_PROFILE = "linux-x86_64-private-deferred-free-callback"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "registration_remains_crate_private": True,
    "single_callback_context_and_one_same_thread_owner_only": True,
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
    ("src/page.c", 987, 1117, "edc368582efb777195f6a0e47eab72c47bdfaf0394d378c2854c1b231e62d6e0"),
    ("src/theap.c", 89, 155, "c04f23536687d633723539e9ea53296c2c0e39db4cafb3e20ef491c41ccc5807"),
    ("src/static.c", 19, 44, "2a0ce462658c70ce646ba04347dd89cb2d868c84a7ae4173b7f4edf86efca6d2"),
)
EXPECTED_TRACE_VALUES = {
    "trace.deferred_free.context_matches": 1,
    "trace.deferred_free.nested_allocation_completed": 1,
    "trace.deferred_free.nested_reentry_suppressed": 1,
    "trace.deferred_free.first_heartbeat": 1,
    "trace.deferred_free.nested_heartbeat": 2,
    "trace.deferred_free.mini_callbacks": 9,
    "trace.deferred_free.full_callbacks": 1,
    "trace.deferred_free.full_heartbeat": 11,
    "trace.deferred_free.force_callbacks": 1,
    "trace.deferred_free.force_heartbeat_advanced": 1,
    "trace.deferred_free.callback_count": 11,
}

# The fixed upstream amalgamation gives this probe the source's complete
# release closure in one translation unit. It has no alternate allocator,
# stubbed OOM path, or host-runtime allocator fallback.
C_TRACE_PROBE = r'''
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "static.c"

#if !defined(__linux__) || !defined(__x86_64__)
#error this deferred-free fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0
#error this fixture requires the native x86-64 two-level PageMap branch
#endif

typedef struct trace_s {
  mi_theap_t* theap;
  size_t callback_count;
  size_t context_matches;
  size_t nested_allocation_completed;
  size_t nested_reentry_suppressed;
  size_t first_heartbeat;
  size_t nested_heartbeat;
  size_t mini_callbacks;
  size_t full_callbacks;
  size_t full_heartbeat;
  size_t force_callbacks;
  size_t force_heartbeat_advanced;
} trace_t;

static void deferred_callback(bool force, unsigned long long heartbeat, void* argument) {
  trace_t* const trace = (trace_t*)argument;
  const size_t index = trace->callback_count++;
  trace->context_matches = trace->context_matches && (argument == trace);
  if (index == 0) {
    trace->first_heartbeat = (size_t)heartbeat;
    // A direct-small anchor is kept live by `main`, so this is a normal
    // nested allocation on the current source Theap, not another generic
    // administration entry that could change 1k/10k timing.
    void* const nested = mi_malloc(16);
    if (nested != NULL) {
      mi_free(nested);
      trace->nested_allocation_completed = 1;
    }
    _mi_deferred_free(trace->theap, false);
    trace->nested_heartbeat = (size_t)trace->theap->heartbeat;
    trace->nested_reentry_suppressed = (trace->callback_count == 1
      && trace->nested_heartbeat == (size_t)heartbeat + 1);
  }
  if (!force && index < 9) {
    trace->mini_callbacks++;
  }
  if (!force && index == 9) {
    trace->full_callbacks++;
    trace->full_heartbeat = (size_t)heartbeat;
  }
  if (force) {
    trace->force_callbacks++;
    // The forced retry uses the arena heap's distinct Theap, whose source
    // heartbeat starts at zero. Record its one-step local advance instead of
    // comparing raw counters from two unrelated Theaps.
    trace->force_heartbeat_advanced = ((size_t)heartbeat == 1);
  }
}

static void* remote_free(void* block) {
  mi_free(block);
  return NULL;
}

int main(void) {
  trace_t trace = {0};
  void* anchor = NULL;
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_arena_t* arena = NULL;
  void* remote = NULL;
  void* replacement = NULL;
  mi_memid_t claims[1024];
  size_t claim_count = 0;
  pthread_t thread;
  bool started = false;
  bool valid = false;
  int stage = 0;

  stage = 1;
  mi_thread_init();
  anchor = mi_malloc(16);
  if (anchor == NULL) goto cleanup;
  trace.theap = _mi_theap_default();
  if (trace.theap == NULL || !mi_theap_is_initialized(trace.theap)) goto cleanup;
  // The anchor may use the generic fallback only while creating its first
  // direct-small page. Start the measured generic sequence at the exact
  // source counter image used after a successful administration pass.
  trace.theap->generic_count = 0;
  trace.theap->generic_collect_count = 0;
  trace.context_matches = 1;
  mi_register_deferred_free(&deferred_callback, &trace);

  stage = 2;
  for (size_t allocation = 1; allocation <= 10000; allocation++) {
    void* const block = _mi_malloc_generic(trace.theap, 2048, 0, NULL);
    if (block == NULL) goto cleanup;
    mi_free(block);
  }
  if (trace.callback_count != 10 || trace.mini_callbacks != 9
      || trace.full_callbacks != 1 || trace.full_heartbeat != 11
      || trace.force_callbacks != 0 || trace.theap->heartbeat != 11) goto cleanup;

  // This is the unchanged pinned `mi_malloc_generic_fallback` OOM retry:
  // fill one real arena, publish a remote free in another bin, and request a
  // replacement. The first page lookup fails, source force-collects (and
  // therefore calls the registered deferred callback with `force == true`),
  // then retries exactly once.
  stage = 3;
  if (mi_reserve_os_memory_ex(32 * 1024 * 1024, true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto cleanup;
  stage = 4;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto cleanup;
  stage = 5;
  remote = mi_heap_malloc(heap, 32);
  if (remote == NULL) goto cleanup;
  mi_page_t* const page = _mi_ptr_page(remote);
  arena = page->memid.mem.arena.arena;
  if (arena == NULL) goto cleanup;
  stage = 6;
  while (claim_count < 1024
      && mi_arena_try_alloc_at(arena, 1, true, 0, &claims[claim_count]) != NULL) {
    claim_count++;
  }
  if (claim_count == 0 || claim_count == 1024) goto cleanup;
  stage = 7;
  if (pthread_create(&thread, NULL, remote_free, remote) != 0) goto cleanup;
  started = true;
  if (pthread_join(thread, NULL) != 0) goto cleanup;
  started = false;
  remote = NULL;
  stage = 8;
  replacement = mi_heap_malloc(heap, 64);
  if (replacement == NULL) goto cleanup;

  stage = 9;
  valid = trace.context_matches == 1
    && trace.nested_allocation_completed == 1
    && trace.nested_reentry_suppressed == 1
    && trace.first_heartbeat == 1
    && trace.nested_heartbeat == 2
    && trace.mini_callbacks == 9
    && trace.full_callbacks == 1
    && trace.full_heartbeat == 11
    && trace.force_callbacks == 1
    && trace.force_heartbeat_advanced == 1
    && trace.callback_count == 11;
cleanup:
  mi_register_deferred_free(NULL, NULL);
  if (started) pthread_join(thread, NULL);
  if (remote != NULL) mi_free(remote);
  if (replacement != NULL) mi_free(replacement);
  if (arena != NULL) {
    for (size_t index = 0; index < claim_count; index++) {
      (void)mi_bbitmap_setN(arena->slices_free, claims[index].mem.arena.slice_index, 1);
    }
  }
  if (heap != NULL) mi_heap_delete(heap);
  if (anchor != NULL) mi_free(anchor);
  if (!valid) {
    fprintf(stderr,
            "deferred-free callback C fixture failed at stage %d: callbacks=%zu mini=%zu full=%zu force=%zu heartbeat=%zu claims=%zu replacement=%d\n",
            stage, trace.callback_count, trace.mini_callbacks, trace.full_callbacks,
            trace.force_callbacks, (size_t)(trace.theap == NULL ? 0 : trace.theap->heartbeat),
            claim_count, replacement != NULL);
    return 2;
  }
  printf("CRABC_MI_DEFERRED_FREE_TRACE_BEGIN\n");
  printf("trace.deferred_free.context_matches=%zu\n", trace.context_matches);
  printf("trace.deferred_free.nested_allocation_completed=%zu\n", trace.nested_allocation_completed);
  printf("trace.deferred_free.nested_reentry_suppressed=%zu\n", trace.nested_reentry_suppressed);
  printf("trace.deferred_free.first_heartbeat=%zu\n", trace.first_heartbeat);
  printf("trace.deferred_free.nested_heartbeat=%zu\n", trace.nested_heartbeat);
  printf("trace.deferred_free.mini_callbacks=%zu\n", trace.mini_callbacks);
  printf("trace.deferred_free.full_callbacks=%zu\n", trace.full_callbacks);
  printf("trace.deferred_free.full_heartbeat=%zu\n", trace.full_heartbeat);
  printf("trace.deferred_free.force_callbacks=%zu\n", trace.force_callbacks);
  printf("trace.deferred_free.force_heartbeat_advanced=%zu\n", trace.force_heartbeat_advanced);
  printf("trace.deferred_free.callback_count=%zu\n", trace.callback_count);
  printf("CRABC_MI_DEFERRED_FREE_TRACE_END\n");
  return 0;
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
        return set(observed) == set(expected) and all(exactly_matches(observed[key], expected[key]) for key in expected)
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(exactly_matches(left, right) for left, right in zip(observed, expected))
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


def source_anchor_template() -> list[dict[str, object]]:
    return [
        {"member": member, "start_line": start, "end_line": end, "sha256": digest}
        for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
    ]


def schema_template() -> dict[str, Any]:
    return {
        "format": 1,
        "schema": "crabc-mimalloc-x86_64-deferred-free-callback-evidence",
        "profile": EXPECTED_PROFILE,
        "target": EXPECTED_TARGET,
        "upstream": EXPECTED_UPSTREAM,
        "scope": EXPECTED_SCOPE,
        "compile_definitions": list(EXPECTED_COMPILE_DEFINITIONS),
        "release_flags": list(run.CONFIGURATION_PROFILES["release"]),
        "release_source_set": ["src/static.c"],
        "source_anchors": source_anchor_template(),
        "rust_test": {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER},
        "c_probe_sha256": sha256_bytes(C_TRACE_PROBE.encode()),
        "trace": {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES},
    }


def load_schema(path: Path | None = None) -> dict[str, Any]:
    try:
        schema = json.loads((SCHEMA_PATH if path is None else path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read deferred-free callback evidence schema") from error
    if not exactly_matches(schema, schema_template()):
        raise EvidenceError("deferred-free callback checked-in schema drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate pinned deferred-free upstream identity") from error
    if {key: pin[key] for key in ("archive_root", "revision", "version")} != EXPECTED_UPSTREAM or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("deferred-free callback upstream archive pin drifted")
    return schema


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    anchors = []
    for anchor in schema["source_anchors"]:
        member = str(anchor["member"])
        actual = sha256_bytes(source_range((source / member).read_bytes(), int(anchor["start_line"]), int(anchor["end_line"])))
        if actual != anchor["sha256"]:
            raise EvidenceError(f"pinned deferred-free source anchor drifted: {member}")
        anchors.append(dict(anchor))
    return anchors


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(output, begin=TRACE_BEGIN, end=TRACE_END, description=description)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    wrong = [key for key, expected in EXPECTED_TRACE_VALUES.items() if type(trace.get(key)) is not int or trace[key] != expected]
    if missing or unexpected or wrong:
        raise EvidenceError(f"{description} violates the fixed deferred-free callback trace")


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    result = []
    temporary_text, source_text = str(temporary), str(source) if source is not None else None
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            result.append(NORMALIZED_PINNED_SOURCE + part[len(source_text):])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            result.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text):])
        else:
            result.append(part)
    return result


def c_trace_command(compiler: str, source: Path, probe: Path, binary: Path, schema: Mapping[str, Any]) -> list[str]:
    return [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"), *schema["release_flags"], str(probe), "-pthread", "-o", str(binary)]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    if [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS] != list(schema["compile_definitions"]):
        raise EvidenceError("C compile definitions drifted")
    if [part for part in command if part in run.CONFIGURATION_PROFILES["release"]] != list(schema["release_flags"]):
        raise EvidenceError("C release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("C command lacks pthread/TLS requirements")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    expected = ["-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src", *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/deferred-free-callback.c", "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/deferred-free-callback-c"]
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise EvidenceError("normalized C command drifted")


def rust_trace_command(cargo: str, target_dir: Path) -> list[str]:
    return [cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir), "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]


def validate_normalized_rust_command(command: object) -> None:
    expected = ["test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target", "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]
    if not isinstance(command, list) or not command or Path(command[0]).name != "cargo" or command[1:] != expected:
        raise EvidenceError("normalized Rust command drifted")


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    probe, binary = temporary / "deferred-free-callback.c", temporary / "deferred-free-callback-c"
    probe.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe, binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "deferred-free C build")
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "deferred-free C ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source)
        run.require_success(execution, "deferred-free C execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C deferred-free trace")
    validate_trace(trace, description="pinned C deferred-free trace")
    return {"build_command": normalize_command(command, temporary, source), "elf": elf, "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/deferred-free-callback-c"], "source_sha256": sha256_bytes(C_TRACE_PROBE.encode()), "trace": trace}


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    command = rust_trace_command(cargo, temporary / "rust-target")
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, env=environment)
        run.require_success(execution, "Rust deferred-free callback fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust deferred-free callback fixture passed {passed} tests")
    trace = parse_trace(str(execution["stdout"]) + "\n" + str(execution["stderr"]), description="Rust deferred-free trace")
    validate_trace(trace, description="Rust deferred-free trace")
    return {"cargo_command": normalize_command(command, temporary, None), "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}, "passed_test_count": passed, "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}, "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}, "trace": trace}


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="C deferred-free trace")
    validate_trace(rust_trace, description="Rust deferred-free trace")
    mismatch = [key for key in EXPECTED_TRACE_VALUES if c_trace[key] != rust_trace[key]]
    if mismatch:
        raise EvidenceError("C/Rust deferred-free trace mismatch: " + ", ".join(mismatch))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def report_from_results(schema: Mapping[str, Any], provenance: Mapping[str, str], archive_sha256: str, anchors: Sequence[Mapping[str, Any]], c_probe: Mapping[str, Any], rust_probe: Mapping[str, Any]) -> dict[str, Any]:
    return {"c_probe": dict(c_probe), "comparison": compare_traces(c_probe["trace"], rust_probe["trace"]), "format": 1, "kind": "mimalloc-x86_64-deferred-free-callback-differential-evidence", "profile": schema["profile"], "provenance": dict(provenance), "rust_probe": dict(rust_probe), "scope": schema["scope"], "source": {"archive_sha256": archive_sha256, "anchors": [dict(anchor) for anchor in anchors], "release_flags": list(schema["release_flags"]), "release_source_set": list(schema["release_source_set"])}, "status": "passed", "target": schema["target"], "trace": schema["trace"], "upstream": schema["upstream"]}


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("deferred-free report shape/status drifted")
    if report["kind"] != "mimalloc-x86_64-deferred-free-callback-differential-evidence" or report["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("deferred-free report identity drifted")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("deferred-free report boundary drifted")
    if report["provenance"] not in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"}):
        raise EvidenceError("deferred-free report lacks native provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("deferred-free report trace drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"} or source["archive_sha256"] != run.load_pin()["sha256"] or not exactly_matches(source["anchors"], schema["source_anchors"]) or not exactly_matches(source["release_flags"], schema["release_flags"]) or not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("deferred-free source drifted")
    c_probe, rust_probe = report["c_probe"], report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"} or not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("deferred-free probe shape drifted")
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF) or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/deferred-free-callback-c"] or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode()):
        raise EvidenceError("deferred-free C identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if rust_probe["passed_test_count"] != 1 or not exactly_matches(rust_probe["target_dir"], {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}):
        raise EvidenceError("deferred-free Rust test selection drifted")
    if not exactly_matches(rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}) or not exactly_matches(rust_probe["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}):
        raise EvidenceError("deferred-free Rust provenance drifted")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])):
        raise EvidenceError("deferred-free comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lock = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with run.temporary_directory("crabc-mimalloc-x86_64-deferred-free-") as name:
        temporary = Path(name)
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
    if sha256_file(LOCKFILE) != before_lock:
        raise EvidenceError("Cargo.lock changed")
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
        print(f"allocator x86-64 deferred-free callback differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(f"allocator x86-64 deferred-free callback differential: PASS ({report['comparison']['compared_value_count']} logical values; report: {relative(arguments.report)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
