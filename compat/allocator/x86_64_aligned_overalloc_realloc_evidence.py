#!/usr/bin/env python3
"""Differentially prove one private x86-64 aligned over-allocation/realloc path.

The fixture deliberately uses one ordinary arena-backed request (33 bytes,
64-byte alignment, offset 7).  It observes only pinned mimalloc internals and
address-independent facts: normalized alignment, interior-base recovery,
adjusted usable size, the aligned ceil-half reuse boundary, replacement copy,
zeroed growth, and terminal arena-page release.  This is private native
Linux/x86-64 engine evidence; it is not public x86 support or AArch64 evidence.
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-aligned-overalloc-realloc-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/aligned-overalloc-realloc.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/single_thread.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "single_thread::tests::x86_64_aligned_overalloc_realloc_trace_matches_pinned_c_protocol"
TRACE_BEGIN = "CRABC_MI_ALIGNED_OVERALLOC_REALLOC_TRACE_BEGIN"
TRACE_END = "CRABC_MI_ALIGNED_OVERALLOC_REALLOC_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded aligned over-allocation differential failed."""


EXPECTED_TARGET = {"architecture": "x86_64", "endianness": "little", "rust_target": TARGET, "system": "linux"}
EXPECTED_UPSTREAM = {"archive_root": "mimalloc-3.5.0", "revision": "18b08671c9302247bfb682286e6bf3cc1773f801", "version": "3.5.0"}
EXPECTED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
EXPECTED_PROFILE = "linux-x86_64-private-aligned-overalloc-realloc"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "native_linux_x86_64_required": True,
    "ordinary_arena_backed_offset_aligned_request_only": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "terminal_arena_release_only": True,
}
EXPECTED_COMPILE_DEFINITIONS = ("-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1")
EXPECTED_C_ELF = {"class": "ELF64", "endianness": "little", "machine": "Advanced Micro Devices X86-64"}

# Values are fixed by the C probe below and are intentionally address-free.
EXPECTED_TRACE_VALUES = {
    "trace.aligned_overalloc.request": 33,
    "trace.aligned_overalloc.alignment": 64,
    "trace.aligned_overalloc.offset": 7,
    "trace.aligned_overalloc.arena_backed": 1,
    "trace.aligned_overalloc.interior_pointer": 1,
    "trace.aligned_overalloc.normalized_alignment": 1,
    "trace.aligned_overalloc.base_recovered": 1,
    "trace.aligned_overalloc.adjust": 57,
    "trace.aligned_overalloc.block_size": 96,
    "trace.aligned_overalloc.usable": 39,
    "trace.aligned_overalloc.ceil_half": 20,
    "trace.aligned_overalloc.reuse_same_pointer": 1,
    "trace.aligned_overalloc.reuse_alignment": 1,
    "trace.aligned_overalloc.replacement_request": 19,
    "trace.aligned_overalloc.replacement_distinct": 1,
    "trace.aligned_overalloc.replacement_alignment": 1,
    "trace.aligned_overalloc.replacement_preserved": 1,
    "trace.aligned_overalloc.replacement_usable": 71,
    "trace.aligned_overalloc.growth_request": 88,
    "trace.aligned_overalloc.growth_distinct": 1,
    "trace.aligned_overalloc.growth_alignment": 1,
    "trace.aligned_overalloc.growth_preserved": 1,
    "trace.aligned_overalloc.growth_zero_tail": 1,
    "trace.aligned_overalloc.growth_usable": 103,
    "trace.aligned_overalloc.final_map_clear": 1,
    "trace.aligned_overalloc.final_span_map_clear": 1,
    "trace.aligned_overalloc.final_arena_page_clear": 1,
    "trace.aligned_overalloc.final_slices_free": 1,
    "trace.aligned_overalloc.valid": 1,
}

C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private aligned-overalloc fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native x86-64 two-level unencoded release path
#endif

static bool bytes_equal(const uint8_t* bytes, size_t size, uint8_t value) {
  for (size_t i = 0; i < size; i++) if (bytes[i] != value) return false;
  return true;
}

int main(void) {
  const size_t request = 33, alignment = 64, offset = 7;
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_page_t* page = NULL;
  mi_arena_t* arena = NULL;
  mi_arena_pages_t* arena_pages = NULL;
  void* current = NULL;
  void* replacement = NULL;
  void* grown = NULL;
  uintptr_t final_address = 0;
  mi_block_t* base = NULL;
  size_t slice_index = 0, slice_count = 0;
  size_t initial_usable = 0, replacement_usable = 0, growth_usable = 0;
  size_t adjust = 0, block_size = 0;
  size_t ceil_half = 0, replacement_request = 0, growth_request = 0;
  int arena_backed = 0, interior_marked = 0, normalized_alignment = 0;
  int base_recovered = 0, reuse_same = 0, reuse_alignment = 0;
  int replacement_distinct = 0, replacement_alignment = 0, replacement_preserved = 0;
  int growth_distinct = 0, growth_alignment = 0, growth_preserved = 0, growth_zero_tail = 0;
  int final_map_clear = 0, final_span_map_clear = 0, final_arena_page_clear = 0;
  int final_slices_free = 0, valid = 0;

  mi_thread_init();
  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) goto output;
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto output;

  current = mi_heap_malloc_aligned_at(heap, request, alignment, offset);
  if (current == NULL) goto output;
  page = _mi_ptr_page(current);
  if (page == NULL || page->memid.memkind != MI_MEM_ARENA) goto output;
  arena_backed = (page->memid.memkind == MI_MEM_ARENA);
  arena = mi_memid_arena(page->memid);
  slice_index = page->memid.mem.arena.slice_index;
  slice_count = page->memid.mem.arena.slice_count;
  arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
  base = _mi_page_ptr_unalign(page, current);
  block_size = page->block_size;
  initial_usable = _mi_page_usable_size(page, current);
  adjust = (size_t)((uintptr_t)current - (uintptr_t)base);
  interior_marked = mi_page_has_interior_pointers(page);
  normalized_alignment = ((((uintptr_t)current + offset) & (alignment - 1)) == 0);
  base_recovered = (base != NULL && (void*)base != current
      && _mi_page_ptr_unalign(page, current) == base
      && initial_usable + adjust == _mi_page_usable_size(page, base));
  if (!arena || !arena_pages || slice_count == 0 || !interior_marked || !normalized_alignment
      || !base_recovered || initial_usable < request) goto output;

  memset(current, 0x96, initial_usable);
  ceil_half = initial_usable - initial_usable / 2;
  replacement_request = ceil_half - 1;
  replacement = mi_heap_realloc_aligned_at(heap, current, ceil_half, alignment, offset);
  if (replacement == NULL || replacement != current) goto output;
  reuse_same = (replacement == current);
  reuse_alignment = ((((uintptr_t)replacement + offset) & (alignment - 1)) == 0);

  replacement = mi_heap_realloc_aligned_at(heap, replacement, replacement_request, alignment, offset);
  if (replacement == NULL) goto output;
  replacement_distinct = (replacement != current);
  replacement_alignment = ((((uintptr_t)replacement + offset) & (alignment - 1)) == 0);
  replacement_preserved = bytes_equal((const uint8_t*)replacement, replacement_request, 0x96);
  replacement_usable = _mi_page_usable_size(_mi_ptr_page(replacement), replacement);
  if (!replacement_distinct || !replacement_alignment || !replacement_preserved) goto output;

  memset(replacement, 0x47, replacement_usable);
  growth_request = replacement_usable + 17;
  grown = mi_heap_rezalloc_aligned_at(heap, replacement, growth_request, alignment, offset);
  if (grown == NULL) goto output;
  growth_distinct = (grown != replacement);
  growth_alignment = ((((uintptr_t)grown + offset) & (alignment - 1)) == 0);
  growth_usable = _mi_page_usable_size(_mi_ptr_page(grown), grown);
  growth_preserved = bytes_equal((const uint8_t*)grown, replacement_usable, 0x47);
  growth_zero_tail = bytes_equal((const uint8_t*)grown + replacement_usable,
                                 growth_usable - replacement_usable, 0);
  if (!growth_distinct || !growth_alignment || !growth_preserved || !growth_zero_tail) goto output;

  final_address = (uintptr_t)grown;
  mi_free(grown);
  grown = NULL;
  mi_heap_collect(heap, true);
  final_map_clear = (_mi_safe_ptr_page((const void*)final_address) == NULL);
  final_span_map_clear = true;
  for (size_t i = 0; i < slice_count; i++) {
    const uint8_t* start = (const uint8_t*)arena->start + (slice_index + i) * MI_ARENA_SLICE_SIZE;
    if (_mi_safe_ptr_page(start) != NULL) final_span_map_clear = false;
  }
  final_arena_page_clear = mi_bitmap_is_clearN(arena_pages->pages, slice_index, slice_count);
  final_slices_free = mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count);
  current = NULL;
  replacement = NULL;
  valid = request == 33 && alignment == 64 && offset == 7 && arena_backed && interior_marked
      && normalized_alignment && base_recovered && adjust == 57 && block_size == 96
      && initial_usable == 39 && ceil_half == 20 && reuse_same && reuse_alignment
      && replacement_request == 19 && replacement_distinct && replacement_alignment
      && replacement_preserved && replacement_usable == 71 && growth_request == 88
      && growth_distinct && growth_alignment && growth_preserved && growth_zero_tail
      && growth_usable == 103 && final_map_clear && final_span_map_clear
      && final_arena_page_clear && final_slices_free;

output:
  printf("%s\n", "CRABC_MI_ALIGNED_OVERALLOC_REALLOC_TRACE_BEGIN");
  printf("trace.aligned_overalloc.request=%zu\n", request);
  printf("trace.aligned_overalloc.alignment=%zu\n", alignment);
  printf("trace.aligned_overalloc.offset=%zu\n", offset);
  printf("trace.aligned_overalloc.arena_backed=%d\n", arena_backed);
  printf("trace.aligned_overalloc.interior_pointer=%d\n", interior_marked);
  printf("trace.aligned_overalloc.normalized_alignment=%d\n", normalized_alignment);
  printf("trace.aligned_overalloc.base_recovered=%d\n", base_recovered);
  printf("trace.aligned_overalloc.adjust=%zu\n", adjust);
  printf("trace.aligned_overalloc.block_size=%zu\n", block_size);
  printf("trace.aligned_overalloc.usable=%zu\n", initial_usable);
  printf("trace.aligned_overalloc.ceil_half=%zu\n", ceil_half);
  printf("trace.aligned_overalloc.reuse_same_pointer=%d\n", reuse_same);
  printf("trace.aligned_overalloc.reuse_alignment=%d\n", reuse_alignment);
  printf("trace.aligned_overalloc.replacement_request=%zu\n", replacement_request);
  printf("trace.aligned_overalloc.replacement_distinct=%d\n", replacement_distinct);
  printf("trace.aligned_overalloc.replacement_alignment=%d\n", replacement_alignment);
  printf("trace.aligned_overalloc.replacement_preserved=%d\n", replacement_preserved);
  printf("trace.aligned_overalloc.replacement_usable=%zu\n", replacement_usable);
  printf("trace.aligned_overalloc.growth_request=%zu\n", growth_request);
  printf("trace.aligned_overalloc.growth_distinct=%d\n", growth_distinct);
  printf("trace.aligned_overalloc.growth_alignment=%d\n", growth_alignment);
  printf("trace.aligned_overalloc.growth_preserved=%d\n", growth_preserved);
  printf("trace.aligned_overalloc.growth_zero_tail=%d\n", growth_zero_tail);
  printf("trace.aligned_overalloc.growth_usable=%zu\n", growth_usable);
  printf("trace.aligned_overalloc.final_map_clear=%d\n", final_map_clear);
  printf("trace.aligned_overalloc.final_span_map_clear=%d\n", final_span_map_clear);
  printf("trace.aligned_overalloc.final_arena_page_clear=%d\n", final_arena_page_clear);
  printf("trace.aligned_overalloc.final_slices_free=%d\n", final_slices_free);
  printf("trace.aligned_overalloc.valid=%d\n", valid);
  printf("%s\n", "CRABC_MI_ALIGNED_OVERALLOC_REALLOC_TRACE_END");
  if (grown != NULL) mi_free(grown);
  else if (replacement != NULL && replacement != current) mi_free(replacement);
  else if (current != NULL) mi_free(current);
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
        return set(observed) == set(expected) and all(exactly_matches(observed[k], expected[k]) for k in expected)  # type: ignore[index]
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(exactly_matches(a, b) for a, b in zip(observed, expected))  # type: ignore[arg-type]
    return observed == expected


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise EvidenceError("aligned-overalloc source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1:end_line])


def _schema_template() -> dict[str, Any]:
    return {
        "format": 1,
        "schema": "crabc-mimalloc-x86_64-aligned-overalloc-realloc-evidence",
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
        "c_probe_sha256": sha256_bytes(C_TRACE_PROBE.encode()),
        "rust_test": {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER},
        "trace": {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": dict(EXPECTED_TRACE_VALUES)},
    }


def load_schema(path: Path | None = None) -> dict[str, Any]:
    try:
        schema = json.loads((SCHEMA_PATH if path is None else path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 aligned-overalloc evidence schema") from error
    if not exactly_matches(schema, _schema_template()):
        raise EvidenceError("aligned-overalloc checked-in schema drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate pinned aligned-overalloc upstream identity") from error
    if {k: pin[k] for k in ("archive_root", "revision", "version")} != EXPECTED_UPSTREAM or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("aligned-overalloc upstream archive pin drifted")
    return schema


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


EXPECTED_SOURCE_ANCHORS = (
    ("src/alloc-aligned.c", 68, 155, "43aabca0f0646e6e138d2b53266fc8d15d021c2f08ba4ffd9f565edfcc9506ae"),
    ("src/alloc-aligned.c", 347, 377, "74971303dc503fb0efb27e67c05b36b4d7c422f6b647bcac8406792350b59ebe"),
    ("src/free.c", 372, 514, "eaf65f9f62222c15c4dce40efd742faea833d79c0b6f97180f4ae098958aae59"),
    ("src/arena.c", 1183, 1204, "09e82c9f0473e73a9fad065943d41fdab4b85faf570274bddbac77aee3b6860a"),
    ("include/mimalloc/internal.h", 997, 1006, "bce6577118b578ceea75ef9ba0d562a6d2e9e3e2e96d5eaee92cbadf9f12b27c"),
)


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated = []
    for anchor in schema["source_anchors"]:
        member = str(anchor["member"])
        observed = sha256_bytes(source_range((source / member).read_bytes(), int(anchor["start_line"]), int(anchor["end_line"])))
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned aligned-overalloc source anchor drifted: {member}")
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    # The shared Rust contract names these logical booleans after the source
    # page/pointer concepts.  The generic runner conservatively rejects any
    # ``pointer`` field as a possible raw address, so normalize only these two
    # exact, schema-bound boolean keys while retaining the public trace names.
    aliases = {
        "trace.aligned_overalloc.interior_pointer": "trace.aligned_overalloc.interior_marked",
        "trace.aligned_overalloc.reuse_same_pointer": "trace.aligned_overalloc.reuse_same",
    }
    normalized = output
    for source_key, safe_key in aliases.items():
        normalized = normalized.replace(source_key + "=", safe_key + "=")
    try:
        parsed = run.parse_address_independent_trace(normalized, begin=TRACE_BEGIN, end=TRACE_END, description=description)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    reverse_aliases = {safe_key: source_key for source_key, safe_key in aliases.items()}
    return {reverse_aliases.get(key, key): value for key, value in parsed.items()}


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    mismatches = [f"{key} (expected {EXPECTED_TRACE_VALUES[key]}, observed {trace[key]})" for key in sorted(set(trace) & set(EXPECTED_TRACE_VALUES)) if type(trace[key]) is not int or trace[key] != EXPECTED_TRACE_VALUES[key]]
    if missing or unexpected or mismatches:
        details = []
        if missing: details.append("missing: " + ", ".join(missing))
        if unexpected: details.append("unexpected: " + ", ".join(unexpected))
        if mismatches: details.append("value mismatches: " + ", ".join(mismatches))
        raise EvidenceError(f"{description} differs from fixed aligned-overalloc trace: " + "; ".join(details))


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C aligned-overalloc trace")
    validate_trace(rust_trace, description="Rust aligned-overalloc trace")
    mismatches = [f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})" for key in sorted(EXPECTED_TRACE_VALUES) if c_trace[key] != rust_trace[key]]
    if mismatches:
        raise EvidenceError("Rust aligned-overalloc trace differs from pinned C: " + ", ".join(mismatches))
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized = []
    temporary_text, source_text = str(temporary), str(source) if source is not None else None
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
    if [p for p in command if p in EXPECTED_COMPILE_DEFINITIONS] != list(EXPECTED_COMPILE_DEFINITIONS) or [p for p in command if p in run.CONFIGURATION_PROFILES["release"]] != list(schema["release_flags"]):
        raise EvidenceError("aligned-overalloc C command release selection drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("aligned-overalloc C command lacks fixed pthread/TLS selection")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    expected = ["-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src", *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/aligned-overalloc-realloc.c", *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]), "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/aligned-overalloc-realloc-c"]
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise EvidenceError("aligned-overalloc report C command drifted")


def rust_trace_command(cargo: str, target_dir: Path) -> list[str]:
    return [cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir), "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]


def validate_normalized_rust_command(command: object) -> None:
    expected = ["test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target", "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]
    if not isinstance(command, list) or not command or Path(command[0]).name != "cargo" or command[1:] != expected:
        raise EvidenceError("aligned-overalloc report Rust command drifted")


def build_c_trace(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    probe_source, probe_binary = temporary / "aligned-overalloc-realloc.c", temporary / "aligned-overalloc-realloc-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C aligned-overalloc fixture build")
        header = run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        run.require_success(header, "pinned C aligned-overalloc fixture ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(probe_binary),), cwd=source)
        run.require_success(execution, "pinned C aligned-overalloc fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C aligned-overalloc trace")
    validate_trace(trace, description="pinned C aligned-overalloc trace")
    return {"build_command": normalize_command(command, temporary, source), "elf": elf, "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/aligned-overalloc-realloc-c"], "source_sha256": sha256_bytes(C_TRACE_PROBE.encode()), "trace": trace}


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    target_dir = temporary / "rust-target"
    command = rust_trace_command(cargo, target_dir)
    environment = os.environ.copy(); environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, environment=environment)
        run.require_success(execution, "Rust aligned-overalloc fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust aligned-overalloc fixture passed {passed} tests, expected one")
    trace = parse_trace(str(execution["stdout"]) + "\n" + str(execution["stderr"]), description="Rust aligned-overalloc trace")
    validate_trace(trace, description="Rust aligned-overalloc trace")
    return {"cargo_command": normalize_command(command, temporary, None), "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}, "passed_test_count": passed, "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}, "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}, "trace": trace}


def report_from_results(*, schema: Mapping[str, Any], provenance: Mapping[str, str], archive_sha256: str, anchors: Sequence[Mapping[str, Any]], c_probe: Mapping[str, Any], rust_probe: Mapping[str, Any]) -> dict[str, Any]:
    report = {"c_probe": dict(c_probe), "comparison": compare_traces(c_probe["trace"], rust_probe["trace"]), "format": 1, "kind": "mimalloc-x86_64-aligned-overalloc-realloc-differential-evidence", "profile": schema["profile"], "provenance": dict(provenance), "rust_probe": dict(rust_probe), "scope": schema["scope"], "source": {"archive_sha256": archive_sha256, "anchors": [dict(a) for a in anchors], "release_flags": list(schema["release_flags"]), "release_source_set": list(schema["release_source_set"])}, "status": "passed", "target": schema["target"], "trace": schema["trace"], "upstream": schema["upstream"]}
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("aligned-overalloc report schema/format/status drifted")
    if report["kind"] != "mimalloc-x86_64-aligned-overalloc-realloc-differential-evidence" or not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("aligned-overalloc report identity drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("aligned-overalloc report private boundary drifted")
    if not any(exactly_matches(report["provenance"], p) for p in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"})):
        raise EvidenceError("aligned-overalloc report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]): raise EvidenceError("aligned-overalloc report trace contract drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"} or source["archive_sha256"] != EXPECTED_ARCHIVE_SHA256 or not exactly_matches(source["anchors"], schema["source_anchors"]) or not exactly_matches(source["release_flags"], schema["release_flags"]) or not exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("aligned-overalloc report source identity drifted")
    c_probe, rust_probe = report["c_probe"], report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}: raise EvidenceError("aligned-overalloc report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}: raise EvidenceError("aligned-overalloc report Rust probe record drifted")
    if not exactly_matches(c_probe["elf"], EXPECTED_C_ELF) or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/aligned-overalloc-realloc-c"] or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode()): raise EvidenceError("aligned-overalloc report C identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if type(rust_probe["passed_test_count"]) is not int or rust_probe["passed_test_count"] != 1: raise EvidenceError("aligned-overalloc report Rust test selection drifted")
    if not exactly_matches(rust_probe["target_dir"], {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}): raise EvidenceError("aligned-overalloc report Rust target directory drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not exactly_matches(rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}): raise EvidenceError("aligned-overalloc report Rust lockfile identity drifted")
    if not exactly_matches(rust_probe["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}): raise EvidenceError("aligned-overalloc report Rust source identity drifted")
    if not exactly_matches(report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])): raise EvidenceError("aligned-overalloc report comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64(); schema = load_schema(); before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin(); archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error: raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-aligned-overalloc-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
            compiler, readelf, cargo = run.require_tool("musl-gcc"), run.require_tool("readelf"), run.require_tool("cargo")
        except run.HarnessError as error: raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source); c_probe = build_c_trace(compiler, readelf, source, temporary, schema); rust_probe = build_rust_trace(cargo, temporary)
        report = report_from_results(schema=schema, provenance=provenance, archive_sha256=sha256_file(archive), anchors=anchors, c_probe=c_probe, rust_probe=rust_probe)
    if sha256_file(LOCKFILE) != before_lockfile: raise EvidenceError("Cargo.lock changed despite --locked Rust trace")
    run.write_json(report_path, report); return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--offline", action="store_true"); parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try: report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 aligned-overalloc differential: FAIL: {error}", file=os.sys.stderr); return 1
    print(f"allocator x86-64 aligned-overalloc differential: PASS ({report['comparison']['compared_value_count']} logical values; report: {relative(arguments.report)})"); return 0


if __name__ == "__main__":
    raise SystemExit(main())
