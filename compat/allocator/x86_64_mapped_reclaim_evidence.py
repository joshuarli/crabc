#!/usr/bin/env python3
"""Differentially prove one mapped-arena same-origin reclaim on native x86-64.

The private pinned-C fixture creates an arena-backed regular page, abandons it
through the source page-queue transition while two allocations remain live,
then frees one block through ``mi_free``. The remaining allocation prevents
the page from being released, so the fixture can require the source's
same-origin reclaim-on-free transition. One crate-private Rust test emits the
same address-independent record.

This is bounded private allocator-engine evidence only. It does not claim
general abandonment/adoption, cross-thread reclaim, public ``mi_*`` behavior,
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-mapped-reclaim-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/mapped-reclaim.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/dynamic_theap.rs"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "dynamic_theap::tests::x86_64_mapped_reclaim_trace_matches_pinned_c_protocol"
TRACE_BEGIN = "CRABC_MI_MAPPED_RECLAIM_TRACE_BEGIN"
TRACE_END = "CRABC_MI_MAPPED_RECLAIM_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded mapped-reclaim differential could not establish its claim."""


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
EXPECTED_PROFILE = "linux-x86_64-private-mapped-arena-same-origin-reclaim"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "arena_backed_only": True,
    "cross_thread_reclaim_claimed": False,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "same_origin_reclaim_only": True,
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
    ("src/page.c", 276, 303, "d908cf80ab5954ff40fc81b2530f80ae2b9ba8dfd0c3d649a4418f682d2a947c"),
    ("src/arena.c", 1304, 1409, "6a6d08e7cb4a45803619ce1c9d7efab31808068a756a727a4d3fd3d48d30413f"),
    ("include/mimalloc/prim-tls.h", 412, 421, "466e1c5ef5f6fcddae9a518965638676a61bd41b8cbde85a5c0bcba76e2710dd"),
)
EXPECTED_TRACE_VALUES = {
    "trace.mapped_reclaim.arena_backed": 1,
    "trace.mapped_reclaim.mapped_before_free": 1,
    "trace.mapped_reclaim.abandoned_before_free": 1,
    "trace.mapped_reclaim.origin_theap_present": 1,
    "trace.mapped_reclaim.free_block_is_same_page": 1,
    "trace.mapped_reclaim.reclaimed_after_free": 1,
    "trace.mapped_reclaim.abandoned_after_free": 0,
    "trace.mapped_reclaim.valid": 1,
}


# The source-shaped abandon call removes the live page from its owning queue,
# preserves its former theap for same-origin reclamation, and marks its arena
# map. ``mi_free`` then enters the pinned abandoned-page collector. The
# survivor keeps the page nonempty, making a release impossible on the
# inspected path. No raw pointer is printed.
C_TRACE_PROBE = r"""
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"

#include <stdbool.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private mapped-reclaim fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private mapped-reclaim fixture requires the fixed release profile
#endif

int main(void) {
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_queue_t* queue = NULL;
  void* block = NULL;
  void* survivor = NULL;
  bool valid = false;

  int arena_backed = 0;
  int mapped_before_free = 0;
  int abandoned_before_free = 0;
  int origin_theap_present = 0;
  int free_block_is_same_page = 0;
  int reclaimed_after_free = 0;
  int abandoned_after_free = 1;

  // The fixed request exceeds the direct small fast path. It leaves ample
  // room for two blocks in the ordinary arena-backed page selected here.
  const size_t request = MI_SMALL_SIZE_MAX + 1024;

  if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &arena_id) != 0
      || arena_id == _mi_arena_id_none()) {
    goto cleanup;
  }
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) goto cleanup;
  block = mi_heap_malloc(heap, request);
  survivor = mi_heap_malloc(heap, request);
  if (block == NULL || survivor == NULL) goto cleanup;

  page = _mi_ptr_page(block);
  theap = _mi_heap_theap(heap);
  if (page == NULL || theap == NULL || _mi_ptr_page(survivor) != page
      || page->block_size <= MI_SMALL_SIZE_MAX
      || page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || page->memid.memkind != MI_MEM_ARENA
      || mi_page_is_full(page)) {
    goto cleanup;
  }
  queue = mi_page_queue(theap, page->block_size);
  if (queue == NULL || queue->count != 1 || queue->first != page) goto cleanup;

  // This is the full source queue-to-abandoned-map transition. Calling the
  // arena helper directly would violate its precondition that the page is
  // already abandoned and detached from its owning queue.
  _mi_page_abandon(page, queue);
  arena_backed = (page->memid.memkind == MI_MEM_ARENA);
  mapped_before_free = mi_page_is_abandoned_mapped(page);
  abandoned_before_free = mi_page_is_abandoned(page);
  origin_theap_present = (page->theap == theap
                          && _mi_page_associated_theap_peek(page) == theap);
  free_block_is_same_page = (_mi_ptr_page(block) == page
                             && _mi_ptr_page(survivor) == page);
  if (!arena_backed || !mapped_before_free || !abandoned_before_free
      || !origin_theap_present || !free_block_is_same_page
      || queue->count != 0 || page->next != NULL || page->prev != NULL) {
    goto cleanup;
  }

  // The surviving live block keeps ``page`` valid to inspect after the public
  // free claims the abandoned page and applies same-origin reclaim-on-free.
  mi_free(block);
  block = NULL;

  reclaimed_after_free = (!mi_page_is_abandoned(page)
                          && !mi_page_is_abandoned_mapped(page));
  abandoned_after_free = mi_page_is_abandoned(page);
  valid = (reclaimed_after_free && !abandoned_after_free
           && page->theap == theap
           && _mi_page_associated_theap_peek(page) == theap
           && _mi_ptr_page(survivor) == page
           && page->used == 1 && !mi_page_all_free(page)
           && queue->count == 1 && queue->first == page);

  printf("CRABC_MI_MAPPED_RECLAIM_TRACE_BEGIN\n");
  printf("trace.mapped_reclaim.arena_backed=%d\n", arena_backed);
  printf("trace.mapped_reclaim.mapped_before_free=%d\n", mapped_before_free);
  printf("trace.mapped_reclaim.abandoned_before_free=%d\n", abandoned_before_free);
  printf("trace.mapped_reclaim.origin_theap_present=%d\n", origin_theap_present);
  printf("trace.mapped_reclaim.free_block_is_same_page=%d\n", free_block_is_same_page);
  printf("trace.mapped_reclaim.reclaimed_after_free=%d\n", reclaimed_after_free);
  printf("trace.mapped_reclaim.abandoned_after_free=%d\n", abandoned_after_free);
  printf("trace.mapped_reclaim.valid=%d\n", valid);
  printf("CRABC_MI_MAPPED_RECLAIM_TRACE_END\n");

cleanup:
  if (block != NULL) mi_free(block);
  if (survivor != NULL) mi_free(survivor);
  if (heap != NULL) mi_heap_destroy(heap);
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
        raise EvidenceError("mapped-reclaim source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    """Read and fail-closed validate the checked-in native-only contract."""

    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 mapped-reclaim schema") from error
    if not isinstance(schema, dict):
        raise EvidenceError("x86-64 mapped-reclaim schema is not an object")
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
        raise EvidenceError("x86-64 mapped-reclaim schema fields drifted")
    if (
        type(schema.get("format")) is not int
        or schema.get("format") != 1
        or schema.get("schema") != "crabc-mimalloc-x86_64-mapped-reclaim-evidence"
    ):
        raise EvidenceError("unsupported x86-64 mapped-reclaim schema")
    if not exactly_matches(schema.get("target"), EXPECTED_TARGET):
        raise EvidenceError("mapped-reclaim schema target is not native Linux/x86-64")
    if not exactly_matches(schema.get("upstream"), EXPECTED_UPSTREAM):
        raise EvidenceError("mapped-reclaim schema upstream is not pinned mimalloc 3.5.0")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate the pinned mapped-reclaim upstream identity") from error
    if not exactly_matches(
        {"archive_root": pin["archive_root"], "revision": pin["revision"], "version": pin["version"]},
        EXPECTED_UPSTREAM,
    ) or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("mapped-reclaim upstream pin drifted")
    if schema.get("profile") != EXPECTED_PROFILE:
        raise EvidenceError("mapped-reclaim schema profile drifted")
    if not exactly_matches(schema.get("scope"), EXPECTED_SCOPE):
        raise EvidenceError("mapped-reclaim schema private boundary drifted")
    if not exactly_matches(schema.get("release_source_set"), list(run.ORACLE_SOURCES)):
        raise EvidenceError("mapped-reclaim C source set differs from the pinned oracle")
    if not exactly_matches(schema.get("release_flags"), list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("mapped-reclaim C release flags drifted")
    if not exactly_matches(schema.get("compile_definitions"), list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("mapped-reclaim C compile definitions drifted")
    if not exactly_matches(
        schema.get("rust_test"),
        {"path": relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER},
    ):
        raise EvidenceError("mapped-reclaim Rust test selection drifted")
    if not exactly_matches(
        schema.get("trace"),
        {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES},
    ):
        raise EvidenceError("mapped-reclaim fixed trace schema drifted")
    if schema.get("c_probe_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("mapped-reclaim C probe source hash drifted")

    anchors = schema.get("source_anchors")
    observed: list[tuple[str, int, int, str]] = []
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("mapped-reclaim source anchors drifted")
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("mapped-reclaim source anchor has an invalid shape")
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
            raise EvidenceError("mapped-reclaim source anchor has invalid values")
        observed.append((member, start_line, end_line, digest))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("mapped-reclaim source anchor contract drifted")
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
            raise EvidenceError(f"pinned source lacks mapped-reclaim anchor member: {member}")
        observed = sha256_bytes(
            source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))
        )
        if observed != anchor["sha256"]:
            raise EvidenceError(f"pinned mapped-reclaim source anchor drifted: {member}")
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
        raise EvidenceError(f"{description} differs from the fixed mapped-reclaim trace: " + "; ".join(failures))


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C mapped-reclaim trace")
    validate_trace(rust_trace, description="Rust mapped-reclaim trace")
    mismatches = [
        f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})"
        for key in sorted(EXPECTED_TRACE_VALUES)
        if c_trace[key] != rust_trace[key]
    ]
    if mismatches:
        raise EvidenceError("Rust mapped-reclaim trace differs from pinned C: " + ", ".join(mismatches))
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
        raise EvidenceError("mapped-reclaim C command compile definitions drifted")
    if flags != list(schema["release_flags"]):
        raise EvidenceError("mapped-reclaim C command release flags drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("mapped-reclaim C command lacks the fixed pthread/TLS mode")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("mapped-reclaim report C command is malformed")
    if Path(command[0]).name != "musl-gcc":
        raise EvidenceError("mapped-reclaim report C command compiler drifted")
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
        f"{NORMALIZED_EVIDENCE_ROOT}/mapped-reclaim.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/mapped-reclaim-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("mapped-reclaim report C command drifted")


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
        raise EvidenceError("mapped-reclaim report Rust command is malformed")
    if Path(command[0]).name != "cargo":
        raise EvidenceError("mapped-reclaim report Rust command compiler drifted")
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
        raise EvidenceError("mapped-reclaim report Rust command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]
) -> dict[str, Any]:
    probe_source = temporary / "mapped-reclaim.c"
    probe_binary = temporary / "mapped-reclaim-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C mapped-reclaim fixture build")
        header = run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        run.require_success(header, "pinned C mapped-reclaim fixture ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(probe_binary),), cwd=source)
        run.require_success(execution, "pinned C mapped-reclaim fixture execution")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C mapped-reclaim trace")
    validate_trace(trace, description="pinned C mapped-reclaim trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/mapped-reclaim-c"],
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
        run.require_success(execution, "Rust mapped-reclaim fixture")
        passed = run.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if passed != 1:
        raise EvidenceError(f"Rust mapped-reclaim fixture passed {passed} tests, expected one")
    trace = parse_trace(
        str(execution["stdout"]) + "\n" + str(execution["stderr"]),
        description="Rust mapped-reclaim trace",
    )
    validate_trace(trace, description="Rust mapped-reclaim trace")
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
        raise EvidenceError("mapped-reclaim report inputs lack trace records")
    report: dict[str, Any] = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": "mimalloc-x86_64-mapped-arena-same-origin-reclaim-differential-evidence",
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
        raise EvidenceError("mapped-reclaim report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("mapped-reclaim report must record a passing format-1 result")
    if report["kind"] != "mimalloc-x86_64-mapped-arena-same-origin-reclaim-differential-evidence":
        raise EvidenceError("mapped-reclaim report kind drifted")
    if report["profile"] != EXPECTED_PROFILE or not exactly_matches(report["target"], EXPECTED_TARGET):
        raise EvidenceError("mapped-reclaim report target/profile drifted")
    if not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("mapped-reclaim report source or private boundary drifted")
    if not exactly_matches(report["trace"], {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES}):
        raise EvidenceError("mapped-reclaim report trace contract drifted")
    if not any(
        exactly_matches(report["provenance"], candidate)
        for candidate in (
            {"execution_mode": "native", "host_architecture": "x86_64"},
            {"execution_mode": "native", "host_architecture": "amd64"},
        )
    ):
        raise EvidenceError("mapped-reclaim report lacks native x86-64 provenance")

    schema = load_schema()
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("mapped-reclaim report source record is malformed")
    if source.get("archive_sha256") != run.load_pin()["sha256"]:
        raise EvidenceError("mapped-reclaim report archive identity drifted")
    if not exactly_matches(source.get("anchors"), schema["source_anchors"]):
        raise EvidenceError("mapped-reclaim report source anchors drifted")
    if not exactly_matches(source.get("release_flags"), schema["release_flags"]):
        raise EvidenceError("mapped-reclaim report release flags drifted")
    if not exactly_matches(source.get("release_source_set"), schema["release_source_set"]):
        raise EvidenceError("mapped-reclaim report source set drifted")

    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("mapped-reclaim report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("mapped-reclaim report Rust probe record drifted")
    if not exactly_matches(c_probe.get("elf"), EXPECTED_C_ELF):
        raise EvidenceError("mapped-reclaim report C ELF identity drifted")
    if not exactly_matches(c_probe.get("run_command"), [f"{NORMALIZED_EVIDENCE_ROOT}/mapped-reclaim-c"]):
        raise EvidenceError("mapped-reclaim report C run command drifted")
    if c_probe.get("source_sha256") != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("mapped-reclaim report C source hash drifted")
    validate_normalized_c_command(c_probe.get("build_command"), schema)
    if type(rust_probe.get("passed_test_count")) is not int or rust_probe["passed_test_count"] != 1:
        raise EvidenceError("mapped-reclaim report Rust selection did not pass exactly one test")
    if not exactly_matches(
        rust_probe.get("target_dir"),
        {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"},
    ):
        raise EvidenceError("mapped-reclaim report Rust target directory drifted")
    validate_normalized_rust_command(rust_probe.get("cargo_command"))
    if not exactly_matches(rust_probe.get("lockfile"), {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}):
        raise EvidenceError("mapped-reclaim report Rust lockfile identity drifted")
    if not exactly_matches(rust_probe.get("source"), {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}):
        raise EvidenceError("mapped-reclaim report Rust source identity drifted")
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("mapped-reclaim report lacks C/Rust trace records")
    if not exactly_matches(report["comparison"], compare_traces(c_trace, rust_trace)):
        raise EvidenceError("mapped-reclaim report comparison drifted")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    before_lockfile = sha256_file(LOCKFILE)
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-mapped-reclaim-") as temporary_name:
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
        print(f"allocator x86-64 mapped-reclaim differential: FAIL: {error}", file=os.sys.stderr)
        return 1
    comparison = report["comparison"]
    print(
        "allocator x86-64 mapped-reclaim differential: PASS "
        f"({comparison['compared_value_count']} logical values; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
