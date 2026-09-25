#!/usr/bin/env python3
"""Pinned C/Rust native x86-64 exclusive-arena Theap slice differential.

`m2_metadata_arena_x86_64.c` drives pinned `mi_heap_new_in_arena`: the
Heap's first allocation makes `_mi_theap_alloc` claim the Theap slice from
the exclusive arena, pages come from that arena, and heap destruction returns
the slice through `_mi_meta_free`; an exhausted or arena-disallowed exclusive
arena yields no Theap and no fallback. The two Rust tests below drive the
same transitions through `DynamicTheapAttachment` with a requested arena and
print the same measured keys (Theap slice offset/count/claim/release, client
placement, and the arena's free-slice counts at each step). Every key must
match.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping


FIXTURE_NAME = "m2_metadata_arena_x86_64.c"
CHECK_ID = "initialization-exclusive-arena-theap-slice-c-rust-differential"
TARGET = "dynamic_theap::tests::requested_arena_dynamic_owner_collects_live_pages_before_typed_metadata_release"
EXHAUSTED_TARGET = "dynamic_theap::tests::exhausted_requested_arena_rejects_theap_without_fallback_or_published_roots"
KEYS = (
    "theap_in_exclusive", "theap_slice_offset", "theap_slice_count", "theap_slice_claimed",
    "clients_in_exclusive", "free_before", "free_after_alloc", "preserved_through_collect",
    "free_after_pages", "theap_slice_released", "free_after_theap",
    "exhausted_claims", "exhausted_no_fallback", "disallowed_no_fallback",
)
FIELD = re.compile(r"m2\.metadata\.arena\.([a-z_]+)=([0-9]+)")


def parse_trace(output: str, *, source: str) -> dict[str, int]:
    trace: dict[str, int] = {}
    for match in FIELD.finditer(output):
        key, value = match.group(1), int(match.group(2))
        if key in trace:
            raise ValueError(f"{source} exclusive-arena Theap trace repeats {key}")
        trace[key] = value
    if set(trace) != set(KEYS):
        raise ValueError(
            f"{source} exclusive-arena Theap trace keys changed: "
            f"missing {sorted(set(KEYS) - set(trace))}, extra {sorted(set(trace) - set(KEYS))}"
        )
    return trace


def run_evidence(
    harness: Any, *, offline: bool, test_program: Mapping[str, Any], check: Mapping[str, Any],
) -> dict[str, Any]:
    harness.require_native_x86_64()
    if check.get("id") != CHECK_ID or check.get("target") != TARGET:
        raise harness.HarnessError("native x86 exclusive-arena Theap check changed")
    fixture = harness.ALLOCATOR_ROOT / FIXTURE_NAME
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-exclusive-arena-theap"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "oracle"
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-exclusive-arena-theap-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            str(fixture), "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C exclusive-arena Theap oracle build")
        run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
        harness.require_success(run, "pinned C exclusive-arena Theap oracle")
    exhausted_check = {
        "expected_passed_test_count": 1, "id": f"{CHECK_ID}-exhausted", "target": EXHAUSTED_TARGET,
    }
    try:
        c_trace = parse_trace(str(run["stdout"]), source="pinned C")
        rust, output = harness._x86_64_run_exact_program_check(
            test_program, check, nocapture=True, gate_name="native x86 M2 exclusive-arena Theap",
        )
        _, exhausted_output = harness._x86_64_run_exact_program_check(
            test_program, exhausted_check, nocapture=True,
            gate_name="native x86 M2 exclusive-arena Theap exhaustion",
        )
        rust_trace = parse_trace(output + "\n" + exhausted_output, source="Rust")
    except ValueError as error:
        raise harness.HarnessError(str(error)) from error
    if c_trace != rust_trace:
        different = sorted(key for key in KEYS if c_trace[key] != rust_trace[key])
        raise harness.HarnessError(
            "native x86 exclusive-arena Theap differs from pinned C: "
            + ", ".join(f"{key} C={c_trace[key]} Rust={rust_trace[key]}" for key in different)
        )
    evidence = {
        "c_command": command,
        "comparison": {"compared_value_count": len(c_trace), "status": "matched"},
        "fixture": harness.artifact_record(fixture),
        "rust_command": rust["command"],
        "rust_passed_test_count": rust["passed_test_count"],
        "status": "passed",
        "trace": dict(sorted(c_trace.items())),
    }
    harness.write_json(artifacts / "evidence.json", evidence)
    return evidence
