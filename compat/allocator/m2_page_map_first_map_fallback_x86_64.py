#!/usr/bin/env python3
"""Pinned C/Rust native x86-64 PageMap first-map fallback differential.

`m2_page_map_first_map_fallback_x86_64.c` fails the first `mmap` (the page
map's direct map) under `show_errors`. Pinned `mi_page_map_init_once` maps
through `_mi_os_alloc_aligned`, whose aligned over-allocation fallback maps
and trims the extent, so startup recovers and allocation proceeds.
`process_page_map::tests::emit_m2_page_map_first_map_fallback_c_rust_trace`
fails the same first Rust map. The startup output, initialization, VM
statistics, and first-allocation result must match.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping


FIXTURE_NAME = "m2_page_map_first_map_fallback_x86_64.c"
CHECK_ID = "page-map-first-map-fallback-c-rust-differential"
TARGET = "process_page_map::tests::emit_m2_page_map_first_map_fallback_c_rust_trace"
FIELD = re.compile(r"^m2\.page_map\.first_map_fallback\.([a-z_]+)=([0-9a-f]*)$", re.MULTILINE)


def parse_trace(output: str, *, source: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in FIELD.findall(output):
        if key in values:
            raise ValueError(f"{source} PageMap first-map fallback trace repeats {key}")
        values[key] = value
    if not values:
        raise ValueError(f"{source} PageMap first-map fallback trace is empty")
    return values


def run_evidence(
    harness: Any, *, offline: bool, test_program: Mapping[str, Any], check: Mapping[str, Any],
) -> dict[str, Any]:
    harness.require_native_x86_64()
    if check.get("id") != CHECK_ID or check.get("target") != TARGET:
        raise harness.HarnessError("native x86 PageMap first-map fallback check changed")
    fixture = harness.ALLOCATOR_ROOT / FIXTURE_NAME
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-page-map-first-map-fallback"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "oracle"
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-page-map-first-map-fallback-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            str(fixture), "-Wl,--wrap=mmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C PageMap first-map fallback oracle build")
        run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
        harness.require_success(run, "pinned C PageMap first-map fallback oracle")
    try:
        c_trace = parse_trace(str(run["stdout"]), source="pinned C")
        rust, output = harness._x86_64_run_exact_program_check(
            test_program, check, nocapture=True, gate_name="native x86 M2 PageMap first-map fallback",
        )
        rust_trace = parse_trace(output, source="Rust")
    except ValueError as error:
        raise harness.HarnessError(str(error)) from error
    if c_trace != rust_trace:
        raise harness.HarnessError(
            f"native x86 PageMap first-map fallback differs from pinned C: C={c_trace} Rust={rust_trace}"
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
