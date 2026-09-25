#!/usr/bin/env python3
"""Pinned C/Rust native x86-64 startup statistics differential.

`m2_startup_statistics_x86_64.c` prints the pinned main-subprocess VM
statistics (reserved and committed current/total/peak, mmap and commit
calls) after `mi_process_init`, after the first allocation, and after its
free; `os::tests::emit_m2_startup_statistics_c_rust_trace` prints the same
fields for the Rust runtime startup. The page map's reservation and
commitment are part of both totals. Every field must match.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping


FIXTURE_NAME = "m2_startup_statistics_x86_64.c"
CHECK_ID = "page-map-startup-statistics-c-rust-differential"
TARGET = "os::tests::emit_m2_startup_statistics_c_rust_trace"
FIELD = re.compile(r"m2\.startup\.statistics\.([0-9]+)=(-?[0-9]+)")


def parse_trace(output: str, *, source: str) -> list[int]:
    values: list[int] = []
    for match in FIELD.finditer(output):
        if int(match.group(1)) != len(values):
            raise ValueError(f"{source} startup statistics trace is out of order")
        values.append(int(match.group(2)))
    if not values:
        raise ValueError(f"{source} startup statistics trace is empty")
    return values


def run_evidence(
    harness: Any, *, offline: bool, test_program: Mapping[str, Any], check: Mapping[str, Any],
) -> dict[str, Any]:
    harness.require_native_x86_64()
    if check.get("id") != CHECK_ID or check.get("target") != TARGET:
        raise harness.HarnessError("native x86 startup statistics check changed")
    fixture = harness.ALLOCATOR_ROOT / FIXTURE_NAME
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-startup-statistics"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "oracle"
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-startup-statistics-") as directory:
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
        harness.require_success(build, "pinned C startup statistics oracle build")
        run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
        harness.require_success(run, "pinned C startup statistics oracle")
    try:
        c_trace = parse_trace(str(run["stdout"]), source="pinned C")
        rust, output = harness._x86_64_run_exact_program_check(
            test_program, check, nocapture=True, gate_name="native x86 M2 startup statistics",
        )
        rust_trace = parse_trace(output, source="Rust")
    except ValueError as error:
        raise harness.HarnessError(str(error)) from error
    if c_trace != rust_trace:
        raise harness.HarnessError(
            f"native x86 startup statistics differ from pinned C: C={c_trace} Rust={rust_trace}"
        )
    evidence = {
        "c_command": command,
        "comparison": {"compared_value_count": len(c_trace), "status": "matched"},
        "fixture": harness.artifact_record(fixture),
        "rust_command": rust["command"],
        "rust_passed_test_count": rust["passed_test_count"],
        "status": "passed",
        "trace": c_trace,
    }
    harness.write_json(artifacts / "evidence.json", evidence)
    return evidence
