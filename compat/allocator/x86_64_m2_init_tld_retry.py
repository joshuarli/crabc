#!/usr/bin/env python3
"""Compare pinned direct TLD metadata failure, retry, and release with Rust."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

FIXTURE = "x86_64_m2_init_tld_retry.c"
CHECK_ID = "initialization-later-tld-metadata-fault-retry-c-rust-differential"
TARGET = "tld::tests::emit_m2_later_tld_fault_retry_c_rust_trace"
FIELD = re.compile(r"m2\.init\.tld_retry\.([0-9]+)=([0-9]+)")
FIELD_COUNT = 9


def parse_trace(output: str, *, source: str) -> list[int]:
    values: list[int] = []
    for line in output.splitlines():
        prefix = f"test {TARGET} ... "
        if line.startswith(prefix):
            line = line[len(prefix):]
        if "m2.init.tld_retry." not in line:
            continue
        match = FIELD.fullmatch(line)
        if match is None or int(match.group(1)) != len(values):
            raise ValueError(f"{source} TLD retry trace has malformed field: {line!r}")
        values.append(int(match.group(2)))
    if len(values) != FIELD_COUNT:
        raise ValueError(f"{source} TLD retry trace has {len(values)} fields")
    return values


def run_evidence(
    harness: Any, *, offline: bool, test_program: Mapping[str, Any], check: Mapping[str, Any],
) -> dict[str, Any]:
    harness.require_native_x86_64()
    if check.get("id") != CHECK_ID or check.get("target") != TARGET:
        raise harness.HarnessError("native x86 TLD retry check changed")
    fixture = harness.ALLOCATOR_ROOT / FIXTURE
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-init-tld-retry"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "oracle"
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-init-tld-retry-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(fixture), *(str(source / item) for item in harness.M2_LATER_TLD_METADATA_FAILURE_ORACLE_SOURCES),
            "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C TLD metadata fault/retry oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
        harness.require_success(c_run, "pinned C TLD metadata fault/retry oracle")
    try:
        c_trace = parse_trace(str(c_run["stdout"]), source="pinned C")
        rust, rust_output = harness._x86_64_run_exact_program_check(
            test_program, check, nocapture=True, gate_name="native x86 M2 TLD fault/retry",
        )
        rust_trace = parse_trace(rust_output, source="Rust")
    except ValueError as error:
        raise harness.HarnessError(str(error)) from error
    if c_trace != rust_trace:
        raise harness.HarnessError(f"native x86 TLD fault/retry differs: C={c_trace} Rust={rust_trace}")
    evidence = {
        "c_command": command,
        "c_trace": c_trace,
        "comparison": {"compared_value_count": len(c_trace), "status": "matched"},
        "fixture": harness.artifact_record(fixture),
        "rust_command": rust["command"],
        "rust_passed_test_count": rust["passed_test_count"],
        "rust_trace": rust_trace,
        "status": "passed",
    }
    harness.write_json(artifacts / "evidence.json", evidence)
    return evidence
