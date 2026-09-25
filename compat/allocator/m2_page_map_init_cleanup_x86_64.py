#!/usr/bin/env python3
"""Pinned C/Rust native x86-64 PageMap initialization cleanup differential.

`m2_page_map_init_cleanup_x86_64.c` runs pinned `mi_page_map_init_once` with
its initial or trailing-submap commit failing and the `_mi_os_free` cleanup's
`munmap` failing too; `page_map::tests::emit_m2_page_map_init_cleanup_c_rust_trace`
runs Rust `PageMap::initialize` under the same fault plan (commit ordinal 1
or 2, then the first release after it). Both record initialization failure,
the commit-attempt count, one failed release, and the leaked mapping staying
live, and every field must match. The aggregate `allocator-m2` gate calls
`run_evidence` with its prebuilt test binary.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


FIXTURE_NAME = "m2_page_map_init_cleanup_x86_64.c"
CHECK_ID = "page-map-initialization-cleanup-leak-c-rust-differential"
TARGET = "page_map::tests::emit_m2_page_map_init_cleanup_c_rust_trace"
FIELD = re.compile(r"m2\.page_map\.init_cleanup\.([0-9]+)=([0-9]+)")
FIELD_COUNT = 10
RUST_INLINE_PREFIX = f"test {TARGET} ... "


def parse_trace(output: str, *, source: str) -> list[int]:
    values: list[int] = []
    for line in output.splitlines():
        if line.startswith(RUST_INLINE_PREFIX):
            line = line[len(RUST_INLINE_PREFIX):]
        if "m2.page_map.init_cleanup." not in line:
            continue
        match = FIELD.fullmatch(line)
        if match is None or int(match.group(1)) != len(values):
            raise ValueError(f"{source} PageMap init-cleanup trace has a malformed field: {line!r}")
        values.append(int(match.group(2)))
    if len(values) != FIELD_COUNT:
        raise ValueError(f"{source} PageMap init-cleanup trace has {len(values)} fields")
    return values


def run_evidence(
    harness: Any, *, offline: bool, test_program: Mapping[str, Any], check: Mapping[str, Any],
) -> dict[str, Any]:
    harness.require_native_x86_64()
    if check.get("id") != CHECK_ID or check.get("target") != TARGET:
        raise harness.HarnessError("native x86 PageMap init-cleanup check changed")
    fixture = harness.ALLOCATOR_ROOT / FIXTURE_NAME
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-page-map-init-cleanup"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "oracle"
    from pathlib import Path
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-page-map-init-cleanup-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            str(fixture), *(str(source / item) for item in harness.M2_PAGE_MAP_ORACLE_SOURCES),
            "-Wl,--wrap=munmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C PageMap init-cleanup oracle build")
        run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
        harness.require_success(run, "pinned C PageMap init-cleanup oracle")
    try:
        c_trace = parse_trace(str(run["stdout"]), source="pinned C")
        rust, rust_output = harness._x86_64_run_exact_program_check(
            test_program, check, nocapture=True, gate_name="native x86 M2 PageMap init cleanup",
        )
        rust_trace = parse_trace(rust_output, source="Rust")
    except ValueError as error:
        raise harness.HarnessError(str(error)) from error
    if c_trace != rust_trace:
        raise harness.HarnessError(
            f"native x86 PageMap init-cleanup differs from pinned C: C={c_trace} Rust={rust_trace}"
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
