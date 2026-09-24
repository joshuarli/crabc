#!/usr/bin/env python3
"""Pinned C/Rust native x86-64 arena destruction differential.

`arena_destroy.c` drives the unchanged pinned `_mi_arenas_unsafe_destroy_all`
teardown caller of `_mi_os_free_ex` through `static.c`, with a `munmap` link
wrapper that fails one selected release. It covers regular reserved and
committed arenas, an external callback arena, a failed parent release of a
spanning reservation, and a failed release inside a huge-kind arena.
`arena::owned::tests::destroy_all_retires_regular_external_and_huge_owners_with_exact_retries`
emits the same thirteen ordered fields. The aggregate `allocator-m2` gate
calls `run_evidence` with its one prebuilt test binary;
`allocator-arena-destroy` runs `main` for focused development.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


FIXTURE = Path(__file__).with_suffix(".c").resolve()
CHECK_ID = "arena-destruction-c-rust-differential"
TARGET = "arena::owned::tests::destroy_all_retires_regular_external_and_huge_owners_with_exact_retries"
FIELD_COUNT = 13


def trace(output: str, *, source: str) -> list[int]:
    rows = re.findall(r"^m2\.arena\.destroy\.(\d+)=(-?\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in rows] != list(range(FIELD_COUNT)):
        raise ValueError(f"{source} arena destruction trace must contain exactly thirteen ordered fields")
    return [int(value) for _, value in rows]


def run_oracle(harness: Any, *, offline: bool) -> tuple[list[str], list[int], Path]:
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/arena-destroy"
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory(prefix="arena-destroy-source-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [harness.require_tool("musl-gcc"), "-std=c11", "-fPIC",
            "-ftls-model=initial-exec", "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT",
            "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-pthread", "-Wl,--wrap=munmap",
            "-o", str(artifacts / "oracle")]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "arena destruction C oracle build")
        oracle = harness.command_record([str(artifacts / "oracle")], cwd=source, timeout_seconds=60)
        harness.require_success(oracle, "arena destruction C oracle")
    (artifacts / "c.log").write_text(str(oracle["stdout"]), encoding="utf-8")
    return command, trace(str(oracle["stdout"]), source="pinned C"), artifacts


def run_evidence(
    harness: Any, *, offline: bool, test_program: Mapping[str, Any], check: Mapping[str, Any],
) -> dict[str, Any]:
    """Run the differential against the aggregate gate's prebuilt test binary."""

    harness.require_native_x86_64()
    if check.get("id") != CHECK_ID or check.get("target") != TARGET:
        raise harness.HarnessError("native x86 arena destruction check changed")
    try:
        c_command, c_trace, artifacts = run_oracle(harness, offline=offline)
        rust, rust_output = harness._x86_64_run_exact_program_check(
            test_program, check, nocapture=True, gate_name="native x86 M2 arena destruction",
        )
        if c_trace != trace(rust_output, source="Rust"):
            raise ValueError("pinned C/Rust arena destruction differs")
    except ValueError as error:
        raise harness.HarnessError(str(error)) from error
    evidence = {
        "c_command": c_command,
        "comparison": {"compared_value_count": len(c_trace), "status": "matched"},
        "fixture": harness.artifact_record(FIXTURE),
        "rust_command": rust["command"],
        "rust_passed_test_count": rust["passed_test_count"],
        "status": "passed",
        "trace_sha256": hashlib.sha256(
            json.dumps(c_trace, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    harness.write_json(artifacts / "evidence.json", evidence)
    return evidence


def main() -> None:
    import run as harness  # this script's directory is first on sys.path

    harness.require_native_x86_64()
    _, c_trace, artifacts = run_oracle(harness, offline=True)
    rust = harness.command_record(["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=900)
    harness.require_success(rust, "arena destruction Rust ownership checks")
    (artifacts / "rust.log").write_text(str(rust["stdout"]), encoding="utf-8")
    if c_trace != trace(str(rust["stdout"]), source="Rust"):
        raise harness.HarnessError("pinned C/Rust arena destruction differs")
    print(f"arena destruction: pinned C/Rust match; {artifacts}")


if __name__ == "__main__":
    main()
