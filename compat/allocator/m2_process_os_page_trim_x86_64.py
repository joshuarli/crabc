#!/usr/bin/env python3
"""Pinned C and process-owned Rust fresh OS-page suffix failure receiver."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import m2_legacy_os_page_trim_x86_64 as source_receiver
import run as harness


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = source_receiver.FIXTURE
TARGET = "os::tests::emit_process_os_page_suffix_trim_trace"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-process-os-page-trim"
SHARED = (*source_receiver.COMMON, *source_receiver.STATS, *source_receiver.WARNINGS)
RUST_EXTRA = ("suffix_still_live",)


def parse_rust_trace(output: str) -> dict[str, int]:
    expected = (*SHARED, *RUST_EXTRA)
    values: dict[str, int] = {}
    for line in output.splitlines():
        if not line.startswith("process.claim."):
            continue
        key, separator, raw = line.partition("=")
        name = key.removeprefix("process.claim.")
        if not separator or name not in expected or name in values or not raw.lstrip("-").isdecimal():
            raise ValueError(f"process-owned OS-page observation changed: {line}")
        values[name] = int(raw)
    if set(values) != set(expected):
        raise ValueError(f"process-owned OS-page roster changed: {sorted(values)}")
    return values


def compare(c: dict[str, int], rust: dict[str, int]) -> dict[str, Any]:
    mismatches = {key: {"c": c[key], "rust": rust[key]}
        for key in SHARED if c[key] != rust[key]}
    if mismatches:
        raise ValueError(f"process-owned OS-page C/Rust red: {json.dumps(mismatches, sort_keys=True)}")
    if [c[key] for key in source_receiver.COMMON] != [1, 1, 1, 196608, 4096, 1, 1, 1]:
        raise ValueError("pinned C physical mapping, MemoryId, or raw cleanup changed")
    if [c[key] for key in source_receiver.STATS] != [196608, 65536, 2, 0, 0]:
        raise ValueError("pinned C subprocess statistics changed")
    if [c[key] for key in source_receiver.WARNINGS] != [6, 3, 1, 1]:
        raise ValueError("pinned C warning bytes, order, or counter timing changed")
    if rust["suffix_still_live"] != 1:
        raise ValueError("Rust raw retry disturbed the escaped suffix")
    return {"status": "matched", "compared_value_count": len(SHARED)}


def run(*, offline: bool, rust_test_binary: Path | None = None) -> dict[str, Any]:
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    before = harness.m2_memory_substrate_source_state()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(prefix="crabc-m2-process-os-page-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-oracle"
        build = harness.command_record(source_receiver.c_command(
            harness.require_tool("musl-gcc"), source, binary,
        ), cwd=source, timeout_seconds=300)
        harness.write_json(ARTIFACTS / "c-build.json", build)
        harness.require_success(build, "process-owned OS-page pinned C build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=90)
        harness.write_json(ARTIFACTS / "c-run.json", c_run)
        harness.require_success(c_run, "process-owned OS-page pinned C receiver")
    if rust_test_binary is None:
        program = harness._x86_64_unit_test_program(harness._m2_x86_64_vm_rust_execution(),
            harness.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET,
            gate_name="process-owned OS-page trim receiver")
        rust_test_binary = program["path"]
    rust_command = [str(rust_test_binary), TARGET, "--exact", "--test-threads=1", "--nocapture"]
    rust_run = harness.command_record(rust_command, cwd=ROOT, timeout_seconds=300)
    harness.write_json(ARTIFACTS / "rust-run.json", rust_run)
    harness.require_success(rust_run, "process-owned OS-page Rust receiver")
    if harness.parse_rust_test_count(rust_run["stdout"] + rust_run["stderr"]) != 1:
        raise ValueError("process-owned OS-page Rust exact test count changed")
    c = source_receiver.parse_trace(c_run["stdout"], language="C")
    rust = parse_rust_trace(rust_run["stdout"] + rust_run["stderr"])
    comparison = compare(c, rust)
    after = harness.m2_memory_substrate_source_state()
    if before != after:
        raise ValueError("process-owned OS-page source changed during receiver")
    report = {"status": "passed", "pinned_revision": pin["revision"],
        "archive_sha256": pin["sha256"], "source_before": before, "source_after": after,
        "c_build": build, "c_run": c_run, "rust_run": rust_run,
        "fixture": harness.artifact_record(FIXTURE), "c_trace": c, "rust_trace": rust,
        "comparison": comparison}
    harness.write_json(ARTIFACTS / "evidence.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--rust-test-binary", type=Path)
    arguments = parser.parse_args()
    try:
        report = run(offline=arguments.offline, rust_test_binary=arguments.rust_test_binary)
    except Exception as error:
        print(f"process-owned OS-page trim receiver: {error}", file=sys.stderr)
        return 1
    print("process-owned OS-page trim receiver PASS "
          f"({report['comparison']['compared_value_count']} exact relations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
