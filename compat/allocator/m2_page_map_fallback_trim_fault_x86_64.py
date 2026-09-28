#!/usr/bin/env python3
"""Compare a failed PageMap fallback trim with pinned source in fresh processes."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import run as harness


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_page_map_fallback_trim_fault_x86_64.c"
TARGET = "process_page_map::tests::emit_m2_page_map_fallback_trim_fault_c_rust_trace"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-page-map-fallback-trim-fault"
FIELD = re.compile(r"^m2\.page_map\.fallback_trim_fault\.([a-z_]+)=([0-9a-f]*)$", re.MULTILINE)
EXPECTED = {"output", "initialized", "reserved", "committed", "mmap_calls",
    "commit_calls", "suffix_length", "suffix_live", "allocated", "raw_cleanup"}


def parse_trace(output: str, source: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in FIELD.findall(output):
        if key in values:
            raise ValueError(f"{source} repeated {key}")
        values[key] = value
    if set(values) != EXPECTED:
        raise ValueError(f"{source} PageMap observation roster changed: {sorted(values)}")
    return values


def run(offline: bool) -> dict[str, object]:
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(prefix="crabc-m2-page-map-fallback-trim-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        c_binary = ARTIFACTS / "pinned-c-oracle"
        c_build = harness.command_record([
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=munmap", "-pthread",
            "-o", str(c_binary),
        ], cwd=source, timeout_seconds=300)
        harness.write_json(ARTIFACTS / "c-build.json", c_build)
        harness.require_success(c_build, "PageMap fallback trim pinned C build")
        c_run = harness.command_record([str(c_binary)], cwd=source, timeout_seconds=120)
        harness.write_json(ARTIFACTS / "c-run.json", c_run)
        harness.require_success(c_run, "PageMap fallback trim pinned C process")

    program = harness._x86_64_unit_test_program(harness._m2_x86_64_vm_rust_execution(),
        harness.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET,
        gate_name="PageMap fallback trim fault")
    rust_run = harness.command_record([str(program["path"]), TARGET, "--exact",
        "--test-threads=1", "--nocapture"], cwd=ROOT, timeout_seconds=300)
    harness.write_json(ARTIFACTS / "rust-run.json", rust_run)
    harness.require_success(rust_run, "PageMap fallback trim Rust process")
    if harness.parse_rust_test_count(rust_run["stdout"] + rust_run["stderr"]) != 1:
        raise ValueError("PageMap fallback trim Rust exact test count changed")
    c = parse_trace(c_run["stdout"], "pinned C")
    rust = parse_trace(rust_run["stdout"] + rust_run["stderr"], "Rust")
    warnings = bytes.fromhex(c["output"]).decode("ascii").splitlines()
    if len(warnings) != 3 or not all(line.startswith("mimalloc: warning: thread 0xTID:")
        for line in warnings):
        raise ValueError("pinned C PageMap warning count or routing changed")
    if not ("unable to allocate OS memory" in warnings[0]
        and "fall back to over-allocation" in warnings[1]
        and "unable to free OS memory" in warnings[2]
        and "address: 0xSUFFIX" in warnings[2]):
        raise ValueError("pinned C PageMap warning order or release range changed")
    expected_c = {"initialized": "1", "reserved": "2359296", "committed": "2359296",
        "mmap_calls": "2", "commit_calls": "0", "suffix_length": "4096",
        "suffix_live": "1", "allocated": "1", "raw_cleanup": "1"}
    if any(c[key] != value for key, value in expected_c.items()):
        raise ValueError("pinned C PageMap recovery or VM accounting changed")
    report: dict[str, object] = {"status": "matched" if c == rust else "red",
        "c": c, "rust": rust,
        "mismatches": {key: {"c": c[key], "rust": rust[key]}
            for key in EXPECTED if c[key] != rust[key]}}
    harness.write_json(ARTIFACTS / "evidence.json", report)
    if c != rust:
        raise ValueError(f"PageMap fallback trim source/Rust red: {json.dumps(report['mismatches'], sort_keys=True)}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    try:
        report = run(arguments.offline)
    except Exception as error:
        print(f"PageMap fallback trim fault: {error}", file=sys.stderr)
        return 1
    print(f"PageMap fallback trim fault PASS ({len(report['c'])} relations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
