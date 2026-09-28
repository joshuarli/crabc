#!/usr/bin/env python3
"""Pinned C and process-owned Rust fresh OS-page block-commit rollback."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import run as harness


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_process_os_page_block_commit_x86_64.c"
TARGET = "os_page::tests::emit_fresh_os_area_block_commit_cleanup_failure_trace"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-process-os-page-block-commit"
FIELDS = ("mapping_length", "reserved_final", "committed_final", "commit_calls",
    "warning_fragments", "release_exact", "retained", "warning_order",
    "warning_before_stats", "raw_release", "raw_no_stats")


def parse_trace(output: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        position = line.find("block.rollback.")
        if position < 0:
            continue
        line = line[position:]
        key, separator, raw = line.partition("=")
        name = key.removeprefix("block.rollback.")
        if not separator or name not in FIELDS or name in values or not raw.lstrip("-").isdecimal():
            raise ValueError(f"OS-page block-commit observation changed: {line}")
        values[name] = int(raw)
    if set(values) != set(FIELDS):
        raise ValueError(f"OS-page block-commit roster changed: {sorted(values)}")
    return values


def c_command(compiler: str, source: Path, binary: Path) -> list[str]:
    return [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
        "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
        str(FIXTURE), "-Wl,--wrap=mprotect", "-Wl,--wrap=munmap", "-pthread",
        "-o", str(binary)]


def run(*, offline: bool, rust_test_binary: Path | None = None) -> dict[str, Any]:
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    before = harness.m2_memory_substrate_source_state()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(prefix="crabc-m2-process-os-block-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-oracle"
        build = harness.command_record(c_command(harness.require_tool("musl-gcc"), source, binary),
            cwd=source, timeout_seconds=300)
        harness.write_json(ARTIFACTS / "c-build.json", build)
        harness.require_success(build, "OS-page block-commit pinned C build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=90)
        harness.write_json(ARTIFACTS / "c-run.json", c_run)
        harness.require_success(c_run, "OS-page block-commit pinned C receiver")
    if rust_test_binary is None:
        program = harness._x86_64_unit_test_program(harness._m2_x86_64_vm_rust_execution(),
            harness.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET,
            gate_name="process-owned OS-page block-commit receiver")
        rust_test_binary = program["path"]
    rust_command = [str(rust_test_binary), TARGET, "--exact", "--test-threads=1", "--nocapture"]
    rust_run = harness.command_record(rust_command, cwd=ROOT, timeout_seconds=300)
    harness.write_json(ARTIFACTS / "rust-run.json", rust_run)
    harness.require_success(rust_run, "OS-page block-commit Rust receiver")
    if harness.parse_rust_test_count(rust_run["stdout"] + rust_run["stderr"]) != 1:
        raise ValueError("OS-page block-commit Rust exact test count changed")
    c = parse_trace(c_run["stdout"])
    rust = parse_trace(rust_run["stdout"] + rust_run["stderr"])
    mismatches = {key: {"c": c[key], "rust": rust[key]}
        for key in FIELDS if c[key] != rust[key]}
    if mismatches:
        raise ValueError(f"OS-page block-commit C/Rust red: {json.dumps(mismatches, sort_keys=True)}")
    if [c[key] for key in FIELDS] != [131072, 0, -131072, 2, 4, 1, 1, 1, 1, 1, 1]:
        raise ValueError("pinned C block-commit rollback outcome changed")
    after = harness.m2_memory_substrate_source_state()
    if before != after:
        raise ValueError("OS-page block-commit source changed during receiver")
    report = {"status": "passed", "pinned_revision": pin["revision"],
        "archive_sha256": pin["sha256"], "source_before": before, "source_after": after,
        "c_build": build, "c_run": c_run, "rust_run": rust_run,
        "fixture": harness.artifact_record(FIXTURE), "c_trace": c, "rust_trace": rust,
        "comparison": {"status": "matched", "compared_value_count": len(FIELDS)}}
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
        print(f"OS-page block-commit receiver: {error}", file=sys.stderr)
        return 1
    print("OS-page block-commit receiver PASS "
          f"({report['comparison']['compared_value_count']} exact relations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
