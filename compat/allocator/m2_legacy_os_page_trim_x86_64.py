#!/usr/bin/env python3
"""Pinned C and native Rust trace for one processless aligned OS page claim."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import run as harness


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_legacy_os_page_trim_x86_64.c"
TARGET = "os::tests::emit_legacy_os_page_suffix_trim_trace"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-legacy-os-page-trim"
COMMON = ("memory_exact", "suffix_exact", "terminal_exact", "middle_length",
    "escaped_suffix_length", "raw_middle", "raw_suffix", "raw_no_stats")
STATS = ("reserved_claim", "committed_claim", "mmap_claim",
    "reserved_final", "committed_final")
WARNINGS = ("warning_fragments", "warning_bodies", "warning_order", "warning_before_stats")
RUST_EXTRA = ("suffix_still_live",)


def parse_trace(output: str, *, language: str) -> dict[str, int]:
    expected = (*COMMON, *STATS, *(WARNINGS if language == "C" else RUST_EXTRA))
    values: dict[str, int] = {}
    for line in output.splitlines():
        if not line.startswith("legacy.claim."):
            continue
        key, separator, raw = line.partition("=")
        name = key.removeprefix("legacy.claim.")
        if not separator or name not in expected or name in values or not raw.lstrip("-").isdecimal():
            raise ValueError(f"{language} legacy OS-page observation changed: {line}")
        values[name] = int(raw)
    if set(values) != set(expected):
        raise ValueError(f"{language} legacy OS-page observation roster changed: {sorted(values)}")
    return values


def compare(c: dict[str, int], rust: dict[str, int], *, strict_equality: bool) -> dict[str, Any]:
    mismatches = {key: {"c": c[key], "rust": rust[key]}
        for key in (*COMMON, *STATS) if c[key] != rust[key]}
    if strict_equality and mismatches:
        raise ValueError(f"legacy OS-page source/Rust red: {json.dumps(mismatches, sort_keys=True)}")
    if any(c[key] != rust[key] for key in COMMON):
        raise ValueError("legacy OS-page physical ownership or exact range differs")
    if [c[key] for key in STATS] != [196608, 65536, 2, 0, 0]:
        raise ValueError("pinned C aligned OS-page statistics changed")
    if [rust[key] for key in STATS] != [0, 0, 0, 0, 0]:
        raise ValueError("processless Rust aligned OS-page statistics changed")
    if [c[key] for key in WARNINGS] != [6, 3, 1, 1]:
        raise ValueError("pinned C warning fragments, order, or timing changed")
    if rust["suffix_still_live"] != 1:
        raise ValueError("Rust raw retry disturbed the escaped suffix")
    if [c[key] for key in COMMON] != [1, 1, 1, 196608, 4096, 1, 1, 1]:
        raise ValueError("legacy OS-page exact mapping or cleanup changed")
    return {"status": "source-different", "shared_relations": len(COMMON),
        "known_differences": mismatches,
        "reason": "the legacy Rust claim has no VmProcess for source warning or subprocess accounting"}


def c_command(compiler: str, source: Path, binary: Path) -> list[str]:
    return [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
        "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
        str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=munmap", "-pthread",
        "-o", str(binary)]


def run(*, offline: bool, rust_test_binary: Path | None = None,
        strict_equality: bool = False) -> dict[str, Any]:
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    before = harness.m2_memory_substrate_source_state()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(prefix="crabc-m2-legacy-os-page-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-oracle"
        build = harness.command_record(c_command(harness.require_tool("musl-gcc"), source, binary),
            cwd=source, timeout_seconds=300)
        harness.write_json(ARTIFACTS / "c-build.json", build)
        harness.require_success(build, "legacy OS-page pinned C build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=90)
        harness.write_json(ARTIFACTS / "c-run.json", c_run)
        harness.require_success(c_run, "legacy OS-page pinned C receiver")
        c_source = str(source)
    if rust_test_binary is None:
        program = harness._x86_64_unit_test_program(harness._m2_x86_64_vm_rust_execution(),
            harness.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET,
            gate_name="legacy OS-page trim receiver")
        rust_test_binary = program["path"]
    rust_command = [str(rust_test_binary), TARGET, "--exact", "--test-threads=1", "--nocapture"]
    rust_run = harness.command_record(rust_command, cwd=ROOT, timeout_seconds=300)
    harness.write_json(ARTIFACTS / "rust-run.json", rust_run)
    harness.require_success(rust_run, "legacy OS-page Rust receiver")
    if harness.parse_rust_test_count(rust_run["stdout"] + rust_run["stderr"]) != 1:
        raise ValueError("legacy OS-page Rust exact test count changed")
    c = parse_trace(c_run["stdout"], language="C")
    rust = parse_trace(rust_run["stdout"] + rust_run["stderr"], language="Rust")
    comparison = compare(c, rust, strict_equality=strict_equality)
    if "mimalloc: warning:" in rust_run["stderr"]:
        raise ValueError("processless Rust receiver unexpectedly emitted a source warning")
    after = harness.m2_memory_substrate_source_state()
    if before != after:
        raise ValueError("legacy OS-page source changed during the receiver")
    report = {"status": "passed", "pinned_revision": pin["revision"],
        "archive_sha256": pin["sha256"], "source_before": before, "source_after": after,
        "c_source": c_source, "c_build": build, "c_run": c_run, "rust_run": rust_run,
        "fixture": harness.artifact_record(FIXTURE), "c_trace": c, "rust_trace": rust,
        "comparison": comparison}
    harness.write_json(ARTIFACTS / "evidence.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--rust-test-binary", type=Path)
    parser.add_argument("--strict-equality", action="store_true")
    arguments = parser.parse_args()
    try:
        report = run(offline=arguments.offline, rust_test_binary=arguments.rust_test_binary,
            strict_equality=arguments.strict_equality)
    except Exception as error:
        print(f"legacy OS-page trim receiver: {error}", file=sys.stderr)
        return 1
    print("legacy OS-page trim receiver PASS "
          f"({report['comparison']['shared_relations']} shared relations, "
          f"{len(report['comparison']['known_differences'])} explicit source differences)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
