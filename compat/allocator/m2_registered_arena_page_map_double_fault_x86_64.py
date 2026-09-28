#!/usr/bin/env python3
"""Compare consecutive PageMap commit faults while an earlier arena remains live."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_registered_arena_page_map_double_fault_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-registered-arena-page-map-double-fault"
TEST = "process_arena::tests::emit_m2_registered_arena_page_map_double_fault_c_rust_trace"
FIELDS = (
    "first_reserved", "second_reserved", "first_claim_held", "partial_top",
    "registry_before_fault", "reserved_before_fault", "committed_before_fault",
    "commits_before_fault", "mmaps_before_fault", "first_returned",
    "first_in_second", "faults", "protection_calls", "first_protection_offset",
    "first_protection_length", "second_protection_offset", "second_protection_length",
    "third_protects_top", "third_protection_length", "third_protection_flags",
    "fourth_replays_top", "fourth_protection_flags", "fifth_replays_top",
    "fifth_protection_length", "fifth_protection_flags",
    "top_advanced_after_fault", "registry_after_failure", "reserved_after_failure",
    "committed_after_failure", "commits_after_failure", "mmaps_after_failure",
    "first_mapped", "second_mapped", "warning_order", "warning_count",
    "warning_first_commits", "warning_second_commits", "warning_first_committed",
    "warning_second_committed", "warning1_commits", "warning2_commits",
    "warning3_commits", "warning4_commits", "warning1_committed",
    "warning2_committed", "warning3_committed", "warning4_committed",
    "initial_top_count", "warning1_top_count", "warning2_top_count",
    "warning3_top_count", "warning4_top_count", "warning1_registry",
    "warning2_registry", "warning3_registry", "warning4_registry",
    "retry_in_second", "retry_published",
    "retry_cleared", "top_advanced", "registry_after_retry", "terminal_registry",
    "terminal_reserved", "terminal_committed", "terminal_first_gone",
    "terminal_second_gone",
)
HEADER_DEPENDENT_FIELDS = (
    "initial_top_count", "warning1_top_count", "warning2_top_count",
    "warning3_top_count", "warning4_top_count",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_REGISTERED_ARENA_PAGE_MAP_DOUBLE_FAULT_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_REGISTERED_ARENA_PAGE_MAP_DOUBLE_FAULT_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} PageMap fault markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} PageMap fault field is malformed")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} PageMap fault fields differ: {sorted(values)}")
    return values


def expected() -> dict[str, int]:
    return {
        "first_reserved": 1, "second_reserved": 1, "first_claim_held": 1,
        "partial_top": 1, "registry_before_fault": 2,
        "reserved_before_fault": 2 * 32 * 1024 * 1024,
        "committed_before_fault": 1_179_648,
        "commits_before_fault": 2, "mmaps_before_fault": 2,
        "first_returned": 1, "first_in_second": 1, "faults": 2,
        "protection_calls": 5, "first_protection_offset": 1_048_576,
        "first_protection_length": 524_288, "second_protection_offset": 0,
        "second_protection_length": 524_288, "third_protects_top": 1,
        "third_protection_length": 327_680, "fourth_replays_top": 1,
        "third_protection_flags": 3, "fourth_protection_flags": 3,
        "fifth_replays_top": 1, "fifth_protection_length": 327_680,
        "fifth_protection_flags": 3,
        "top_advanced_after_fault": 1, "registry_after_failure": 2,
        "reserved_after_failure": 67_174_400,
        "committed_after_failure": 2_621_440,
        "commits_after_failure": 7, "mmaps_after_failure": 3,
        "first_mapped": 1, "second_mapped": 1,
        "warning_order": 1212, "warning_count": 4,
        "warning_first_commits": 6, "warning_second_commits": 6,
        "warning_first_committed": 2_228_224,
        "warning_second_committed": 2_228_224,
        "warning1_commits": 5, "warning2_commits": 5,
        "warning3_commits": 6, "warning4_commits": 6,
        "warning1_committed": 2_228_224, "warning2_committed": 2_228_224,
        "warning3_committed": 2_228_224, "warning4_committed": 2_228_224,
        "initial_top_count": 16_886,
        "warning1_top_count": 16_886, "warning2_top_count": 16_886,
        "warning3_top_count": 16_886, "warning4_top_count": 16_886,
        "warning1_registry": 2, "warning2_registry": 2,
        "warning3_registry": 2, "warning4_registry": 2,
        "retry_in_second": 1, "retry_published": 1, "retry_cleared": 1,
        "top_advanced": 1, "registry_after_retry": 2,
        "terminal_registry": 0, "terminal_reserved": 65_536,
        "terminal_committed": -64_487_424,
        "terminal_first_gone": 1, "terminal_second_gone": 1,
    }


def c_oracle(*, offline: bool) -> tuple[dict[str, int], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-registered-page-map-fault-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-registered-arena-page-map-fault"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=mprotect",
            "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C registered arena PageMap fault build")
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, "pinned C registered arena PageMap fault")
        return trace(str(execution["stdout"]), "C"), {
            "build_status": build["status"], "run_status": execution["status"],
            "stderr": execution["stderr"],
        }


def rust_receiver() -> tuple[dict[str, int], dict[str, Any]]:
    command = [
        "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", "--no-run",
        "--message-format=json",
    ]
    build = harness.command_record(command, cwd=ROOT, timeout_seconds=3600)
    harness.require_success(build, "Rust registered arena PageMap fault receiver build")
    candidates: list[Path] = []
    for line in str(build["stdout"]).splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = event.get("target", {})
        profile = event.get("profile", {})
        if (event.get("reason") == "compiler-artifact" and target.get("name") == "crabc_mimalloc"
                and target.get("kind") == ["lib"] and profile.get("test") is True
                and isinstance(event.get("executable"), str)):
            candidates.append(Path(event["executable"]))
    if len(candidates) != 1:
        raise RuntimeError(f"expected one Rust library test binary, found {len(candidates)}")
    execution = harness.command_record(
        [str(candidates[0]), TEST, "--exact", "--nocapture", "--test-threads=1"],
        cwd=ROOT, env={}, timeout_seconds=120,
    )
    harness.require_success(execution, "Rust registered arena PageMap fault receiver")
    if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
        raise RuntimeError("Rust registered arena PageMap fault receiver did not execute once")
    return trace(str(execution["stdout"]), "RUST"), {
        "build_status": build["status"], "run_status": execution["status"],
        "stderr": execution["stderr"],
    }


def run(*, offline: bool, c_only: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = ({}, {}) if c_only else rust_receiver()
    mismatches = [f"c.{field}" for field, value in expected().items() if c[field] != value]
    if not c_only:
        mismatches.extend(f"rust.{field}" for field, value in expected().items()
                          if field not in HEADER_DEPENDENT_FIELDS and rust[field] != value)
        mismatches.extend(f"differential.{field}" for field in FIELDS
                          if field not in HEADER_DEPENDENT_FIELDS and c[field] != rust[field])
        # The mapped header occupies different numbers of pointer slots, so
        # each implementation must preserve its own initial published prefix
        # during both failures before the final successful commit advances it.
        if rust["initial_top_count"] <= 0:
            mismatches.append("rust.initial_top_count")
        for field in HEADER_DEPENDENT_FIELDS[1:]:
            if rust[field] != rust["initial_top_count"]:
                mismatches.append(f"rust.{field}")
    if c_commands["stderr"]:
        mismatches.append("c.unrouted_diagnostics")
    if not c_only and rust_commands["stderr"]:
        mismatches.append("rust.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red", "c": c, "rust": rust,
        "mismatches": mismatches, "c_commands": c_commands,
        "rust_commands": rust_commands,
        "header_dependent_top_counts": {
            "c": {field: c[field] for field in HEADER_DEPENDENT_FIELDS},
            "rust": {field: rust[field] for field in HEADER_DEPENDENT_FIELDS} if not c_only else {},
        },
        "scope": "two failed lazy PageMap top commits during one high-level first-page allocation from the second explicit arena, followed by retry, retained first arena, and terminal release",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"registered arena PageMap double fault {report['status'].upper()} ({len(FIELDS)} fields)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline, c_only=arguments.c_only)["status"] == "matched" else 1)
