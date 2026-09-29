#!/usr/bin/env python3
"""Compare one process-owned unprotect failure and same-range retry with pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_process_owned_unprotect_fault_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-process-owned-unprotect-fault"
TEST = "os::tests::emit_m2_process_owned_unprotect_fault_c_rust_trace"
FIELDS = (
    "allocated", "memid_os", "page_size", "mapping_size", "request_offset",
    "request_size", "initially_protected", "mapped_while_protected",
    "failed_unprotect", "mapped_after_failure", "retry_unprotect",
    "writable_after_retry", "protection_calls", "protect_offset", "protect_length",
    "protect_flags", "unprotect1_offset", "unprotect1_length", "unprotect1_flags",
    "unprotect2_offset", "unprotect2_length", "unprotect2_flags",
    "warning_order", "warning_count",
    "warning_errno", "warning_text_exact", "warning_offset", "warning_size",
    "warning_protection_calls",
    "reserved_at_map", "committed_at_map", "commits_at_map", "mmaps_at_map",
    "warning_reserved", "warning_committed", "warning_commit_calls",
    "warning_mmap_calls", "reserved_after_protection", "committed_after_protection",
    "commits_after_protection", "mmaps_after_protection", "terminal_reserved",
    "terminal_committed", "terminal_unmapped",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_PROCESS_OWNED_UNPROTECT_FAULT_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_PROCESS_OWNED_UNPROTECT_FAULT_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} unprotect fault markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} unprotect fault field is malformed")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} unprotect fault fields differ: {sorted(values)}")
    return values


def expected() -> dict[str, int]:
    return {
        "allocated": 1, "memid_os": 1, "page_size": 4096,
        "mapping_size": 12288, "request_offset": 19, "request_size": 8197,
        "initially_protected": 1, "mapped_while_protected": 1,
        "failed_unprotect": 1, "mapped_after_failure": 1,
        "retry_unprotect": 1, "writable_after_retry": 1,
        "protection_calls": 3, "protect_offset": 4096,
        "protect_length": 4096, "protect_flags": 0,
        "unprotect1_offset": 4096, "unprotect1_length": 4096,
        "unprotect1_flags": 3, "unprotect2_offset": 4096,
        "unprotect2_length": 4096, "unprotect2_flags": 3,
        "warning_order": 2, "warning_count": 1, "warning_errno": 12,
        "warning_text_exact": 1,
        "warning_offset": 4096, "warning_size": 4096,
        "warning_protection_calls": 2, "reserved_at_map": 12288,
        "committed_at_map": 12288, "commits_at_map": 0,
        "mmaps_at_map": 1, "warning_reserved": 12288,
        "warning_committed": 12288, "warning_commit_calls": 0,
        "warning_mmap_calls": 1, "reserved_after_protection": 12288,
        "committed_after_protection": 12288,
        "commits_after_protection": 0, "mmaps_after_protection": 1,
        "terminal_reserved": 0, "terminal_committed": 0,
        "terminal_unmapped": 1,
    }


def c_oracle(*, offline: bool) -> tuple[dict[str, int], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-process-owned-unprotect-fault-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-process-owned-unprotect-fault"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mprotect", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        (ARTIFACTS / "pinned-c-build.json").write_text(json.dumps(build, indent=2) + "\n")
        harness.require_success(build, "pinned C process-owned unprotect fault build")
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        (ARTIFACTS / "pinned-c-run.json").write_text(json.dumps(execution, indent=2) + "\n")
        harness.require_success(execution, "pinned C process-owned unprotect fault")
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
    (ARTIFACTS / "rust-build.json").write_text(json.dumps(build, indent=2) + "\n")
    harness.require_success(build, "Rust process-owned unprotect fault receiver build")
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
    (ARTIFACTS / "rust-run.json").write_text(json.dumps(execution, indent=2) + "\n")
    harness.require_success(execution, "Rust process-owned unprotect fault receiver")
    if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
        raise RuntimeError("Rust process-owned unprotect fault receiver did not execute once")
    return trace(str(execution["stdout"]), "RUST"), {
        "build_status": build["status"], "run_status": execution["status"],
        "stderr": execution["stderr"],
    }


def run(*, offline: bool, c_only: bool) -> dict[str, Any]:
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = ({}, {}) if c_only else rust_receiver()
    mismatches = [f"c.{field}" for field, value in expected().items() if c[field] != value]
    if not c_only:
        mismatches.extend(f"rust.{field}" for field, value in expected().items()
                          if rust[field] != value)
        mismatches.extend(f"differential.{field}" for field in FIELDS
                          if c[field] != rust[field])
    if c_commands["stderr"]:
        mismatches.append("c.unrouted_diagnostics")
    if not c_only and rust_commands["stderr"]:
        mismatches.append("rust.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red", "c": c, "rust": rust,
        "mismatches": mismatches, "c_commands": c_commands,
        "rust_commands": rust_commands,
        "scope": "regular process-owned OS mapping, conservative interior range, successful protect, injected first unprotect failure, same-range retry, and terminal free",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"process-owned unprotect fault {report['status'].upper()} ({len(FIELDS)} fields)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline, c_only=arguments.c_only)["status"] == "matched" else 1)
