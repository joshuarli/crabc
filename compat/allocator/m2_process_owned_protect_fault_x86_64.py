#!/usr/bin/env python3
"""Compare one process-owned protect failure and same-range retry with pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_process_owned_protect_fault_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-process-owned-protect-fault"
TEST = "os::tests::emit_m2_process_owned_protect_fault_c_rust_trace"
FIELDS = (
    "allocated", "memid_os", "page_size", "mapping_size", "request_offset",
    "request_size", "failed_protect", "writable_after_failure", "retry_protect",
    "mapped_while_protected", "unprotected", "writable_after_unprotect",
    "protection_calls", "protect1_offset", "protect1_length", "protect1_flags",
    "protect2_offset", "protect2_length", "protect2_flags", "unprotect_offset",
    "unprotect_length", "unprotect_flags", "warning_order", "warning_count",
    "warning_errno", "warning_text_exact", "warning_offset", "warning_size",
    "warning_protection_calls",
    "reserved_at_map", "committed_at_map", "commits_at_map", "mmaps_at_map",
    "warning_reserved", "warning_committed", "warning_commit_calls",
    "warning_mmap_calls", "reserved_after_protection", "committed_after_protection",
    "commits_after_protection", "mmaps_after_protection", "terminal_reserved",
    "terminal_committed", "terminal_unmapped",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_PROCESS_OWNED_PROTECT_FAULT_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_PROCESS_OWNED_PROTECT_FAULT_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} protect fault markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} protect fault field is malformed")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} protect fault fields differ: {sorted(values)}")
    return values


def expected() -> dict[str, int]:
    return {
        "allocated": 1, "memid_os": 1, "page_size": 4096,
        "mapping_size": 12288, "request_offset": 19, "request_size": 8197,
        "failed_protect": 1, "writable_after_failure": 1,
        "retry_protect": 1, "mapped_while_protected": 1,
        "unprotected": 1, "writable_after_unprotect": 1,
        "protection_calls": 3, "protect1_offset": 4096,
        "protect1_length": 4096, "protect1_flags": 0,
        "protect2_offset": 4096, "protect2_length": 4096,
        "protect2_flags": 0, "unprotect_offset": 4096,
        "unprotect_length": 4096, "unprotect_flags": 3,
        "warning_order": 1, "warning_count": 1, "warning_errno": 12,
        "warning_text_exact": 1,
        "warning_offset": 4096, "warning_size": 4096,
        "warning_protection_calls": 1, "reserved_at_map": 12288,
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
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-process-owned-protect-fault-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-process-owned-protect-fault"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mprotect", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C process-owned protect fault build")
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, "pinned C process-owned protect fault")
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
    harness.require_success(build, "Rust process-owned protect fault receiver build")
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
    harness.require_success(execution, "Rust process-owned protect fault receiver")
    if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
        raise RuntimeError("Rust process-owned protect fault receiver did not execute once")
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
        "scope": "regular process-owned OS mapping, conservative interior protect range, injected first mprotect failure, same-range protect retry, unprotect, and terminal free",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"process-owned protect fault {report['status'].upper()} ({len(FIELDS)} fields)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline, c_only=arguments.c_only)["status"] == "matched" else 1)
