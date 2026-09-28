#!/usr/bin/env python3
"""Compare a second metadata fault with a live explicit arena against pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_registered_arena_metadata_fault_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-registered-arena-metadata-fault"
TEST = "process_arena::tests::emit_m2_registered_arena_metadata_fault_c_rust_trace"
FIELDS = (
    "size", "alignment", "first_exact", "first_registry", "first_reserved",
    "first_committed", "first_mmap", "first_commit", "second_refused",
    "first_id_retained", "first_survives", "second_gone",
    "after_failure_registry", "failed_reserved", "failed_committed",
    "failed_mmap", "failed_commit", "failed_arena", "warning_order",
    "warning_count", "warning_timing", "fault_geometry", "survivor_claim",
    "survivor_rw", "first_after_claim", "claim_registry", "claim_committed",
    "claim_commit", "terminal_exact", "first_gone", "terminal_registry",
    "terminal_reserved", "terminal_committed", "terminal_arena",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_REGISTERED_ARENA_METADATA_FAULT_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_REGISTERED_ARENA_METADATA_FAULT_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} registered arena metadata markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} registered arena metadata field is malformed")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} registered arena metadata fields differ: {sorted(values)}")
    return values


def expected() -> dict[str, int]:
    return {
        "size": 32 * 1024 * 1024,
        "alignment": 256 * 1024 * 1024,
        "first_exact": 1, "first_registry": 1,
        "first_reserved": 32 * 1024 * 1024,
        "first_committed": 589824,
        "first_mmap": 1, "first_commit": 1,
        "second_refused": 1, "first_id_retained": 1,
        "first_survives": 1, "second_gone": 1,
        "after_failure_registry": 1,
        "failed_reserved": 32 * 1024 * 1024,
        "failed_committed": 589824,
        "failed_mmap": 2, "failed_commit": 2, "failed_arena": 1,
        "warning_order": 23, "warning_count": 2, "warning_timing": 1,
        "fault_geometry": 1,
        "survivor_claim": 1, "survivor_rw": 1,
        "first_after_claim": 1, "claim_registry": 1,
        "claim_committed": 655360, "claim_commit": 3,
        "terminal_exact": 1, "first_gone": 1,
        "terminal_registry": 0,
        "terminal_reserved": 0,
        "terminal_committed": -(32 * 1024 * 1024 - 655360),
        "terminal_arena": 1,
    }


def c_oracle(*, offline: bool) -> tuple[dict[str, int], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-registered-meta-fault-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-registered-arena-metadata-fault"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=mprotect",
            "-Wl,--wrap=munmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C registered arena metadata fault build")
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, "pinned C registered arena metadata fault")
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
    harness.require_success(build, "Rust registered arena metadata receiver build")
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
    harness.require_success(execution, "Rust registered arena metadata receiver")
    if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
        raise RuntimeError("Rust registered arena metadata receiver did not execute once")
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
        "scope": "second explicit arena metadata mprotect ENOMEM while first remains registered, survivor claim and terminal release",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"registered arena metadata fault {report['status'].upper()} ({len(FIELDS)} fields)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline, c_only=arguments.c_only)["status"] == "matched" else 1)
