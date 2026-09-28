#!/usr/bin/env python3
"""Compare explicit aligned arena metadata failure and cleanup with pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_explicit_arena_metadata_fault_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-explicit-arena-metadata-fault"
TEST = "process_arena::tests::emit_m2_explicit_arena_metadata_fault_c_rust_trace"
PROFILES = ("clean", "leaked")
FIELDS = (
    "profile", "size", "alignment", "prefix", "suffix", "refused",
    "no_memory_id", "geometry", "protection_exact", "protection_length",
    "warning_order", "warning_count", "warning_timing", "registry",
    "reserved_delta", "committed_delta", "mmap_calls_delta", "commit_calls_delta",
    "arena_count_delta", "middle_live", "raw_cleanup", "middle_gone",
    "raw_reserved_delta",
    "recovery_success", "recovery_memory_exact", "recovery_registry",
    "prior_live_during_recovery", "recovery_live", "recovery_reserved_delta",
    "recovery_committed_delta", "recovery_mmap_calls_delta",
    "recovery_commit_calls_delta", "recovery_arena_count_delta",
    "recovery_warning_count", "recovery_warning_order",
    "recovery_release_exact", "recovery_gone", "recovery_terminal_registry",
    "prior_live_after_release", "recovery_terminal_reserved_delta",
    "recovery_terminal_committed_delta",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_EXPLICIT_ARENA_METADATA_FAULT_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_EXPLICIT_ARENA_METADATA_FAULT_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} metadata fault markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} metadata fault malformed field")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} metadata fault fields differ: {sorted(values)}")
    return values


def expected(profile: str) -> dict[str, int]:
    leaked = profile == "leaked"
    return {
        "profile": int(leaked), "size": 32 * 1024 * 1024,
        "alignment": 256 * 1024 * 1024, "prefix": 256 * 1024 * 1024 - 4096,
        "suffix": 4096, "refused": 1, "no_memory_id": 1,
        "geometry": 1, "protection_exact": 1,
        "warning_order": 1234 if leaked else 123,
        "warning_count": 4 if leaked else 3,
        "warning_timing": 1, "registry": 0,
        "reserved_delta": 0, "committed_delta": 0,
        "mmap_calls_delta": 2, "commit_calls_delta": 1,
        "arena_count_delta": 0, "middle_live": int(leaked),
        "raw_cleanup": 1, "middle_gone": 1, "raw_reserved_delta": 0,
        "recovery_success": 1, "recovery_memory_exact": 1,
        "recovery_registry": 1, "prior_live_during_recovery": 1,
        "recovery_live": 1, "recovery_warning_count": 0,
        "recovery_warning_order": 1234 if leaked else 123,
        "recovery_reserved_delta": 32 * 1024 * 1024,
        "recovery_committed_delta": 589824,
        "recovery_mmap_calls_delta": 3,
        "recovery_commit_calls_delta": 2,
        "recovery_arena_count_delta": 1,
        "recovery_release_exact": 1, "recovery_gone": 1,
        "recovery_terminal_registry": 0, "prior_live_after_release": 1,
        "recovery_terminal_reserved_delta": 0,
        "recovery_terminal_committed_delta": -(32 * 1024 * 1024 - 589824),
    }


def c_oracle(*, offline: bool) -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-explicit-meta-fault-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-explicit-arena-metadata-fault"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=mprotect",
            "-Wl,--wrap=munmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C explicit arena metadata fault build")
        rows: dict[str, dict[str, int]] = {}
        runs = {}
        for profile in PROFILES:
            execution = harness.command_record([str(binary), profile], cwd=source, env={}, timeout_seconds=120)
            harness.require_success(execution, f"pinned C explicit metadata {profile}")
            rows[profile] = trace(str(execution["stdout"]), "C")
            runs[profile] = {"status": execution["status"], "stderr": execution["stderr"]}
        return rows, {"build_status": build["status"], "runs": runs}


def rust_receiver() -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    command = [
        "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", "--no-run",
        "--message-format=json",
    ]
    build = harness.command_record(command, cwd=ROOT, timeout_seconds=3600)
    harness.require_success(build, "Rust explicit metadata receiver build")
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
    rows: dict[str, dict[str, int]] = {}
    runs = {}
    for profile in PROFILES:
        execution = harness.command_record(
            [str(candidates[0]), TEST, "--exact", "--nocapture", "--test-threads=1"],
            cwd=ROOT, env={"CRABC_M2_EXPLICIT_METADATA_PROFILE": profile}, timeout_seconds=120,
        )
        harness.require_success(execution, f"Rust explicit metadata {profile}")
        if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
            raise RuntimeError(f"Rust explicit metadata {profile} did not execute once")
        rows[profile] = trace(str(execution["stdout"]), "RUST")
        runs[profile] = {"status": execution["status"], "stderr": execution["stderr"]}
    return rows, {"build_status": build["status"], "runs": runs}


def run(*, offline: bool, c_only: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = ({}, {}) if c_only else rust_receiver()
    mismatches = []
    for profile in PROFILES:
        for language, rows in (("c", c), ("rust", rust)):
            if language == "rust" and c_only:
                continue
            mismatches.extend(f"{language}.{profile}.{field}" for field, value in expected(profile).items()
                              if rows[profile][field] != value)
        if not c_only:
            mismatches.extend(f"differential.{profile}.{field}" for field in FIELDS
                              if c[profile][field] != rust[profile][field])
    if any(run["stderr"] for run in c_commands["runs"].values()):
        mismatches.append("c.unrouted_diagnostics")
    if not c_only and any(run["stderr"] for run in rust_commands["runs"].values()):
        mismatches.append("rust.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red", "c": c, "rust": rust,
        "mismatches": mismatches, "c_commands": c_commands,
        "rust_commands": rust_commands,
        "scope": "explicit aligned overmap metadata mprotect ENOMEM, prepublication cleanup success or failed munmap, subsequent successful reservation and terminal destroy, retained prior range and raw-only cleanup",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"explicit arena metadata fault {report['status'].upper()} ({len(PROFILES)} profiles, {len(FIELDS)} fields each)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline, c_only=arguments.c_only)["status"] == "matched" else 1)
