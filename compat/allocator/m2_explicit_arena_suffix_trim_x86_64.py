#!/usr/bin/env python3
"""Compare explicit process-owned arena suffix trim and terminal release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_explicit_arena_suffix_trim_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-explicit-arena-suffix-trim"
TEST = "process_arena::tests::emit_m2_explicit_arena_suffix_trim_c_rust_trace"
FIELDS = (
    "size", "alignment", "prefix", "suffix", "reserve_success", "memory_exact",
    "geometry", "warning_order", "warning_count", "warning_timing",
    "warning_fallback_reserved", "warning_free_reserved",
    "warning_fallback_committed", "warning_free_committed",
    "registry_claimed", "claimed_reserved", "claimed_committed", "claimed_mmap_calls",
    "claimed_arena_delta", "escaped_live", "middle_live", "terminal_exact",
    "middle_gone", "escaped_still_live", "registry_terminal", "terminal_reserved",
    "terminal_committed", "terminal_arena_delta", "raw_cleanup", "escaped_gone",
    "raw_reserved",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_EXPLICIT_ARENA_SUFFIX_TRIM_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_EXPLICIT_ARENA_SUFFIX_TRIM_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} explicit trim trace markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} explicit trim trace has malformed field")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} explicit trim fields differ: {sorted(values)}")
    return values


def c_oracle(*, offline: bool) -> tuple[dict[str, int], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-explicit-arena-trim-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-explicit-arena-suffix-trim"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=munmap", "-pthread",
            "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C explicit arena trim build")
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, "pinned C explicit arena trim")
        return trace(str(execution["stdout"]), "C"), {
            "build_status": build["status"], "run_status": execution["status"],
            "stderr": str(execution["stderr"]),
        }


def rust_receiver() -> tuple[dict[str, int], dict[str, Any]]:
    command = [
        "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", "--no-run",
        "--message-format=json",
    ]
    build = harness.command_record(command, cwd=ROOT, timeout_seconds=3600)
    harness.require_success(build, "Rust explicit arena trim receiver build")
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
    harness.require_success(execution, "Rust explicit arena trim receiver")
    if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
        raise RuntimeError("Rust explicit arena trim receiver did not execute once")
    return trace(str(execution["stdout"]), "RUST"), {
        "build_status": build["status"], "run_status": execution["status"],
        "stderr": str(execution["stderr"]),
    }


def run(*, offline: bool, c_only: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = ({}, {}) if c_only else rust_receiver()
    mismatches = [] if c_only else [field for field in FIELDS if c[field] != rust[field]]
    expected = {
        "size": 32 * 1024 * 1024, "alignment": 256 * 1024 * 1024,
        "prefix": 128 * 1024 * 1024, "suffix": 128 * 1024 * 1024,
        "reserve_success": 1, "memory_exact": 1,
        "geometry": 1, "warning_order": 12, "warning_count": 2,
        "warning_timing": 1, "warning_fallback_committed": 0,
        "warning_free_committed": 0,
        "warning_fallback_reserved": 32 * 1024 * 1024,
        "warning_free_reserved": 160 * 1024 * 1024,
        "registry_claimed": 1,
        "claimed_reserved": 32 * 1024 * 1024, "claimed_committed": 589824,
        "claimed_mmap_calls": 2,
        "claimed_arena_delta": 1, "escaped_live": 1, "middle_live": 1,
        "terminal_exact": 1, "middle_gone": 1, "escaped_still_live": 1,
        "registry_terminal": 0, "terminal_reserved": 0,
        "terminal_committed": 589824 - 32 * 1024 * 1024,
        "terminal_arena_delta": 1, "raw_cleanup": 1, "escaped_gone": 1,
        "raw_reserved": 0,
    }
    for language, row in (("c", c), ("rust", rust)):
        if language == "rust" and c_only:
            continue
        mismatches.extend(f"{language}.{field}" for field, value in expected.items()
                          if row[field] != value)
    if c_commands["stderr"] or (not c_only and rust_commands["stderr"]):
        mismatches.append("unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red", "c": c, "rust": rust,
        "mismatches": mismatches, "c_commands": c_commands,
        "rust_commands": rust_commands,
        "scope": "explicit regular OS arena reserve; source-sized fixed unaligned direct and overmap targets; failed suffix release, published arena, terminal arena destroy, escaped suffix raw-only cleanup",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"explicit arena suffix trim {report['status'].upper()} ({len(FIELDS)} exact fields)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline, c_only=arguments.c_only)["status"] == "matched" else 1)
