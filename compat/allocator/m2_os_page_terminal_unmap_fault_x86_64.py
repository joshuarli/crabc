#!/usr/bin/env python3
"""Compare a failed published OS-page release and later owner with pinned C."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import run as harness


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_suffix(".c")
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-os-page-terminal-unmap-fault"
TEST = "os_page::tests::emit_m2_os_page_terminal_unmap_fault_c_rust_trace"
FIELDS = (
    "first_published", "first_size", "first_page_map_clear", "unmap_calls",
    "failed_range_exact", "warning_calls", "warning_exact", "warning_before_stats",
    "first_escaped", "first_reserved_delta", "first_committed_delta",
    "first_commit_calls_delta", "first_mmap_calls_delta", "second_published",
    "second_size", "second_live_reserved", "second_live_committed",
    "second_range_exact", "second_unmapped", "first_still_escaped",
    "second_reserved_delta", "second_committed_delta", "raw_cleanup",
    "terminal_unmapped", "raw_reserved_delta", "raw_committed_delta",
)
LINE = re.compile(r"^([a-z_]+)=(-?[0-9]+)$")


def trace(output: str, label: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            continue
        key, value = match.groups()
        if key in FIELDS:
            if key in values:
                raise harness.HarnessError(f"{label} repeats {key}")
            values[key] = int(value)
    if set(values) != set(FIELDS):
        raise harness.HarnessError(f"{label} trace roster differs: {sorted(values)}")
    return values


def c_oracle(offline: bool) -> tuple[dict[str, int], dict]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(prefix="m2-os-page-terminal-unmap-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-oracle"
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=munmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C published OS-page terminal unmap build")
        execution = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
        harness.require_success(execution, "pinned C published OS-page terminal unmap")
    (ARTIFACTS / "pinned-c.stdout").write_text(str(execution["stdout"]))
    (ARTIFACTS / "pinned-c.stderr").write_text(str(execution["stderr"]))
    return trace(str(execution["stdout"]), "pinned C"), {
        "build_status": build["status"], "run_status": execution["status"],
        "stderr": execution["stderr"],
    }


def rust_receiver() -> tuple[dict[str, int], dict]:
    command = ["python3", "compat/allocator/run_unit_x86_64.py", TEST]
    execution = harness.command_record(command, cwd=ROOT, timeout_seconds=900)
    (ARTIFACTS / "rust.stdout").write_text(str(execution["stdout"]))
    (ARTIFACTS / "rust.stderr").write_text(str(execution["stderr"]))
    harness.require_success(execution, "Rust published OS-page terminal unmap receiver")
    return trace(str(execution["stdout"]), "Rust"), {
        "run_status": execution["status"], "stderr": execution["stderr"],
    }


def run(offline: bool, c_only: bool) -> dict:
    harness.require_native_x86_64()
    c, c_commands = c_oracle(offline)
    rust, rust_commands = ({}, {}) if c_only else rust_receiver()
    # A fresh randomized VA can select another lazy PageMap submap. Its 64 KiB
    # node remains live after the OS page is freed, independent of page ownership.
    node_dependent = {
        "second_live_reserved", "second_live_committed", "second_reserved_delta",
        "second_committed_delta", "raw_reserved_delta", "raw_committed_delta",
    }
    mismatches = [] if c_only else [field for field in FIELDS
                                     if field not in node_dependent and c[field] != rust[field]]
    node_growth: dict[str, int] = {}
    for label, values in (("c", c), ("rust", rust)):
        if not values:
            continue
        extra = values["second_live_reserved"] - values["second_size"]
        node_growth[label] = extra
        if (extra not in (0, 65536)
                or values["second_live_committed"] != values["second_size"] - 65536 + extra
                or any(values[field] != extra for field in (
                    "second_reserved_delta", "second_committed_delta",
                    "raw_reserved_delta", "raw_committed_delta"))):
            mismatches.append(f"{label}.second_page_map_accounting")
    required_ones = {
        "first_published", "first_page_map_clear", "failed_range_exact",
        "warning_calls", "warning_exact", "warning_before_stats", "first_escaped",
        "second_published", "second_range_exact", "second_unmapped", "first_still_escaped",
        "raw_cleanup", "terminal_unmapped",
    }
    mismatches.extend(f"c.{field}" for field in required_ones if c[field] != 1)
    if c["unmap_calls"] != 2 or c["first_size"] != c["second_size"]:
        mismatches.append("c.source_order")
    if c_commands["stderr"]:
        mismatches.append("c.unrouted_diagnostics")
    if not c_only and rust_commands["stderr"]:
        mismatches.append("rust.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red", "c": c, "rust": rust,
        "mismatches": sorted(mismatches), "c_commands": c_commands,
        "rust_commands": rust_commands,
        "second_page_map_node_bytes": node_growth,
        "scope": "fully committed published OS page, failed terminal unmap, PageMap removal, independent later OS page, raw leaked-map cleanup",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"published OS-page terminal unmap fault {report['status'].upper()} ({len(FIELDS)} fields)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(arguments.offline, arguments.c_only)["status"] == "matched" else 1)
