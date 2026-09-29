#!/usr/bin/env python3
"""Compare a faulted fresh arena and later healthy claim with pinned C."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import run as harness


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_suffix(".c")
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-fresh-arena-dual-fault"
TEST = "arena::tests::emit_m2_fresh_arena_dual_fault_c_rust_trace"
FIELDS = (
    "refused", "no_memory_id", "registry_before", "failed_registry",
    "metadata_calls", "metadata_size", "metadata_exact", "cleanup_calls",
    "escaped_size", "escaped_aligned", "escaped_live",
    "warning_fragments", "warning_bodies", "warning_order",
    "fallback_warning_before_stats",
    "warning_commit_before_stats", "warning_meta_before_stats",
    "warning_free_before_stats",
    "reserved_after_failure", "committed_after_failure",
    "mmap_after_failure", "commit_after_failure", "arena_after_failure",
    "recovery_memory", "recovery_slice_index", "recovery_slice_count",
    "recovery_initially_committed", "recovery_initially_zero",
    "recovery_is_pinned", "recovery_arena_info_slices", "recovery_arena_size",
    "recovery_registry", "recovery_bitmap_claimed",
    "prior_live_during_recovery", "recovery_reserved_delta",
    "recovery_committed_delta", "recovery_mmap_delta",
    "recovery_commit_delta", "recovery_arena_delta", "claim_released",
    "recovery_mapping_live", "prior_live_after_release",
    "release_warnings", "raw_cleanup", "raw_gone", "raw_no_stats",
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
    with harness.temporary_directory(prefix="m2-fresh-arena-dual-fault-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-oracle"
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=munmap", "-Wl,--wrap=mprotect",
            "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C fresh arena dual fault build")
        execution = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
        harness.require_success(execution, "pinned C fresh arena dual fault")
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
    harness.require_success(execution, "Rust fresh arena dual fault receiver")
    return trace(str(execution["stdout"]), "Rust"), {
        "run_status": execution["status"], "stderr": execution["stderr"],
    }


def run(offline: bool, c_only: bool) -> dict:
    harness.require_native_x86_64()
    c, c_commands = c_oracle(offline)
    rust, rust_commands = ({}, {}) if c_only else rust_receiver()
    required_ones = {
        "refused", "no_memory_id", "metadata_exact", "escaped_aligned",
        "escaped_live", "fallback_warning_before_stats",
        "warning_commit_before_stats", "warning_meta_before_stats",
        "warning_free_before_stats",
        "recovery_memory", "recovery_bitmap_claimed", "prior_live_during_recovery",
        "claim_released", "recovery_mapping_live", "prior_live_after_release",
        "raw_cleanup", "raw_gone", "raw_no_stats",
    }
    alignment_dependent = {
        "mmap_after_failure", "recovery_mmap_delta", "warning_bodies",
        "warning_fragments", "warning_order",
    }
    mismatches = [] if c_only else [field for field in FIELDS
                                     if field not in alignment_dependent and c[field] != rust[field]]
    selected_alignment_fallback: dict[str, int] = {}
    for label, values in (("c", c), ("rust", rust)):
        if not values:
            continue
        fallback = values["mmap_after_failure"] - 1
        selected_alignment_fallback[label] = fallback
        if (fallback not in (0, 1)
                or values["recovery_mmap_delta"] != 2 + fallback
                or values["warning_bodies"] != 3 + fallback
                or values["warning_fragments"] != 3 + fallback
                or values["warning_order"] != (4123 if fallback else 123)):
            mismatches.append(f"{label}.aligned_map_branch")
    mismatches.extend(f"c.{field}" for field in required_ones if c[field] != 1)
    if (c["metadata_calls"] != 1 or c["cleanup_calls"] != 1
            or c["failed_registry"] != c["registry_before"]
            or c["recovery_registry"] != c["registry_before"] + 1):
        mismatches.append("c.source_order")
    if c_commands["stderr"]:
        mismatches.append("c.unrouted_diagnostics")
    if not c_only and rust_commands["stderr"]:
        mismatches.append("rust.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red", "c": c, "rust": rust,
        "mismatches": sorted(mismatches), "c_commands": c_commands,
        "rust_commands": rust_commands,
        "selected_alignment_fallback": selected_alignment_fallback,
        "scope": "fresh arena metadata commit and cleanup unmap fail; later independent arena claim releases while registered arena stays process-lived; raw cleanup of escaped map",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"fresh arena dual fault {report['status'].upper()} ({len(FIELDS)} fields)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(arguments.offline, arguments.c_only)["status"] == "matched" else 1)
