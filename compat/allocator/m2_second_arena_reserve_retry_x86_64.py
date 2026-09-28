#!/usr/bin/env python3
"""Compare failed second-arena mapping and retry against pinned C."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "process_arena::tests::emit_m2_second_arena_reserve_retry_c_rust_trace"
C_ONLY = ("failed_maps", "failed_direct", "failed_overmap", "failed_unmaps")
RUST_ONLY = ("rust_failed_map_attempts",)
FIELDS = (
    "first_full", "failed_null", "failed_registry", "first_claims_live",
    "failed_map_absent", "failed_mmap_calls", "failed_commit_calls",
    "failed_committed_delta", "failed_arena_delta", "os_warnings",
    "aligned_warnings", "failed_warning_order", "failed_warning_counter_order",
    "retry_second", "registry_order", "mapped_both", "reserved_delta",
    "arena_delta", "purge_calls", "released", "mappings_retained",
    "terminal_unmapped", "terminal_registry", "terminal_reserved_delta",
    "terminal_committed_delta",
)
LINE = re.compile(r"^m2\.second_reserve_retry\.([a-z_]+)=(-?[0-9]+)$")
EXPECTED = {
    "first_full": 1, "failed_null": 1, "failed_registry": 1,
    "first_claims_live": 1, "failed_map_absent": 1,
    "failed_maps": 4, "failed_direct": 2, "failed_overmap": 2,
    "failed_unmaps": 0, "failed_mmap_calls": 2,
    "failed_commit_calls": 0, "failed_committed_delta": 0,
    "failed_arena_delta": 0, "os_warnings": 2, "aligned_warnings": 1,
    "failed_warning_order": 121, "failed_warning_counter_order": 11,
    "retry_second": 1, "registry_order": 1, "mapped_both": 1,
    "reserved_delta": 64 * 1024 * 1024, "arena_delta": 1,
    "purge_calls": 0, "released": 1, "mappings_retained": 1,
    "terminal_unmapped": 1, "terminal_registry": 0,
    "terminal_reserved_delta": -(64 * 1024 * 1024),
    "terminal_committed_delta": -133627904,
    "rust_failed_map_attempts": 2,
}


def parse_trace(output: str, source: str, fields: set[str]) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.second_reserve_retry."):
                raise harness.HarnessError(f"{source} has malformed trace line: {candidate}")
            continue
        field, raw = match.groups()
        if field in values:
            raise harness.HarnessError(f"{source} repeats {field}")
        values[field] = int(raw)
    if set(values) != fields:
        raise harness.HarnessError(
            f"{source} trace roster differs: missing={sorted(fields - set(values))}, "
            f"unexpected={sorted(set(values) - fields)}"
        )
    return values


def run(offline: bool) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-second-arena-reserve-retry"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-second-arena-reserve-retry-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=munmap", "-pthread",
            "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C second-arena reservation oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C second-arena reservation oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C", set(FIELDS + C_ONLY))
    for field in FIELDS + C_ONLY:
        if c_trace[field] != EXPECTED[field]:
            raise harness.HarnessError(
                f"pinned C {field}={c_trace[field]}, expected {EXPECTED[field]}"
            )

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust second-arena reservation receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust", set(FIELDS + RUST_ONLY))
    differences = [f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
                   for field in FIELDS if c_trace[field] != rust_trace[field]]
    if rust_trace["rust_failed_map_attempts"] != EXPECTED["rust_failed_map_attempts"]:
        differences.append(
            f"Rust map attempts={rust_trace['rust_failed_map_attempts']}, expected 2"
        )
    if differences:
        raise harness.HarnessError("second-arena reservation differs: " + "; ".join(differences))
    evidence = {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET, "trace": rust_trace,
        "c_primitive_calls": {field: c_trace[field] for field in C_ONLY},
    }
    path = artifacts / "evidence.json"
    harness.write_json(path, evidence)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        print(run(args.offline))
    except (harness.HarnessError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
