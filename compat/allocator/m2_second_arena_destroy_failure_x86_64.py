#!/usr/bin/env python3
"""Compare a failed regular arena destroy with pinned C source."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "process_arena::tests::emit_m2_second_arena_destroy_failure_c_rust_trace"
COMMON = (
    "setup", "before_mapped", "unmap_calls", "failed_range_exact",
    "other_range_exact", "warning_calls", "warning_before_accounting",
    "registry_after", "failed_map_live", "other_map_gone",
    "reserved_delta", "committed_delta", "arena_count_delta",
    "purge_calls", "post_cleanup_unmapped",
)
C_ONLY = (
    "next_reserved", "leak_survives_next", "next_cleaned",
    "after_next_reserved_delta", "after_next_committed_delta", "raw_cleanup",
)
RUST_ONLY = (
    "retained_owner", "retry_released", "retry_reserved_delta",
    "retry_committed_delta",
)
LINE = re.compile(r"^m2\.second_destroy_failure\.([a-z_]+)=(-?[0-9]+)$")
EXPECTED_C = {
    "setup": 1, "before_mapped": 1, "unmap_calls": 2,
    "failed_range_exact": 1, "other_range_exact": 1,
    "warning_calls": 1, "warning_before_accounting": 1,
    "registry_after": 0, "failed_map_live": 1, "other_map_gone": 1,
    "reserved_delta": -(128 * 1024 * 1024),
    "committed_delta": -(128 * 1024 * 1024),
    "arena_count_delta": 0, "purge_calls": 0,
    "next_reserved": 1, "leak_survives_next": 1, "next_cleaned": 1,
    "after_next_reserved_delta": -(128 * 1024 * 1024),
    "after_next_committed_delta": -200736768,
    "raw_cleanup": 1, "post_cleanup_unmapped": 1,
}
EXPECTED_RUST_ONLY = {
    "retained_owner": 1, "retry_released": 1,
    "retry_reserved_delta": -(128 * 1024 * 1024),
    "retry_committed_delta": -(128 * 1024 * 1024),
}


def parse_trace(output: str, source: str, fields: set[str]) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.second_destroy_failure."):
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
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-second-arena-destroy-failure"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-second-arena-destroy-failure-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=munmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C failed arena destroy oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C failed arena destroy oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C", set(COMMON + C_ONLY))
    for field, want in EXPECTED_C.items():
        if c_trace[field] != want:
            raise harness.HarnessError(f"pinned C {field}={c_trace[field]}, expected {want}")

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust failed arena destroy receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust", set(COMMON + RUST_ONLY))
    differences = [f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
                   for field in COMMON if c_trace[field] != rust_trace[field]]
    differences.extend(
        f"Rust {field}={rust_trace[field]}, expected {want}"
        for field, want in EXPECTED_RUST_ONLY.items() if rust_trace[field] != want
    )
    if differences:
        raise harness.HarnessError("failed arena destroy differs: " + "; ".join(differences))
    evidence = {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET, "trace": rust_trace,
        "c_source_continuation": {field: c_trace[field] for field in C_ONLY},
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
