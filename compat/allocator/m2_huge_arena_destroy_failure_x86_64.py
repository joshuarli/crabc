#!/usr/bin/env python3
"""Compare a failed huge-arena destroy with pinned C source."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "process_arena::tests::emit_m2_huge_arena_destroy_failure_c_rust_trace"
COMMON = (
    "setup", "before_mapped", "unmap_calls", "warning_calls",
    "warning_before_accounting", "registry_after", "failed_live",
    "other_huge_gone", "reserved_delta", "committed_delta",
    "arena_count_delta", "purge_calls", "raw_retry",
    "terminal_unmapped", "terminal_registry",
)
C_ONLY = ("exact_ranges",)
RUST_ONLY = ("retained_owner",)
LINE = re.compile(r"^m2\.huge_destroy_failure\.([a-z_]+)=(-?[0-9]+)$")
EXPECTED_C = {
    "setup": 1, "before_mapped": 1, "unmap_calls": 2,
    "exact_ranges": 2, "warning_calls": 1,
    "warning_before_accounting": 1, "registry_after": 0,
    "failed_live": 1, "other_huge_gone": 1,
    "reserved_delta": -(2 * 1024 * 1024 * 1024),
    "committed_delta": -(2 * 1024 * 1024 * 1024),
    "arena_count_delta": 0, "purge_calls": 0,
    "raw_retry": 1, "terminal_unmapped": 1, "terminal_registry": 1,
}


def parse_trace(output: str, source: str, fields: set[str]) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.huge_destroy_failure."):
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
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-huge-arena-destroy-failure"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-huge-arena-destroy-failure-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=munmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C failed huge-arena destroy oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C failed huge-arena destroy oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C", set(COMMON + C_ONLY))
    for field, want in EXPECTED_C.items():
        if c_trace[field] != want:
            raise harness.HarnessError(f"pinned C {field}={c_trace[field]}, expected {want}")

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=900,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust failed huge-arena destroy receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust", set(COMMON + RUST_ONLY))
    differences = [f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
                   for field in COMMON if c_trace[field] != rust_trace[field]]
    if rust_trace["retained_owner"] != 1:
        differences.append(f"Rust retained_owner={rust_trace['retained_owner']}, expected 1")
    if differences:
        raise harness.HarnessError("failed huge-arena destroy differs: " + "; ".join(differences))
    evidence = {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET, "trace": rust_trace,
        "c_exact_unmap_ranges": c_trace["exact_ranges"],
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
