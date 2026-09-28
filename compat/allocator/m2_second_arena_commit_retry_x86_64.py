#!/usr/bin/env python3
"""Compare a failed second-arena commit claim and retry against pinned C."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "process_arena::tests::emit_m2_second_arena_commit_retry_c_rust_trace"
C_ONLY = ("failed_protect_exact", "protect_exact")
FIELDS = (
    "setup", "failed_null", "failed_free", "failed_dirty", "failed_uncommitted",
    "failed_protect_calls", "failed_warnings", "failed_warning_order",
    "failed_commit_calls", "failed_committed_delta", "retry_same",
    "retry_committed", "retry_dirty", "retry_zero_flag", "protect_calls",
    "warning_calls", "commit_calls", "committed_delta", "purge_calls",
    "arena_purges", "reserved_delta", "maps_live", "failed_slice",
    "survivor_slice",
)
LINE = re.compile(r"^m2\.second_commit_retry\.([a-z_]+)=([0-9]+)$")
EXPECTED = {
    "setup": 1, "failed_null": 1, "failed_free": 1, "failed_dirty": 1,
    "failed_uncommitted": 1, "failed_protect_calls": 1,
    "failed_protect_exact": 1, "failed_warnings": 1,
    "failed_warning_order": 1, "failed_commit_calls": 1,
    "failed_committed_delta": 0, "retry_same": 1,
    "retry_committed": 1, "retry_dirty": 1, "retry_zero_flag": 1,
    "protect_calls": 2, "protect_exact": 2, "warning_calls": 1,
    "commit_calls": 2, "committed_delta": 64 * 1024,
    "purge_calls": 0, "arena_purges": 0, "reserved_delta": 0,
    "maps_live": 1, "failed_slice": 266, "survivor_slice": 265,
}


def parse_trace(output: str, source: str, fields: set[str]) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.second_commit_retry."):
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
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-second-arena-commit-retry"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-second-arena-commit-retry-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mprotect", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C second-arena commit oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C second-arena commit oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C", set(FIELDS + C_ONLY))
    for field, want in EXPECTED.items():
        if c_trace[field] != want:
            raise harness.HarnessError(f"pinned C {field}={c_trace[field]}, expected {want}")

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust second-arena commit receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust", set(FIELDS))
    differences = [f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
                   for field in FIELDS if c_trace[field] != rust_trace[field]]
    if differences:
        raise harness.HarnessError("second-arena commit receiver differs: " + "; ".join(differences))
    evidence = {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET, "trace": rust_trace,
        "c_primitive_range": {field: c_trace[field] for field in C_ONLY},
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
