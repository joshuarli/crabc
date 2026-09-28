#!/usr/bin/env python3
"""Compare a failed arena decommit and later successful purge in pinned C and Rust."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "process_arena::tests::emit_m2_second_arena_purge_failure_c_rust_trace"
FIELDS = (
    "setup", "pending", "failed_state", "failed_calls", "failed_exact",
    "failed_warnings", "failed_warning_order", "same_span", "retry_pending",
    "retried_state", "advice_calls", "advice_exact", "warning_calls",
    "maps_live", "released_slice", "survivor_slice", "purge_calls",
    "purged_bytes", "arena_purges",
)
LINE = re.compile(r"^m2\.second_purge_failure\.([a-z_]+)=([0-9]+)$")


def parse_trace(output: str, source: str, *, expected_source: bool = False) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.second_purge_failure."):
                raise harness.HarnessError(f"{source} has malformed trace line: {candidate}")
            continue
        field, raw = match.groups()
        if field in values:
            raise harness.HarnessError(f"{source} repeats {field}")
        values[field] = int(raw)
    if set(values) != set(FIELDS):
        raise harness.HarnessError(
            f"{source} trace roster differs: missing={sorted(set(FIELDS) - set(values))}, "
            f"unexpected={sorted(set(values) - set(FIELDS))}"
        )
    expected = {
        "setup": 1, "pending": 1, "failed_state": 1, "failed_calls": 1,
        "failed_exact": 1, "failed_warnings": 1, "failed_warning_order": 1,
        "same_span": 1, "retry_pending": 1, "retried_state": 1,
        "advice_calls": 2, "advice_exact": 2, "warning_calls": 1,
        "maps_live": 1, "released_slice": 265, "survivor_slice": 266,
        "purge_calls": 2, "purged_bytes": 2 * 64 * 1024, "arena_purges": 2,
    }
    if expected_source:
        for field, want in expected.items():
            if values[field] != want:
                raise harness.HarnessError(f"{source} {field}={values[field]}, expected {want}")
    return values


def run(offline: bool) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-second-arena-purge-failure"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-second-arena-purge-failure-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=madvise", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C failed-purge oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C failed-purge oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C", expected_source=True)

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust failed-purge receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        differences = [f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
                       for field in FIELDS if c_trace[field] != rust_trace[field]]
        raise harness.HarnessError("failed-purge receiver differs: " + "; ".join(differences))
    evidence = {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET, "trace": c_trace,
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
