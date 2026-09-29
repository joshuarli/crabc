#!/usr/bin/env python3
"""Compare two disjoint delayed arena purges with mixed OS outcomes."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "arena::tests::emit_m2_delayed_purge_mixed_outcome_c_rust_trace"
FIELDS = (
    "setup", "pending", "pending_quiet", "ordered", "bitmaps",
    "advice_count", "warning_count", "warning_order", "warning_stats",
    "collected_calls", "collected_bytes", "collected_visits", "committed_delta",
    "no_retry", "survivor", "terminal", "a_slice", "neighbor_slice", "b_slice",
    "registry", "reserved_delta", "purge_calls", "purged_bytes", "arena_purges",
)
LINE = re.compile(r"^m2\.delayed_purge_mixed\.([a-z_]+)=(-?[0-9]+)$")


def parse_trace(output: str, source: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.delayed_purge_mixed."):
                raise harness.HarnessError(f"{source} malformed trace: {candidate}")
            continue
        field, raw = match.groups()
        if field in values:
            raise harness.HarnessError(f"{source} repeats {field}")
        values[field] = int(raw)
    if set(values) != set(FIELDS):
        raise harness.HarnessError(
            f"{source} trace roster: missing={sorted(set(FIELDS)-set(values))}, "
            f"unexpected={sorted(set(values)-set(FIELDS))}"
        )
    return values


def run(offline: bool, c_only: bool = False) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-delayed-purge-mixed-outcome"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-delayed-purge-mixed-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=madvise", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C mixed delayed-purge oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C mixed delayed-purge oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C")
    expected = {
        "setup": 1, "pending": 1, "pending_quiet": 1, "ordered": 1,
        "bitmaps": 1, "advice_count": 2, "warning_count": 1,
        "warning_order": 1, "warning_stats": 1, "collected_calls": 2,
        "collected_bytes": 131072, "collected_visits": 1,
        "committed_delta": 0, "no_retry": 1, "survivor": 1,
        "terminal": 1, "a_slice": 9, "neighbor_slice": 10,
        "b_slice": 11, "registry": 1, "reserved_delta": 0,
        "purge_calls": 2, "purged_bytes": 131072, "arena_purges": 1,
    }
    for field, want in expected.items():
        if c_trace[field] != want:
            raise harness.HarnessError(f"pinned C {field}={c_trace[field]}, expected {want}")
    if c_only:
        return artifacts / "pinned-c.stdout"

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust mixed delayed-purge receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        differences = [f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
                       for field in FIELDS if c_trace[field] != rust_trace[field]]
        raise harness.HarnessError("mixed delayed purge differs: " + "; ".join(differences))
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
    parser.add_argument("--c-only", action="store_true")
    args = parser.parse_args()
    try:
        print(run(args.offline, args.c_only))
    except (harness.HarnessError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
