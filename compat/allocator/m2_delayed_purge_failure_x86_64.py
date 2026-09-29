#!/usr/bin/env python3
"""Compare delayed arena purge failure and independent reuse against pinned C."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "arena::tests::emit_m2_delayed_purge_failure_c_rust_trace"
FIELDS = (
    "setup", "pending", "pending_purge", "pending_committed", "pending_free",
    "pending_survivor", "pending_expiry", "pending_no_advice", "consumed", "first_calls",
    "first_exact", "first_warnings", "warning_after_stats", "first_purges",
    "first_bytes", "first_visits", "first_committed", "no_retry",
    "later_disjoint", "later_pending", "owner_live", "terminal",
    "released_slice", "survivor_slice", "later_slice", "registry", "reserved",
    "purge_calls", "purged_bytes", "arena_purges", "advice_calls", "warnings",
)
LINE = re.compile(r"^m2\.delayed_purge_failure\.([a-z_]+)=(-?[0-9]+)$")


def parse_trace(output: str, source: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.delayed_purge_failure."):
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
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-delayed-purge-failure"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-delayed-purge-failure-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=madvise", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C delayed-purge oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C delayed-purge oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C")
    expected = {
        "setup": 1, "pending": 1, "pending_purge": 1,
        "pending_committed": 1, "pending_free": 1, "pending_survivor": 1,
        "pending_expiry": 1, "pending_no_advice": 1, "consumed": 1,
        "first_calls": 1, "first_exact": 1, "first_warnings": 1,
        "warning_after_stats": 1, "first_purges": 1, "first_bytes": 65536,
        "first_visits": 1, "first_committed": 0, "no_retry": 1,
        "later_disjoint": 1, "later_pending": 1, "owner_live": 1,
        "terminal": 1, "released_slice": 9, "survivor_slice": 10,
        "later_slice": 11, "registry": 1, "reserved": 0,
        "purge_calls": 1, "purged_bytes": 65536,
        "arena_purges": 1, "advice_calls": 1, "warnings": 1,
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
    harness.require_success(rust, "Rust delayed-purge receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        differences = [f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
                       for field in FIELDS if c_trace[field] != rust_trace[field]]
        raise harness.HarnessError("delayed purge differs: " + "; ".join(differences))
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
