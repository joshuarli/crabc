#!/usr/bin/env python3
"""Compare a failed bounded arena visit with pinned mimalloc."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "arena::owned::tests::emit_m2_arena_purge_budget_failure_c_rust_trace"
FIELDS = (
    "setup", "initial_pending", "first_pending", "first_expiry",
    "first_advice", "first_exact", "first_visits", "first_calls",
    "first_bytes", "first_committed", "second_pending", "second_expiry",
    "second_advice", "second_visits", "third_pending", "third_expiry",
    "third_advice", "third_visits", "global_cleared", "calls", "bytes",
    "registry",
)
LINE = re.compile(r"^m2\.arena_purge_budget_failure\.([a-z_]+)=(-?[0-9]+)$")


def parse(output: str, label: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.arena_purge_budget_failure."):
                raise harness.HarnessError(f"{label} malformed trace: {candidate}")
            continue
        field, raw = match.groups()
        if field in values:
            raise harness.HarnessError(f"{label} repeats {field}")
        values[field] = int(raw)
    if set(values) != set(FIELDS):
        raise harness.HarnessError(f"{label} trace roster differs: {sorted(values)}")
    return values


def run(offline: bool) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-arena-purge-budget-failure"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-arena-purge-budget-failure-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        build = harness.command_record([
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=madvise", "-pthread", "-o", str(binary),
        ], cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C arena purge budget build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C arena purge budget")
    c_trace = parse(str(c_run["stdout"]), "pinned C")
    expected = {
        "setup": 1, "initial_pending": 7, "first_pending": 5,
        "first_expiry": 2, "first_advice": 1, "first_exact": 1,
        "first_visits": 1, "first_calls": 1, "first_bytes": 65536,
        "first_committed": 1, "second_pending": 1, "second_expiry": 6,
        "second_advice": 2, "second_visits": 2, "third_pending": 0,
        "third_expiry": 7, "third_advice": 3, "third_visits": 3,
        "global_cleared": 1, "calls": 3, "bytes": 196608, "registry": 3,
    }
    for field, want in expected.items():
        if c_trace[field] != want:
            raise harness.HarnessError(f"pinned C {field}={c_trace[field]}, expected {want}")
    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust arena purge budget receiver")
    rust_trace = parse(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        differences = [f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
                       for field in FIELDS if c_trace[field] != rust_trace[field]]
        raise harness.HarnessError("arena purge budget differs: " + "; ".join(differences))
    path = artifacts / "evidence.json"
    harness.write_json(path, {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET, "trace": c_trace,
    })
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        print(run(args.offline))
    except (harness.HarnessError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
