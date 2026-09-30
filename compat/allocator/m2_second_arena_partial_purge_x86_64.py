#!/usr/bin/env python3
"""Compare pinned C and Rust arena selection, sibling purge, and exact reuse."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "process_arena::tests::emit_m2_second_arena_partial_purge_c_rust_trace"
FIELDS = (
    "setup", "pending", "partial", "later_pending", "later_purged",
    "first_survives", "maps_live", "first_purge_calls", "first_purged_bytes",
    "first_arena_purges", "released_slice", "survivor_slice",
    "purge_calls", "purged_bytes", "arena_purges",
    "occupied_fallback", "survivor_contents", "second_reuse_exact",
    "second_recommit", "second_zero", "first_reuse_exact", "owners_preserved",
    "released_all", "exclusive_skipped", "exclusive_requested", "exclusive_reused",
    "exclusive_sibling_preserved", "exclusive_released",
)
LINE = re.compile(r"^m2\.second_purge\.([a-z_]+)=([0-9]+)$")


def parse_trace(output: str, source: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.second_purge."):
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
    wanted = {
        "setup": 1, "pending": 1, "partial": 1, "later_pending": 1,
        "later_purged": 1, "first_survives": 1, "maps_live": 1,
        "first_purge_calls": 5, "first_purged_bytes": 16 * 1024 * 1024,
        "first_arena_purges": 1, "released_slice": 9, "survivor_slice": 265,
        "purge_calls": 6, "purged_bytes": 16 * 1024 * 1024 + 64 * 1024,
        "arena_purges": 2,
        "occupied_fallback": 1, "survivor_contents": 1, "second_reuse_exact": 1,
        "second_recommit": 1, "second_zero": 1, "first_reuse_exact": 1,
        "owners_preserved": 1, "released_all": 1, "exclusive_skipped": 1,
        "exclusive_requested": 1, "exclusive_reused": 1,
        "exclusive_sibling_preserved": 1, "exclusive_released": 1,
    }
    for field, want in wanted.items():
        if values[field] != want:
            raise harness.HarnessError(f"{source} {field}={values[field]}, expected {want}")
    return values


def run(offline: bool) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-second-arena-partial-purge"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-second-arena-partial-purge-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C partial purge oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C partial purge oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C")

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust partial purge receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        raise harness.HarnessError(f"partial purge receiver differs: C={c_trace} Rust={rust_trace}")
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
