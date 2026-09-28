#!/usr/bin/env python3
"""Compare the pinned C and Rust second regular-arena claim lifecycle."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "process_arena::tests::emit_m2_second_regular_arena_c_rust_trace"
CLAIM_FIELDS = ("registry", "arena", "slice", "count", "occupied")
FINAL_FIELDS = (
    "registry_final", "distinct", "owners", "first_exhausted_for_256",
    "arena_size", "reserved_bytes", "arena_count", "restored", "purge_calls",
    "purged_bytes", "mapped_both", "reserved_still", "registry_still",
)
LINE = re.compile(r"^m2\.arena_scale\.([a-z0-9_]+)=([0-9]+)$")


def parse_trace(output: str, source: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.arena_scale."):
                raise harness.HarnessError(f"{source} has malformed trace line: {candidate}")
            continue
        field, raw = match.groups()
        if field in values:
            raise harness.HarnessError(f"{source} repeats {field}")
        values[field] = int(raw)
    expected = set(FINAL_FIELDS) | {
        f"claim{index}_{field}" for index in range(4) for field in CLAIM_FIELDS
    }
    if set(values) != expected:
        raise harness.HarnessError(
            f"{source} trace roster differs: missing={sorted(expected - set(values))}, "
            f"unexpected={sorted(set(values) - expected)}"
        )
    for index in range(4):
        for field, sequence in (
            ("registry", (1, 1, 1, 2)),
            ("arena", (0, 0, 0, 1)),
            ("slice", (9, 512, 768, 9)),
            ("count", (256,) * 4),
            ("occupied", (1,) * 4),
        ):
            key = f"claim{index}_{field}"
            if values[key] != sequence[index]:
                raise harness.HarnessError(f"{source} {key}={values[key]}, expected {sequence[index]}")
    wanted = {
        "registry_final": 2, "distinct": 1, "owners": 1,
        "first_exhausted_for_256": 1, "arena_size": 64 * 1024 * 1024,
        "reserved_bytes": 128 * 1024 * 1024, "arena_count": 2,
        "restored": 1, "purge_calls": 4, "purged_bytes": 64 * 1024 * 1024,
        "mapped_both": 1, "reserved_still": 1, "registry_still": 1,
    }
    for field, want in wanted.items():
        if values[field] != want:
            raise harness.HarnessError(f"{source} {field}={values[field]}, expected {want}")
    return values


def run(offline: bool) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-second-regular-arena"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-second-regular-arena-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C second-arena oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C second-arena oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C")

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust second-arena receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        raise harness.HarnessError(f"second-arena receiver differs: C={c_trace} Rust={rust_trace}")
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
