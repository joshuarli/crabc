#!/usr/bin/env python3
"""Compare the bounded process-wide arena purge rotation with pinned mimalloc."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
ARCH = harness.native_evidence_architecture()
TARGET = "arena::owned::tests::emit_m2_arena_purge_rotation_c_rust_trace"
PREFIX = "m2.arena_purge_rotation."
LINE = re.compile(r"^m2\.arena_purge_rotation\.([a-z_]+)=(-?[0-9]+)$")


def parse(output: str, label: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith(PREFIX):
                raise harness.HarnessError(f"{label} malformed trace: {candidate}")
            continue
        field, raw = match.groups()
        if field in values:
            raise harness.HarnessError(f"{label} repeats {field}")
        values[field] = int(raw)
    if not values:
        raise harness.HarnessError(f"{label} emitted no purge rotation trace")
    return values


def run(offline: bool) -> Path:
    harness.require_native_evidence(ARCH)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / ARCH / "m2-arena-purge-rotation"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-arena-purge-rotation-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        build = harness.command_record([
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=madvise", "-pthread", "-o", str(binary),
        ], cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C arena purge rotation build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C arena purge rotation")
    c_trace = parse(str(c_run["stdout"]), "pinned C")
    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust arena purge rotation receiver")
    rust_trace = parse(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        differences = [f"{field}: C={c_trace.get(field)} Rust={rust_trace.get(field)}"
                       for field in sorted(set(c_trace) | set(rust_trace))
                       if c_trace.get(field) != rust_trace.get(field)]
        raise harness.HarnessError("arena purge rotation differs: " + "; ".join(differences))
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
