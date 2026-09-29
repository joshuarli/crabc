#!/usr/bin/env python3
"""Compare the empty huge-reservation warning reached during startup."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "arena::owned::huge::tests::failed_startup_huge_reservation_reports_the_source_failure_warning"
FIELD = re.compile(r"^m2\.startup_huge_failure\.([a-z_]+)=([0-9]+)$")


def fields(output: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        line = line.rsplit(" ... ", 1)[-1]
        match = FIELD.fullmatch(line)
        if match:
            name, value = match.groups()
            if name in values:
                raise harness.HarnessError(f"repeated startup huge field {name}")
            values[name] = int(value)
    return values


def run(offline: bool) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-startup-huge-failure"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-startup-huge-failure-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        build = harness.command_record([
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-pthread", "-o", str(binary),
        ], cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C startup huge failure oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C startup huge failure oracle")
    c_values = fields(str(c_run["stdout"]))
    if c_values != {"explicit_warnings": 1, "interleaved_warnings": 1}:
        raise harness.HarnessError(f"pinned C startup huge failure changed: {c_values}")

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=900,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust startup huge failure receiver")
    rust_values = fields(str(rust["stdout"]))
    if rust_values != c_values:
        raise harness.HarnessError(f"startup huge failure warning differs: C={c_values}, Rust={rust_values}")
    path = artifacts / "evidence.json"
    harness.write_json(path, {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET, "trace": rust_values,
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
