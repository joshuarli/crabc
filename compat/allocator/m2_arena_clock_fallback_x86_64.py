#!/usr/bin/env python3
"""Compare arena purge scheduling after the preferred clock fails."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "arena::owned::tests::process_arena_purge_uses_process_cpu_clock_after_monotonic_fault"
EXPECTED = {"schedule_clock": 1, "scheduled": 1, "purge_clock": 1, "cleared": 1, "purges": 1}
LINE = re.compile(r"^m2\.arena_clock\.([a-z_]+)=([0-9]+)$")


def parse_trace(output: str, source: str) -> dict[str, int]:
    values = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.arena_clock."):
                raise harness.HarnessError(f"{source} malformed arena clock trace: {candidate}")
            continue
        name, raw = match.groups()
        if name in values:
            raise harness.HarnessError(f"{source} repeats arena clock field {name}")
        values[name] = int(raw)
    if values != EXPECTED:
        raise harness.HarnessError(f"{source} arena clock trace differs: {values}")
    return values


def run(offline: bool) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-arena-clock-fallback"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-arena-clock-fallback-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=clock_gettime", "-Wl,--wrap=clock",
            "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C arena clock fallback build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C arena clock fallback")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C")
    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
        cwd=harness.ROOT, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust arena clock fallback")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        raise harness.HarnessError("pinned C and Rust arena clock fallback traces differ")
    path = artifacts / "evidence.json"
    harness.write_json(path, {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET, "trace": c_trace,
    })
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    print(run(args.offline))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
