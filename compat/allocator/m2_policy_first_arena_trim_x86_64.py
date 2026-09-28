#!/usr/bin/env python3
"""Compare pinned C and Rust policy-first arena trim-failure receivers."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "process_arena::tests::emit_m2_policy_first_arena_trim_c_rust_trace"
FIELDS = (
    "owner", "geometry", "escaped_live", "warning_order", "warning_count",
    "warning_statistics_order",
    "statistics", "later_valid",
)
LINE = re.compile(r"^m2\.policy_trim\.(prefix|suffix)\.([a-z_]+)=([0-9]+)$")


def parse_trace(output: str, source: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        # Libtest prints its test name and status prefix without a newline
        # before the first `--nocapture` line.
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.policy_trim."):
                raise harness.HarnessError(f"{source} has malformed trace line: {candidate}")
            continue
        case, field, raw = match.groups()
        key = f"{case}.{field}"
        if key in values:
            raise harness.HarnessError(f"{source} repeats {key}")
        values[key] = int(raw)
    expected = {f"{case}.{field}" for case in ("prefix", "suffix") for field in FIELDS}
    if set(values) != expected:
        raise harness.HarnessError(
            f"{source} trace roster differs: missing={sorted(expected - set(values))}, "
            f"unexpected={sorted(set(values) - expected)}"
        )
    for case in ("prefix", "suffix"):
        for field in FIELDS:
            want = 12 if field == "warning_order" else 2 if field == "warning_count" else 1
            if values[f"{case}.{field}"] != want:
                raise harness.HarnessError(
                    f"{source} {case}.{field}={values[f'{case}.{field}']}, expected {want}"
                )
    return values


def run(offline: bool) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-policy-first-arena-trim"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-policy-first-arena-trim-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=munmap", "-pthread",
            "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C policy-first trim oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C policy-first trim oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C")

    rust_command = [
        "python3", "compat/allocator/run_unit_x86_64.py", TARGET,
    ]
    rust = harness.command_record(rust_command, cwd=harness.ROOT, timeout_seconds=300)
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust policy-first trim receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        raise harness.HarnessError(f"policy-first trim receiver differs: C={c_trace} Rust={rust_trace}")
    evidence = {
        "status": "passed",
        "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET,
        "trace": c_trace,
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
