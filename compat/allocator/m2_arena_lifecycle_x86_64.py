#!/usr/bin/env python3
"""Pinned C/Rust native x86-64 arena reservation and slice-lifecycle differential.

`m2_arena_lifecycle_x86_64.c` drives the unchanged pinned `src/arena.c`
reservation, registry search, slice claim, and release routines through
`static.c`; `arena::owned::tests::emit_native_arena_lifecycle_trace` drives the
Rust `ProcessArenaBacking` entries for the same scenarios. Both emit the same
ordered, address-free `m2.arena.lifecycle.N=V` fields, and every field must
match. The aggregate `allocator-m2` gate calls `run_evidence` with its one
prebuilt test binary; `allocator-m2-arena-lifecycle` runs `main` for focused
development without producing a milestone receipt.

The differential covers arena creation and OS reservation. It is not evidence
for abandonment, abandoned-page reclaim, or cross-thread page lifecycle.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


FIXTURE = Path(__file__).with_suffix(".c").resolve()
CHECK_ID = "arena-reservation-lifecycle-c-rust-differential"
TARGET = "arena::owned::tests::emit_native_arena_lifecycle_trace"
FIELD = re.compile(r"m2\.arena\.lifecycle\.([0-9]+)=(-?[0-9]+)")
# libtest's `--nocapture` output places the first field after this delimiter.
RUST_INLINE_PREFIX = f"test {TARGET} ... "
# Scenario markers are `-1000 - scenario`; the final marker is scenario 10.
FINAL_MARKER = -1010


def parse_trace(output: str, *, source: str) -> list[int]:
    """Return the complete ordered field list, rejecting gaps and stray text."""

    values: list[int] = []
    for line in output.splitlines():
        if line.startswith(RUST_INLINE_PREFIX):
            line = line[len(RUST_INLINE_PREFIX):]
        if "m2.arena.lifecycle." not in line:
            continue
        match = FIELD.fullmatch(line)
        if match is None or int(match.group(1)) != len(values):
            raise ValueError(f"{source} arena lifecycle trace has a malformed or out-of-order field: {line!r}")
        values.append(int(match.group(2)))
    if not values or values[0] != -1001 or values[-1] != FINAL_MARKER:
        raise ValueError(f"{source} arena lifecycle trace is incomplete")
    return values


def compare(c_trace: list[int], rust_trace: list[int]) -> dict[str, Any]:
    """Require field-for-field equality and name the first divergences."""

    if c_trace == rust_trace:
        return {"compared_value_count": len(c_trace), "status": "matched"}
    mismatches = [
        f"{index}: C={c}, Rust={r}"
        for index, (c, r) in enumerate(zip(c_trace, rust_trace))
        if c != r
    ][:16]
    if len(c_trace) != len(rust_trace):
        mismatches.append(f"field count: C={len(c_trace)}, Rust={len(rust_trace)}")
    raise ValueError("native x86 arena lifecycle differs from pinned C: " + "; ".join(mismatches))


def run_oracle(harness: Any, *, offline: bool) -> tuple[list[str], list[int]]:
    """Build the fixture against the pinned archive and return its trace."""

    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-arena-lifecycle"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "oracle"
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-arena-lifecycle-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            # The fixture includes `static.c`, the single pinned translation unit.
            str(FIXTURE), "-Wl,--wrap=mmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C native x86 arena lifecycle oracle build")
        run = harness.command_record([str(binary)], cwd=source, timeout_seconds=180)
        harness.require_success(run, "pinned C native x86 arena lifecycle oracle")
    (artifacts / "c.log").write_text(str(run["stdout"]), encoding="utf-8")
    return command, parse_trace(str(run["stdout"]), source="pinned C")


def run_evidence(
    harness: Any, *, offline: bool, test_program: Mapping[str, Any], check: Mapping[str, Any],
) -> dict[str, Any]:
    """Run the differential against the aggregate gate's prebuilt test binary."""

    harness.require_native_x86_64()
    if check.get("id") != CHECK_ID or check.get("target") != TARGET:
        raise harness.HarnessError("native x86 arena lifecycle check changed")
    try:
        c_command, c_trace = run_oracle(harness, offline=offline)
        rust, rust_output = harness._x86_64_run_exact_program_check(
            test_program, check, nocapture=True, gate_name="native x86 M2 arena lifecycle",
        )
        comparison = compare(c_trace, parse_trace(rust_output, source="Rust"))
    except ValueError as error:
        raise harness.HarnessError(str(error)) from error
    evidence = {
        "c_command": c_command,
        "comparison": comparison,
        "fixture": harness.artifact_record(FIXTURE),
        "rust_command": rust["command"],
        "rust_passed_test_count": rust["passed_test_count"],
        "status": "passed",
        "trace_sha256": hashlib.sha256(
            json.dumps(c_trace, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    harness.write_json(harness.ARTIFACT_ROOT / "x86_64/m2-arena-lifecycle/evidence.json", evidence)
    return evidence


def main() -> int:
    import run as harness  # this script's directory is first on sys.path

    harness.require_native_x86_64()
    try:
        _, c_trace = run_oracle(harness, offline=True)
        rust = harness.command_record(
            ["python3", "compat/allocator/run_unit_x86_64.py", TARGET],
            cwd=harness.ROOT, timeout_seconds=1800,
        )
        harness.require_success(rust, "Rust arena lifecycle trace")
        artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-arena-lifecycle"
        (artifacts / "rust.log").write_text(str(rust["stdout"]), encoding="utf-8")
        comparison = compare(c_trace, parse_trace(str(rust["stdout"]), source="Rust"))
    except (ValueError, harness.HarnessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"arena lifecycle: pinned C/Rust matched {comparison['compared_value_count']} fields; {artifacts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
