#!/usr/bin/env python3
"""Pinned C/Rust native x86-64 arena reservation and slice-lifecycle differential.

`m2_arena_lifecycle_x86_64.c` drives the unchanged pinned `src/arena.c`
reservation, registry search, slice claim, and release routines through
`static.c`; `arena::owned::tests::emit_native_arena_lifecycle_trace` drives the
Rust `ProcessArenaBacking` entries for the same scenarios. Both emit the same
ordered, address-free `m2.arena.lifecycle.N=V` fields, and every field must
match, except that scenario 23's default-option reservations carry the
recorded `CRABC-MI-ARENA-RESERVATION-NO-THP` advice (`expected_rust`). The aggregate `allocator-m2` gate calls `run_evidence` with its one
prebuilt test binary; `allocator-m2-arena-lifecycle` runs `main` for focused
development without producing an aggregate receipt.

The differential covers arena creation, OS reservation, and caller-owned
external callback commitment/purge, refusal/retry, bitmap transitions, registry
retirement, and caller release. Real private managed arenas additionally cover
small, medium, and large regular-page abandonment, a foreign held-owner claim
refusal with bitmap/count restoration, retry and same-owner reassociation,
foreign remote-free publication, owner collection, and terminal span/map release.
The cross-thread caller additionally exercises natural owner exit, a distinct
replacement owner, held-claim restoration, reassociation, and terminal page
release. Hardware memory policy remains a separate condition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


FIXTURE = Path(__file__).with_suffix(".c").resolve()
CHECK_ID = "arena-reservation-lifecycle-c-rust-differential"
TARGET = "arena::owned::tests::emit_native_arena_lifecycle_trace"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
PROFILE_FEATURES = {"release": [], "debug-1": ["mi-debug-1", "mi-stat-1", "mi-stat-2"],
                    "stat-1": ["mi-stat-1"], "stat-2": ["mi-stat-1", "mi-stat-2"]}
FIELD = re.compile(r"m2\.arena\.lifecycle\.([0-9]+)=(-?[0-9]+)")
# libtest's `--nocapture` output places the first field after this delimiter.
RUST_INLINE_PREFIX = f"test {TARGET} ... "
# Scenario markers are `-1000 - scenario`; the final marker is scenario 26.
FINAL_MARKER = -1026
THP_SCENARIO = -1023
# Scenario 23 cells: this sentinel, allow_thp, eager commit, advised, last
# advice, and whether every advice call carried it.
THP_CELL = -2300
MADV_NOHUGEPAGE = 15


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


def expected_rust(c_trace: list[int]) -> list[int]:
    """The pinned C trace with the one recorded divergence applied.

    At the
    default allow_thp=1 without large OS pages, a Rust arena reservation is
    advised MADV_NOHUGEPAGE where pinned C advises MADV_HUGEPAGE or nothing.
    Only scenario 23's advice records change; every other field, including
    the allow_thp=0 and allow_thp=2 cells, must equal pinned C.
    """

    expected = list(c_trace)
    start = expected.index(THP_SCENARIO)
    for index in range(start, expected.index(FINAL_MARKER)):
        if expected[index] == THP_CELL and expected[index + 1] == 1:
            expected[index + 3:index + 6] = [1, MADV_NOHUGEPAGE, 1]
    return expected


def compare(c_trace: list[int], rust_trace: list[int]) -> dict[str, Any]:
    """Require field-for-field equality with the recorded divergence and name the first differences."""

    c_trace = expected_rust(c_trace)
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


def run_oracle(harness: Any, *, offline: bool, profile: str = "release") -> tuple[list[str], list[int]]:
    """Build the fixture against the pinned archive and return its trace."""

    if profile not in PROFILES:
        raise harness.HarnessError("unsupported arena lifecycle configuration")
    import x86_64_m4_gate as profiles

    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-arena-lifecycle"
    if profile != "release":
        artifacts /= profile
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "oracle"
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-arena-lifecycle-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *(harness.CONFIGURATION_PROFILES["release"] if profile == "release"
              else profiles.api_profile_flags(profile)),
            # The fixture includes `static.c`, the single pinned translation unit.
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=mprotect", "-Wl,--wrap=madvise", "-Wl,--wrap=munmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.write_json(artifacts / "c-build.json", build)
        harness.require_success(build, "pinned C native x86 arena lifecycle oracle build")
        run = harness.command_record([str(binary)], cwd=source, timeout_seconds=180)
        harness.write_json(artifacts / "c-execute.json", run)
        (artifacts / "c.log").write_text(str(run["stdout"]), encoding="utf-8")
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


def native_program(harness: Any, profile: str, artifacts: Path) -> dict[str, Any]:
    """Build and retain the matching Cargo-emitted native test executable."""
    if profile not in PROFILES:
        raise harness.HarnessError("unsupported arena lifecycle configuration")
    manifest = harness.ROOT / "crabc-mimalloc/Cargo.toml"
    command = [harness.require_tool("cargo"), "test", "--manifest-path", str(manifest),
               "--locked", "--offline", "--target", "x86_64-unknown-linux-musl",
               "--lib", "--no-default-features"]
    if profile != "release":
        command.extend(("--features", "mi-" + profile))
    command.extend(("--no-run", "--message-format=json"))
    build = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=3600)
    harness.write_json(artifacts / "rust-build.json", build)
    harness.require_success(build, "native arena lifecycle test product build")
    candidates = []
    for line in str(build["stdout"]).splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (isinstance(event, Mapping) and event.get("reason") == "compiler-artifact"
                and event.get("manifest_path") == str(manifest)
                and event.get("target", {}).get("name") == "crabc_mimalloc"
                and event.get("target", {}).get("src_path") == str(manifest.parent / "src/lib.rs")
                and event.get("target", {}).get("kind") == ["lib"]
                and event.get("profile", {}).get("test") is True
                and event.get("features") == PROFILE_FEATURES[profile]
                and isinstance(event.get("executable"), str)):
            candidates.append(event)
    if len(candidates) != 1 or not Path(candidates[0]["executable"]).is_file():
        raise harness.HarnessError("native arena lifecycle compiler executable authority differs")
    import shutil
    binary = artifacts / "native-program"
    shutil.copy2(candidates[0]["executable"], binary)
    harness.write_json(artifacts / "compiler-artifact.json", candidates[0])
    return {"path": binary, "execution": {"test_threads": 1, "timeout_seconds": 180}}


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=(*PROFILES, "all"), default="release")
    arguments = parser.parse_args(arguments)
    import run as harness  # this script's directory is first on sys.path

    harness.require_native_x86_64()
    status = 0
    for profile in (PROFILES if arguments.profile == "all" else (arguments.profile,)):
        artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-arena-lifecycle"
        if profile != "release":
            artifacts /= profile
        artifacts.mkdir(parents=True, exist_ok=True)
        try:
            _, c_trace = run_oracle(harness, offline=True, profile=profile)
            program = native_program(harness, profile, artifacts)
            command = harness._x86_64_program_check_command(
                program, TARGET, nocapture=True, gate_name="native arena lifecycle")
            rust = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=180)
            harness.write_json(artifacts / "rust-execute.json", rust)
            (artifacts / "rust.log").write_text(str(rust["stdout"]) + str(rust["stderr"]), encoding="utf-8")
            harness.require_success(rust, "native arena lifecycle trace")
            output = str(rust["stdout"]) + "\n" + str(rust["stderr"])
            if harness.parse_rust_test_count(output) != 1:
                raise harness.HarnessError("exact arena lifecycle selection did not execute one passing test")
            comparison = compare(c_trace, parse_trace(output, source="Rust"))
        except (ValueError, harness.HarnessError) as error:
            print(f"ERROR: {profile}: {error}", file=sys.stderr)
            status = 1
            continue
        print(f"arena lifecycle {profile}: pinned C/Rust matched {comparison['compared_value_count']} fields; {artifacts}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
