#!/usr/bin/env python3
"""Compare regular-arena reset retry and fallback advice with pinned mimalloc."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_name("m2_second_arena_reset_failure_x86_64.c")
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-second-arena-reset-advice"
PROFILES = (
    ("warning-eio", 0, 1, 2, 8, 8, 0, 1),
    ("retry-eagain", 1, 2, 3, 8, 8, 8, 0),
    ("fallback-einval", 2, 2, 3, 8, 4, 4, 0),
)
FIELDS = (
    "profile", "setup", "pending", "first_state", "first_calls",
    "first_ranges_exact", "first_advice", "second_advice", "first_warnings",
    "first_warning_order", "same_span", "retry_pending", "final_state",
    "total_calls", "total_ranges_exact", "third_advice", "warning_calls",
    "maps_live", "released_slice", "survivor_slice", "purge_calls",
    "purged_bytes", "arena_purges", "reset_calls", "reset_bytes",
    "committed_delta",
)
LINE = re.compile(r"^m2\.second_reset_advice\.([a-z_]+)=([0-9]+)$")


def parse_trace(output: str, source: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith("m2.second_reset_advice."):
                raise harness.HarnessError(f"{source} malformed trace line: {candidate}")
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
    return values


def expected_trace(profile: tuple[str, int, int, int, int, int, int, int]) -> dict[str, int]:
    _, number, first_calls, total_calls, first, second, third, warnings = profile
    return {
        "profile": number, "setup": 1, "pending": 1, "first_state": 1,
        "first_calls": first_calls, "first_ranges_exact": first_calls,
        "first_advice": first, "second_advice": second,
        "first_warnings": warnings, "first_warning_order": warnings,
        "same_span": 1, "retry_pending": 1, "final_state": 1,
        "total_calls": total_calls, "total_ranges_exact": total_calls,
        "third_advice": third, "warning_calls": warnings, "maps_live": 1,
        "released_slice": 265, "survivor_slice": 266,
        "purge_calls": 2, "purged_bytes": 2 * 64 * 1024,
        "arena_purges": 2, "reset_calls": 2,
        "reset_bytes": 2 * 64 * 1024, "committed_delta": 0,
    }


def run(offline: bool, source_only: bool, rust_test_binary: Path | None = None) -> Path:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    binary = ARTIFACTS / "pinned-c-oracle"
    source_traces: dict[str, dict[str, int]] = {}
    rust_traces: dict[str, dict[str, int]] = {}
    rust_tests: list[str] = []
    rust_commands: list[list[str]] = []
    with harness.temporary_directory(prefix="m2-second-arena-reset-advice-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=madvise", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C reset-advice oracle build")
        for profile in PROFILES:
            name = profile[0]
            c_run = harness.command_record([str(binary), name], cwd=source, timeout_seconds=120)
            (ARTIFACTS / f"{name}-pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
            (ARTIFACTS / f"{name}-pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
            harness.require_success(c_run, f"pinned C {name} reset-advice oracle")
            actual = parse_trace(str(c_run["stdout"]), f"pinned C {name}")
            expected = expected_trace(profile)
            if actual != expected:
                differences = [f"{field}: C={actual[field]} expected={expected[field]}"
                               for field in FIELDS if actual[field] != expected[field]]
                raise harness.HarnessError(f"pinned C {name} differs: " + "; ".join(differences))
            source_traces[name] = actual

    if not source_only:
        for profile in PROFILES:
            name = profile[0]
            target = "process_arena::tests::emit_m2_second_arena_reset_advice_" + name.replace("-", "_") + "_c_rust_trace"
            command = (
                [str(rust_test_binary), target, "--exact", "--test-threads=1", "--nocapture"]
                if rust_test_binary is not None else
                ["python3", "compat/allocator/run_unit_x86_64.py", target]
            )
            rust = harness.command_record(
                command,
                cwd=harness.ROOT, timeout_seconds=300,
            )
            (ARTIFACTS / f"{name}-rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
            (ARTIFACTS / f"{name}-rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
            harness.require_success(rust, f"Rust {name} reset-advice receiver")
            if harness.parse_rust_test_count(str(rust["stdout"]) + "\n" + str(rust["stderr"])) != 1:
                raise harness.HarnessError(f"Rust {name} did not run one exact receiver")
            actual = parse_trace(str(rust["stdout"]), f"Rust {name}")
            expected = source_traces[name]
            if actual != expected:
                differences = [f"{field}: C={expected[field]} Rust={actual[field]}"
                               for field in FIELDS if actual[field] != expected[field]]
                raise harness.HarnessError(f"{name} reset-advice receiver differs: " + "; ".join(differences))
            rust_traces[name] = actual
            rust_tests.append(target)
            rust_commands.append(command)

    evidence = {
        "status": "source-only" if source_only else "passed",
        "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "source_traces": source_traces,
        "rust_traces": rust_traces,
        "rust_tests": rust_tests,
        "rust_commands": rust_commands,
        "compared_value_count": len(FIELDS) * len(rust_traces),
    }
    path = ARTIFACTS / "evidence.json"
    harness.write_json(path, evidence)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--rust-test-binary", type=Path)
    args = parser.parse_args()
    try:
        print(run(args.offline, args.source_only, args.rust_test_binary))
    except (harness.HarnessError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
