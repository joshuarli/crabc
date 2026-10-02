#!/usr/bin/env python3
"""Compare selected partial huge primitive progress with pinned source."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import run as harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_suffix(".c")
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-huge-reservation-progress"
TEST = "os::tests::emit_m2_huge_reservation_progress_c_rust_trace"
ARENA_TEST = "arena::owned::huge::tests::huge_partial_reservation_publishes_claims_and_releases_the_source_arena"
FIELDS = (
    "pages", "size_gib", "base_exact", "memory_huge", "memory_pinned",
    "memory_committed", "memory_zero", "huge_calls", "huge_1g_calls",
    "huge_2m_calls", "exact_hints", "warning_fragments", "warning_order",
    "warning_after_first", "first_live", "second_absent", "reserved_after",
    "committed_after", "mmap_after", "arena_after", "ordinary_live",
    "ordinary_memory", "reserved_with_ordinary", "committed_with_ordinary",
    "ordinary_gone", "huge_gone", "reserved_terminal", "committed_terminal",
    "mmap_terminal", "arena_terminal",
    "arena_published", "arena_partial", "arena_base_exact", "arena_memory_huge",
    "arena_memory_pinned", "arena_reserved_after", "arena_committed_after",
    "arena_count_after", "arena_claim_writable", "arena_claim_pinned",
    "arena_claim_committed", "arena_claim_released", "arena_terminal_released",
    "arena_terminal_registry", "arena_reserved_terminal", "arena_committed_terminal",
    "arena_terminal_absent",
)
LINE = re.compile(r"^m2\.huge_reservation_progress\.([a-z0-9_]+)=(-?[0-9]+)$")


def trace(output: str, label: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        match = LINE.fullmatch(line.rsplit(" ... ", 1)[-1])
        if match and match.group(1) in FIELDS:
            if match.group(1) in values:
                raise harness.HarnessError(f"{label} repeated {match.group(1)}")
            values[match.group(1)] = int(match.group(2))
    if set(values) != set(FIELDS):
        raise harness.HarnessError(f"{label} field roster: {sorted(values)}")
    return values


def c_oracle(offline: bool) -> tuple[dict[str, int], dict]:
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(prefix="m2-huge-reservation-progress-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-oracle"
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C huge progress build")
        execution = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
        harness.require_success(execution, "pinned C huge progress")
    (ARTIFACTS / "pinned-c.stdout").write_text(str(execution["stdout"]))
    (ARTIFACTS / "pinned-c.stderr").write_text(str(execution["stderr"]))
    return trace(str(execution["stdout"]), "pinned C"), {
        "build_status": build["status"], "run_status": execution["status"],
        "stderr": execution["stderr"],
    }


def rust_receiver() -> tuple[dict[str, int], dict]:
    executions = []
    for target in (TEST, ARENA_TEST):
        command = ["python3", "compat/allocator/run_unit_x86_64.py", target]
        execution = harness.command_record(command, cwd=ROOT, timeout_seconds=900)
        executions.append(execution)
        (ARTIFACTS / "rust.stdout").write_text(
            "\n".join(str(record["stdout"]) for record in executions))
        (ARTIFACTS / "rust.stderr").write_text(
            "\n".join(str(record["stderr"]) for record in executions))
        harness.require_success(execution, f"Rust huge progress receiver {target}")
    stdout = "\n".join(str(execution["stdout"]) for execution in executions)
    stderr = "\n".join(str(execution["stderr"]) for execution in executions).strip()
    (ARTIFACTS / "rust.stdout").write_text(stdout)
    (ARTIFACTS / "rust.stderr").write_text(stderr)
    return trace(stdout, "Rust"), {
        "run_status": 0, "stderr": stderr,
        "commands": [execution["command"] for execution in executions],
    }


def run(offline: bool, c_only: bool) -> dict:
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline)
    rust, rust_commands = ({}, {}) if c_only else rust_receiver()
    mismatches = [] if c_only else [field for field in FIELDS if c[field] != rust[field]]
    expected = {
        "pages": 1, "size_gib": 1, "base_exact": 1, "memory_huge": 1,
        "memory_pinned": 1, "memory_committed": 1, "memory_zero": 1,
        "huge_calls": 3, "huge_1g_calls": 2, "huge_2m_calls": 1,
        "exact_hints": 3, "warning_fragments": 4, "warning_order": 12,
        "warning_after_first": 2, "first_live": 1, "second_absent": 1,
        "reserved_after": 1, "committed_after": 1, "mmap_after": 0,
        "arena_after": 0, "ordinary_live": 1, "ordinary_memory": 1,
        "reserved_with_ordinary": 1, "committed_with_ordinary": 1,
        "ordinary_gone": 1, "huge_gone": 1, "reserved_terminal": 0,
        "committed_terminal": 0, "mmap_terminal": 1, "arena_terminal": 0,
        "arena_published": 1, "arena_partial": 1, "arena_base_exact": 1,
        "arena_memory_huge": 1, "arena_memory_pinned": 1,
        "arena_reserved_after": 1, "arena_committed_after": 1,
        "arena_count_after": 1, "arena_claim_writable": 1,
        "arena_claim_pinned": 1, "arena_claim_committed": 1,
        "arena_claim_released": 1, "arena_terminal_released": 1,
        "arena_terminal_registry": 0, "arena_reserved_terminal": 0,
        "arena_committed_terminal": 0, "arena_terminal_absent": 1,
    }
    mismatches.extend(f"c.{field}" for field in FIELDS if c[field] != expected[field])
    if c_commands["stderr"]:
        mismatches.append("c.unrouted_diagnostics")
    if not c_only and rust_commands["stderr"]:
        mismatches.append("rust.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red", "c": c, "rust": rust,
        "mismatches": mismatches, "c_commands": c_commands,
        "rust_commands": rust_commands,
        "scope": "process-owned huge OS primitive partial progress, later ordinary map, and source huge reservation through arena publication, writable slice claim/free, and terminal destruction; synthetic huge mmap success establishes software state only and leaves physical huge-page residency and NUMA placement unqualified",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"huge reservation progress {report['status'].upper()} ({len(FIELDS)} fields)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(arguments.offline, arguments.c_only)["status"] == "matched" else 1)
