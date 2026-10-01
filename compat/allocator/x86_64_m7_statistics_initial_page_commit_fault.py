#!/usr/bin/env python3
"""Compare statistics after a failed initial regular-page commit and recovery."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

import run as harness
import x86_64_m7_gate as m7
import m2_arena_lifecycle_x86_64 as lifecycle
import x86_64_foundation_gate_receipts as receipts


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_initial_page_commit_fault_driver.c"
TEST = "page::tests::failed_initial_regular_page_commit_recovers_source_statistics"
BEGIN = "CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_BEGIN"
END = "CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_END"
REPORT = m7.ARTIFACTS / "statistics-initial-page-commit-fault.json"


def require_commit_failure_shape(trace: dict[str, str], side: str) -> None:
    expected = {
        "profile.level": "2",
        "profile.on_demand": "1",
        "profile.eager_arena": "0",
        "profile.show_errors": "1",
        "before.pages": "0,0,0",
        "before.page_committed": "0,0,0",
        "before.commit_calls": "0",
        "fault.nonnull": "1",
        "fault.commit_size": "114688",
        "fault.pages": "1,1,1",
        "fault.page_committed": "114688,114688,114688",
        "fault.bin": "51:1,1,1",
        "fault.page_bin": "51:1,1",
        "fault.commit_calls": "2",
        "fault.warnings": "1",
        "fault.failures": "1",
        "recovery.nonnull": "1",
        "recovery.pages": "1,1,1",
        "recovery.page_committed": "229376,229376,229376",
        "recovery.bin": "51:2,2,2",
        "recovery.page_bin": "51:1,1",
        "recovery.commit_calls": "3",
        "recovery.warnings": "1",
        "recovery.failures": "1",
        "freed.pages": "1,1,1",
        "freed.normal": "229376,229312,0",
        "freed.bin": "51:2,2,0",
        "freed.page_bin": "51:1,1",
        "freed.commit_calls": "3",
        "freed.warnings": "1",
        "freed.failures": "1",
    }
    for key, value in expected.items():
        if trace.get(key) != value:
            raise harness.HarnessError(
                f"{side} initial-page commit shape {key}: expected {value}, got {trace.get(key)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    execution_before = harness.require_native_x86_64(require_image_identity=True)
    source_before = m7.integrated.source_seal()
    git_before = m7.engine.git_provenance()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    artifacts = REPORT.with_suffix("")
    artifacts.mkdir(parents=True, exist_ok=True)
    compiled_input = artifacts / "compiled-input.c"
    shutil.copy2(DRIVER, compiled_input)
    retained_archive = artifacts / "upstream.tar.gz"
    shutil.copy2(archive, retained_archive)
    with harness.temporary_directory("crabc-m7-statistics-initial-page-commit-fault-") as name:
        temporary = Path(name)
        source = harness.safe_extract(retained_archive, artifacts / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        flags = ["-DMI_STAT=2" if flag == "-DMI_STAT=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]]
        c_binary = artifacts / "oracle"
        c_build = harness.command_record([
            compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            *flags, "-Dmprotect=crabc_fault_mprotect",
            "-I", str(source / "include"), str(compiled_input),
            str(source / "src/static.c"), "-pthread", "-o", str(c_binary),
        ], cwd=source)
        harness.write_json(artifacts / "c-build.json", c_build)
        harness.require_success(c_build, "pinned initial-page commit fault C build")
        c_run = harness.command_record([str(c_binary)], cwd=temporary, env={}, timeout_seconds=60)
        harness.write_json(artifacts / "c-execute.json", c_run)
        harness.require_success(c_run, "pinned initial-page commit fault C execution")

        program = lifecycle.native_program(harness, "stat-2", artifacts)
        build = harness.read_json(artifacts / "rust-build.json")
        selected = harness.read_json(artifacts / "compiler-artifact.json")
        # The build event names the original executable. Its retained copy is
        # useful for other callers but cannot replace compiler product authority.
        program["path"] = Path(selected["executable"])
        (artifacts / "native-program").unlink()
        unit_program = {"build": build, "build_command": build["command"],
                        "cargo_target": str(harness.WORK_ROOT / "target"),
                        "execution": program["execution"],
                        "artifact": harness.artifact_record(program["path"])}
        receipts.authenticate_unit_program(unit_program, features=["mi-stat-1", "mi-stat-2"])
        rust_run = harness.command_record(harness._x86_64_program_check_command(
            program, TEST, nocapture=True, gate_name="initial-page commit fault"),
            cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=m7.EVIDENCE_TIMEOUT_SECONDS)
        harness.write_json(artifacts / "rust-execute.json", rust_run)
        report = {
            "status": "failed", "c_build": c_build, "c_run": c_run,
            "rust_test": rust_run,
            "fault_placement": "one failed initial page write-enable after arena warmup; subsequent page commits reach the kernel",
            "physical_inputs": {
                "unit_program": unit_program,
                "c_program": harness.artifact_record(c_binary),
                "fixture": harness.artifact_record(compiled_input),
                "archive": harness.artifact_record(retained_archive),
                "oracle_source": harness.source_file_records(source, sorted(
                    path.relative_to(source).as_posix()
                    for parent in (source / "include", source / "src")
                    for path in parent.rglob("*") if path.is_file())),
            },
            "native_execution_provenance": harness.native_execution_attestation(
                execution_before, harness.require_native_x86_64(require_image_identity=True)),
            "provenance": {
                "pin": {key: pin[key] for key in ("tag", "revision", "sha256")},
                "git": git_before,
                "source_seal": source_before,
                "files": {name: m7.engine.file_record(path) for name, path in (
                    ("c_driver", DRIVER), ("rust_page", harness.ROOT / "crabc-mimalloc/src/page.rs"),
                    ("reader", Path(__file__)),
                )},
            },
        }
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        harness.write_json(REPORT, report)
        if m7.integrated.source_seal() != source_before or m7.engine.git_provenance() != git_before:
            raise harness.HarnessError("initial-page commit source changed during collection")
        harness.require_success(rust_run, "native initial-page commit fault test")
        if harness.parse_rust_test_count(str(rust_run["stdout"]) + str(rust_run["stderr"])) != 1:
            raise harness.HarnessError("initial-page commit selection did not execute one passing test")
        traces = {
            "c": m7.parse_options_trace(str(c_run["stdout"]), "pinned initial-page commit fault", BEGIN, END),
            "rust": m7.parse_options_trace(str(rust_run["stdout"]), "native initial-page commit fault", BEGIN, END),
        }
        report.update(c_trace=traces["c"], rust_trace=traces["rust"])
        harness.write_json(REPORT, report)
        for side in ("c", "rust"):
            require_commit_failure_shape(traces[side], side)
        m7.compare_options_traces(traces["c"], traces["rust"])
        report["compared_key_count"] = len(traces["c"])
        report["status"] = "passed"
        harness.write_json(REPORT, report)
    print(f"Initial-page commit fault: passed ({report['compared_key_count']} exact keys)")
    print(REPORT)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
