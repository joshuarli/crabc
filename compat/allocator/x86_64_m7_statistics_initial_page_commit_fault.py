#!/usr/bin/env python3
"""Compare statistics after a failed initial regular-page commit and recovery."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import run as harness
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_initial_page_commit_fault_driver.c"
TEST = "page::tests::failed_initial_regular_page_commit_recovers_source_statistics"
BEGIN = "CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_BEGIN"
END = "CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_END"
REPORT = m7.ARTIFACTS / "statistics-initial-page-commit-fault.json"
TARGET = "x86_64-unknown-linux-musl"


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
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    with harness.temporary_directory("crabc-m7-statistics-initial-page-commit-fault-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        flags = ["-DMI_STAT=2" if flag == "-DMI_STAT=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]]
        c_binary = temporary / "initial-page-commit-fault-c"
        c_build = harness.command_record([
            compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            *flags, "-Dmprotect=crabc_fault_mprotect",
            "-I", str(source / "include"), str(DRIVER),
            str(source / "src/static.c"), "-pthread", "-o", str(c_binary),
        ], cwd=source)
        harness.require_success(c_build, "pinned initial-page commit fault C build")
        c_run = harness.command_record([str(c_binary)], cwd=temporary, env={}, timeout_seconds=60)
        harness.require_success(c_run, "pinned initial-page commit fault C execution")

        cargo = harness.require_tool("cargo")
        target_dir = harness.WORK_ROOT / "target"
        rust_run = harness.command_record([
            cargo, "test", "--locked", "--offline", "--target", TARGET,
            "-p", "crabc-mimalloc", "--no-default-features", "--features", "mi-stat-2",
            "--lib", TEST, "--target-dir", str(target_dir),
            "--", "--exact", "--nocapture", "--test-threads=1",
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=m7.EVIDENCE_TIMEOUT_SECONDS)
        report = {
            "status": "failed", "c_build": c_build, "c_run": c_run,
            "rust_test": rust_run,
            "fault_placement": "one failed initial page write-enable after arena warmup; subsequent page commits reach the kernel",
            "provenance": {
                "pin": {key: pin[key] for key in ("tag", "revision", "sha256")},
                "git": m7.engine.git_provenance(),
                "source_seal": m7.integrated.source_seal(),
                "files": {name: m7.engine.file_record(path) for name, path in (
                    ("c_driver", DRIVER), ("rust_page", harness.ROOT / "crabc-mimalloc/src/page.rs"),
                    ("reader", Path(__file__)),
                )},
            },
        }
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        harness.write_json(REPORT, report)
        harness.require_success(rust_run, "native initial-page commit fault test")
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
