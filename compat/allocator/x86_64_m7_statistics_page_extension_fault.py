#!/usr/bin/env python3
"""Compare the public statistics around one failed regular-page commit and retry."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import run as harness
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_page_extension_fault_driver.c"
TEST = "page::tests::failed_second_regular_extension_commit_retries_same_page_statistics"
BEGIN = "CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_BEGIN"
END = "CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_END"
REPORT = m7.ARTIFACTS / "statistics-page-extension-fault.json"
TARGET = "x86_64-unknown-linux-musl"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    with harness.temporary_directory("crabc-m7-statistics-page-extension-fault-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        flags = ["-DMI_STAT=2" if flag == "-DMI_STAT=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]]
        c_binary = temporary / "page-extension-fault-c"
        c_build = harness.command_record([
            compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            *flags, "-Dmprotect=crabc_fault_mprotect",
            "-I", str(source / "include"), str(DRIVER),
            str(source / "src/static.c"), "-pthread", "-o", str(c_binary),
        ], cwd=source)
        harness.require_success(c_build, "pinned page-extension fault C build")
        c_run = harness.command_record([str(c_binary)], cwd=temporary, env={}, timeout_seconds=60)
        harness.require_success(c_run, "pinned page-extension fault C execution")

        cargo = harness.require_tool("cargo")
        target_dir = temporary / "cargo-target"
        rust_run = harness.command_record([
            cargo, "test", "--locked", "--offline", "--target", TARGET,
            "-p", "crabc-mimalloc", "--no-default-features", "--features", "mi-stat-2",
            "--lib", TEST, "--target-dir", str(target_dir),
            "--", "--exact", "--nocapture", "--test-threads=1",
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=m7.EVIDENCE_TIMEOUT_SECONDS)
        harness.require_success(rust_run, "native page-extension fault test")

        traces = {
            "c": m7.parse_options_trace(str(c_run["stdout"]), "pinned page-extension fault", BEGIN, END),
            "rust": m7.parse_options_trace(str(rust_run["stdout"]), "native page-extension fault", BEGIN, END),
        }
        report = {
            "status": "failed", "c_trace": traces["c"], "rust_trace": traces["rust"],
            "c_build": c_build["command"], "c_run": c_run["command"],
            "rust_test": rust_run["command"],
            "fault_placement": "one failed write-enable after 128 live 64-byte blocks; later commits reach the kernel",
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
        for side in ("c", "rust"):
            m7.require_statistics_page_extend(traces[side], f"{side} page-extension fault", faulted=True)
        m7.compare_options_traces(traces["c"], traces["rust"])
        report["compared_key_count"] = len(traces["c"])
        report["status"] = "passed"
        harness.write_json(REPORT, report)
    print(f"Page-extension commit fault: passed ({report['compared_key_count']} exact keys)")
    print(REPORT)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
