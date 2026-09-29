#!/usr/bin/env python3
"""Compare reset, owner exit, and cross-thread free statistics with pinned C."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

import run as harness
import perf_engine_x86_64 as engine
from x86_64_m7_gate import parse_options_trace


FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_worker_transfer_oracle.c"
REPORT = harness.ARTIFACT_ROOT / "x86_64/m7-statistics-worker-transfer/profile.json"
BEGIN = "CRABC_MI_M7_STATISTICS_WORKER_TRANSFER_TRACE_BEGIN"
END = "CRABC_MI_M7_STATISTICS_WORKER_TRANSFER_TRACE_END"
STAGES = ("before", "first_alloc", "first_reset", "first_exit", "second_attach",
          "remote_free", "second_reset", "local_free", "second_exit")
COUNT_FIELDS = ("normal", "requested", "first_bin", "second_bin", "pages",
                "first_page_bin", "second_page_bin", "threads", "theaps")
TARGET = "x86_64-unknown-linux-musl"


def source_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def count(trace: dict[str, str], stage: str, field: str) -> tuple[int, int, int]:
    parts = tuple(int(part) for part in trace[f"{stage}.{field}"].split(","))
    if len(parts) != 3:
        raise harness.HarnessError(f"invalid {stage}.{field} count")
    return parts


def validate(trace: dict[str, str], side: str) -> None:
    expected = {"profile.level", "first.bin", "second.bin"}
    expected.update(f"{stage}.{field}" for stage in STAGES
                    for field in (*COUNT_FIELDS, "normal_count"))
    if set(trace) != expected or trace["profile.level"] != "2":
        raise harness.HarnessError(f"{side} has an incomplete worker transfer trace")
    if (trace["first.bin"], trace["second.bin"]) != ("8", "2"):
        raise harness.HarnessError(f"{side} did not exercise the source block bins")
    for stage in STAGES:
        for field in COUNT_FIELDS:
            count(trace, stage, field)
        int(trace[f"{stage}.normal_count"])
    # These values expose the source's live reset, negative remote debit, and
    # owner exits. The requested count intentionally remains live after free.
    anchors = {
        ("first_alloc", "normal"): (64, 64, 64),
        ("first_reset", "normal"): (64, 64, 64),
        ("first_exit", "threads"): (1, 1, 0),
        ("second_attach", "normal"): (80, 80, 80),
        ("second_attach", "pages"): (2, 2, 2),
        ("remote_free", "normal"): (80, 80, 16),
        ("remote_free", "first_bin"): (1, 1, 0),
        ("remote_free", "pages"): (2, 2, 1),
        ("second_reset", "normal"): (80, 80, 16),
        ("local_free", "normal"): (80, 80, 0),
        ("second_exit", "pages"): (2, 2, 0),
        ("second_exit", "requested"): (80, 80, 80),
        ("second_exit", "theaps"): (2, 1, 0),
    }
    for (stage, field), expected_count in anchors.items():
        if count(trace, stage, field) != expected_count:
            raise harness.HarnessError(f"{side} lost source {stage}.{field} transition")
    if trace["second_exit.normal_count"] != "2":
        raise harness.HarnessError(f"{side} lost source allocation count")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    cc = harness.require_tool("musl-gcc")
    cargo = harness.require_tool("cargo")
    with harness.temporary_directory("crabc-m7-statistics-worker-transfer-") as temp_name:
        temp = Path(temp_name)
        source = harness.safe_extract(archive, temp / "source", pin["archive_root"])
        flags = ["-DMI_STAT=2" if flag == "-DMI_STAT=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]]
        common = [cc, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *flags, "-I", str(source / "include"), str(FIXTURE)]
        c_driver = temp / "worker-transfer-c"
        c_build = harness.command_record([*common, str(source / "src/static.c"),
                                          "-pthread", "-o", str(c_driver)], cwd=source)
        harness.require_success(c_build, "pinned worker transfer build")
        target_dir = temp / "cargo-target"
        rust_build = harness.command_record([
            cargo, "build", "--locked", "--offline", "--release", "--target", TARGET,
            "-p", "crabc-mimalloc-native-mi-adapter", "--no-default-features",
            "--features", "crabc-mimalloc/mi-stat-2", "--target-dir", str(target_dir),
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=3600)
        harness.require_success(rust_build, "native worker transfer adapter build")
        rust_driver = temp / "worker-transfer-rust"
        library = target_dir / TARGET / "release" / "libcrabc_mimalloc_native_mi_adapter.a"
        rust_link = harness.command_record([*common, str(library), "-pthread", "-o", str(rust_driver)],
                                           cwd=source)
        harness.require_success(rust_link, "native worker transfer driver link")
        traces = {}
        executions = {}
        for side, driver in (("c", c_driver), ("rust", rust_driver)):
            execution = harness.command_record([str(driver)], cwd=source, env={}, timeout_seconds=60)
            harness.require_success(execution, f"{side} worker transfer execution")
            trace = parse_options_trace(str(execution["stdout"]), side, BEGIN, END)
            validate(trace, side)
            traces[side] = trace
            executions[side] = execution
        mismatch = sorted(key for key in traces["c"] if traces["c"][key] != traces["rust"][key])
        report = {
            "status": "red" if mismatch else "passed",
            "git": engine.git_provenance(),
            "pin": {key: pin[key] for key in ("revision", "sha256", "tag")},
            "source_files": harness.source_file_records(source, (
                "include/mimalloc-stats.h", "src/stats.c", "src/init.c", "src/heap.c",
                "src/theap.c", "src/alloc.c", "src/free.c", "src/page.c", "src/static.c")),
            "fixture_sha256": source_hash(FIXTURE),
            "reader_sha256": source_hash(Path(__file__)),
            "rust_source_sha256": {
                path: source_hash(harness.ROOT / path)
                for path in ("crabc-mimalloc/src/statistics.rs",
                             "crabc-mimalloc/src/runtime_lifecycle.rs",
                             "crabc-mimalloc/src/subproc_main_heaps.rs",
                             "crabc-mimalloc/src/single_thread.rs",
                             "compat/allocator/native-mi-adapter/src/lib.rs")
            },
            "c_build_command": c_build["command"],
            "rust_build_command": rust_build["command"],
            "rust_link_command": rust_link["command"],
            "executions": executions,
            "traces": traces,
            "mismatch_keys": mismatch,
        }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    harness.write_json(REPORT, report)
    print(f"worker transfer statistics: {report['status']} ({len(mismatch)} differing keys)")
    print(f"report: {harness.relative(REPORT)}")
    return 1 if mismatch else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
