#!/usr/bin/env python3
"""Compare two production MI_STAT=1 worker merges with pinned mimalloc."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import run as harness
from x86_64_m7_gate import parse_options_trace


FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_two_owner_driver.c"
BEGIN = "CRABC_MI_M7_STATISTICS_TWO_OWNER_TRACE_BEGIN"
END = "CRABC_MI_M7_STATISTICS_TWO_OWNER_TRACE_END"
REPORT = harness.ARTIFACT_ROOT / "x86_64/m7-gate/statistics-two-owner.json"
TARGET = "x86_64-unknown-linux-musl"
STAGES = ("before", "merged_first", "merged_second", "freed_first", "freed_second")
FIELDS = ("normal", "pages", "threads", "theaps")


def count(value: str) -> tuple[int, int, int]:
    parts = tuple(int(part) for part in value.split(","))
    if len(parts) != 3:
        raise harness.HarnessError(f"malformed statistics count: {value}")
    return parts


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {"profile.level", "worker_first.binned", "worker_second.binned"}
    expected.update(f"{stage}.{field}" for stage in STAGES for field in FIELDS)
    if set(trace) != expected or trace["profile.level"] != "1":
        raise harness.HarnessError(f"{side} has an incomplete two-owner trace")
    for stage in STAGES:
        for field in FIELDS:
            count(trace[f"{stage}.{field}"])
    expected_counts = {
        "before": {"normal": (0, 0, 0), "pages": (0, 0, 0),
                   "threads": (1, 1, 1), "theaps": (1, 1, 1)},
        "merged_first": {"normal": (64, 64, 64), "pages": (1, 1, 1),
                         "threads": (2, 2, 1), "theaps": (2, 2, 1)},
        "merged_second": {"normal": (192, 192, 192), "pages": (2, 2, 2),
                          "threads": (3, 2, 1), "theaps": (3, 2, 1)},
        "freed_first": {"normal": (192, 192, 128), "pages": (2, 2, 1),
                        "threads": (3, 2, 1), "theaps": (3, 2, 1)},
        "freed_second": {"normal": (192, 192, 0), "pages": (2, 2, 0),
                         "threads": (3, 2, 1), "theaps": (3, 2, 1)},
    }
    if any(count(trace[f"{stage}.{field}"]) != expected
           for stage, fields in expected_counts.items()
           for field, expected in fields.items()):
        raise harness.HarnessError(f"{side} lost a source worker merge or free: {trace}")
    for stage in ("worker_first", "worker_second"):
        try:
            row = bytes.fromhex(trace[f"{stage}.binned"])
        except ValueError as error:
            raise harness.HarnessError(f"{side} has an invalid {stage} row") from error
        size = b"64" if stage == "worker_first" else b"128"
        if not (row.startswith(b"  binned") and size in row and b"not all freed" in row):
            raise harness.HarnessError(f"{side} omitted the live {stage} row")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    cc = harness.require_tool("musl-gcc")
    cargo = harness.require_tool("cargo")
    with harness.temporary_directory("crabc-m7-statistics-two-owner-") as temp_name:
        temp = Path(temp_name)
        source = harness.safe_extract(archive, temp / "source", pin["archive_root"])
        flags = ["-DMI_STAT=1" if flag == "-DMI_STAT=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]]
        common = [cc, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *flags, "-I", str(source / "include"), str(FIXTURE)]
        c_driver = temp / "two-owner-c"
        c_build = harness.command_record([*common, str(source / "src/static.c"),
                                          "-pthread", "-o", str(c_driver)], cwd=source)
        harness.require_success(c_build, "pinned two-owner statistics build")
        target_dir = temp / "cargo-target"
        rust_build = harness.command_record([
            cargo, "build", "--locked", "--offline", "--release", "--target", TARGET,
            "-p", "crabc-mimalloc-native-mi-adapter", "--no-default-features",
            "--features", "crabc-mimalloc/mi-stat-1", "--target-dir", str(target_dir),
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=3600)
        harness.require_success(rust_build, "native two-owner statistics adapter build")
        library = target_dir / TARGET / "release" / "libcrabc_mimalloc_native_mi_adapter.a"
        rust_driver = temp / "two-owner-rust"
        rust_link = harness.command_record([*common, str(library), "-pthread", "-o", str(rust_driver)],
                                           cwd=source)
        harness.require_success(rust_link, "native two-owner statistics driver link")
        traces = {}
        executions = {}
        for side, driver in (("c", c_driver), ("rust", rust_driver)):
            execution = harness.command_record([str(driver)], cwd=source, env={}, timeout_seconds=60)
            harness.require_success(execution, f"{side} two-owner statistics process")
            trace = parse_options_trace(str(execution["stdout"]), side, BEGIN, END)
            require_trace(trace, side)
            traces[side] = trace
            executions[side] = execution["command"]
        mismatches = {key: {side: traces[side][key] for side in traces}
                      for key in traces["c"] if traces["c"][key] != traces["rust"][key]}
        if mismatches:
            raise harness.HarnessError(f"two-owner statistics differ: {mismatches}")
        report = {
            "schema": "crabc-mimalloc-m7-statistics-two-owner-v1", "status": "passed",
            "pin": pin, "c_build_command": c_build["command"],
            "rust_build_command": rust_build["command"], "rust_link_command": rust_link["command"],
            "execution_commands": executions, "compared_key_count": len(traces["c"]),
            "c_trace": traces["c"], "rust_trace": traces["rust"],
        }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    harness.write_json(REPORT, report)
    print(f"M7 two-owner statistics differential passed: {report['compared_key_count']} keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
