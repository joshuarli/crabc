#!/usr/bin/env python3
"""Compare OS-backed large remote-free statistics with raw VM events retained."""

from __future__ import annotations

import argparse
import sys
from typing import Mapping

import run as harness
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_os_large_remote_stats_driver.c"
BEGIN = "CRABC_MI_M7_OS_LARGE_REMOTE_STATS_BEGIN"
END = "CRABC_MI_M7_OS_LARGE_REMOTE_STATS_END"
STAGES = ("allocated", "owner_merged", "worker_merged", "released")
FIELDS = ("bin", "page_bin", "pages", "requested", "normal", "reserved",
          "committed", "normal_count", "mmap_calls", "arena_count")


def require_source_shape(trace: Mapping[str, str], description: str, *, warmed: bool) -> None:
    """Require the worker debit and the owner's later OS page release."""

    expected_keys = {"request", "usable", "bin", "heap_region", "control.warm_os_map",
                     "disallow_arena_alloc", "worker.bin.hex"}
    if warmed:
        expected_keys.update({"warm.reserved", "warm.committed", "warm.mmap_calls"})
    expected_keys.update(f"{stage}.{field}" for stage in STAGES for field in FIELDS)
    if set(trace) != expected_keys:
        raise harness.HarnessError(f"{description}: incomplete large-page trace: {trace}")
    for key, value in (("request", "86706"), ("usable", "98304"), ("bin", "50"),
                       ("heap_region", "1"), ("disallow_arena_alloc", "1")):
        if trace[key] != value:
            raise harness.HarnessError(f"{description}: {key} is {trace[key]!r}, expected {value!r}")
    if trace["control.warm_os_map"] != ("1" if warmed else "0"):
        raise harness.HarnessError(f"{description}: warm-up mode changed")
    stage_values = {
        "allocated": ("1,1,1", "1,1,1", "1,1,1", "86706,86706,86706",
                      "98304,98304,98304", "1"),
        "owner_merged": ("1,1,1", "1,1,1", "1,1,1", "86706,86706,86706",
                         "98304,98304,98304", "1"),
        "worker_merged": ("2,2,0", "2,2,1", "2,2,1", "173412,173412,173412",
                          "196608,196608,0", "2"),
        "released": ("2,2,0", "2,2,0", "2,2,0", "173412,173412,173412",
                     "196608,196608,0", "2"),
    }
    for stage, values in stage_values.items():
        for field, expected in zip(("bin", "page_bin", "pages", "requested", "normal",
                                    "normal_count"), values):
            if trace[f"{stage}.{field}"] != expected:
                raise harness.HarnessError(f"{description}: {stage}.{field} lost its source transition")
        if trace[f"{stage}.mmap_calls"] not in {"1", "2"} or trace[f"{stage}.arena_count"] != "0":
            raise harness.HarnessError(f"{description}: the ordinary large page lost its OS route")
    try:
        reserved = {stage: tuple(map(int, trace[f"{stage}.reserved"].split(",")))
                    for stage in STAGES}
        committed = {stage: tuple(map(int, trace[f"{stage}.committed"].split(",")))
                    for stage in STAGES}
        worker_bin = bytes.fromhex(trace["worker.bin.hex"]).decode("ascii").split()
        if warmed:
            warm_reserved = tuple(map(int, trace["warm.reserved"].split(",")))
            warm_committed = tuple(map(int, trace["warm.committed"].split(",")))
            warm_mmaps = int(trace["warm.mmap_calls"])
    except (ValueError, UnicodeDecodeError) as error:
        raise harness.HarnessError(f"{description}: invalid VM or worker statistics") from error
    if (any(len(value) != 3 for value in (*reserved.values(), *committed.values()))
            or reserved["allocated"][0] not in {4456448, 4521984}
            or committed["allocated"][0] not in {4194304, 4259840}
            or reserved["allocated"] != reserved["owner_merged"]
            or committed["allocated"] != committed["owner_merged"]
            or reserved["worker_merged"][2] - reserved["released"][2]
               != 4456448
            or committed["worker_merged"][2] <= committed["released"][2]):
        raise harness.HarnessError(f"{description}: OS mapping was not allocated and released")
    if warmed and (len(warm_reserved) != 3 or len(warm_committed) != 3
                   or warm_reserved[0] not in {4456448, 4521984}
                   or warm_committed[0] not in {4194304, 4259840}
                   or warm_mmaps not in {1, 2}):
        raise harness.HarnessError(f"{description}: the PageMap warm-up did not map memory")
    if worker_bin != ["bin", "L", "50:", "96.3", "KiB", "96.3", "KiB",
                      "-96.3", "KiB", "96.3", "KiB", "1", "not", "all", "freed"]:
        raise harness.HarnessError(f"{description}: freeing worker lost its large-bin debit")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cold", action="store_true", help="compare an unprimed PageMap in full")
    mode.add_argument("--full", action="store_true", help="compare every controlled VM stage in full")
    args = parser.parse_args()
    warmed = not args.cold
    payload_only = not args.cold and not args.full
    # Address placement can put the one lazy 64-KiB PageMap submap in the
    # warm allocation or the measured allocation. Retain both raw stages and
    # compare their cumulative VM events separately from the page/bin payload.
    excluded = (frozenset(f"{stage}.{field}" for stage in STAGES
                          for field in ("reserved", "committed", "mmap_calls"))
                | frozenset({"warm.reserved", "warm.committed", "warm.mmap_calls"}))
    report_name = ("os-large-remote-stats-cold.json" if args.cold else
                   "os-large-remote-stats-payload.json" if payload_only else
                   "os-large-remote-stats-controlled.json")
    report = m7.run_public_statistics_differential(
        args.offline, subject="os-large-remote-stats", driver=DRIVER,
        begin=BEGIN, end=END, report_name=report_name,
        stat_level=2,
        driver_defines=("-DCRABC_MI_WARM_OS_MAP=1",) if warmed else (),
        comparison_excluded_keys=excluded if payload_only else frozenset(),
        require_complete=lambda trace, description: require_source_shape(
            trace, description, warmed=warmed,
        ),
    )
    if payload_only:
        c, rust = report["c_trace"], report["rust_trace"]
        vm_fields = ("reserved", "committed", "mmap_calls")
        stage_differences = {
            f"{stage}.{field}": {"pinned_c": c[f"{stage}.{field}"],
                                 "rust": rust[f"{stage}.{field}"]}
            for stage in ("warm", *STAGES) for field in vm_fields
            if c[f"{stage}.{field}"] != rust[f"{stage}.{field}"]
        }
        cumulative = {}
        for field in vm_fields:
            c_total = sum(int(c[f"{stage}.{field}"].split(",")[0])
                          for stage in ("warm", "allocated"))
            rust_total = sum(int(rust[f"{stage}.{field}"].split(",")[0])
                             for stage in ("warm", "allocated"))
            if c_total != rust_total:
                raise harness.HarnessError(f"cumulative warm/target {field} differs: {c_total} != {rust_total}")
            cumulative[field] = c_total
        report["vm_stage_differences"] = stage_differences
        report["cumulative_warm_target_vm"] = cumulative
        report["comparison_scope"] = "statistics payload; raw VM stages retained"
        harness.write_json(m7.ARTIFACTS / report_name, report)
    print(f"OS-backed large remote statistics: {report['status']} "
          f"({report['compared_key_count']} C/Rust keys)")
    print(m7.ARTIFACTS / report_name)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
