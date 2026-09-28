#!/usr/bin/env python3
"""Check whether each extra OS mapping follows a new PageMap submap index."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Mapping, Any

import run as harness
import x86_64_m7_gate as m7
import x86_64_m7_os_large_remote_stats as stats


def source_placement(trace: Mapping[str, str], *, warmed: bool) -> dict[str, Any]:
    """Account for each persistent 64-KiB submap at its allocation stage."""

    def total(name: str) -> int:
        return int(trace[name].split(",")[0])

    try:
        worker = int(trace["placement.worker_index"])
        seen = {worker}
        result = {"worker_index": worker}
        if warmed:
            warm = int(trace["placement.warm_index"])
            warm_extra = int(trace["warm.mmap_calls"]) - 1
            result.update(warm_index=warm, warm_extra_mmap=warm_extra,
                          warm_extra_reserved=total("warm.reserved") - 4456448,
                          warm_extra_committed=total("warm.committed") - 4194304,
                          warm_new_submap=int(warm not in seen))
            seen.add(warm)
        target = int(trace["placement.target_index"])
        target_extra = int(trace["allocated.mmap_calls"]) - 1
        result.update(target_index=target, target_extra_mmap=target_extra,
                      target_extra_reserved=total("allocated.reserved") - 4456448,
                      target_extra_committed=total("allocated.committed") - 4194304,
                      target_new_submap=int(target not in seen))
    except (KeyError, ValueError) as error:
        raise harness.HarnessError(f"malformed PageMap placement trace: {error}") from error
    for stage in (("warm", "target") if warmed else ("target",)):
        submap = result[f"{stage}_new_submap"]
        if (result[f"{stage}_extra_mmap"] != submap
                or result[f"{stage}_extra_reserved"] != 65536 * submap
                or result[f"{stage}_extra_committed"] != 65536 * submap):
            raise harness.HarnessError(f"{stage} VM event did not follow one new submap: {result}")

    # The source keeps each allocated submap until PageMap destruction. Its
    # three count components therefore retain the same placement charge in
    # every later snapshot, even after the ordinary large page is released.
    accounted_vm = {}
    for stage in (("warm", *stats.STAGES) if warmed else stats.STAGES):
        charge = result[("warm" if stage == "warm" else "target") + "_new_submap"]
        for field in ("reserved", "committed", "mmap_calls"):
            key = f"{stage}.{field}"
            try:
                parts = tuple(int(value) for value in trace[key].split(","))
            except (KeyError, ValueError) as error:
                raise harness.HarnessError(f"malformed {key}: {error}") from error
            if len(parts) != (1 if field == "mmap_calls" else 3):
                raise harness.HarnessError(f"malformed {key}: {trace[key]}")
            unit = 1 if field == "mmap_calls" else 65536
            accounted_vm[key] = ",".join(str(value - unit * charge) for value in parts)
            if field == "mmap_calls" and accounted_vm[key] != "1":
                raise harness.HarnessError(f"{key} added an unexplained OS mapping")
    for stage in (("warm", "allocated", "owner_merged") if warmed else
                  ("allocated", "owner_merged")):
        for field, expected in (("reserved", 4456448), ("committed", 4194304)):
            key = f"{stage}.{field}"
            if accounted_vm[key] != ",".join([str(expected)] * 3):
                raise harness.HarnessError(f"{key} changed beyond its PageMap submap charge")
    result["accounted_vm"] = accounted_vm
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--cold", action="store_true")
    args = parser.parse_args()
    warmed = not args.cold
    placement_keys = {"placement.worker_index", "placement.target_index"}
    if warmed:
        placement_keys.add("placement.warm_index")
    vm_keys = {f"{stage}.{field}" for stage in stats.STAGES
               for field in ("reserved", "committed", "mmap_calls")}
    if warmed:
        vm_keys.update({"warm.reserved", "warm.committed", "warm.mmap_calls"})
    report_name = ("os-large-remote-stats-placement-warm.json" if warmed else
                   "os-large-remote-stats-placement-cold.json")

    def require_trace(trace: Mapping[str, str], description: str) -> None:
        expected = {"request", "usable", "bin", "heap_region", "control.warm_os_map",
                    "disallow_arena_alloc", "worker.bin.hex"}
        expected.update(f"{stage}.{field}" for stage in stats.STAGES for field in stats.FIELDS)
        if warmed:
            expected.update({"warm.reserved", "warm.committed", "warm.mmap_calls"})
        if set(trace) - placement_keys != expected:
            raise harness.HarnessError(f"{description}: placement fields changed")
        stats.require_source_shape({key: value for key, value in trace.items()
                                    if key not in placement_keys}, description, warmed=warmed)

    report = m7.run_public_statistics_differential(
        args.offline, subject="os-large-remote-stats-placement", driver=stats.DRIVER,
        begin=stats.BEGIN, end=stats.END, report_name=report_name,
        stat_level=2, driver_defines=("-DCRABC_MI_TRACE_PLACEMENT=1",)
        + (("-DCRABC_MI_WARM_OS_MAP=1",) if warmed else ()),
        comparison_excluded_keys=frozenset(placement_keys | vm_keys),
        require_complete=require_trace,
    )
    report["status"] = "failed"
    pin = harness.load_pin()
    report["provenance"] = {
        "pin": {key: pin[key] for key in ("tag", "revision", "sha256")},
        "git": m7.engine.git_provenance(),
        "source_seal": m7.integrated.source_seal(),
        "files": {name: m7.engine.file_record(path) for name, path in (
            ("driver", stats.DRIVER), ("payload_reader", Path(stats.__file__)),
            ("placement_reader", Path(__file__)))},
    }
    harness.write_json(m7.ARTIFACTS / report_name, report)
    placements = {side: source_placement(report[f"{side}_trace"], warmed=warmed)
                  for side in ("c", "rust")}
    accounted = {
        side: {key: value for key, value in report[f"{side}_trace"].items()
               if key not in placement_keys | vm_keys} | placements[side]["accounted_vm"]
        for side in ("c", "rust")
    }
    report["payload_precheck_excluded_keys"] = report.pop("comparison_excluded_keys")
    report["comparison_excluded_keys"] = sorted(placement_keys)
    report["placements"] = {side: {key: value for key, value in placement.items()
                                    if key != "accounted_vm"}
                            for side, placement in placements.items()}
    report["stage_accounted_vm"] = {side: placement["accounted_vm"]
                                    for side, placement in placements.items()}
    report["stage_accounted_keys"] = sorted(vm_keys)
    report["compared_key_count"] = len(accounted["c"])
    report["comparison_scope"] = "all non-address trace keys with exact persistent PageMap submap charges"
    harness.write_json(m7.ARTIFACTS / report_name, report)
    m7.compare_options_traces(accounted["c"], accounted["rust"])
    report["status"] = "passed"
    harness.write_json(m7.ARTIFACTS / report_name, report)
    print(f"PageMap placement: passed ({report['compared_key_count']} stage-accounted keys)")
    print(m7.ARTIFACTS / report_name)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
