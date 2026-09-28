#!/usr/bin/env python3
"""Judge registered-slice plateaus at drained allocator soak checkpoints."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Sequence


# Each window spans a quarter of the run. Its median excludes a brief remote
# free backlog while retaining growth that persists across later churn.
def _median_twice(values: Sequence[int]) -> int:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return 2 * ordered[middle] if len(ordered) % 2 else ordered[middle - 1] + ordered[middle]


def page_map_stability(entries: Sequence[int]) -> dict[str, int | float | bool]:
    """Keep peak counts visible and bound sustained late registered-slice growth."""

    if len(entries) < 8:
        raise ValueError("PageMap stability needs at least eight drained checkpoints")
    if any(entry <= 0 for entry in entries):
        raise ValueError("PageMap stability needs positive registered-slice counts")
    window = len(entries) // 4
    first_twice = _median_twice(entries[:window])
    last_twice = _median_twice(entries[-window:])
    half = len(entries) // 2
    return {
        "first_half_max": max(entries[:half]),
        "second_half_max": max(entries[half:]),
        "window_checkpoints": window,
        "first_window_median": first_twice / 2,
        "last_window_median": last_twice / 2,
        "exceeds_ten_percent": last_twice * 10 > first_twice * 11,
    }


EXACT = {"live_threads": 1, "metadata_live": 0, "later_theaps": 0, "abandoned_pages": 0,
         "attached_workers": 0}
# Current RSS is -1 where the execution root mounts no /proc. Its high-water
# records a transient peak and is reported by the probe without a growth gate.
BOUNDED = ("page_map_entries", "page_map_submaps", "arenas", "metadata_high_water", "rss_kib")


def fields(line: str) -> dict[str, str]:
    return {key: value for key, value in (item.split("=", 1) for item in line.split()[1:])}


def evaluate_soak_output(output: str, label: str) -> tuple[dict[str, object], list[str]]:
    """Read one completed soak transcript without dropping its raw observations."""

    lines = output.splitlines()
    checkpoints = [fields(line) for line in lines if line.startswith("checkpoint ")]
    record: dict[str, object] = {
        "header": fields(lines[0]),
        "summary": fields(next(line for line in lines if line.startswith("summary "))),
        "checkpoints": checkpoints,
    }
    failures: list[str] = []
    if len(checkpoints) < 4:
        failures.append(f"{label}: {len(checkpoints)} checkpoints are too few to judge growth")
        return record, failures
    half = len(checkpoints) // 2
    growth: dict[str, object] = {}
    for key in BOUNDED:
        if key not in checkpoints[0] or int(checkpoints[0][key]) < 0:
            continue
        entries = [int(point[key]) for point in checkpoints]
        if key == "page_map_entries":
            try:
                plateau = page_map_stability(entries)
            except ValueError as error:
                failures.append(f"{label}: {error}")
                continue
            growth[key] = plateau
            if plateau["exceeds_ten_percent"]:
                failures.append(
                    f"{label}: {key} window median grew from {plateau['first_window_median']} "
                    f"to {plateau['last_window_median']} across equivalent churn"
                )
        else:
            first = max(entries[:half])
            later = max(entries[half:])
            growth[key] = {"first_half_max": first, "second_half_max": later}
            if later > first + first // 10:
                failures.append(f"{label}: {key} grew from {first} to {later} across equivalent churn")
    record["growth"] = growth
    for point in checkpoints:
        for key, expected in EXACT.items():
            if key in point and int(point[key]) != expected:
                failures.append(f"{label}: round {point['round']} {key}={point[key]}, expected {expected}")
    return record, failures


def main() -> None:
    work = Path(sys.argv[1])
    summary: dict[str, object] = {}
    failures: list[str] = []
    for stdout in sorted(work.glob("soak-*.stdout")):
        label = stdout.stem
        record, case_failures = evaluate_soak_output(stdout.read_text(), label)
        summary[label] = record
        failures.extend(case_failures)
    (work / "soak-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    for label, record in summary.items():
        last = record["checkpoints"][-1]
        print(f"{label}: {record['summary']} final {last}")
    if failures:
        raise SystemExit("native-allocator-soak: " + "; ".join(failures))


if __name__ == "__main__":
    main()
