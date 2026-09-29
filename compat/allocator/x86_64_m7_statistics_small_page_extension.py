#!/usr/bin/env python3
"""Compare 8 KiB regular-page extension producers with pinned mimalloc C."""

from __future__ import annotations

import argparse
import sys

import run as harness
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_small_page_extension_driver.c"
BEGIN = "CRABC_MI_M7_SMALL_PAGE_EXTENSION_BEGIN"
END = "CRABC_MI_M7_SMALL_PAGE_EXTENSION_END"
STAGES = ("one", "eight", "sixteen", "thirty_two", "forty_eight", "freed")
FIELDS = ("extensions", "page_committed", "pages", "page_bin", "normal", "bin", "requested")


def require_source_shape(trace: dict[str, str], side: str) -> None:
    expected = {"request", "bin.index"} | {f"{stage}.{field}" for stage in STAGES for field in FIELDS}
    if set(trace) != expected or trace["request"] != "8192" or trace["bin.index"] != "36":
        raise harness.HarnessError(f"{side}: incomplete 8 KiB regular-page trace")
    if trace["one.normal"] != "8192,8192,8192" or trace["one.bin"] != "1,1,1":
        raise harness.HarnessError(f"{side}: first block lost normal/bin accounting")
    stage_counts = {"one": (1, 1), "eight": (8, 1), "sixteen": (16, 2),
                    "thirty_two": (32, 4), "forty_eight": (48, 6)}
    for stage, (blocks, pages) in stage_counts.items():
        bytes_used = blocks * 8192
        required = {
            "extensions": str(blocks),
            "page_committed": f"{bytes_used},{bytes_used},{bytes_used}",
            "pages": f"{pages},{pages},{pages}",
            "page_bin": f"{pages},{pages},{pages}",
            "normal": f"{bytes_used},{bytes_used},{bytes_used}",
            "bin": f"{blocks},{blocks},{blocks}",
            "requested": f"{bytes_used},{bytes_used},{bytes_used}",
        }
        for field, value in required.items():
            if trace[f"{stage}.{field}"] != value:
                raise harness.HarnessError(f"{side}: {stage}.{field} lost source accounting")
    final = {"extensions": "48", "page_committed": "393216,393216,393216",
             "pages": "6,6,1", "page_bin": "6,6,1", "normal": "393216,393216,0",
             "bin": "48,48,0", "requested": "393216,393216,393216"}
    for field, value in final.items():
        if trace[f"freed.{field}"] != value:
            raise harness.HarnessError(f"{side}: freed.{field} lost source lifetime accounting")
    for stage in STAGES:
        for field in FIELDS[1:]:
            if len(trace[f"{stage}.{field}"].split(",")) != 3:
                raise harness.HarnessError(f"{side}: malformed {stage}.{field}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    report = m7.run_public_statistics_differential(
        args.offline, subject="small-page-extension", driver=DRIVER,
        begin=BEGIN, end=END, report_name="statistics-small-page-extension.json",
        stat_level=2, require_complete=require_source_shape,
    )
    print(f"8 KiB regular-page statistics: {report['status']} ({report['compared_key_count']} exact keys)")
    print(m7.ARTIFACTS / "statistics-small-page-extension.json")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
