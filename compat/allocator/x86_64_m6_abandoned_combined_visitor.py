#!/usr/bin/env python3
"""Compare combined regular and OS abandoned-page visitation against pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_abandoned_visitor import visitor_main


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_abandoned_combined_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-abandoned-combined-visitor"
STAGES = ("areas", "blocks", "stop_regular_area", "stop_regular_block", "ordinary")
BEGIN = "CRABC_MI_M6_ABANDONED_COMBINED_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_ABANDONED_COMBINED_VISITOR_TRACE_END"
SOURCE_COMBINED_PAGES = {
    "combined.areas": "1,1,1,0,0,0,2,1,RO",
    "combined.blocks": "1,1,1,2,1,0,2,1,R13OS",
    "combined.stop_regular_area": "0,1,0,0,0,0,2,0,R",
    "combined.stop_regular_block": "0,1,0,1,0,0,2,0,R1",
    "combined.ordinary": "1,1,1,2,1,0,2,1,R13OS",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"combined.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} combined visitor keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){7},[RO13FS]*", trace[f"combined.{stage}"]):
            raise harness.HarnessError(f"{side} combined.{stage} is malformed")
    if trace != SOURCE_COMBINED_PAGES:
        raise harness.HarnessError(f"pinned C combined abandoned-page image changed: {trace}")



def compare_runs(c_stdout, c_stderr, native_stdout, native_stderr, profile):
    c_trace = m7.parse_options_trace(c_stdout, "c", BEGIN, END)
    native_trace = m7.parse_options_trace(native_stdout, "native", BEGIN, END)
    require_trace(c_trace, "c")
    require_trace(native_trace, "native")
    m7.compare_options_traces(c_trace, native_trace)
    if c_stdout != native_stdout:
        raise harness.HarnessError("abandoned visitor complete stdout differs")
    if c_stderr != "source.transfer=1,1,1,1,1\n" or native_stderr:
        raise harness.HarnessError("abandoned visitor source ownership assertions or diagnostics differ")


def main():
    visitor_main(DRIVER, ARTIFACTS, "allocator-abandoned-combined-visitor", compare_runs, source_internal=True)


if __name__ == "__main__":
    main()
