#!/usr/bin/env python3
"""Compare OS singleton abandoned-page visitation against pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_abandoned_visitor import visitor_main


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_abandoned_os_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-abandoned-os-visitor"
STAGES = ("areas", "blocks", "stop_area", "stop_block", "ordinary")
BEGIN = "CRABC_MI_M6_ABANDONED_OS_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_ABANDONED_OS_VISITOR_TRACE_END"
SOURCE_OS_SINGLETON = {
    "os.areas": "1,1,0,1,1,0,0,0,1",
    "os.blocks": "1,1,1,1,1,1,0,0,12",
    "os.stop_area": "0,1,0,1,1,0,0,0,1",
    "os.stop_block": "0,1,1,1,1,1,0,0,12",
    "os.ordinary": "1,1,1,1,1,1,0,0,12",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"os.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} OS abandoned visitor keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){8}", trace[f"os.{stage}"]):
            raise harness.HarnessError(f"{side} os.{stage} is malformed")
    if trace["os.areas"].split(",")[:3] != ["1", "1", "0"] \
            or trace["os.blocks"].split(",")[:3] != ["1", "1", "1"] \
            or trace["os.stop_area"].split(",")[:3] != ["0", "1", "0"] \
            or trace["os.stop_block"].split(",")[:3] != ["0", "1", "1"]:
        raise harness.HarnessError(f"{side} did not visit one live OS singleton with early stops")
    if trace != SOURCE_OS_SINGLETON:
        raise harness.HarnessError(f"pinned C abandoned OS singleton image changed: {trace}")



def compare_runs(c_stdout, c_stderr, native_stdout, native_stderr, profile):
    c_trace = m7.parse_options_trace(c_stdout, "c", BEGIN, END)
    native_trace = m7.parse_options_trace(native_stdout, "native", BEGIN, END)
    require_trace(c_trace, "c")
    require_trace(native_trace, "native")
    m7.compare_options_traces(c_trace, native_trace)
    if c_stdout != native_stdout:
        raise harness.HarnessError("abandoned visitor complete stdout differs")
    if c_stderr != "source.os=1,1\nsource.transfer=1,1,1\n" or native_stderr:
        raise harness.HarnessError("abandoned visitor source ownership assertions or diagnostics differ")


def main():
    visitor_main(DRIVER, ARTIFACTS, "allocator-abandoned-os-visitor", compare_runs, source_internal=True)


if __name__ == "__main__":
    main()
