#!/usr/bin/env python3
"""Compare OS singleton abandoned-page visitation against pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_abandoned_visitor import visitor_main


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_abandoned_os_visitor_driver.c"
GUARDED_PROFILES = tuple(m4.GUARDED_API_PROFILE_BASES)
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


def require_trace(trace: dict[str, str], side: str, profile="release") -> None:
    expected = {f"os.{stage}" for stage in STAGES}
    guarded = profile in GUARDED_PROFILES
    if guarded:
        expected.update(f"os.{stage}.guard" for stage in STAGES)
        expected.add("os.protected")
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
    if {key: trace[key] for key in SOURCE_OS_SINGLETON} != SOURCE_OS_SINGLETON:
        raise harness.HarnessError(f"pinned C abandoned OS singleton image changed: {trace}")
    if guarded:
        geometry = trace["os.areas.guard"]
        if (trace["os.protected"] != "1,1"
                or not re.fullmatch(r"1(?:,[0-9]+){5}", geometry)
                or any(trace[f"os.{stage}.guard"] != geometry for stage in STAGES)):
            raise harness.HarnessError(f"{side} guarded OS tag, protection or stopped geometry differs")
        _, usable, full, offset, callback_size, page_size = map(int, geometry.split(","))
        # Canonical slots include their final guard page and optional padding;
        # the retained interior client ends immediately before that OS page.
        padding = 8 if profile.startswith("guarded-debug-") or profile == "guarded-secure-3" else 0
        if (page_size < 4096 or page_size & (page_size - 1) or full % page_size
                or offset < 8 or usable < 1024 * 1024 + 1
                or full - offset - page_size != usable or full - padding != callback_size):
            raise harness.HarnessError(f"{side} guarded OS usable prefix or canonical geometry differs")



def compare_runs(c_stdout, c_stderr, native_stdout, native_stderr, profile):
    c_trace = m7.parse_options_trace(c_stdout, "c", BEGIN, END)
    native_trace = m7.parse_options_trace(native_stdout, "native", BEGIN, END)
    require_trace(c_trace, "c", profile)
    require_trace(native_trace, "native", profile)
    m7.compare_options_traces(c_trace, native_trace)
    if c_stdout != native_stdout:
        raise harness.HarnessError("abandoned visitor complete stdout differs")
    if c_stderr != "source.os=1,1\nsource.transfer=1,1,1\n" or native_stderr:
        raise harness.HarnessError("abandoned visitor source ownership assertions or diagnostics differ")


def main():
    visitor_main(DRIVER, ARTIFACTS, "allocator-abandoned-os-visitor", compare_runs, source_internal=True,
        available_profiles=("release", "debug-1", "stat-1", "stat-2", *GUARDED_PROFILES))


if __name__ == "__main__":
    main()
