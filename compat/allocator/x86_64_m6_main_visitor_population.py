#!/usr/bin/env python3
"""Compare main-Heap page populations around Heap destruction and collection."""

from __future__ import annotations

import re
from pathlib import Path

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_main_visitor_population_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-main-visitor-population"
CASES = (
    ("direct", "plain", "one"),
    ("fork", "plain", "one"),
    ("direct", "plain", "2"),
    ("direct", "plain", "10"),
    ("direct", "plain", "100"),
    ("direct", "plain", "250"),
    ("direct", "plain", "500"),
    ("direct", "plain", "many"),
    ("direct", "reserve", "many"),
    ("fork", "reserve", "many"),
)

THEAP_LINE = re.compile(
    r"^source\.theap_(live|destroyed|after_visit)=(0x[0-9a-f]+),(\d+),(\d+),(\d+),(\d+)$",
    re.MULTILINE,
)
CLASS_LINE = re.compile(r"^population\.class=(\d+),(\d+)$", re.MULTILINE)
REPLACED_SLOT_SIZES = (320, 640, 1280, 2560, 5120, 10240, 20480)
POPULATION_STAGES = ("before", "live", "destroyed", "visited_blocks", "after_visit", "collected")
IMAGE_STAGES = ("live", "destroyed", "after_visit")


def require_population_trace(trace: dict[str, str], case: tuple[str, str, str], side: str) -> None:
    expected = {f"population.{stage}{suffix}"
                for stage in POPULATION_STAGES for suffix in ("", "_classes")}
    expected.update(f"population.image_{stage}" for stage in IMAGE_STAGES)
    expected.update(("population.allocated", "population.image_usable"))
    if case[0] == "fork":
        expected.add("population.child")
    if case[1] == "reserve":
        expected.update(("population.reserve", "population.reserved", "population.reserved_classes"))
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} population keys differ: missing={sorted(expected - set(trace))} "
            f"extra={sorted(set(trace) - expected)}"
        )
    count = 1 if case[2] == "one" else 1000 if case[2] == "many" else int(case[2])
    if trace["population.allocated"] != str(count) or not trace["population.image_usable"].isdigit() \
            or int(trace["population.image_usable"]) == 0:
        raise harness.HarnessError(f"{side} did not create all requested live Heaps")
    if case[1] == "reserve" and trace["population.reserve"] != "0":
        raise harness.HarnessError(f"{side} did not establish the requested OS reservation")
    for stage in POPULATION_STAGES + (("reserved",) if case[1] == "reserve" else ()):
        if not re.fullmatch(r"[01](?:,[0-9]+){6},-?[0-9]+", trace[f"population.{stage}"]):
            raise harness.HarnessError(f"{side} population.{stage} is malformed")
        if not re.fullmatch(r"[0-9]+(?:,[0-9]+){5}", trace[f"population.{stage}_classes"]):
            raise harness.HarnessError(f"{side} population.{stage}_classes is malformed")
    for stage in IMAGE_STAGES:
        if not re.fullmatch(r"[01],[0-9]+,[0-9]+", trace[f"population.image_{stage}"]):
            raise harness.HarnessError(f"{side} population.image_{stage} is malformed")
    if case[0] == "fork" and trace["population.child"] != "1":
        raise harness.HarnessError(f"{side} forked population child did not complete")


def check_source_theap_collection(stderr: str) -> None:
    states = {stage: (address, int(size), int(thread), int(used), int(head))
              for stage, address, size, thread, used, head in THEAP_LINE.findall(stderr)}
    if set(states) != {"live", "destroyed", "after_visit"}:
        raise harness.HarnessError("source detached Theap lifetime observations are incomplete")
    live, destroyed, after = (states[stage] for stage in ("live", "destroyed", "after_visit"))
    if (live[:4], destroyed[:4], after[:4]) != (
        (live[0], 8104, 8, 1), (live[0], 8104, 8, 1), (live[0], 8104, 8, 0)
    ) or live[4] != 1 or destroyed[4] & 1 != 1 or destroyed[4] & ~1 == 0 or after[4] != 1:
        raise harness.HarnessError("source detached Theap was not remotely freed then visitor-collected")


def check_replaced_slot_images(c_stderr: str, rust_stderr: str) -> None:
    expected = [(size, 1) for size in REPLACED_SLOT_SIZES]
    for side, stderr in (("C", c_stderr), ("Rust", rust_stderr)):
        actual = sorted((int(size), int(used)) for size, used in CLASS_LINE.findall(stderr))
        if actual != expected:
            raise harness.HarnessError(f"{side} live detached slot images differ: {actual}")


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-main-population-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "main-population-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1",
             *harness.CONFIGURATION_PROFILES["release"], "-I", str(source / "include"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        harness.require_success(build, "main population C build")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "main-population-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)],
            cwd=source,
        )
        harness.require_success(link, "main population Rust link")
        differences = []
        for case in CASES:
            traces = {}
            diagnostics = {}
            for side, driver in (("c", c_driver), ("rust", rust_driver)):
                run = harness.command_record([str(driver), *case], cwd=temporary, env={}, timeout_seconds=300)
                label = "-".join((side, *case))
                (ARTIFACTS / f"{label}.log").write_text(str(run["stdout"]) + str(run["stderr"]))
                harness.require_success(run, f"main population {label}")
                diagnostics[side] = str(run["stderr"])
                traces[side] = m7.parse_options_trace(
                    str(run["stdout"]), label,
                    "CRABC_MI_M6_MAIN_POPULATION_TRACE_BEGIN",
                    "CRABC_MI_M6_MAIN_POPULATION_TRACE_END",
                )
                require_population_trace(traces[side], case, side)
            try:
                m7.compare_options_traces(traces["c"], traces["rust"])
                if case == ("direct", "plain", "one"):
                    check_source_theap_collection(diagnostics["c"])
                if case == ("direct", "plain", "many"):
                    check_replaced_slot_images(diagnostics["c"], diagnostics["rust"])
            except harness.HarnessError as error:
                differences.append(f"{'/'.join(case)}: {error}")
            else:
                print(f"main population {'/'.join(case)}: {len(traces['c'])} keys match")
    if differences:
        raise harness.HarnessError("\n".join(differences))


if __name__ == "__main__":
    main()
