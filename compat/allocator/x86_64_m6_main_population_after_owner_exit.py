#!/usr/bin/env python3
"""Compare accumulated main-Heap pages after worker Heap owners exit."""

from pathlib import Path

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_main_population_after_owner_exit_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-main-population-after-owner-exit"
BEGIN = "CRABC_MI_M6_MAIN_POPULATION_AFTER_OWNER_EXIT_BEGIN"
END = "CRABC_MI_M6_MAIN_POPULATION_AFTER_OWNER_EXIT_END"
STAGES = (
    "baseline", "exited", "deleted", "destroyed", "freed_small",
    "freed_medium", "freed_singleton", "collected",
)


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"population.{stage}" for stage in STAGES}
    expected.update({
        "population.created", "population.exited_membership", "population.payload",
        "population.deleted_membership", "population.destroyed_region",
        "population.final",
    })
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} population keys differ: missing={sorted(expected - set(trace))} "
            f"extra={sorted(set(trace) - expected)}"
        )
    for key, wanted in (
        ("population.created", "1"),
        ("population.exited_membership", "1,1,1,1,1,1"),
        ("population.payload", "1,1,1,1,1,1"),
        ("population.deleted_membership", "1,1,1"),
        ("population.destroyed_region", "0,0,0"),
        ("population.final", "37,0,0,0"),
    ):
        if trace[key] != wanted:
            raise harness.HarnessError(f"{side} {key} = {trace[key]}, expected {wanted}")
    for stage in STAGES:
        fields = trace[f"population.{stage}"].split(",")
        if len(fields) != 12 or fields[0] != "1" or not all(
            field.isdigit() for field in fields[1:-1]
        ):
            raise harness.HarnessError(f"{side} population.{stage} is malformed")
        if sum(int(field) for field in fields[7:10]) != int(fields[10]):
            raise harness.HarnessError(f"{side} population.{stage} class use does not sum")
        if int(fields[1]) != sum(
            int(field) for field in fields[4:7]
        ):
            raise harness.HarnessError(f"{side} population.{stage} visitor totals disagree")
    exited = [int(field) for field in trace["population.exited"].split(",")]
    deleted = [int(field) for field in trace["population.deleted"].split(",")]
    destroyed = [int(field) for field in trace["population.destroyed"].split(",")]
    freed_small = [int(field) for field in trace["population.freed_small"].split(",")]
    freed_medium = [int(field) for field in trace["population.freed_medium"].split(",")]
    freed_singleton = [int(field) for field in trace["population.freed_singleton"].split(",")]
    collected = [int(field) for field in trace["population.collected"].split(",")]
    if not (
        exited[1] > 0
        and deleted[1] > exited[1]
        and deleted[5] > 0
        and deleted[8] > 0
        and deleted[2] > destroyed[2] > freed_small[2] > freed_medium[2]
        > freed_singleton[2] == collected[2] == 0
    ):
        raise harness.HarnessError(f"{side} did not populate and release the main Heap")


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-main-population-after-owner-exit-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "main-population-after-owner-exit-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             *harness.CONFIGURATION_PROFILES["release"], "-I", str(source / "include"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "main population after owner exit C build")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "main-population-after-owner-exit-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "main population after owner exit Rust link")
        traces = {}
        for side, driver in (("c", c_driver), ("rust", rust_driver)):
            run = harness.command_record([str(driver)], cwd=temporary, env={}, timeout_seconds=120)
            (ARTIFACTS / f"{side}.log").write_text(str(run["stdout"]) + str(run["stderr"]))
            harness.require_success(run, f"main population after owner exit {side} run")
            trace = m7.parse_options_trace(str(run["stdout"]), side, BEGIN, END)
            require_trace(trace, side)
            traces[side] = trace
        m7.compare_options_traces(traces["c"], traces["rust"])
        return len(traces["c"])


if __name__ == "__main__":
    print(f"main population after owner exit: {run_differential()} source-built C/Rust keys match")
