#!/usr/bin/env python3
"""Compare accumulated main-Heap populations after every worker owner exits."""

from pathlib import Path
import sys

import run as harness
import x86_64_m7_gate as m7
import x86_64_m6_main_visitor_population as population

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


RUNNER = "allocator-main-population-after-owner-exit"
CASES = ((),)
WATCHDOG = 120
SOURCE_INTERNAL = False


def validate_population(trace, case, side):
    require_trace(trace, side)


def check_population_diagnostics(c_stderr, native_stderr, case, profile):
    pass


def run_differential() -> int:
    return population.run_profiles(sys.modules[__name__], ("release",))


def main(arguments=None):
    return population.dispatch(sys.modules[__name__], arguments)


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, population.receipts.ReceiptError, population.stress.EvidenceError) as error:
        print(f"main population after owner exit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
