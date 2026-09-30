#!/usr/bin/env python3
"""Compare two-worker child arena Heap ownership with pinned mimalloc."""

from pathlib import Path
import sys

import x86_64_m6_child_heap_in_arena as arena

import run as harness


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_heap_in_arena_two_worker_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-heap-in-arena-two-worker"
BEGIN = "CRABC_MI_M6_TWO_WORKER_ARENA_BEGIN"
END = "CRABC_MI_M6_TWO_WORKER_ARENA_END"
EXPECTED = {
    "two.reserved": "1,1,1,1",
    "two.first_page": "1,1",
    "two.second_page": "1,1",
    "two.theaps": "1,1,1",
    "two.deleted": "1",
    "two.first_released": "1",
    "two.no_early_reuse": "1,1",
    "two.second_held": "1,1",
    "two.second_released": "1",
    "two.final": "1,1",
    "two.joined": "1,1",
    "two.teardown": "1",
}
SOURCE = {
    "source.two_before": "1,1,1,1,1,1",
    "source.two_refs": "2,2",
    "source.two_detached": "1,1,1,1",
    "source.two_first_released": "1,1,1",
    "source.two_held": "1,1",
    "source.two_released": "1,1",
}


RUNNER = "allocator-child-heap-in-arena-two-worker"


def run_differential() -> int:
    return arena.run_fixture(sys.modules[__name__], ("release",))


if __name__ == "__main__":
    try:
        raise SystemExit(arena.main(sys.modules[__name__]))
    except (harness.HarnessError, arena.receipts.ReceiptError) as error:
        print(f"Two-worker Child Heap arena failed: {error}", file=sys.stderr)
        raise SystemExit(1)
