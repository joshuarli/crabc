#!/usr/bin/env python3
"""Compare Heap deletion after the creating thread has exited."""

import argparse
import sys

import run as harness
from x86_64_m6_deleted_heap_remote_exit import ownership_matrix, PROFILES, receipts, stress


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_delete_after_owner_exit_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-delete-after-owner-exit"
BEGIN = "CRABC_MI_M6_HEAP_DELETE_AFTER_OWNER_EXIT_BEGIN"
END = "CRABC_MI_M6_HEAP_DELETE_AFTER_OWNER_EXIT_END"
EXPECTED = {
    "exit.created": "1",
    "exit.live": "1,1,1,1",
    "exit.deleted": "0,0,1,1",
    "exit.freed": "37,0,0",
    "exit.collected": "0,0",
}


RUNNER = "allocator-heap-delete-after-owner-exit"


def run_differential():
    ownership_matrix(DRIVER, ARTIFACTS, RUNNER, ("release",), ("joined",),
                     BEGIN, END, {"joined": EXPECTED})
    return len(EXPECTED)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=PROFILES, default="release")
    selection.add_argument("--matrix", action="store_true", help="execute the unchanged full workload in all four profiles")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--source-only", action="store_true")
    action.add_argument("--read", action="store_true")
    action.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    ownership_matrix(DRIVER, ARTIFACTS, RUNNER, PROFILES if args.matrix else (args.profile,),
                     ("joined",), BEGIN, END, {"joined": EXPECTED},
                     source_only=args.source_only, read=args.read, replay=args.replay)


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Heap delete after owner exit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
