#!/usr/bin/env python3
"""Compare Heap destruction while an exited creator's second worker stays attached."""

import sys

import x86_64_m6_heap_delete_with_attached_worker as attached

import run as harness


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_destroy_with_attached_worker_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-destroy-with-attached-worker"
BEGIN = "CRABC_MI_M6_HEAP_DESTROY_WITH_ATTACHED_WORKER_BEGIN"
END = "CRABC_MI_M6_HEAP_DESTROY_WITH_ATTACHED_WORKER_END"
EXPECTED = {
    "attached.owner": "1,1",
    "attached.live": "1,1,1,1",
    "attached.destroy": "37,0,1,1",
    "attached.stats": "1,0",
    "attached.joined": "0,1,1",
}


RUNNER = "allocator-heap-destroy-attached-worker"


def run_differential() -> int:
    return attached.run_fixture(sys.modules[__name__], ("release",))


if __name__ == "__main__":
    try:
        raise SystemExit(attached.main(sys.modules[__name__]))
    except (harness.HarnessError, attached.receipts.ReceiptError) as error:
        print(f"attached-worker Heap destroy failed: {error}", file=sys.stderr)
        raise SystemExit(1)
