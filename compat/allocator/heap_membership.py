#!/usr/bin/env python3
"""Run the exact native Heap membership and page-lifetime regressions."""

from __future__ import annotations

import run as harness


TESTS = (
    "source_heap_api::heap_membership_tests::live_interior_foreign_and_moved_page_queries_follow_page_identity",
    "source_heap_api::heap_membership_tests::joined_remote_free_exposes_non_head_page_utilization",
)


def main() -> None:
    harness.require_native_x86_64()
    artifacts = harness.ARTIFACT_ROOT / "x86_64/heap-membership"
    artifacts.mkdir(parents=True, exist_ok=True)
    for index, name in enumerate(TESTS):
        execution = harness.command_record(
            ["python3", "compat/allocator/run_unit_x86_64.py", name],
            cwd=harness.ROOT,
            timeout_seconds=900,
        )
        (artifacts / f"unit-{index}.log").write_text(
            str(execution["stdout"]) + str(execution["stderr"])
        )
        harness.require_success(execution, f"Heap membership unit {name}")
        print(f"passed {name}")


if __name__ == "__main__":
    main()
