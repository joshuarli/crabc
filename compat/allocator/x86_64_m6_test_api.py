#!/usr/bin/env python3
"""Run the unmodified pinned test-api.c through the native adapter for M6.

The M4 gate owns the link and run (`x86_64_m4_gate.py --upstream-test-api`);
this M6 runner additionally requires its Heap and reservation checks to be
among the passing ones.
"""

from __future__ import annotations

import run as harness
import x86_64_m4_gate as m4


M6_CHECKS = ("heap-os1", "heap-os2", "heap-many", "arena_reserve")


def main() -> int:
    report = m4.run_upstream_test_api(offline=True)
    missing = [name for name in M6_CHECKS if report["checks"].get(name) is not True]
    if missing:
        raise harness.HarnessError(f"test-api M6 checks did not pass: {missing}")
    print(f"upstream test-api passed: {len(report['checks'])} checks, including {', '.join(M6_CHECKS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
