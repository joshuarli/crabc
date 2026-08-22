"""Host-only contract tests for the performance-report helpers."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_perf", MODULE)
assert SPEC is not None and SPEC.loader is not None
perf = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = perf
SPEC.loader.exec_module(perf)


class SyscallSummaryTests(unittest.TestCase):
    def test_counts_multiple_strace_layouts_and_errors(self) -> None:
        trace = """[pid 12] clock_gettime(CLOCK_MONOTONIC, {tv_sec=1, tv_nsec=2}) = 0
13 openat(AT_FDCWD, \"/missing\", O_RDONLY) = -1 ENOENT (No such file or directory)
getpid() = 13
"""
        self.assertEqual(
            perf.syscall_summary(trace),
            {
                "calls": {
                    "clock_gettime": {"calls": 1, "errors": 0},
                    "getpid": {"calls": 1, "errors": 0},
                    "openat": {"calls": 1, "errors": 1},
                },
                "total_calls": 3,
                "total_errors": 1,
            },
        )


class SummaryTests(unittest.TestCase):
    def test_summary_keeps_resource_units_and_median(self) -> None:
        samples = []
        for value in (10, 20, 30):
            samples.append(
                {
                    "elapsed_wall_ns": value,
                    "resources": {
                        "user_cpu_ns": value,
                        "system_cpu_ns": value,
                        "max_rss_kib": value,
                        "minor_faults": value,
                        "major_faults": value,
                        "voluntary_context_switches": value,
                        "involuntary_context_switches": value,
                    },
                }
            )
        summary = perf.summarize_samples(samples)
        self.assertEqual(summary["elapsed_wall_ns"], {"min": 10, "median": 20, "p95": 30, "max": 30})
        self.assertEqual(summary["resources.max_rss_kib"]["median"], 20)


if __name__ == "__main__":
    unittest.main()
