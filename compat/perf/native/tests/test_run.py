"""Host-only tests for the Rustybench facade-report aggregation contract."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_perf_native", MODULE)
assert SPEC is not None and SPEC.loader is not None
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)


def resource(value: int) -> dict[str, object]:
    return {
        "status": "supported",
        "memory_status": "supported",
        "user_cpu_ns": value,
        "system_cpu_ns": value,
        "voluntary_context_switches": value,
        "involuntary_context_switches": value,
        "minor_page_faults": value,
        "major_page_faults": value,
        "rss_bytes": value,
        "pss_bytes": value,
    }


class AggregateRunsTests(unittest.TestCase):
    def test_medians_preserve_resource_contract(self) -> None:
        runs = [
            {"benchmarks": [{"name": "native::getpid", "median_ns": value, "alloc_count": 0,
                "alloc_bytes": 0, "max_alloc_count": 0, "max_alloc_bytes": 0,
                "process_resources": resource(value)}]}
            for value in (10, 20, 30)
        ]
        summary = native.aggregate_runs(runs)
        getpid = summary["native::getpid"]
        self.assertEqual(getpid["median_ns"], 20)
        self.assertEqual(getpid["process_resources"]["rss_bytes"], 20)
        self.assertEqual(getpid["invocation_count"], 3)


if __name__ == "__main__":
    unittest.main()
