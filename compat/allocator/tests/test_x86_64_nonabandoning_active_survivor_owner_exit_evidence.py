#!/usr/bin/env python3
"""Observable trace contract for active-survivor medium retirement."""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_nonabandoning_active_survivor_owner_exit_evidence.py"
spec = importlib.util.spec_from_file_location("active_survivor_owner_exit_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class TraceContractTests(unittest.TestCase):
    def test_complete_matching_lifecycle(self):
        trace = dict(evidence.EXPECTED_TRACE)
        c = evidence.parse_trace(evidence.render_trace(trace), "C")
        rust = evidence.parse_trace(evidence.render_trace(trace), "Rust")
        self.assertEqual(evidence.compare_traces(c, rust), trace)

    def test_missing_or_mutated_survivor_release_fails(self):
        trace = dict(evidence.EXPECTED_TRACE)
        trace.pop("medium_released_after_collect")
        with self.assertRaisesRegex(evidence.EvidenceError, "missing"):
            evidence.parse_trace(evidence.render_trace(trace), "C")
        trace = dict(evidence.EXPECTED_TRACE)
        trace["medium_retired_expire"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "medium_retired_expire"):
            evidence.compare_traces(evidence.EXPECTED_TRACE, trace)

    def test_duplicate_or_address_line_fails(self):
        raw = evidence.render_trace(evidence.EXPECTED_TRACE)
        with self.assertRaisesRegex(evidence.EvidenceError, "duplicate"):
            evidence.parse_trace(raw.replace("medium_released_after_collect=1", "medium_released_after_collect=1\nmedium_released_after_collect=1"), "C")
        with self.assertRaisesRegex(evidence.EvidenceError, "address"):
            evidence.parse_trace(raw.replace(evidence.TRACE_END, "address=0x123\n" + evidence.TRACE_END), "C")


if __name__ == "__main__":
    unittest.main()
