#!/usr/bin/env python3
"""Reader checks for the concurrent process-init differential record."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "x86_64_m2_concurrent_init.py"
spec = importlib.util.spec_from_file_location("concurrent_init", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class ConcurrentInitReaderTests(unittest.TestCase):
    def record(self, language: str) -> str:
        lines = [f"trace.concurrent_init.{field}=1" for field in evidence.FIELDS]
        return (f"CRABC_MI_CONCURRENT_INIT_{language}_TRACE_BEGIN\n"
                + "\n".join(lines)
                + f"\nCRABC_MI_CONCURRENT_INIT_{language}_TRACE_END\n")

    def test_complete_matching_observations(self) -> None:
        c_record = evidence.parse_trace(self.record("C"), "C")
        rust_record = evidence.parse_trace(self.record("RUST"), "RUST")
        evidence.compare(c_record, rust_record)

    def test_missing_and_duplicate_observations_are_rejected(self) -> None:
        c_trace = self.record("C")
        with self.assertRaises(ValueError):
            evidence.parse_trace(c_trace.replace("trace.concurrent_init.contender_waits=1\n", ""), "C")
        with self.assertRaises(ValueError):
            evidence.parse_trace(c_trace.replace("trace.concurrent_init.contender_waits=1\n",
                                                  "trace.concurrent_init.contender_waits=1\n" * 2), "C")

    def test_cross_language_disagreement_is_rejected(self) -> None:
        c_record = evidence.parse_trace(self.record("C"), "C")
        rust_record = evidence.parse_trace(self.record("RUST"), "RUST")
        rust_record["contender_waits"] = 0
        with self.assertRaises(ValueError):
            evidence.compare(c_record, rust_record)


if __name__ == "__main__":
    unittest.main()
