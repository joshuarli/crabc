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
    def record(self, language: str, *, tail: bool = False) -> str:
        prefix = "loader_tail" if tail else "concurrent_init"
        marker = "LOADER_TAIL" if tail else "CONCURRENT_INIT"
        fields = evidence.TAIL_FIELDS if tail else evidence.FIELDS
        lines = [f"trace.{prefix}.{field}=1" for field in fields]
        return (f"CRABC_MI_{marker}_{language}_TRACE_BEGIN\n"
                + "\n".join(lines)
                + f"\nCRABC_MI_{marker}_{language}_TRACE_END\n")

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

    def test_loader_tail_observations_require_the_opposite_once_boundary(self) -> None:
        c_record = evidence.parse_trace(self.record("C", tail=True), "C", tail=True)
        rust_record = evidence.parse_trace(self.record("RUST", tail=True), "RUST", tail=True)
        evidence.compare(c_record, rust_record)
        rust_record["contender_completes_during_tail"] = 0
        with self.assertRaises(ValueError):
            evidence.compare(c_record, rust_record)

    def test_loader_tail_missing_duplicate_and_body_record_are_rejected(self) -> None:
        record = self.record("C", tail=True)
        field = "trace.loader_tail.ready_before_tail_output=1\n"
        for invalid in (record.replace(field, ""), record.replace(field, field * 2), self.record("C")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                evidence.parse_trace(invalid, "C", tail=True)

    def test_cross_language_disagreement_is_rejected(self) -> None:
        c_record = evidence.parse_trace(self.record("C"), "C")
        rust_record = evidence.parse_trace(self.record("RUST"), "RUST")
        rust_record["contender_waits"] = 0
        with self.assertRaises(ValueError):
            evidence.compare(c_record, rust_record)


if __name__ == "__main__":
    unittest.main()
