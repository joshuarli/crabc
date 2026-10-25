"""Reject incomplete and different M1 clock fallback traces."""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))

import m1_clock_fallback_x86_64 as producer


class ClockFallbackTrace(unittest.TestCase):
    def test_complete_source_fallback_trace_is_accepted(self):
        output = "\n".join((
            producer.BEGIN,
            "preferred.calls=1",
            "fallback.calls=1",
            "clock.milliseconds=1234",
            producer.END,
        ))
        self.assertEqual(producer.trace(output, "fixture"), producer.EXPECTED)

    def test_missing_fallback_observation_is_rejected(self):
        output = "\n".join((
            producer.BEGIN,
            "preferred.calls=1",
            "clock.milliseconds=1234",
            producer.END,
        ))
        with self.assertRaisesRegex(producer.harness.HarnessError, "differs"):
            producer.trace(output, "fixture")

    def test_wrong_tick_conversion_is_rejected(self):
        output = "\n".join((
            producer.BEGIN,
            "preferred.calls=1",
            "fallback.calls=1",
            "clock.milliseconds=1235",
            producer.END,
        ))
        with self.assertRaisesRegex(producer.harness.HarnessError, "differs"):
            producer.trace(output, "fixture")


if __name__ == "__main__":
    unittest.main()
