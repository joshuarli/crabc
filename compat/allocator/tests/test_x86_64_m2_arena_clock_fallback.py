from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
import m2_arena_clock_fallback_x86_64 as producer


class ArenaClockFallbackTraceTests(unittest.TestCase):
    def test_trace_requires_each_observed_transition_once(self):
        rows = [f"m2.arena_clock.{name}={value}" for name, value in producer.EXPECTED.items()]
        self.assertEqual(producer.parse_trace("\n".join(rows), "fixture"), producer.EXPECTED)
        for changed in (rows[:-1], [*rows, rows[0]], [*rows[:-1], "m2.arena_clock.purges=0"]):
            with self.subTest(rows=changed), self.assertRaises(producer.harness.HarnessError):
                producer.parse_trace("\n".join(changed), "fixture")


if __name__ == "__main__":
    unittest.main()
