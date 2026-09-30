"""Observe statistics mode and release failure boundaries in retained traces."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run as harness
from x86_64_m7_statistics_regular_page_release_fault import comparable_trace


class RegularPageReleaseStatisticsTests(unittest.TestCase):
    def trace(self, *, level=2, debug=False, faulted=True):
        normal = (72 if debug else 64) if level else 0
        bin_index = 9 if debug else 8
        trace = {"profile.level": str(level), "profile.disallow_arena": "1"}
        for stage in ("allocated", "freed", "failed_release"):
            released = stage == "failed_release"
            trace.update({
                f"{stage}.pages": f"1,0,{int(not released)}",
                f"{stage}.normal": f"{normal},0,{normal if stage == 'allocated' else 0}",
                f"{stage}.page_bin": f"{bin_index}:1,{int(not released)}",
                f"{stage}.reserved": f"65536,65536,{0 if released else 65536}",
                f"{stage}.committed": f"65536,65536,{0 if released else 65536}",
                f"{stage}.warnings": str(int(released and faulted)),
                f"{stage}.failures": str(int(released and faulted)),
            })
        if debug:
            trace["geometry.block_size"] = "80"
        return trace

    def test_failed_unmap_still_debits_released_page_and_vm_current(self):
        trace = self.trace()
        comparable_trace(trace)
        for field in ("pages", "reserved", "committed"):
            with self.subTest(field=field):
                trace = self.trace()
                trace[f"failed_release.{field}"] = trace[f"freed.{field}"]
                with self.assertRaises(harness.HarnessError):
                    comparable_trace(trace)

    def test_level_zero_keeps_page_lifetime_and_disables_normal_bytes(self):
        trace = self.trace(level=0)
        compared = comparable_trace(trace, level=0)
        self.assertEqual(compared["failed_release.pages"], "1,0,0")
        trace["allocated.normal"] = "64,0,64"
        with self.assertRaises(harness.HarnessError):
            comparable_trace(trace, level=0)

    def test_successful_release_control_has_no_warning_or_failure(self):
        trace = self.trace(faulted=False)
        comparable_trace(trace, faulted=False)
        for field in ("warnings", "failures"):
            with self.subTest(field=field):
                trace = self.trace(faulted=False)
                trace[f"failed_release.{field}"] = "1"
                with self.assertRaises(harness.HarnessError):
                    comparable_trace(trace, faulted=False)

    def test_debug_padding_uses_source_bin_and_unpadded_normal_bytes(self):
        trace = self.trace(debug=True)
        comparable_trace(trace, debug=True)
        trace["allocated.normal"] = "80,0,80"
        with self.assertRaises(harness.HarnessError):
            comparable_trace(trace, debug=True)


if __name__ == "__main__":
    unittest.main()
