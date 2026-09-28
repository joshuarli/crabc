"""PageMap plateau behavior at drained allocator soak checkpoints."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import allocator_page_map_stability as stability


# The pinned C and native static-PIE source runs each crossed the old
# first-half/second-half peak bound once but returned to their usual level.
PINNED_C_SPIKE = [
    846, 830, 861, 831, 847, 771, 853, 821, 766, 830,
    990, 821, 765, 773, 821, 821, 821, 824, 757, 845,
]
NATIVE_SPIKE = [
    777, 865, 726, 831, 840, 906, 822, 857, 872, 852,
    859, 900, 998, 781, 846, 839, 894, 856, 823, 858,
]


def soak_output(entries: list[int]) -> str:
    lines = ["soak seed=0x000000005eed0002 rounds=1200 workers=8 checkpoint_interval=60"]
    for index, count in enumerate(entries, 1):
        lines.append(
            f"checkpoint round={index * 60} allocations={index} frees={index} "
            f"page_map_entries={count} page_map_submaps=3 arenas=1 metadata_high_water=16 "
            "live_threads=1 metadata_live=0 later_theaps=0 abandoned_pages=0 attached_workers=0"
        )
    lines.append("summary allocations=1200 frees=1200 cleanup_runs=9600")
    return "\n".join(lines) + "\n"


class PageMapStabilityTests(unittest.TestCase):
    def test_pinned_c_peak_is_transient_across_equivalent_churn(self) -> None:
        result = stability.page_map_stability(PINNED_C_SPIKE)
        self.assertEqual((result["first_half_max"], result["second_half_max"]), (861, 990))
        self.assertEqual((result["first_window_median"], result["last_window_median"]), (846, 821))
        self.assertFalse(result["exceeds_ten_percent"])

    def test_native_peak_is_transient_across_equivalent_churn(self) -> None:
        result = stability.page_map_stability(NATIVE_SPIKE)
        self.assertEqual((result["first_half_max"], result["second_half_max"]), (906, 998))
        self.assertEqual((result["first_window_median"], result["last_window_median"]), (831, 856))
        self.assertFalse(result["exceeds_ten_percent"])

    def test_two_medium_pages_accumulating_each_checkpoint_are_rejected(self) -> None:
        for source in (PINNED_C_SPIKE, NATIVE_SPIKE):
            accumulating = [entries + 16 * index for index, entries in enumerate(source)]
            self.assertTrue(stability.page_map_stability(accumulating)["exceeds_ten_percent"])

    def test_soak_reader_uses_the_same_plateau_and_keeps_other_bounds(self) -> None:
        record, failures = stability.evaluate_soak_output(soak_output(NATIVE_SPIKE), "soak-static-pie")
        self.assertEqual(failures, [])
        self.assertEqual(record["growth"]["page_map_entries"], stability.page_map_stability(NATIVE_SPIKE))
        self.assertEqual(record["growth"]["page_map_submaps"],
                         {"first_half_max": 3, "second_half_max": 3})
        accumulating = [entries + 16 * index for index, entries in enumerate(NATIVE_SPIKE)]
        _, failures = stability.evaluate_soak_output(soak_output(accumulating), "soak-static-pie")
        self.assertEqual(len(failures), 1)
        self.assertIn("page_map_entries window median grew", failures[0])

    def test_too_few_checkpoints_cannot_establish_a_plateau(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least eight"):
            stability.page_map_stability([100] * 7)


if __name__ == "__main__":
    unittest.main()
