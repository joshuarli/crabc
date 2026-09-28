"""Behavior checks for the pinned C soak's registered-slice reader."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = Path(__file__).resolve().parents[1] / "pinned_c_page_map_soak.py"
sys.path.insert(0, str(MODULE.parent))
SPEC = importlib.util.spec_from_file_location("pinned_c_page_map_soak_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
soak = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(soak)


def output(*, first: int = 900, second: int = 990, missing: int | None = None,
           undrained: int | None = None) -> str:
    lines = ["soak seed=0x000000005eed0002 rounds=1200 workers=8 checkpoint_interval=60"]
    for round_ in range(60, 1201, 60):
        if round_ == missing:
            continue
        entries = first if round_ <= 600 else second
        frees = round_ - 1 if round_ == undrained else round_
        lines.append(
            f"checkpoint round={round_} allocations={round_} frees={frees} "
            f"page_map_entries={entries} page_map_submaps=3"
        )
    lines.append("summary allocations=1200 frees=1200 cleanup_runs=9600")
    return "\n".join(lines) + "\n"


class PageMapSoakReaderTests(unittest.TestCase):
    def test_equal_ten_percent_growth_is_within_the_existing_bound(self) -> None:
        result = soak.parse_soak(output())
        self.assertEqual(result["first_half_max"], 900)
        self.assertEqual(result["second_half_max"], 990)
        self.assertEqual(result["second_half_allowed_at_ten_percent"], 990)
        self.assertFalse(result["exceeds_ten_percent"])
        self.assertEqual(len(result["checkpoints"]), 20)

    def test_one_extra_registered_slice_exceeds_the_bound(self) -> None:
        result = soak.parse_soak(output(second=991))
        self.assertTrue(result["exceeds_ten_percent"])

    def test_missing_checkpoint_or_undrained_owner_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "omitted or reordered"):
            soak.parse_soak(output(missing=660))
        with self.assertRaisesRegex(ValueError, "did not drain"):
            soak.parse_soak(output(undrained=660))

    def test_absent_page_map_observation_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "observation is absent"):
            soak.parse_soak(output(first=0))


if __name__ == "__main__":
    unittest.main()
