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
           undrained: int | None = None, classes: bool = False) -> str:
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
    if classes:
        for half, round_, entries in (("first", 60, first), ("second", 660, second)):
            lines.append(
                f"class_snapshot half={half} round={round_} entries={entries} "
                f"small_empty=0 small_used=40 medium_empty=16 medium_used=144 "
                f"large_empty=0 large_used={entries - 200} singleton_empty=0 singleton_used=0 "
                f"unknown_kind=0 abandoned=0 detached=2 attached={entries - 2} nonprimary=0 "
                f"medium_abandoned=0 medium_detached=0 medium_attached=160 "
                f"medium_remote_pending=144 medium_reusable=160 medium_retired=16"
            )
    return "\n".join(lines) + "\n"


class PageMapSoakReaderTests(unittest.TestCase):
    def test_static_pie_uses_only_the_self_relocating_startfile(self) -> None:
        installed = f"*startfile:\n{soak.SHARED_STARTFILE} crti.o crtbeginS.o\n"
        corrected = soak.static_pie_specs(installed)
        self.assertEqual(
            corrected, f"*startfile:\n{soak.PIE_STARTFILE} crti.o crtbeginS.o\n"
        )
        with self.assertRaisesRegex(ValueError, "startup selection"):
            soak.static_pie_specs(installed.replace(soak.SHARED_STARTFILE, "crt1.o"))

    def test_link_modes_keep_the_original_raw_series_separate(self) -> None:
        self.assertEqual(soak.artifact_dir("static"), soak.ARTIFACTS)
        self.assertEqual(soak.artifact_dir("static-pie"), soak.ARTIFACTS / "static-pie")
        with self.assertRaisesRegex(ValueError, "unsupported"):
            soak.artifact_dir("dynamic")

    def test_class_snapshots_use_a_separate_raw_series(self) -> None:
        self.assertEqual(
            soak.artifact_dir("static-pie", class_snapshot=True),
            soak.ARTIFACTS / "static-pie/classes",
        )

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

    def test_class_snapshots_match_the_two_registered_entry_peaks(self) -> None:
        result = soak.parse_soak(output(classes=True), require_class_snapshot=True)
        self.assertEqual(
            [(point["half"], point["round"], point["entries"])
             for point in result["class_snapshots"]],
            [("first", 60, 900), ("second", 660, 990)],
        )
        self.assertEqual(result["class_snapshots"][0]["medium_remote_pending"], 144)

    def test_class_snapshots_reject_missing_or_inconsistent_state(self) -> None:
        with self.assertRaisesRegex(ValueError, "class snapshot"):
            soak.parse_soak(output(), require_class_snapshot=True)
        with self.assertRaisesRegex(ValueError, "medium owner"):
            soak.parse_soak(
                output(classes=True).replace("medium_attached=160", "medium_attached=159", 1),
                require_class_snapshot=True,
            )

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
