from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/allocator/medium_capacity_transition.py"
SPEC = importlib.util.spec_from_file_location("medium_capacity_transition", MODULE)
assert SPEC is not None and SPEC.loader is not None
capacity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capacity)


def trace(usable: int, first_new_page: int, first_abandoned: int) -> str:
    lines = []
    for index in range(10):
        medium_used = 8 if index < first_new_page else 16
        abandoned = 8 if index >= first_abandoned else 0
        lines.append(
            f"trace index={index} request=65536 usable={usable} entries={medium_used} "
            f"medium_used={medium_used} medium_abandoned={abandoned}\n"
        )
    return "".join(lines) + "done blocks=10 request=65536\n"


class MediumCapacityTransitionReaderTest(unittest.TestCase):
    def test_reader_finds_first_size_and_page_transition(self) -> None:
        c = capacity.parse_trace(trace(65536, 8, 7))
        native = capacity.parse_trace(trace(81920, 6, 5))
        result = capacity.compare(c, native)
        self.assertEqual(result["first_usable_divergence"], 0)
        self.assertEqual(result["c_first_new_medium_page"], 8)
        self.assertEqual(result["native_first_new_medium_page"], 6)
        self.assertEqual(result["c_first_abandoned_page"], 7)
        self.assertEqual(result["native_first_abandoned_page"], 5)
        self.assertFalse(result["source_parity"])
        self.assertTrue(capacity.compare(c, c)["source_parity"])

    def test_reader_rejects_missing_or_reordered_allocations(self) -> None:
        with self.assertRaises(capacity.DiagnosticError):
            capacity.parse_trace(trace(65536, 8, 7).replace("index=5", "index=6"))
        with self.assertRaises(capacity.DiagnosticError):
            capacity.parse_trace(trace(65536, 8, 7).replace("done blocks=10", "done blocks=9"))

    def test_alignment_reader_checks_every_requested_size(self) -> None:
        lines = [
            f"alignment size={size} aligned16=16 usable_min={size} usable_max={size}\n"
            for size in capacity.ALIGNMENT_SIZES
        ]
        output = "".join(lines) + "done sizes=10 samples_per_size=16\n"
        self.assertEqual(len(capacity.parse_alignment(output)), 10)
        with self.assertRaises(capacity.DiagnosticError):
            capacity.parse_alignment(output.replace("aligned16=16", "aligned16=17", 1))

    def test_alignment_parity_keeps_small_c_abi_exception(self) -> None:
        c_sizes = (8, 8, 16, 16, 16, 32, 32, 32, 12288, 65536)
        native_sizes = (32, 32, 16, 16, 16, 32, 32, 32, 12288, 65536)
        c = [
            {"size": size, "aligned16": 8 if size <= 8 else 16,
             "usable_min": usable, "usable_max": usable}
            for size, usable in zip(capacity.ALIGNMENT_SIZES, c_sizes)
        ]
        native = [
            {"size": size, "aligned16": 16, "usable_min": usable,
             "usable_max": usable}
            for size, usable in zip(capacity.ALIGNMENT_SIZES, native_sizes)
        ]
        self.assertTrue(capacity.alignment_parity(c, native))
        native[2]["usable_max"] = 32
        self.assertFalse(capacity.alignment_parity(c, native))
        native[2]["usable_max"] = 16
        native[0]["aligned16"] = 8
        self.assertFalse(capacity.alignment_parity(c, native))


if __name__ == "__main__":
    unittest.main()
