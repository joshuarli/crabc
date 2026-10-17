"""Bounded Heap stress selection preserves the full qualification matrix."""

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_upstream_heap_stress as stress


class HeapStressSelectionTests(unittest.TestCase):
    def test_default_selection_keeps_the_full_matrix(self):
        self.assertEqual(stress.parse_cases([]), (stress.MATRIX, False))

    def test_selected_case_is_one_exact_frozen_matrix_tuple(self):
        self.assertEqual(stress.parse_cases(["--case", "4", "1", "8"]), (((4, 1, 8),), True))

    def test_case_outside_frozen_matrix_is_rejected(self):
        with self.assertRaises(SystemExit):
            stress.parse_cases(["--case", "4", "2", "8"])

    def test_focused_result_does_not_publish_qualification_receipt(self):
        with mock.patch.object(stress.receipts, "write_receipt") as publish:
            self.assertIsNone(stress.write_receipt(((4, 1, 8),), True, {}, []))
        publish.assert_not_called()

    def test_partial_matrix_cannot_publish_qualification_receipt(self):
        with mock.patch.object(stress.receipts, "write_receipt") as publish:
            with self.assertRaisesRegex(stress.harness.HarnessError, "partial upstream Heap stress matrix"):
                stress.write_receipt(((4, 1, 8),), False, {}, [])
        publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
