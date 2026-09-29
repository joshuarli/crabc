"""Focused parser checks for the retained memmove object and loader copy."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_abi_memmove_import_receipt as receipt


def completed(stdout: str, returncode: int = 0):
    return mock.Mock(stdout=stdout, returncode=returncode)


class MemmoveImportReceiptTests(unittest.TestCase):
    def test_workload_requires_every_declared_import_call(self):
        symbols = "\n".join(
            f"  {index}: 0000000000000000 0 NOTYPE GLOBAL DEFAULT UND {name}"
            for index, name in enumerate(("memmove", "realpath", "bcopy"), 1))
        relocations = "\n".join(
            f"000000000000000{index} 0000000000000000 R_X86_64_PLT32 0000000000000000 {name} - 4"
            for index, name in enumerate(("memmove", "realpath", "bcopy"), 1))
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(relocations))):
            rows = receipt.workload_rows(Path("workload.o"))
        self.assertEqual(set(rows), {"memmove", "realpath", "bcopy"})
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(relocations.replace("memmove - 4", "foreign - 4")))):
            with self.assertRaisesRegex(receipt.MemmoveImportError, "memmove workload memmove"):
                receipt.workload_rows(Path("workload.o"))

    def test_loader_copy_is_defined_without_an_external_relocation(self):
        symbol = "  4: 00000000000153f5 40 FUNC GLOBAL DEFAULT 6 memmove\n"
        product = Path("product")
        with mock.patch.object(receipt, "regular", return_value=Path("loader")), \
                mock.patch.object(receipt, "digest", return_value="a" * 64), \
                mock.patch.object(receipt.subprocess, "run", side_effect=(
                    completed(symbol), completed(""))):
            self.assertEqual(receipt.loader_occurrence(product), {
                "loader_sha256": "a" * 64, "address": 0x153f5,
                "size_bytes": 40, "section_index": "6"})
        with mock.patch.object(receipt, "regular", return_value=Path("loader")), \
                mock.patch.object(receipt.subprocess, "run", side_effect=(
                    completed(symbol), completed("R_X86_64_JUMP_SLOT memmove\n"))):
            with self.assertRaisesRegex(receipt.MemmoveImportError, "loader occurrence differs"):
                receipt.loader_occurrence(product)


if __name__ == "__main__":
    unittest.main()
