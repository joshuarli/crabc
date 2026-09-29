"""Focused checks for the wide printer's owned wctomb importer receipt."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_abi_wctomb_import_receipt as receipt


class WctombImportReceiptTests(unittest.TestCase):
    def test_workload_retains_wprintf_without_importing_wctomb(self):
        symbols = "  1: 0000000000000000 0 NOTYPE GLOBAL DEFAULT UND wprintf\n"
        relocations = "0000000000000001 0000000000000000 R_X86_64_PLT32 0000000000000000 wprintf - 4\n"
        completed = lambda output: mock.Mock(stdout=output, returncode=0)
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(relocations))):
            self.assertEqual(set(receipt.workload_rows(Path("workload.o"))), {"wprintf"})
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(""))):
            with self.assertRaisesRegex(receipt.WctombImportError, "workload wprintf"):
                receipt.workload_rows(Path("workload.o"))
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols + "  2: 0000000000000000 0 NOTYPE GLOBAL DEFAULT UND wctomb\n"),
                completed(relocations))):
            with self.assertRaisesRegex(receipt.WctombImportError, "provider directly"):
                receipt.workload_rows(Path("workload.o"))


if __name__ == "__main__":
    unittest.main()
