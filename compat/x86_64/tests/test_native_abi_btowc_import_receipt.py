"""Focused physical import checks for the owned wide printer's btowc call."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_abi_btowc_import_receipt as receipt


class BtowcImportReceiptTests(unittest.TestCase):
    def test_workload_requires_btowc_relocation(self):
        symbols = "  1: 0000000000000000 0 NOTYPE GLOBAL DEFAULT UND btowc\n"
        relocations = "0000000000000001 0000000000000000 R_X86_64_PLT32 0000000000000000 btowc - 4\n"
        completed = lambda output: mock.Mock(stdout=output, returncode=0)
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(relocations))):
            self.assertEqual(set(receipt.workload_rows(Path("workload.o"))), {"btowc"})
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(""))):
            with self.assertRaisesRegex(receipt.BtowcImportError, "workload btowc"):
                receipt.workload_rows(Path("workload.o"))


if __name__ == "__main__":
    unittest.main()
