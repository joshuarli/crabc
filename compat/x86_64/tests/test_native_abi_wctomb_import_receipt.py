"""Focused checks for the wide scanner's owned wctomb importer receipt."""
from __future__ import annotations

from pathlib import Path
import json
import os
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_abi_wctomb_import_receipt as receipt
import native_abi_selection as selection


class WctombImportReceiptTests(unittest.TestCase):
    def test_workload_retains_scanner_and_direct_provider_import(self):
        symbols = ("  1: 0000000000000000 0 NOTYPE GLOBAL DEFAULT UND fwscanf\n"
                   "  2: 0000000000000000 0 NOTYPE GLOBAL DEFAULT UND wctomb\n")
        relocations = ("0000000000000001 0000000000000000 R_X86_64_PLT32 0000000000000000 fwscanf - 4\n"
                       "0000000000000005 0000000000000000 R_X86_64_PLT32 0000000000000000 wctomb - 4\n")
        completed = lambda output: mock.Mock(stdout=output, returncode=0)
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(relocations))):
            self.assertEqual(set(receipt.workload_rows(Path("workload.o"))), {"fwscanf", "wctomb"})
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(""))):
            with self.assertRaisesRegex(receipt.WctombImportError, "workload fwscanf"):
                receipt.workload_rows(Path("workload.o"))
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols),
                completed(relocations.splitlines(keepends=True)[0]))):
            with self.assertRaisesRegex(receipt.WctombImportError, "workload wctomb"):
                receipt.workload_rows(Path("workload.o"))

    def test_source_bound_receipt_rejects_mutated_workload(self):
        work_name = os.environ.get("CRABC_WCTOMB_ORDINARY_IMPORT_WORK")
        if work_name is None:
            self.skipTest("set CRABC_WCTOMB_ORDINARY_IMPORT_WORK to retained physical evidence")
        work = Path(work_name)
        report = json.loads((work / "report.json").read_text())
        static = Path(report["static_product"])
        dynamic = Path(report["dynamic_product"])
        receipt.validate_report(work / "report.json", static_product=static, dynamic_product=dynamic)
        original_digest = receipt.digest
        def changed_workload(path):
            return "0" * 64 if Path(path) == work / "workload.o" else original_digest(path)
        with mock.patch.object(receipt, "digest", side_effect=changed_workload):
            with self.assertRaisesRegex(receipt.WctombImportError, "source, products, or workload changed"):
                receipt.validate_report(work / "report.json", static_product=static, dynamic_product=dynamic)

    def test_selector_removes_only_wctomb_ordinary_import_reason(self):
        before_name = os.environ.get("CRABC_WCTOMB_SELECTION_BASELINE")
        after_name = os.environ.get("CRABC_WCTOMB_SELECTION_FINAL")
        if before_name is None or after_name is None:
            self.skipTest("set both CRABC_WCTOMB_SELECTION report paths")
        before = json.loads(Path(before_name).read_text())
        after = json.loads(Path(after_name).read_text())
        blocker = {"code": "identity-unresolved",
                   "identity": {"name": "wctomb", "version": None, "version_default": False},
                   "reason": selection.ORDINARY_IMPORT_REASON}
        self.assertIn(blocker, before["closure"]["blockers"])
        self.assertNotIn(blocker, after["closure"]["blockers"])
        self.assertEqual([row for row in before["closure"]["blockers"] if row != blocker],
                         after["closure"]["blockers"])
        self.assertEqual(before["measurement"], after["measurement"])
        self.assertEqual(len(before["occurrences"]), len(after["occurrences"]))
        self.assertEqual([row["identity"] for row in after["ordinary_static_import_joins"]
                          if row["identity"] == blocker["identity"]], [blocker["identity"]])


if __name__ == "__main__":
    unittest.main()
