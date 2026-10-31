"""Focused parser checks for the retained native import receipts."""
from __future__ import annotations

from pathlib import Path
import dataclasses
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_abi_memcmp_import_receipt as receipt


def completed(stdout: str, returncode: int = 0):
    return mock.Mock(stdout=stdout, returncode=returncode)


class MemcmpImportReceiptTests(unittest.TestCase):
    def test_workload_requires_every_declared_import_call(self):
        symbols = "\n".join(
            f"  {index}: 0000000000000000 0 NOTYPE GLOBAL DEFAULT UND {name}"
            for index, name in enumerate(("memcmp", "bcmp"), 1))
        relocations = "\n".join(
            f"000000000000000{index} 0000000000000000 R_X86_64_PLT32 0000000000000000 {name} - 4"
            for index, name in enumerate(("memcmp", "bcmp"), 1))
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(relocations))):
            rows = receipt.workload_rows(Path("workload.o"), "memcmp")
        self.assertEqual(set(rows), {"memcmp", "bcmp"})
        with mock.patch.object(receipt.subprocess, "run", side_effect=(
                completed(symbols), completed(relocations.replace("memcmp - 4", "foreign - 4")))):
            with self.assertRaisesRegex(receipt.ImportReceiptError, "memcmp workload memcmp"):
                receipt.workload_rows(Path("workload.o"), "memcmp")

    def test_loader_copy_is_defined_without_an_external_relocation(self):
        symbol = "  4: 00000000000153f5 40 FUNC GLOBAL DEFAULT 6 memcmp\n"
        product = Path("product")
        with mock.patch.object(receipt, "regular", return_value=Path("loader")), \
                mock.patch.object(receipt, "digest", return_value="a" * 64), \
                mock.patch.object(receipt.subprocess, "run", side_effect=(
                    completed(symbol), completed(""))):
            self.assertEqual(receipt.loader_occurrence(product, "memcmp"), {
                "loader_sha256": "a" * 64, "address": 0x153f5,
                "size_bytes": 40, "section_index": "6"})
        with mock.patch.object(receipt, "regular", return_value=Path("loader")), \
                mock.patch.object(receipt.subprocess, "run", side_effect=(
                    completed(symbol), completed("R_X86_64_JUMP_SLOT memcmp\n"))):
            with self.assertRaisesRegex(receipt.ImportReceiptError, "loader occurrence differs"):
                receipt.loader_occurrence(product, "memcmp")
        bcmp = "  4: 00000000000153a4 28 FUNC GLOBAL DEFAULT 6 bcmp\n"
        with mock.patch.object(receipt, "regular", return_value=Path("loader")), \
                mock.patch.object(receipt, "digest", return_value="a" * 64), \
                mock.patch.object(receipt.subprocess, "run", side_effect=(
                    completed(bcmp), completed(""))):
            self.assertEqual(receipt.loader_occurrence(product, "bcmp")["address"], 0x153a4)

    def test_shared_bcmp_tail_branch_targets_the_shared_provider(self):
        symbols = "\n".join(
            f"  {index}: {address:016x} {size} FUNC GLOBAL DEFAULT 9 {name}"
            for index, (name, address, size) in enumerate((
                ("bcmp", 0x1000, 5), ("bcmp", 0x1000, 5),
                ("memcmp", 0x1010, 20), ("memcmp", 0x1010, 20)), 1))
        with mock.patch.object(receipt, "regular", return_value=Path("libc")), \
                mock.patch.object(receipt, "digest", return_value="b" * 64), \
                mock.patch.object(Path, "read_bytes", return_value=b"ELF"), \
                mock.patch.object(receipt.subprocess, "run", return_value=completed(symbols)), \
                mock.patch.object(receipt.boundary, "_public_weak_virtual_bytes",
                                  return_value=b"\xe9\x0b\0\0\0"):
            self.assertEqual(receipt.shared_tail_call(Path("product"), "memcmp"), {
                "libc_sha256": "b" * 64, "bcmp_address": 0x1000,
                "call_address": 0x1000, "provider_address": 0x1010,
                "branch_kind": "direct-tail-jump"})
        with mock.patch.object(receipt, "regular", return_value=Path("libc")), \
                mock.patch.object(Path, "read_bytes", return_value=b"ELF"), \
                mock.patch.object(receipt.subprocess, "run", return_value=completed(symbols)), \
                mock.patch.object(receipt.boundary, "_public_weak_virtual_bytes",
                                  return_value=b"\xe9\x0c\0\0\0"):
            with self.assertRaisesRegex(receipt.ImportReceiptError, "resolves elsewhere"):
                receipt.shared_tail_call(Path("product"), "memcmp")


class SharedImportReceiptTableTests(unittest.TestCase):
    SOURCE = {"revision": "a" * 40, "content_sha256": "b" * 64, "clean": True}

    def reports(self):
        parent = ROOT / ".work/x86_64/native-abi-import-receipt-tests"
        parent.mkdir(parents=True, exist_ok=True)
        directory = mock.Mock(side_effect=lambda path, _d: Path(path))
        with tempfile.TemporaryDirectory(dir=parent) as root, \
                mock.patch.multiple(receipt, directory=directory, digest=mock.Mock(return_value="c" * 64),
                                    capture=mock.Mock(return_value={"argv": [], "status": 0}),
                                    workload_rows=mock.Mock(return_value={}),
                                    loader_occurrence=mock.Mock(return_value={}),
                                    shared_tail_call=mock.Mock(return_value={})), \
                mock.patch.object(receipt.product_evidence, "validate_link", return_value={}), \
                mock.patch.object(receipt.inventory, "collector_source_seal", return_value=self.SOURCE):
            for symbol, row in receipt.ROWS.items():
                yield row, receipt.collect(ROOT / "static", ROOT / "dynamic",
                                           Path(root) / symbol, symbol)

    def test_every_symbol_collects_the_declared_shape(self):
        self.assertEqual(set(receipt.ROWS), {"btowc", "fchdir", "memcmp", "memmove",
                                             "strlen", "wcsrtombs", "wctomb"})
        for row, report in self.reports():
            with self.subTest(symbol=row.name):
                extras = {key for key, _ in row.loader_checks}
                if row.tail_call is not None:
                    extras.add(row.tail_call.key)
                self.assertEqual(set(report), receipt.REPORT_KEYS | extras)
                self.assertEqual(report["schema"],
                                 f"crabc.x86_64-native-abi-{row.name}-import-receipt/v1")

    def test_swapped_or_duplicated_rows_fail(self):
        strlen, memcmp = receipt.ROWS["strlen"], receipt.ROWS["memcmp"]
        with self.assertRaisesRegex(receipt.ImportReceiptError, "duplicate native ABI import row"):
            receipt.build_rows((strlen, strlen))
        for field in ("schema", "fixture"):
            with self.subTest(field=field), self.assertRaisesRegex(
                    receipt.ImportReceiptError, "row memcmp differs"):
                receipt.build_rows((dataclasses.replace(
                    memcmp, **{field: getattr(strlen, field)}),))


if __name__ == "__main__":
    unittest.main()
