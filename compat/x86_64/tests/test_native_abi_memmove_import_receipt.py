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

    def test_shared_bcopy_tail_branch_targets_the_shared_provider(self):
        symbols = "\n".join(
            f"  {index}: {address:016x} {size} FUNC GLOBAL DEFAULT 9 {name}"
            for index, (name, address, size) in enumerate((
                ("bcopy", 0x1000, 8), ("bcopy", 0x1000, 8),
                ("memmove", 0x1010, 20), ("memmove", 0x1010, 20)), 1))
        with mock.patch.object(receipt, "regular", return_value=Path("libc")), \
                mock.patch.object(receipt, "digest", return_value="b" * 64), \
                mock.patch.object(Path, "read_bytes", return_value=b"ELF"), \
                mock.patch.object(receipt.subprocess, "run", return_value=completed(symbols)), \
                mock.patch.object(receipt.boundary, "_public_weak_virtual_bytes",
                                  return_value=b"\x48\x87\xfe\xe9\x08\0\0\0"):
            self.assertEqual(receipt.shared_bcopy_direct_call(Path("product")), {
                "libc_sha256": "b" * 64, "bcopy_address": 0x1000,
                "call_address": 0x1003, "provider_address": 0x1010,
                "branch_kind": "direct-tail-jump"})
        with mock.patch.object(receipt, "regular", return_value=Path("libc")), \
                mock.patch.object(Path, "read_bytes", return_value=b"ELF"), \
                mock.patch.object(receipt.subprocess, "run", return_value=completed(symbols)), \
                mock.patch.object(receipt.boundary, "_public_weak_virtual_bytes",
                                  return_value=b"\x48\x87\xfe\xe9\x09\0\0\0"):
            with self.assertRaisesRegex(receipt.MemmoveImportError, "resolves elsewhere"):
                receipt.shared_bcopy_direct_call(Path("product"))


if __name__ == "__main__":
    unittest.main()
