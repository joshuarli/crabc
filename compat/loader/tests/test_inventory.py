#!/usr/bin/env python3
"""Small standard-library tests for the loader inventory contract."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/scripts/generate-aarch64-loader-inventory.py"
spec = importlib.util.spec_from_file_location("loader_inventory", SCRIPT)
assert spec is not None and spec.loader is not None
loader_inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader_inventory)


class ParserTests(unittest.TestCase):
    def test_relocation_parser_accepts_entry_and_entries(self) -> None:
        output = """\
Relocation section '.rela.dyn' at offset 0x0 contains 2 entries:
0000000000000000  0000000000000403 R_AARCH64_RELATIVE 0
0000000000000008  0000000000000401 R_AARCH64_GLOB_DAT 0

Relocation section '.rela.plt' at offset 0x30 contains 1 entry:
0000000000000010  0000000000000402 R_AARCH64_JUMP_SLOT 0
"""
        parsed = loader_inventory.parse_relocations(output)
        self.assertEqual(parsed["entries"], 3)
        self.assertEqual(
            parsed["types"],
            {
                "R_AARCH64_GLOB_DAT": 1,
                "R_AARCH64_JUMP_SLOT": 1,
                "R_AARCH64_RELATIVE": 1,
            },
        )
        self.assertEqual(parsed["sections"][1]["observed_entries"], 1)

    def test_program_header_parser_preserves_spaced_flags(self) -> None:
        output = """\
Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000100 0x000100 R E 0x10000
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10

 Section to Segment mapping:
"""
        parsed = loader_inventory.parse_program_headers(output)
        self.assertEqual([entry["flags"] for entry in parsed], ["RE", "RW"])


class ReportTests(unittest.TestCase):
    def test_checked_in_reports_do_not_claim_verified_features(self) -> None:
        musl = ROOT / "compat/abi/musl-1.2.6/aarch64/loader-runtime.json"
        crabc = ROOT / "compat/abi/crabc/aarch64/loader-features.json"
        if not musl.is_file() or not crabc.is_file():
            self.skipTest("generated loader reports are not present")
        with musl.open(encoding="utf-8") as stream:
            reference = json.load(stream)
        with crabc.open(encoding="utf-8") as stream:
            candidate = json.load(stream)
        self.assertEqual(reference["architecture"], "aarch64")
        self.assertEqual(candidate["architecture"], "aarch64")
        self.assertFalse(candidate["verification"]["verified"])
        self.assertFalse(candidate["verification"]["runtime_tests_executed"])
        self.assertTrue(all(feature["verified"] is False for feature in candidate["features"]))


if __name__ == "__main__":
    unittest.main()
