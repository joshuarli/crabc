#!/usr/bin/env python3
"""Focused contract for the selected x86 ``ferror_unlocked`` C ABI alias."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
IMPLEMENTATION = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
STDIO_HEADER = ROOT / "include" / "stdio.h"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
CALLABLE_INVENTORY = ROOT / "compat" / "x86_64" / "header_callable_inventory.json"


class FerrorUnlockedTests(unittest.TestCase):
    def test_selected_alias_has_one_weak_same_address_implementation_boundary(self) -> None:
        """Musl's ferror alias stays a weak ELF alias, never a forwarding wrapper."""
        implementation = IMPLEMENTATION.read_text(encoding="utf-8")
        header = STDIO_HEADER.read_text(encoding="utf-8")
        exports = {
            line
            for line in STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }

        for required in (
            "src/stdio/ferror.c",
            "weak_alias(ferror, ferror_unlocked)",
            'pub unsafe extern "C" fn ferror',
            ".weak ferror_unlocked",
            ".set ferror_unlocked, ferror",
            "F_ERR",
        ):
            self.assertIn(required, implementation)
        self.assertIn("int ferror_unlocked(FILE *);", header)
        self.assertIn("ferror", exports)
        self.assertIn("ferror_unlocked", exports)
        self.assertNotIn("_IO_ferror_unlocked", exports)

    def test_callable_inventory_closes_the_oracle_visible_profiles(self) -> None:
        """The all-header inventory closes the oracle-visible alias without complement scope."""
        with CALLABLE_INVENTORY.open(encoding="utf-8") as stream:
            inventory = json.load(stream)

        expected_profiles = {"c11-bsd", "c11-gnu", "cxx17-gnu", "cxx17-strict"}
        callables = inventory["callables"]
        assert isinstance(callables, list)
        candidate_rows = [
            record
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "external"
            and record.get("name") == "ferror_unlocked"
        ]
        reference_rows = [
            record
            for record in callables
            if record.get("tree") == "reference"
            and record.get("classification") == "external"
            and record.get("name") == "ferror_unlocked"
        ]
        missing = [
            record
            for record in callables
            if record.get("classification") == "missing"
            and record.get("name") == "ferror_unlocked"
        ]
        candidate = {record["profile"]: record for record in candidate_rows}
        reference = {record["profile"]: record for record in reference_rows}

        self.assertEqual(len(candidate_rows), len(expected_profiles))
        self.assertEqual(len(reference_rows), len(expected_profiles))
        self.assertEqual(set(candidate), expected_profiles)
        self.assertEqual(set(reference), expected_profiles)
        self.assertEqual(missing, [])
        for profile in expected_profiles:
            self.assertEqual(candidate[profile]["type"], "int (FILE *)")
            self.assertEqual(candidate[profile]["type"], reference[profile]["type"])
            self.assertIn("stdio.h", candidate[profile]["visible_from_headers"])
        self.assertNotIn(
            "ferror_unlocked", inventory["static_export_complement"]["members"]
        )


if __name__ == "__main__":
    unittest.main()
