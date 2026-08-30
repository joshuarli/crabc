#!/usr/bin/env python3
"""Contract tests for the derived x86 AArch64-parity inventory."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "aarch64_parity_inventory.py"
SPEC = importlib.util.spec_from_file_location("aarch64_parity_inventory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


class AArch64ParityInventoryTests(unittest.TestCase):
    def test_checked_snapshot_is_source_derived_and_non_promoting(self) -> None:
        report = inventory.validate_inventory()
        self.assertEqual(report["schema"], "crabc.x86_64-aarch64-parity-inventory/v1")
        self.assertEqual(report["baseline"]["capability_count"], 223)
        self.assertEqual(report["baseline"]["aarch64_public_header_count"], 183)
        self.assertEqual(report["x86_boundary"]["promotion_family_count"], 26)
        self.assertFalse(report["x86_boundary"]["promotion_ready"])
        self.assertFalse(report["x86_boundary"]["public_support"])
        self.assertEqual(sum(report["capability_state_counts"].values()), 223)
        self.assertEqual(len(report["families"]), 26)
        self.assertEqual(len(report["capabilities"]), 223)
        self.assertEqual(
            {row["contract_state"] for row in report["capabilities"]},
            {"implemented-foundation", "selected-private", "missing"},
        )
        self.assertEqual(
            report["unsupported_contracts"],
            [{
                "id": "allocator.mimalloc-private",
                "reason": "Private fixed-allocator evidence is neither crabc-libc integration nor x86 runtime/platform support.",
            }],
        )

    def test_snapshot_rejects_any_unreviewed_derived_change(self) -> None:
        actual = inventory.build_inventory()
        expected = json.loads(inventory.INVENTORY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(actual, expected)
        altered = copy.deepcopy(expected)
        altered["x86_boundary"]["public_support"] = True
        self.assertNotEqual(actual, altered)


if __name__ == "__main__":
    unittest.main()
