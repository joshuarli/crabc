#!/usr/bin/env python3
"""Contract tests for the derived x86 AArch64-parity inventory."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "aarch64_parity_inventory.py"
SPEC = importlib.util.spec_from_file_location("aarch64_parity_inventory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


class AArch64ParityInventoryTests(unittest.TestCase):
    @staticmethod
    def family(data: dict[str, object], identifier: str) -> dict[str, object]:
        families = data["family"]
        assert isinstance(families, list)
        for family in families:
            assert isinstance(family, dict)
            if family["id"] == identifier:
                return family
        raise AssertionError(f"missing family: {identifier}")

    def build_with_x86_ledger(self, data: dict[str, object]) -> dict[str, object]:
        original_load_toml = inventory.load_toml

        def load_toml(path: Path) -> dict[str, object]:
            if path == inventory.X86_LEDGER_PATH:
                return copy.deepcopy(data)
            return original_load_toml(path)

        with patch.object(inventory, "load_toml", side_effect=load_toml):
            return inventory.build_inventory()

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

    def test_inventory_rejects_a_verified_slice_from_another_family(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        slices = family.setdefault("verified_slice", [])
        assert isinstance(slices, list)
        slices.append(
            {
                "id": "accounting-cross-family-regression",
                "capabilities": ["error.reporting-termination"],
            }
        )

        with self.assertRaisesRegex(
            inventory.InventoryError, "escapes its owning family"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_duplicate_selected_capabilities(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        slices = family.setdefault("verified_slice", [])
        assert isinstance(slices, list)
        slices.append(
            {
                "id": "accounting-duplicate-capability-regression",
                "capabilities": ["filesystem.lchmod-unsupported"],
            }
        )

        with self.assertRaisesRegex(
            inventory.InventoryError, "selected by more than one verified slice"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_duplicate_verified_record_ids(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        artifacts = family.setdefault("verified_artifact", [])
        assert isinstance(artifacts, list)
        artifacts.append({"id": "static-c-error-strings"})

        with self.assertRaisesRegex(
            inventory.InventoryError, "duplicate verified record id"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_artifacts_that_carry_capabilities(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list) and artifacts
        artifact = artifacts[0]
        assert isinstance(artifact, dict)
        artifact["capabilities"] = ["filesystem.directory"]

        with self.assertRaisesRegex(
            inventory.InventoryError, "must not carry capabilities"
        ):
            self.build_with_x86_ledger(data)


if __name__ == "__main__":
    unittest.main()
