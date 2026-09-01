#!/usr/bin/env python3
"""Mutation tests for the planned x86 owned-static product contract."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "validate_parity_ledger.py"
SPEC = importlib.util.spec_from_file_location("x86_static_product_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)


class StaticProductContractTests(unittest.TestCase):
    def ledger_data(self) -> dict[str, object]:
        return copy.deepcopy(ledger.load_toml(ledger.LEDGER_PATH))

    def contract_data(self) -> dict[str, object]:
        return copy.deepcopy(ledger.load_toml(ledger.STATIC_PRODUCT_CONTRACT_PATH))

    @staticmethod
    def families(data: dict[str, object]) -> dict[str, dict[str, object]]:
        entries = data["family"]
        assert isinstance(entries, list)
        result: dict[str, dict[str, object]] = {}
        for entry in entries:
            assert isinstance(entry, dict)
            identifier = entry["id"]
            assert isinstance(identifier, str)
            result[identifier] = entry
        return result

    def test_checked_in_contract_is_planned_and_normal_ledger_checked(self) -> None:
        data = self.ledger_data()
        contract = self.contract_data()
        report = ledger.validate_ledger(data, static_product_contract=contract)

        self.assertEqual(report["static_product"], {
            "owner_family": "sysroot.static-tls",
            "modes": 2,
            "coverage_obligations": 9,
        })
        self.assertEqual(contract["status"], "planned")
        self.assertEqual(
            contract["static_family_ids"], ["crt.static-pie", "sysroot.static-tls"]
        )
        self.assertNotIn(
            "crt.dynamic-startup",
            self.families(data)["sysroot.static-tls"]["depends_on"],
        )

    def test_modes_inputs_inspections_repro_and_smoke_are_closed(self) -> None:
        data = self.ledger_data()
        families = self.families(data)
        mutations = (
            ("mode", lambda contract: contract["mode"].pop(), "mode contract"),
            (
                "input",
                lambda contract: contract["product"]["required_target_inputs"].remove(
                    "libcrabc-builtins.a"
                ),
                "target-input contract",
            ),
            (
                "inspection",
                lambda contract: contract["inspections"]["required"].pop(),
                "inspection contract",
            ),
            (
                "reproducibility",
                lambda contract: contract["reproducibility"].__setitem__(
                    "clean_installed_builds", 1
                ),
                "reproducibility contract",
            ),
            (
                "extracted smoke",
                lambda contract: contract["extracted_smoke"].__setitem__(
                    "suite", "a different suite"
                ),
                "extracted-smoke contract",
            ),
            (
                "coverage",
                lambda contract: contract["coverage"]["required"].pop(),
                "coverage contract",
            ),
        )
        for name, mutate, error in mutations:
            with self.subTest(name=name):
                contract = self.contract_data()
                mutate(contract)
                with self.assertRaisesRegex(ledger.LedgerError, error):
                    ledger.validate_static_product_contract(contract, families)

    def test_static_families_cannot_reach_dynamic_startup(self) -> None:
        data = self.ledger_data()
        families = self.families(data)
        families["sysroot.static-tls"]["depends_on"].append("crt.dynamic-startup")

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "sysroot.static-tls must depend on the owned-static product prerequisites",
        ):
            ledger.validate_static_product_contract(self.contract_data(), families)

        families["sysroot.static-tls"]["depends_on"].pop()
        families["crt.static-pie"]["depends_on"].append("crt.dynamic-startup")
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "static family crt.static-pie must not depend on crt.dynamic-startup",
        ):
            ledger.validate_static_product_contract(self.contract_data(), families)


if __name__ == "__main__":
    unittest.main()
