#!/usr/bin/env python3
"""Focused contracts for finite x86 header-callable ownership routing."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "header_callable_disposition.py"
CHECKED_REPORT = ROOT / "compat" / "x86_64" / "header_callable_disposition.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


DISPOSITION = load_module("header_callable_disposition_test", SCRIPT)


class HeaderCallableDispositionTests(unittest.TestCase):
    def test_checked_report_routes_every_current_external_without_claiming_linkage(self) -> None:
        contract = DISPOSITION.load_contract()
        report = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))

        DISPOSITION.validate_checked_report(report, contract)

        summary = report["summary"]
        self.assertEqual(summary["candidate_external_callable_count"], 1525)
        self.assertEqual(summary["default_static_callable_count"], 1119)
        self.assertEqual(summary["verified_feature_callable_count"], 52)
        self.assertEqual(summary["unprovided_callable_count"], 354)
        self.assertEqual(
            summary["deferred_resolution_counts"],
            {
                "compiler-builtin": 1,
                "consumer-supplied": 1,
                "oracle-declared-no-provider": 7,
                "planned-provider": 345,
            },
        )
        self.assertEqual(
            sum(summary["deferred_resolution_counts"].values()),
            summary["unprovided_callable_count"],
        )
        self.assertEqual(summary["undispositioned_candidate_callable_count"], 0)
        self.assertEqual(summary["missing_reference_declaration_name_count"], 0)
        self.assertEqual(summary["missing_reference_declaration_record_count"], 0)
        self.assertEqual(summary["undispositioned_missing_reference_name_count"], 0)
        self.assertTrue(summary["missing_reference_declaration_routing_complete"])
        self.assertTrue(summary["header_ownership_routing_complete"])
        self.assertFalse(summary["header_declaration_parity_complete"])
        self.assertFalse(summary["final_provider_archive_closure_complete"])

    def test_statx_is_a_planned_provider_after_its_header_declaration_closes(self) -> None:
        contract = DISPOSITION.load_contract()
        report = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))

        self.assertEqual(contract.missing_reference_declaration_groups, ())
        self.assertEqual(report["missing_reference_declaration_groups"], [])
        deferred = {
            row["id"]: row
            for row in report["primary_disposition"]["deferred_owner_groups"]
        }
        posix_runtime = deferred["x86-cabi-posix-runtime-missing-v1"]
        self.assertEqual(posix_runtime["resolution"], "planned-provider")
        self.assertIn("statx", posix_runtime["members"])
        self.assertNotIn("statx", report["primary_disposition"]["default_static"]["members"])

    def test_structural_dispositions_and_atomic_providers_stay_distinct(self) -> None:
        report = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        deferred = {
            row["id"]: row
            for row in report["primary_disposition"]["deferred_owner_groups"]
        }

        self.assertEqual(
            deferred["x86-header-callable-builtin-v1"]["resolution"],
            "compiler-builtin",
        )
        self.assertEqual(
            deferred["x86-header-callable-consumer-supplied-v1"]["resolution"],
            "consumer-supplied",
        )
        self.assertEqual(
            deferred["x86-header-callable-oracle-no-provider-v1"]["resolution"],
            "oracle-declared-no-provider",
        )
        self.assertNotIn("x86-header-callable-atomic-policy-v1", deferred)
        self.assertIn("alloca", deferred["x86-header-callable-builtin-v1"]["members"])
        self.assertIn(
            "seqbuf_dump",
            deferred["x86-header-callable-consumer-supplied-v1"]["members"],
        )
        self.assertNotIn(
            "tgkill",
            deferred["x86-header-callable-oracle-no-provider-v1"]["members"],
        )
        default_static = report["primary_disposition"]["default_static"]["members"]
        for symbol in (
            "atomic_flag_clear",
            "atomic_flag_clear_explicit",
            "atomic_flag_test_and_set",
            "atomic_flag_test_and_set_explicit",
            "atomic_signal_fence",
            "atomic_thread_fence",
        ):
            self.assertIn(symbol, default_static)

    def test_inventory_must_be_bound_to_the_current_parity_ledger(self) -> None:
        contract = DISPOSITION.load_contract()
        inventory = json.loads(contract.callable_inventory.read_text(encoding="utf-8"))
        inputs = inventory["inputs"]
        assert isinstance(inputs, dict)
        inputs["parity_ledger_sha256"] = "0" * 64

        with TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "stale-inventory.json"
            fixture.write_text(json.dumps(inventory), encoding="utf-8")
            stale_contract = replace(contract, callable_inventory=fixture)
            with self.assertRaisesRegex(
                DISPOSITION.HeaderCallableDispositionError,
                "different parity ledger",
            ):
                DISPOSITION.build_report(stale_contract)

    def test_zero_missing_reference_names_do_not_complete_header_declaration_parity(self) -> None:
        contract = DISPOSITION.load_contract()
        inventory = json.loads(contract.callable_inventory.read_text(encoding="utf-8"))
        callables = inventory["callables"]
        assert isinstance(callables, list)
        inventory["callables"] = [
            row
            for row in callables
            if not (
                isinstance(row, dict)
                and row.get("classification") == "missing"
                and row.get("reference_classification") == "external"
            )
        ]

        with TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "no-missing-reference-names.json"
            fixture.write_text(json.dumps(inventory), encoding="utf-8")
            no_missing_contract = replace(
                contract,
                callable_inventory=fixture,
                missing_reference_declaration_groups=(),
            )
            report = DISPOSITION.build_report(no_missing_contract)

        summary = report["summary"]
        self.assertEqual(summary["missing_reference_declaration_name_count"], 0)
        self.assertTrue(summary["missing_reference_declaration_routing_complete"])
        self.assertFalse(summary["header_declaration_parity_complete"])

    def test_checked_report_rejects_an_omitted_deferred_name(self) -> None:
        contract = DISPOSITION.load_contract()
        report = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        deferred = report["primary_disposition"]["deferred_owner_groups"]
        assert isinstance(deferred, list)
        first = deferred[0]
        assert isinstance(first, dict)
        members = first["members"]
        assert isinstance(members, list)
        members.pop()

        with self.assertRaisesRegex(
            DISPOSITION.HeaderCallableDispositionError,
            "stale or malformed",
        ):
            DISPOSITION.validate_checked_report(report, contract)


if __name__ == "__main__":
    unittest.main()
