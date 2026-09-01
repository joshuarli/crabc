#!/usr/bin/env python3
"""Focused contracts for the generated x86-64 campaign report."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
REPORTER = ROOT / "compat" / "x86_64" / "campaign_report.py"
sys.path.insert(0, str(REPORTER.parent))
import campaign_report as report  # noqa: E402


class CampaignReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Validation is intentionally part of report construction.  Keep the
        # focused tests focused by exercising that real boundary once, then
        # inspect the one generated value in the remaining shape tests.
        cls.value = report.build_report()

    def test_report_is_derived_from_current_validated_contract(self) -> None:
        value = self.value

        self.assertEqual(value["schema"], report.SCHEMA)
        self.assertIn("frozen_baseline", value)
        self.assertIn("source_commit", value["frozen_baseline"])
        self.assertEqual(
            value["validation"]["routine_c_abi_matrix_check"]["command"],
            report.MATRIX_CHECK_COMMAND,
        )
        self.assertEqual(
            value["validation"]["qualification_manifest_check"]["command"],
            report.QUALIFICATION_MANIFEST_CHECK_COMMAND,
        )
        self.assertEqual(
            value["validation"]["qualification_manifest_check"]["incomplete_gates"],
            list(report.QUALIFICATION_CHAIN),
        )
        self.assertEqual(
            value["validation"]["loader_libc_tls_runtime_v1_check"]["command"],
            report.TLS_RUNTIME_V1_CHECK_COMMAND,
        )
        self.assertEqual(
            value["validation"]["loader_libc_tls_runtime_v1_check"]["status"],
            "planned",
        )
        self.assertFalse(
            value["validation"]["loader_libc_tls_runtime_v1_check"][
                "runtime_v1_published"
            ]
        )
        self.assertEqual(
            len(value["families"]),
            sum(value["state_counts"]["families"].values()),
        )
        static_gate = value["gates"]["static_product"]
        self.assertEqual(static_gate["owner_family"], "sysroot.static-tls")
        self.assertEqual(static_gate["contract_status"], "planned")
        self.assertEqual(
            static_gate["machine_gate_command"], report.STATIC_PRODUCT_RUNNER_COMMAND
        )
        self.assertFalse(static_gate["pass"])
        dynamic_gate = value["gates"]["dynamic_product"]
        self.assertEqual(dynamic_gate["owner_family"], "sysroot.owned-artifact")
        self.assertEqual(dynamic_gate["contract_status"], "planned")
        self.assertTrue(dynamic_gate["machine_gate_defined"])
        self.assertEqual(
            dynamic_gate["machine_gate_command"], report.DYNAMIC_PRODUCT_RUNNER_COMMAND
        )
        self.assertFalse(dynamic_gate["pass"])
        promotion_gate = value["gates"]["promotion"]
        self.assertEqual(promotion_gate["contract_status"], "planned")
        self.assertFalse(promotion_gate["machine_gate_defined"])
        self.assertFalse(promotion_gate["pass"])
        qualification_gate = value["gates"]["qualification"]
        self.assertEqual(qualification_gate["contract_status"], "planned")
        self.assertEqual(
            qualification_gate["machine_gate_command"],
            report.QUALIFICATION_RUNNER_COMMAND,
        )
        self.assertEqual(
            qualification_gate["manifest"]["promotion_chain"],
            list(report.QUALIFICATION_CHAIN),
        )
        self.assertEqual(
            qualification_gate["manifest"]["incomplete_gates"],
            list(report.QUALIFICATION_CHAIN),
        )
        self.assertFalse(qualification_gate["pass"])
        self.assertEqual(
            value["validation"]["dynamic_product_contract_check"]["command"],
            report.DYNAMIC_PRODUCT_CONTRACT_CHECK_COMMAND,
        )
        self.assertEqual(
            value["validation"]["dynamic_product_contract_check"]["status"],
            "not-materialized",
        )
        self.assertEqual(
            len(value["capabilities"]),
            sum(value["state_counts"]["capabilities"].values()),
        )
        for family in value["families"]:
            self.assertIn(family["readiness"]["state"], {"complete", "blocked", "ready"})
            self.assertEqual(family["commands"], family["transition"]["commands"])
            self.assertIn("routine_c_abi_matrix", family)
            self.assertIsInstance(family["routine_c_abi_matrix"]["row_ids"], list)
            self.assertEqual(family["transition"]["to"], "foundation-verified")
            self.assertTrue(family["transition"]["commands"])
        self.assertEqual(
            value["next_dependency_ready_transitions"],
            [
                family
                for family in value["families"]
                if family["readiness"]["state"] == "ready"
            ],
        )

    def test_gate_state_is_derived_from_required_family_states(self) -> None:
        families = {
            "complete": {"id": "complete", "status": "foundation-verified", "native_evidence": [{"command": "complete-command"}]},
            "planned": {"id": "planned", "status": "planned", "native_evidence": [{"command": "planned-command"}]},
        }

        blocked = report.gate_report(
            "fixture", ["complete", "planned"], families, has_machine_gate=True
        )
        self.assertEqual(blocked["state"], "blocked")
        self.assertEqual(blocked["incomplete_families"], ["planned"])
        self.assertEqual(blocked["transition_commands"], [{"family": "planned", "commands": ["planned-command"]}])

        passed = report.gate_report(
            "fixture",
            ["complete"],
            families,
            has_machine_gate=True,
            contract_status="foundation-verified",
        )
        self.assertEqual(passed["state"], "passed")
        self.assertTrue(passed["pass"])
        self.assertEqual(passed["transition_commands"], [])

    def test_external_validation_errors_are_wrapped_as_campaign_errors(self) -> None:
        with mock.patch.object(
            report.inventory,
            "validate_frozen_baseline",
            side_effect=report.inventory.InventoryError("frozen baseline drift"),
        ):
            with self.assertRaisesRegex(report.CampaignReportError, "frozen baseline drift"):
                report.build_report()

    def test_family_filter_retains_identity_and_only_owned_capabilities(self) -> None:
        value = self.value
        family_id = value["families"][0]["id"]
        selected = report.select_family(value, family_id)

        self.assertEqual(selected["schema"], report.SCHEMA)
        self.assertEqual(selected["family"]["id"], family_id)
        self.assertEqual(selected["frozen_baseline"], value["frozen_baseline"])
        self.assertTrue(
            all(capability["x86_family"] == family_id for capability in selected["capabilities"])
        )

    def test_cli_rejects_unknown_family(self) -> None:
        with mock.patch.object(report, "build_report", return_value=self.value), mock.patch.object(
            sys, "argv", [str(REPORTER), "--family", "no.such.family"]
        ):
            with self.assertRaisesRegex(
                report.CampaignReportError, "unknown required family"
            ):
                report.main()


if __name__ == "__main__":
    unittest.main()
