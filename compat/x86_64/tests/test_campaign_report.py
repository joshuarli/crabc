#!/usr/bin/env python3
"""Focused contracts for the generated x86-64 campaign report."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
REPORTER = ROOT / "compat" / "x86_64" / "campaign_report.py"
sys.path.insert(0, str(REPORTER.parent))
import campaign_report as report  # noqa: E402
import owned_dynamic_qualification as qualification
import validate_parity_ledger as ledger


class CampaignReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Validation is intentionally part of report construction.  Keep the
        # focused tests focused by exercising that real boundary once, then
        # inspect the one generated value in the remaining shape tests.
        with mock.patch.object(qualification, "load_publication", return_value=None):
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
            list(report.qualification_manifest.active_chain("correctness")),
        )
        self.assertEqual(
            value["validation"]["loader_libc_tls_runtime_v1_check"]["command"],
            report.TLS_RUNTIME_V1_CHECK_COMMAND,
        )
        self.assertEqual(
            value["validation"]["loader_libc_tls_runtime_v1_check"]["status"],
            "implemented-unqualified",
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
        self.assertTrue(promotion_gate["machine_gate_defined"])
        self.assertFalse(promotion_gate["pass"])
        qualification_gate = value["gates"]["qualification"]
        # Every ordered gate is executable; families still block the gate.
        self.assertEqual(qualification_gate["contract_status"], "foundation-verified")
        self.assertEqual(qualification_gate["state"], "blocked")
        self.assertEqual(
            qualification_gate["manifest"]["ready_gate_count"],
            len(report.qualification_manifest.active_chain("correctness")),
        )
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
            list(report.qualification_manifest.active_chain("correctness")),
        )
        self.assertFalse(qualification_gate["pass"])
        self.assertEqual(
            value["validation"]["dynamic_product_contract_check"]["command"],
            report.DYNAMIC_PRODUCT_CONTRACT_CHECK_COMMAND,
        )
        self.assertEqual(
            value["validation"]["dynamic_product_contract_check"]["status"],
            "implemented-unqualified",
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
        posix_runtime = next(
            family for family in value["families"] if family["id"] == "libc.posix-runtime"
        )
        self.assertEqual(
            posix_runtime["routine_c_abi_matrix"]["aggregate_command"],
            "./scripts/dev-x86_64.sh routine-c-abi-matrix libc.posix-runtime",
        )
        self.assertEqual(
            value["next_dependency_ready_transitions"],
            [
                family
                for family in value["families"]
                if family["readiness"]["state"] == "ready" and family["id"] != "performance.release"
            ],
        )

    def test_correctness_defers_performance_without_completing_functional_families(self):
        value = self.value
        self.assertEqual(value['campaign']['qualification_profile'], 'correctness')
        self.assertEqual(value['campaign']['deferred_families'], ['performance.release'])
        self.assertFalse(value['campaign']['performance_qualified'])
        self.assertIn('performance.release', [row['id'] for row in value['families']])
        for name in ('promotion', 'qualification'):
            self.assertNotIn('performance.release', value['gates'][name]['required_families'])
            self.assertFalse(value['gates'][name]['pass'])
        self.assertNotIn('performance.release', [row['id'] for row in value['next_dependency_ready_transitions']])
        self.assertTrue(value['gates']['promotion']['machine_gate_defined'])

    def test_full_scope_retains_performance_and_functional_failure_stays_blocked(self):
        with mock.patch.object(qualification, 'load_publication', return_value=None):
            inputs = list(copy.deepcopy(report.load_validated_campaign_inputs()))
        inputs[1]['completion'] = {'qualification_profile': 'full', 'deferred_families': []}
        document = report.qualification_manifest.load_json(report.qualification_manifest.CONTRACT_PATH, 'fixture')
        document['qualification_profile'] = 'full'
        inputs[6] = report.qualification_manifest.validate_contract(document)
        with mock.patch.object(report, 'load_validated_campaign_inputs', return_value=inputs):
            value = report.build_report()
        self.assertIn('performance.release', value['gates']['promotion']['required_families'])
        self.assertIn('performance.release', value['gates']['qualification']['required_families'])
        self.assertFalse(value['gates']['qualification']['pass'])
        self.assertFalse(value['campaign']['performance_qualified'])

    def test_deferred_performance_cannot_block_ready_functional_chain_or_hide_failure(self):
        with mock.patch.object(qualification, 'load_publication', return_value=None):
            inputs = copy.deepcopy(report.load_validated_campaign_inputs())
        for family in inputs[1]['family']:
            if family['id'] != 'performance.release':
                family['status'] = report.COMPLETED_STATUS
        with mock.patch.object(report, 'load_validated_campaign_inputs', return_value=inputs):
            value = report.build_report()
            self.assertTrue(value['gates']['qualification']['pass'])
            self.assertFalse(value['campaign']['promotion_ready'])
            self.assertTrue(value['gates']['promotion']['machine_gate_defined'])
            next(f for f in inputs[1]['family'] if f['id'] == 'libc.text-math-locale-stdio')['status'] = 'planned'
            blocked = report.build_report()
        self.assertFalse(blocked['gates']['qualification']['pass'])
        self.assertIn('libc.text-math-locale-stdio', blocked['gates']['qualification']['incomplete_families'])
        self.assertNotIn('performance.release', blocked['gates']['qualification']['incomplete_families'])

    def test_promotion_has_terminal_reader_but_missing_receipt_cannot_pass(self):
        with mock.patch.object(qualification, 'load_publication', return_value=None):
            inputs = copy.deepcopy(report.load_validated_campaign_inputs())
        for family in inputs[1]['family']:
            if family['id'] != 'performance.release':
                family['status'] = report.COMPLETED_STATUS
        with mock.patch.object(report, 'load_validated_campaign_inputs', return_value=inputs):
            value = report.build_report()
        self.assertTrue(value['gates']['promotion']['machine_gate_defined'])
        self.assertFalse(value['gates']['promotion']['pass'])
        self.assertFalse(value['campaign']['promotion_ready'])
        self.assertIn('qualification receipt', value['gates']['promotion']['closure_error'])

    def test_scope_mismatch_and_forged_active_gate_ids_fail_closed(self):
        with mock.patch.object(qualification, 'load_publication', return_value=None):
            inputs = list(copy.deepcopy(report.load_validated_campaign_inputs()))
        inputs[6]['qualification_profile'] = 'full'
        with mock.patch.object(report, 'load_validated_campaign_inputs', return_value=inputs):
            with self.assertRaises(report.CampaignReportError):
                report.build_report()
        inputs[6]['qualification_profile'] = 'correctness'
        inputs[6]['active_gate_ids'].append('performance.release')
        with mock.patch.object(report, 'load_validated_campaign_inputs', return_value=inputs):
            with self.assertRaises(report.CampaignReportError):
                report.build_report()

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

    def test_verified_resolver_evidence_does_not_promote_a_blocked_planned_family(self) -> None:
        resolver = {
            "id": "libc.resolver",
            "status": "planned",
            "depends_on": ["libc.headers-layouts"],
            "description": "bounded resolver fixture",
            "native_evidence": [
                {
                    "state": "verified",
                    "command": "./scripts/dev-x86_64.sh owned-resolver-network",
                    "scope": "isolated installed and extracted resolver differential",
                }
            ],
        }
        families = {
            "libc.resolver": resolver,
            "libc.headers-layouts": {"id": "libc.headers-layouts", "status": "planned"},
        }

        records, states = ledger.require_evidence(
            resolver["native_evidence"], "family[libc.resolver].native_evidence", resolver["status"]
        )
        self.assertEqual(records, resolver["native_evidence"])
        self.assertEqual(states, {"verified"})
        self.assertEqual(report.readiness(resolver, families), {
            "state": "blocked",
            "blocking_dependencies": ["libc.headers-layouts"],
        })
        self.assertEqual(report.family_obligation(resolver, []), {
            "id": "family-transition:libc.resolver",
            "family": "libc.resolver",
            "description": "bounded resolver fixture",
            "unresolved_capabilities": [],
            "required_evidence": [],
        })

    def test_reviewed_product_does_not_complete_prerequisite_families_or_platform(self):
        with mock.patch.object(qualification, "load_publication", return_value=None):
            inputs = list(copy.deepcopy(report.load_validated_campaign_inputs()))
        inputs[4]["status"] = "materialized"
        inputs[4]["qualification_source_sha256"] = "a" * 64
        inputs[7]["status"] = "verified"
        inputs[7]["runtime_v1_published"] = True
        inputs[7]["qualification_source_sha256"] = "a" * 64
        with mock.patch.object(report, "load_validated_campaign_inputs", return_value=inputs):
            value = report.build_report()
            dynamic = value["gates"]["dynamic_product"]
            self.assertEqual(dynamic["contract_status"], report.COMPLETED_STATUS)
            self.assertFalse(dynamic["pass"])
            self.assertTrue(dynamic["incomplete_families"])
            self.assertEqual(len(value["families"]), 26)
            self.assertFalse(value["campaign"]["promotion_ready"])
            self.assertFalse(value["campaign"]["public_support"])
            inputs[7]["qualification_source_sha256"] = "b" * 64
            with self.assertRaisesRegex(report.CampaignReportError, "qualification sources differ"):
                report.build_report()

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
