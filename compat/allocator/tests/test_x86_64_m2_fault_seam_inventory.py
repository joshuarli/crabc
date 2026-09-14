#!/usr/bin/env python3
"""Fail-closed assembly checks for the native x86 fault receiver admission."""

from __future__ import annotations

import copy
import unittest
from unittest import mock

from test_runner import RUNNER
from test_x86_64_fault_seam_inventory import (
    INVENTORY,
    _retained_profile_contract,
    _valid_report,
)


class NativeFaultInventoryM2AssemblyTests(unittest.TestCase):
    def summary(self):
        return RUNNER.validate_x86_64_m2_memory_substrate_contract(
            RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT), RUNNER.load_pin()
        )

    def test_fault_component_uses_only_the_fixed_fragment_and_retained_stream_receipt(self) -> None:
        summary = self.summary()
        component = next(item for item in summary["components"] if item["id"] == "fault-injection")
        self.assertEqual(component["native_status"], "partial")
        self.assertEqual(
            component["evidence_fragment"],
            {
                "path": RUNNER.relative(RUNNER.M2_X86_64_FAULT_FRAGMENT),
                "inventory_sha256": RUNNER.M2_X86_64_FAULT_FRAGMENT_DIGEST,
            },
        )
        self.assertEqual(
            [row["id"] for row in component["branch_matrix"]],
            [row.identifier for row in INVENTORY.BRANCH_ROWS],
        )
        with (
            _retained_profile_contract() as (runner, profile),
            mock.patch.object(RUNNER, "_m2_x86_64_fault_producer", return_value=INVENTORY),
        ):
            report = _valid_report(runner, profile)
            records = RUNNER._m2_x86_64_fault_check_records(summary, report)
            self.assertEqual(
                records,
                [{
                    "comparison_status": "source-specific-relation-verified",
                    "component": "fault-injection",
                    "command": report["huge_branch_receipt"]["rust_run"]["command"],
                    "evidence_scope": "fixed-pinned-c-branch-profile-and-private-rust-fault-plan",
                    "id": INVENTORY.FAULT_COMPONENT_CHECK_ID,
                    "passed_test_count": 1,
                    "target": INVENTORY.RUST_TARGET,
                }],
            )

    def test_fault_component_rejects_a_retained_stream_rewrite(self) -> None:
        with (
            _retained_profile_contract() as (runner, profile),
            mock.patch.object(RUNNER, "_m2_x86_64_fault_producer", return_value=INVENTORY),
        ):
            report = copy.deepcopy(_valid_report(runner, profile))
            report["huge_branch_receipt"]["rust_run"]["stdout"] = "test result: ok. 1 passed; 0 failed;\n"
            with self.assertRaisesRegex(RUNNER.HarnessError, "fault-inventory producer result is invalid"):
                RUNNER._m2_x86_64_fault_check_records(self.summary(), report)


if __name__ == "__main__":
    unittest.main()
