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
            {"path": RUNNER.relative(RUNNER.M2_X86_64_FAULT_FRAGMENT)},
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
                }, {
                    "comparison_status": "source-specific-relation-verified",
                    "component": "fault-injection",
                    "command": report["os_publication_receipt"]["rust_run"]["command"],
                    "evidence_scope": "fixed-pinned-c-branch-profile-and-private-rust-fault-plan",
                    "id": INVENTORY.OS_PUBLICATION_CHECK_ID,
                    "passed_test_count": 1,
                    "target": INVENTORY.OS_PUBLICATION_TARGET,
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

    def test_regular_aligned_anchor_uses_the_pinned_v350_pointer_return_definitions(self) -> None:
        """The fixed map/cleanup receiver owns v3.5's pointer-returning helpers."""

        component = next(item for item in self.summary()["components"] if item["id"] == "fault-injection")
        definition = next(
            item for item in component["bounded_source_definitions"]
            if item["id"] == "os-regular-aligned-map-and-cleanup"
        )
        self.assertEqual(
            definition["required_definitions"],
            ["static void* mi_os_prim_alloc_at", "static void* mi_os_prim_alloc_aligned"],
        )

    def test_range_transition_anchor_uses_the_pinned_v350_boolean_commit_definition(self) -> None:
        """The selected range receiver begins with the v3.5 boolean commit owner."""

        component = next(item for item in self.summary()["components"] if item["id"] == "fault-injection")
        definition = next(
            item for item in component["bounded_source_definitions"]
            if item["id"] == "os-range-transition-fault-owners"
        )
        self.assertEqual(
            definition["required_definitions"],
            [
                "bool _mi_os_commit_ex",
                "bool _mi_os_decommit",
                "bool _mi_os_purge_ex",
                "bool _mi_os_protect",
            ],
        )

    def test_huge_branch_anchor_contains_the_pinned_v350_per_page_free_owner(self) -> None:
        """The huge-page branch includes both allocation and its paired source cleanup."""

        component = next(item for item in self.summary()["components"] if item["id"] == "fault-injection")
        definition = next(
            item for item in component["bounded_source_definitions"]
            if item["id"] == "os-huge-branch-fault-owners"
        )
        self.assertEqual(
            definition["source_anchor"],
            {
                "member": "src/os.c",
                "start_line": 771,
                "end_line": 853,
                "sha256": "89affd5d917f2f40f32764001c58d52f72bf9e3faa23cdaa965f49bf322c05c2",
            },
        )


if __name__ == "__main__":
    unittest.main()
