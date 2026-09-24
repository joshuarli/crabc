#!/usr/bin/env python3
"""Contracts for the fail-closed Milestone 6 allocator gate."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
SPEC = importlib.util.spec_from_file_location("m6_gate", ROOT / "compat/allocator/m6_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
harness = gate.harness


class M6GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pin = harness.load_pin()
        self.contract = harness.read_json(gate.CONTRACT)
        self.api = harness.read_json(harness.ALLOCATOR_ROOT / "api-v3.5.0.json")

    def validate(self, contract=None, api=None):
        return gate.validate_contract(
            self.contract if contract is None else contract,
            self.api if api is None else api,
            self.pin,
        )

    def gate_record(self, contract, gate_id):
        return next(entry for entry in contract["gates"] if entry["id"] == gate_id)

    def test_checked_in_contract_partitions_every_applicable_m6_interface(self) -> None:
        summary = self.validate()
        self.assertEqual(summary["item_count"], 105)
        self.assertEqual(summary["gate_ids"], list(gate.GATE_IDS))
        self.assertEqual(summary["runnable_evidence"], {
            "differential:arena-destroy": "compat/allocator/arena_destroy.py",
            "differential:heap-destroy": "compat/allocator/heap_destroy.py",
            "differential:subprocess-lifecycle": "compat/allocator/subprocess_lifecycle.py",
        })
        # No public M6 interface exists yet, so every gate stays blocked.
        self.assertEqual(summary["blocked_gate_ids"], list(gate.GATE_IDS))
        owned = {name for entry in self.contract["gates"] for name in entry["items"]}
        for name in ("mi_heap_new", "mi_heap_destroy", "mi_theap_set_default",
                     "mi_subproc_destroy", "mi_manage_os_memory_ex", "mi_reserve_os_memory_ex",
                     "mi_any_heap_contains", "mi_heap_stl_allocator"):
            self.assertIn(name, owned)
        # Process-wide debug output and inapplicable declarations stay outside M6.
        for name in ("mi_arenas_print", "mi_debug_show_arenas", "mi_collect_reduce", "mi_malloc"):
            self.assertNotIn(name, owned)

    def test_an_omitted_or_doubly_owned_item_is_rejected(self) -> None:
        omitted = copy.deepcopy(self.contract)
        self.gate_record(omitted, "m6.subprocess")["items"].remove("mi_subproc_destroy")
        with self.assertRaisesRegex(harness.HarnessError, "omit applicable inventory items"):
            self.validate(omitted)

        doubled = copy.deepcopy(self.contract)
        self.gate_record(doubled, "m6.theap")["items"].append("mi_heap_new")
        with self.assertRaisesRegex(harness.HarnessError, "owned by both"):
            self.validate(doubled)

    def test_a_new_applicable_authority_item_breaks_closure(self) -> None:
        api = copy.deepcopy(self.api)
        extra = copy.deepcopy(next(item for item in api["items"] if item["name"] == "mi_heap_new"))
        extra["name"] = "mi_heap_new_ex"
        api["items"].append(extra)
        with self.assertRaisesRegex(harness.HarnessError, "mi_heap_new_ex"):
            self.validate(api=api)

    def test_inapplicable_or_unknown_selection_is_rejected(self) -> None:
        inapplicable = copy.deepcopy(self.contract)
        inapplicable["inventory"]["additional_items"].append("mi_collect_reduce")
        with self.assertRaisesRegex(harness.HarnessError, "not applicable"):
            self.validate(inapplicable)

        unowned = copy.deepcopy(self.contract)
        self.gate_record(unowned, "m6.heap-lifecycle")["items"].append("mi_malloc")
        with self.assertRaisesRegex(harness.HarnessError, "unselected item"):
            self.validate(unowned)

    def test_missing_evidence_cannot_be_unblocked_by_editing_the_contract(self) -> None:
        unblocked = copy.deepcopy(self.contract)
        self.gate_record(unblocked, "m6.heap-lifecycle")["blocked_by"] = []
        with self.assertRaisesRegex(harness.HarnessError, "missing evidence without a blocker"):
            self.validate(unblocked)

        undeclared = copy.deepcopy(self.contract)
        self.gate_record(undeclared, "m6.arena")["evidence"].append("differential:invented")
        with self.assertRaisesRegex(harness.HarnessError, "undeclared evidence"):
            self.validate(undeclared)

        absent_runner = copy.deepcopy(self.contract)
        absent_runner["evidence"]["unit:arena"]["runner"] = "compat/allocator/absent.py"
        with self.assertRaisesRegex(harness.HarnessError, "absent runner"):
            self.validate(absent_runner)

    def test_passing_runnable_evidence_never_removes_a_reviewed_blocker(self) -> None:
        summary = self.validate()
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        report = gate.gate_report(self.contract, summary, passed)
        self.assertEqual(report["overall_status"], "unmet")
        self.assertEqual(report["unmet_required"], list(gate.GATE_IDS))
        destruction = next(entry for entry in report["gates"] if entry["id"] == "m6.destruction-lifetime")
        self.assertEqual(destruction["status"], "blocked")
        self.assertEqual(destruction["evidence"], {
            "differential:heap-destroy": "passed", "differential:arena-destroy": "passed",
            "differential:subprocess-lifecycle": "passed",
        })

    def test_a_fully_evidenced_unblocked_gate_passes_and_a_failed_run_fails(self) -> None:
        contract = copy.deepcopy(self.contract)
        for record in contract["evidence"].values():
            record["runner"] = "compat/allocator/heap_destroy.py"
        for entry in contract["gates"]:
            entry["blocked_by"] = []
        summary = self.validate(contract)
        results = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        self.assertEqual(gate.gate_report(contract, summary, results)["overall_status"], "passed")
        results["differential:arena-destroy"] = {"status": "failed"}
        report = gate.gate_report(contract, summary, results)
        self.assertEqual(report["overall_status"], "unmet")
        arena = next(entry for entry in report["gates"] if entry["id"] == "m6.arena")
        self.assertEqual(arena["status"], "failed")


if __name__ == "__main__":
    unittest.main()
