#!/usr/bin/env python3
"""Contracts for fail-closed Heap and subprocess allocator admission."""

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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

    def test_baseline_defers_only_physical_hardware_and_keeps_failed_evidence(self) -> None:
        contract = copy.deepcopy(self.contract)
        for row in contract["gates"]:
            row["blocked_by"] = []
        summary = self.validate(contract=contract)
        results = {name: {"status": "passed", "command": gate.evidence_command(command)}
                   for name, command in summary["runnable_evidence"].items()}
        full = gate.gate_report(contract, summary, results)
        baseline = gate.gate_report(contract, summary, results, qualification_profile="baseline")
        self.assertEqual(full["overall_status"], "unmet")
        self.assertEqual(baseline["overall_status"], "passed")
        self.assertEqual(baseline["unqualified_modes"], ["physical-numa", "2mib-pages", "1gib-pages"])
        row = next(row for row in contract["gates"] if row.get("hardware_blocked_by"))
        row["blocked_by"] = ["ordinary failure/fallback remains unproved"]
        self.assertIn(row["id"], gate.gate_report(
            contract, summary, results, qualification_profile="baseline")["unmet_required"])
        row["blocked_by"] = []
        results[row["evidence"][0]]["status"] = "failed"
        self.assertIn(row["id"], gate.gate_report(
            contract, summary, results, qualification_profile="baseline")["unmet_required"])
        del results[row["evidence"][0]]
        self.assertIn(row["id"], gate.gate_report(
            contract, summary, results, qualification_profile="baseline")["unmet_required"])

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
        owned = {name for entry in self.contract["gates"] for name in entry["items"]}
        for name in ("mi_heap_new", "mi_heap_destroy", "mi_theap_set_default",
                     "mi_subproc_destroy", "mi_manage_os_memory_ex", "mi_reserve_os_memory_ex",
                     "mi_any_heap_contains", "mi_heap_stl_allocator"):
            self.assertIn(name, owned)
        # Process-wide debug output and inapplicable declarations stay outside this interface selection.
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
        selected = self.gate_record(unblocked, "m6.heap-lifecycle")
        selected["blocked_by"] = []
        unblocked["evidence"][selected["evidence"][0]]["runner"] = None
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

    def test_public_reservation_warning_row_is_required_and_failure_is_visible(self) -> None:
        row = "differential:public-reservation-warning"
        removed = copy.deepcopy(self.contract)
        self.gate_record(removed, "m6.arena")["evidence"].remove(row)
        with self.assertRaisesRegex(harness.HarnessError, "declared but unused"):
            self.validate(removed)

        summary = self.validate()
        results = {entry: {"status": "passed", "command": gate.evidence_command(runner)}
                   for entry, runner in summary["runnable_evidence"].items()}
        results[row]["status"] = "failed"
        report = gate.gate_report(self.contract, summary, results)
        arena = self.gate_record(report, "m6.arena")
        self.assertEqual(arena["status"], "failed")
        self.assertEqual(arena["evidence"][row], "failed")

    def test_public_heap_alignment_row_is_required_and_failure_is_visible(self) -> None:
        row = "differential:public-heap-alignment"
        removed = copy.deepcopy(self.contract)
        self.gate_record(removed, "m6.heap-allocation")["evidence"].remove(row)
        with self.assertRaisesRegex(harness.HarnessError, "declared but unused"):
            self.validate(removed)

        summary = self.validate()
        results = {entry: {"status": "passed", "command": gate.evidence_command(runner)}
                   for entry, runner in summary["runnable_evidence"].items()}
        results[row]["status"] = "failed"
        report = gate.gate_report(self.contract, summary, results)
        allocation = self.gate_record(report, "m6.heap-allocation")
        self.assertEqual(allocation["status"], "failed")
        self.assertEqual(allocation["evidence"][row], "failed")

    def test_managed_os_lifecycle_row_is_required_and_failure_is_visible(self) -> None:
        row = "differential:managed-os-lifecycle"
        removed = copy.deepcopy(self.contract)
        self.gate_record(removed, "m6.arena")["evidence"].remove(row)
        with self.assertRaisesRegex(harness.HarnessError, "declared but unused"):
            self.validate(removed)

        summary = self.validate()
        results = {entry: {"status": "passed", "command": gate.evidence_command(runner)}
                   for entry, runner in summary["runnable_evidence"].items()}
        results[row]["status"] = "failed"
        report = gate.gate_report(self.contract, summary, results)
        arena = self.gate_record(report, "m6.arena")
        self.assertEqual(arena["status"], "failed")
        self.assertEqual(arena["evidence"][row], "failed")

    def test_managed_callback_row_is_required_and_failure_is_visible(self) -> None:
        row = "differential:managed-callback"
        removed = copy.deepcopy(self.contract)
        self.gate_record(removed, "m6.arena")["evidence"].remove(row)
        with self.assertRaisesRegex(harness.HarnessError, "declared but unused"):
            self.validate(removed)

        summary = self.validate()
        results = {entry: {"status": "passed", "command": gate.evidence_command(runner)}
                   for entry, runner in summary["runnable_evidence"].items()}
        results[row]["status"] = "failed"
        report = gate.gate_report(self.contract, summary, results)
        arena = self.gate_record(report, "m6.arena")
        self.assertEqual(arena["status"], "failed")
        self.assertEqual(arena["evidence"][row], "failed")

    def test_managed_callback_failure_row_is_required_and_failure_is_visible(self) -> None:
        row = "differential:managed-callback-failure"
        removed = copy.deepcopy(self.contract)
        self.gate_record(removed, "m6.arena")["evidence"].remove(row)
        with self.assertRaisesRegex(harness.HarnessError, "declared but unused"):
            self.validate(removed)

        summary = self.validate()
        results = {entry: {"status": "passed", "command": gate.evidence_command(runner)}
                   for entry, runner in summary["runnable_evidence"].items()}
        results[row]["status"] = "failed"
        report = gate.gate_report(self.contract, summary, results)
        arena = self.gate_record(report, "m6.arena")
        self.assertEqual(arena["status"], "failed")
        self.assertEqual(arena["evidence"][row], "failed")

    def test_child_managed_callback_row_is_required_and_failure_is_visible(self) -> None:
        row = "differential:child-managed-callback"
        removed = copy.deepcopy(self.contract)
        self.gate_record(removed, "m6.arena")["evidence"].remove(row)
        with self.assertRaisesRegex(harness.HarnessError, "declared but unused"):
            self.validate(removed)

        summary = self.validate()
        results = {entry: {"status": "passed", "command": gate.evidence_command(runner)}
                   for entry, runner in summary["runnable_evidence"].items()}
        results[row]["status"] = "failed"
        report = gate.gate_report(self.contract, summary, results)
        arena = self.gate_record(report, "m6.arena")
        self.assertEqual(arena["status"], "failed")
        self.assertEqual(arena["evidence"][row], "failed")

    def test_passing_runnable_evidence_never_removes_a_reviewed_blocker(self) -> None:
        contract = copy.deepcopy(self.contract)
        for entry in contract["gates"]:
            entry["blocked_by"] = []
            entry.pop("hardware_blocked_by", None)
        self.gate_record(contract, "m6.destruction-lifetime")["blocked_by"] = [
            "Live-owner destruction has no matched lifetime evidence."
        ]
        summary = self.validate(contract)
        passed = {entry: {"status": "passed", "command": gate.evidence_command(runner)}
                   for entry, runner in summary["runnable_evidence"].items()}
        report = gate.gate_report(contract, summary, passed)
        self.assertEqual(report["overall_status"], "unmet")
        self.assertEqual(report["unmet_required"], ["m6.destruction-lifetime"])
        destruction = next(entry for entry in report["gates"] if entry["id"] == "m6.destruction-lifetime")
        self.assertEqual(destruction["status"], "blocked")
        self.assertEqual(set(destruction["evidence"].values()), {"passed"})

    def test_a_fully_evidenced_unblocked_gate_passes_and_a_failed_run_fails(self) -> None:
        contract = copy.deepcopy(self.contract)
        for record in contract["evidence"].values():
            record["runner"] = "compat/allocator/heap_destroy.py"
        for entry in contract["gates"]:
            entry["blocked_by"] = []
            entry.pop("hardware_blocked_by", None)
        summary = self.validate(contract)
        results = {entry: {"status": "passed", "command": gate.evidence_command(runner)}
                   for entry, runner in summary["runnable_evidence"].items()}
        self.assertEqual(gate.gate_report(contract, summary, results)["overall_status"], "passed")
        results["differential:arena-destroy"]["status"] = "failed"
        report = gate.gate_report(contract, summary, results)
        self.assertEqual(report["overall_status"], "unmet")
        arena = next(entry for entry in report["gates"] if entry["id"] == "m6.arena")
        self.assertEqual(arena["status"], "failed")


    def test_passed_labels_cannot_replace_current_profile_command_authority(self) -> None:
        contract = copy.deepcopy(self.contract)
        for record in contract["gates"]:
            record["blocked_by"] = []
        summary = self.validate(contract)
        honest = {entry: {"status": "passed", "command": gate.evidence_command(runner)}
                  for entry, runner in summary["runnable_evidence"].items()}
        row = "differential:public-heap-adapter"
        for command in (None, ["python3", summary["runnable_evidence"][row]],
                        ["python3", summary["runnable_evidence"][row], "--profile", "debug-1"],
                        ["python3", "compat/allocator/heap_destroy.py"]):
            with self.subTest(command=command):
                results = copy.deepcopy(honest)
                if command is None:
                    del results[row]["command"]
                else:
                    results[row]["command"] = command
                report = gate.gate_report(contract, summary, results)
                self.assertEqual(report["overall_status"], "unmet")
                self.assertEqual(self.gate_record(report, "m6.heap-allocation")["evidence"][row], "failed")


class M6EvidenceExecutionTests(unittest.TestCase):
    def test_registered_profile_producers_receive_their_complete_cli_selection(self) -> None:
        runnable = {
            "differential:public-heap-adapter": "compat/allocator/x86_64_m6_adapter.py",
            "upstream:test-stress-subprocs": "compat/allocator/x86_64_m6_test_stress_subprocs.py",
            "differential:public-heap-alignment": "compat/allocator/x86_64_m6_public_heap_alignment.py",
        }
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as name:
            with mock.patch.object(harness, "command_record", side_effect=lambda command, **kwargs: {
                "command": command, "status": 0, "stdout": "whole original workload complete", "stderr": "",
            }) as execute:
                results = gate.run_evidence(runnable, Path(name))
        expected = [
            ["python3", runnable["differential:public-heap-adapter"], "--matrix"],
            ["python3", runnable["upstream:test-stress-subprocs"], "--matrix"],
            ["python3", runnable["differential:public-heap-alignment"], "--profile", "all"],
        ]
        self.assertEqual([call.args[0] for call in execute.call_args_list], expected)
        self.assertEqual([entry["command"] for entry in results.values()], expected)

    def test_real_nonzero_profile_producer_keeps_its_raw_failure(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as name:
            work = Path(name)
            runner = work / "profile-producer.py"
            runner.write_text("import sys\nprint('original profile refusal', file=sys.stderr)\nsys.exit(1)\n")
            runnable = {"differential:profile": harness.relative(runner)}
            results = gate.run_evidence(runnable, work)
            entry = results["differential:profile"]
            self.assertEqual(entry["status"], "failed")
            self.assertEqual(entry["command"], ["python3", harness.relative(runner)])
            self.assertEqual((harness.ROOT / entry["log"]).read_text(), "original profile refusal\n")

    def test_shared_producer_runs_once_and_failure_reaches_both_evidence_rows(self) -> None:
        for status in (0, 1):
            with self.subTest(status=status), tempfile.TemporaryDirectory(dir=ROOT / ".work") as name:
                artifacts = Path(name)
                runnable = {
                    "differential:shared": "compat/allocator/heap_destroy.py",
                    "unit:shared": "compat/allocator/heap_destroy.py",
                    "differential:other": "compat/allocator/arena_destroy.py",
                }
                with mock.patch.object(gate.harness, "command_record", side_effect=lambda command, **kwargs: {
                    "command": command, "status": status, "stdout": "observations\n", "stderr": "diagnostic\n",
                }) as execute:
                    results = gate.run_evidence(runnable, artifacts)
                self.assertEqual(execute.call_count, 2)
                for evidence_id, result in results.items():
                    self.assertEqual(result["status"], "passed" if status == 0 else "failed")
                    self.assertEqual((harness.ROOT / result["log"]).read_text(),
                                     "observations\ndiagnostic\n")


if __name__ == "__main__":
    unittest.main()
