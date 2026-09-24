#!/usr/bin/env python3
"""Contracts for the fail-closed Milestone 4 allocator gate."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
SPEC = importlib.util.spec_from_file_location("x86_64_m4_gate", ROOT / "compat/allocator/x86_64_m4_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
harness = gate.harness


class M4GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pin = harness.load_pin()
        self.contract = harness.read_json(gate.CONTRACT)
        self.api = harness.read_json(harness.ALLOCATOR_ROOT / "api-v3.5.0.json")
        self.sibling = gate.sibling_owned_items(self.contract["inventory"])

    def validate(self, contract=None, api=None, sibling=None):
        return gate.validate_contract(
            self.contract if contract is None else contract,
            self.api if api is None else api,
            self.pin,
            self.sibling if sibling is None else sibling,
        )

    def gate_record(self, contract, gate_id):
        return next(entry for entry in contract["gates"] if entry["id"] == gate_id)

    def test_checked_in_contract_partitions_the_m4_items(self) -> None:
        summary = self.validate()
        self.assertEqual(summary["gate_ids"], list(gate.GATE_IDS))
        owned = {name for entry in self.contract["gates"] for name in entry["items"]}
        for name in ("mi_malloc", "mi_calloc", "mi_realloc", "mi_expand", "mi_malloc_aligned_at",
                     "mi_posix_memalign", "mi_usable_size", "mi_good_size", "mi_collect", "mi_strdup"):
            self.assertIn(name, owned)
        # Heap-, arena-, and option-shaped members of the selected groups
        # belong to M6/M7; override-only and callback types are excluded to
        # their named owners rather than dropped.
        for name in ("mi_heap_malloc", "mi_reserve_os_memory", "mi_version", "mi_option_get",
                     "mi_malloc_size", "mi_output_fun"):
            self.assertNotIn(name, owned)
        self.assertIn("mi_malloc_size", summary["excluded_items"])

    def test_an_omitted_or_doubly_owned_item_is_rejected(self) -> None:
        omitted = copy.deepcopy(self.contract)
        self.gate_record(omitted, "m4.realloc")["items"].remove("mi_expand")
        with self.assertRaisesRegex(harness.HarnessError, "omit applicable inventory items"):
            self.validate(omitted)

        doubled = copy.deepcopy(self.contract)
        self.gate_record(doubled, "m4.free")["items"].append("mi_malloc")
        with self.assertRaisesRegex(harness.HarnessError, "owned by both"):
            self.validate(doubled)

    def test_a_new_applicable_authority_entry_breaks_closure(self) -> None:
        api = copy.deepcopy(self.api)
        extra = copy.deepcopy(next(item for item in api["items"] if item["name"] == "mi_malloc"))
        extra["name"] = "mi_malloc_ex"
        api["items"].append(extra)
        with self.assertRaisesRegex(harness.HarnessError, "mi_malloc_ex"):
            self.validate(api=api)

    def test_exclusions_and_sibling_ownership_stay_honest(self) -> None:
        # A sibling-owned item may not be claimed by an M4 gate.
        claimed = copy.deepcopy(self.contract)
        self.gate_record(claimed, "m4.allocation")["items"].append("mi_reserve_os_memory")
        with self.assertRaisesRegex(harness.HarnessError, "unselected item"):
            self.validate(claimed)

        # An exclusion must name something the selection actually reaches.
        stray = copy.deepcopy(self.contract)
        stray["inventory"]["excluded_items"]["mi_heap_new"] = "M6"
        with self.assertRaisesRegex(harness.HarnessError, "does not reach"):
            self.validate(stray)

        unexplained = copy.deepcopy(self.contract)
        unexplained["inventory"]["excluded_items"]["mi_output_fun"] = ""
        with self.assertRaisesRegex(harness.HarnessError, "owner and reason"):
            self.validate(unexplained)

        # Dropping an exclusion without assigning the item breaks closure.
        dropped = copy.deepcopy(self.contract)
        del dropped["inventory"]["excluded_items"]["mi_output_fun"]
        with self.assertRaisesRegex(harness.HarnessError, "mi_output_fun"):
            self.validate(dropped)

    def test_inapplicable_or_itemless_ownership_is_rejected(self) -> None:
        inapplicable = copy.deepcopy(self.contract)
        inapplicable["inventory"]["additional_items"].append("mi_collect_reduce")
        with self.assertRaisesRegex(harness.HarnessError, "not applicable"):
            self.validate(inapplicable)

        itemless = copy.deepcopy(self.contract)
        self.gate_record(itemless, "m4.upstream")["items"].append("mi_malloc")
        with self.assertRaisesRegex(harness.HarnessError, "cross-cutting|owned by both"):
            self.validate(itemless)

    def test_missing_evidence_cannot_be_unblocked_by_editing_the_contract(self) -> None:
        unblocked = copy.deepcopy(self.contract)
        self.gate_record(unblocked, "m4.collection")["blocked_by"] = []
        with self.assertRaisesRegex(harness.HarnessError, "missing evidence without a blocker"):
            self.validate(unblocked)

        undeclared = copy.deepcopy(self.contract)
        self.gate_record(undeclared, "m4.aligned")["evidence"].append("differential:invented")
        with self.assertRaisesRegex(harness.HarnessError, "undeclared evidence"):
            self.validate(undeclared)

        absent_runner = copy.deepcopy(self.contract)
        absent_runner["evidence"]["upstream:test-api"]["command"] = ["python3", "compat/allocator/absent.py"]
        with self.assertRaisesRegex(harness.HarnessError, "absent runner"):
            self.validate(absent_runner)

    def test_passing_runnable_evidence_never_removes_a_reviewed_blocker(self) -> None:
        summary = self.validate()
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        contract = copy.deepcopy(self.contract)
        self.gate_record(contract, "m4.realloc")["blocked_by"] = ["reviewed blocker"]
        report = gate.gate_report(contract, summary, passed)
        self.assertEqual(report["overall_status"], "unmet")
        for record in report["gates"]:
            if record["blocked_by"]:
                self.assertEqual(record["status"], "blocked")
                self.assertIn(record["id"], report["unmet_required"])

    def test_a_fully_evidenced_unblocked_gate_passes_and_a_failed_run_fails(self) -> None:
        contract = copy.deepcopy(self.contract)
        for record in contract["evidence"].values():
            record["command"] = ["python3", "compat/allocator/x86_64_m4_gate.py"]
        for entry in contract["gates"]:
            entry["blocked_by"] = []
        summary = self.validate(contract)
        results = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        self.assertEqual(gate.gate_report(contract, summary, results)["overall_status"], "passed")
        results["differential:collection"] = {"status": "failed"}
        report = gate.gate_report(contract, summary, results)
        self.assertEqual(report["overall_status"], "unmet")
        self.assertEqual(self.gate_record(report, "m4.collection")["status"], "failed")
        # Evidence absent from this run leaves its gate unmet, never passed.
        del results["differential:collection"]
        self.assertEqual(self.gate_record(gate.gate_report(contract, summary, results), "m4.collection")["status"],
                         "blocked")

    def test_evidence_commands_bind_only_their_fresh_scratch_directory(self) -> None:
        bound = gate.evidence_command(["python3", "x.py", "--report", "{scratch}/r.json"], Path("/scratch/run"))
        self.assertEqual(bound, ["python3", "x.py", "--report", "/scratch/run/r.json"])
        self.assertEqual(gate.evidence_command(["python3", "x.py"], Path("/s")), ["python3", "x.py"])


if __name__ == "__main__":
    unittest.main()
