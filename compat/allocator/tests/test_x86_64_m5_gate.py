#!/usr/bin/env python3
"""Contracts for the fail-closed native x86-64 Milestone 5 allocator gate."""

from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
SPEC = importlib.util.spec_from_file_location("x86_64_m5_gate", ROOT / "compat/allocator/x86_64_m5_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
harness = gate.harness


class M5GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pin = harness.load_pin()
        self.contract = harness.read_json(gate.CONTRACT)
        self.targets = gate.native_test_targets()

    def validate(self, contract=None, targets=None):
        return gate.validate_contract(
            self.contract if contract is None else contract,
            self.pin,
            self.targets if targets is None else targets,
        )

    def gate_record(self, contract, gate_id):
        return next(entry for entry in contract["gates"] if entry["id"] == gate_id)

    def test_checked_in_contract_claims_every_native_target_and_blocks_missing_evidence(self) -> None:
        summary = self.validate()
        self.assertEqual(summary["gate_ids"], list(gate.GATE_IDS))
        elsewhere = set(self.contract.get("native_tests_owned_elsewhere", {}))
        self.assertEqual(summary["native_target_count"], len(self.targets - elsewhere))
        missing = set(summary["missing_evidence"])
        for entry in self.contract["gates"]:
            if missing & set(entry["evidence"]):
                self.assertIn(entry["id"], summary["blocked_gate_ids"])

    def test_native_evidence_runs_its_targets_with_the_audit_and_fault_seams(self) -> None:
        command = gate.native_test_command(["native_pointer_first_free", "native_live_remote_free"])
        self.assertEqual(command[:2], ["cargo", "test"])
        self.assertIn(gate.NATIVE_FEATURES, command)
        self.assertEqual(
            [command[index + 1] for index, argument in enumerate(command) if argument == "--test"],
            ["native_pointer_first_free", "native_live_remote_free"],
        )

    def test_a_new_native_target_outside_every_evidence_entry_breaks_closure(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "native_future_witness"):
            self.validate(targets=self.targets | {"native_future_witness"})

    def test_a_doubly_claimed_or_absent_native_target_is_rejected(self) -> None:
        doubled = copy.deepcopy(self.contract)
        target = doubled["evidence"]["native:pointer-dispatch"]["native_tests"][0]
        doubled["evidence"]["native:generic-exit"]["native_tests"].append(target)
        with self.assertRaisesRegex(harness.HarnessError, "claimed by both"):
            self.validate(doubled)

        absent = copy.deepcopy(self.contract)
        absent["evidence"]["native:generic-exit"]["native_tests"].append("native_not_a_target")
        with self.assertRaisesRegex(harness.HarnessError, "absent native target"):
            self.validate(absent)

    def test_a_target_owned_elsewhere_must_be_cited_by_that_gate(self) -> None:
        uncited = copy.deepcopy(self.contract)
        target = uncited["evidence"]["native:pointer-dispatch"]["native_tests"].pop()
        uncited["native_tests_owned_elsewhere"] = {target: "compat/allocator/x86_64_m7_gate.py"}
        with self.assertRaisesRegex(harness.HarnessError, "does not cite it"):
            self.validate(uncited)

    def test_missing_evidence_requires_a_reviewed_blocker(self) -> None:
        unblocked = copy.deepcopy(self.contract)
        self.gate_record(unblocked, "m5.codegen-performance")["blocked_by"] = []
        with self.assertRaisesRegex(harness.HarnessError, "missing evidence without a blocker"):
            self.validate(unblocked)

    def test_malformed_evidence_or_gate_identity_is_rejected(self) -> None:
        both = copy.deepcopy(self.contract)
        both["evidence"]["differential:reclaim-on-free"]["native_tests"] = ["native_reclaim_on_free"]
        with self.assertRaisesRegex(harness.HarnessError, "exactly native_tests, command, or receipt"):
            self.validate(both)

        absent_runner = copy.deepcopy(self.contract)
        absent_runner["evidence"]["differential:reclaim-on-free"]["command"] = [
            "python3", "compat/allocator/not_a_runner.py",
        ]
        with self.assertRaisesRegex(harness.HarnessError, "absent runner"):
            self.validate(absent_runner)

        reordered = copy.deepcopy(self.contract)
        reordered["gates"].reverse()
        with self.assertRaisesRegex(harness.HarnessError, "order or identity"):
            self.validate(reordered)

        malformed = copy.deepcopy(self.contract)
        malformed["evidence"]["receipt:seeded-soak"]["receipt"] = {"runner": "../escape", "case_prefix": "soak-"}
        with self.assertRaisesRegex(harness.HarnessError, "malformed receipt check"):
            self.validate(malformed)

        unused = copy.deepcopy(self.contract)
        unused["evidence"]["differential:unused"] = {"command": None, "scope": "unused"}
        with self.assertRaisesRegex(harness.HarnessError, "declared but unused"):
            self.validate(unused)

    def test_report_fails_on_any_failed_evidence_and_blocks_on_blockers_or_missing_runs(self) -> None:
        summary = self.validate()
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        report = gate.gate_report(self.contract, summary, passed)
        by_id = {record["id"]: record["status"] for record in report["gates"]}
        for entry in self.contract["gates"]:
            expected = "blocked" if entry["id"] in summary["blocked_gate_ids"] else "passed"
            self.assertEqual(by_id[entry["id"]], expected, entry["id"])
        self.assertEqual(report["overall_status"], "unmet")

        failed = dict(passed, **{"ratchet:architecture": {"status": "failed"}})
        report = gate.gate_report(self.contract, summary, failed)
        by_id = {record["id"]: record["status"] for record in report["gates"]}
        self.assertEqual(by_id["m5.pointer-dispatch"], "failed")
        self.assertEqual(by_id["m5.no-forbidden-scaffolding"], "failed")

        not_run = {key: value for key, value in passed.items() if key != "native:generic-exit"}
        report = gate.gate_report(self.contract, summary, not_run)
        self.assertEqual(
            next(record for record in report["gates"] if record["id"] == "m5.generic-exit")["status"],
            "blocked",
        )

    def test_receipt_evidence_is_runnable_and_passes_only_on_a_valid_receipt(self) -> None:
        summary = self.validate()
        for evidence_id in ("receipt:libc-shadow-pthread-teardown", "receipt:upstream-test-stress",
                            "receipt:seeded-soak"):
            self.assertIn(evidence_id, summary["runnable_evidence"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text(".work/\n")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t",
                            "commit", "-qm", "base"], cwd=root, check=True)
            check = {"runner": "owned-native-allocator-stress", "case_prefix": "soak-"}
            passed, message = gate.check_receipt(check, root)
            self.assertFalse(passed)
            self.assertIn("no receipt", message)
            work = root / ".work/x86_64/tmp/run"
            work.mkdir(parents=True)
            (work / "soak.stdout").write_text("summary\n")
            gate.native_shadow_receipt.write_receipt(
                root, check["runner"], work, {"soak-static-pie": work / "soak.stdout"},
                [("soak-1-static-pie", 0, [work / "soak.stdout"])], {}, True,
            )
            passed, message = gate.check_receipt(check, root)
            self.assertTrue(passed, message)
            passed, message = gate.check_receipt(dict(check, case_prefix="stress-"), root)
            self.assertFalse(passed)


if __name__ == "__main__":
    unittest.main()
