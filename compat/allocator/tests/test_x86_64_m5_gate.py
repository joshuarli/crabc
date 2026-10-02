#!/usr/bin/env python3
"""Contracts for the fail-closed native x86-64 allocator lifecycle gate."""

from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
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

    def test_two_publisher_owner_exit_differential_is_required(self) -> None:
        evidence_id = "differential:owner-exit-late-remote-two-producers"
        summary = self.validate()
        self.assertIn(evidence_id, summary["runnable_evidence"])
        records = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        records[evidence_id] = {"status": "failed"}
        report = gate.gate_report(self.contract, summary, records)
        generic_exit = next(entry for entry in report["gates"] if entry["id"] == "m5.generic-exit")
        self.assertEqual(generic_exit["status"], "failed")

    def test_correctness_profile_retains_functional_evidence_and_defers_performance(self) -> None:
        summary = self.validate()
        records = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]
                   if entry not in {"codegen:hot-path-audit", "perf:engine-early-proof"}}
        report = gate.gate_report(self.contract, summary, records, qualification_profile="correctness")
        self.assertEqual(report["qualification_profile"], "correctness")
        self.assertFalse(report["performance_qualified"])
        self.assertEqual(report["deferred_gate_ids"], ["m5.codegen-performance"])
        self.assertEqual(report["overall_status"], "passed")
        self.assertEqual(report["unmet_required"], [])
        statuses = {entry["id"]: entry["status"] for entry in report["gates"]}
        self.assertEqual(statuses.pop("m5.codegen-performance"), "deferred")
        self.assertEqual(set(statuses.values()), {"passed"})
        self.assertEqual(set(report["evidence"]), set(records))
        full = gate.gate_report(self.contract, summary, records)
        self.assertEqual(full["qualification_profile"], "full")
        self.assertEqual(full["deferred_gate_ids"], [])
        self.assertEqual(full["overall_status"], "unmet")

    def test_correctness_profile_requires_every_functional_observation(self) -> None:
        summary = self.validate()
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        for evidence_id in set(passed) - {"codegen:hot-path-audit", "perf:engine-early-proof"}:
            with self.subTest(evidence=evidence_id):
                failed = dict(passed, **{evidence_id: {"status": "failed"}})
                report = gate.gate_report(self.contract, summary, failed, qualification_profile="correctness")
                self.assertEqual(report["overall_status"], "unmet")
                absent = {name: value for name, value in passed.items() if name != evidence_id}
                report = gate.gate_report(self.contract, summary, absent, qualification_profile="correctness")
                self.assertEqual(report["overall_status"], "unmet")

    def test_unknown_qualification_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "qualification profile"):
            gate.gate_report(self.contract, self.validate(), {}, qualification_profile="subset")
        weakened = copy.deepcopy(self.contract)
        weakened["qualification_profiles"]["correctness"]["deferred_evidence"].append("ratchet:architecture")
        with self.assertRaisesRegex(harness.HarnessError, "defer only"):
            self.validate(weakened)

    def test_correctness_cli_executes_only_functional_evidence_in_a_separate_report_directory(self) -> None:
        summary = self.validate()
        records = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        with mock.patch.object(gate.harness, "require_native_x86_64"), \
                mock.patch.object(gate.Path, "mkdir"), \
                mock.patch.object(gate, "run_evidence", return_value=records) as execute, \
                mock.patch.object(gate, "report_provenance", return_value={}), \
                mock.patch.object(gate.harness, "write_json") as write:
            self.assertEqual(gate.main(["--qualification-profile", "correctness"]), 0)
        active = {name: command for name, command in summary["runnable_evidence"].items()
                  if name not in {"codegen:hot-path-audit", "perf:engine-early-proof"}}
        execute.assert_called_once_with(active, gate.ARTIFACTS.with_name("m5-correctness-gate"))
        self.assertEqual(write.call_args.args[0], gate.ARTIFACTS.with_name("m5-correctness-gate") / "report.json")
        report = write.call_args.args[1]
        import x86_64_m9_gate as full_reader
        report["provenance"] = {}
        self.assertIn("report lacks the complete passing gate roster", full_reader.correctness_evidence_unmet(
            "m5", report, gate.ARTIFACTS, None))

    def test_correctness_reader_requires_functional_authenticity_without_codegen_replay(self) -> None:
        import x86_64_m9_gate as audit_reader
        scratch = ROOT / ".work/allocator-x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            artifacts = Path(temporary) / "m5-correctness-gate"
            artifacts.mkdir()
            report_path = artifacts / "report.json"
            report_path.write_text("{}")
            report = {"qualification_profile": "correctness"}
            def read(path):
                if path == report_path:
                    return report
                raise FileNotFoundError(path)

            with mock.patch.object(gate, "ARTIFACTS", artifacts.with_name("m5-gate")), \
                    mock.patch.object(gate.harness, "read_json", side_effect=read) as read_json, \
                    mock.patch.object(audit_reader, "correctness_evidence_unmet", return_value=[]) as classify, \
                    mock.patch.object(audit_reader, "physical_codegen_unmet") as replay:
                self.assertEqual(gate.read_report(profile="correctness"), report)
                classify.assert_called_once_with("m5", report, artifacts, None, qualification_profile="correctness")
                read_json.assert_called_once_with(report_path)
                replay.assert_not_called()
                classify.return_value = ["report lacks current clean source"]
                with self.assertRaisesRegex(harness.HarnessError, "current clean source"):
                    gate.read_report(profile="correctness")
                classify.return_value = []
                full_path = artifacts.with_name("m5-gate") / "report.json"
                full_path.parent.mkdir()
                full_path.write_text("{}")
                report_path = full_path
                with self.assertRaisesRegex(harness.HarnessError, "physical evidence"):
                    gate.read_report(profile="full")

    def test_receipt_requires_the_complete_declared_cases_products_and_parameters(self) -> None:
        check = {"runner": "owned-native-allocator-stress", "case_prefix": "soak-",
                 "required_cases": ["soak-static-pie", "soak-dynamic-pie"],
                 "required_products": ["static-manifest"],
                 "parameters": {"SKIP": ""}}
        read = gate.native_shadow_receipt.Receipt(
            path=ROOT / ".work/receipt.json", runner=check["runner"],
            source={"revision": "a" * 40, "worktree_sha256": "b" * 64},
            products={"static-manifest": {}},
            cases=[{"id": name} for name in check["required_cases"]], parameters={"SKIP": ""})
        with mock.patch.object(gate.native_shadow_receipt, "read_receipt", return_value=read):
            self.assertTrue(gate.check_receipt(check)[0])
            for field, replacement in (("cases", [{"id": "soak-static-pie"}]),
                                       ("products", {}), ("parameters", {"SKIP": "stress"})):
                with self.subTest(field=field):
                    changed = dict(read.__dict__, **{field: replacement})
                    with mock.patch.object(gate.native_shadow_receipt, "read_receipt",
                                           return_value=gate.native_shadow_receipt.Receipt(**changed)):
                        self.assertFalse(gate.check_receipt(check)[0])

    def test_receipt_admission_reopens_original_evidence_and_binds_its_identity(self) -> None:
        summary = self.validate()
        receipt_checks = {name: check for name, check in summary["runnable_evidence"].items()
                          if isinstance(check, dict)}
        report = {"evidence": {name: {"status": "passed", "receipt": check}
                                for name, check in receipt_checks.items()},
                  "provenance": {"receipts": {name: {"sha256": "a", "size": 1}
                                               for name in receipt_checks}}}
        with mock.patch.object(gate, "check_receipt", return_value=(True, "passed")) as reopen, \
                mock.patch.object(gate.engine, "file_record", return_value={"sha256": "a", "size": 1}):
            self.assertEqual(gate.receipt_evidence_unmet(report, receipt_checks), [])
            self.assertEqual(reopen.call_count, len(receipt_checks))
            reopen.return_value = (False, "product changed")
            self.assertIn("product changed", gate.receipt_evidence_unmet(report, receipt_checks)[0])
            reopen.return_value = (True, "passed")
            report["provenance"]["receipts"] = {}
            self.assertTrue(gate.receipt_evidence_unmet(report, receipt_checks))

    def test_receipt_evidence_is_runnable_and_passes_only_on_a_valid_receipt(self) -> None:
        summary = self.validate()
        for evidence_id in ("receipt:libc-shadow-pthread-teardown", "receipt:upstream-test-stress",
                            "receipt:seeded-soak"):
            self.assertIn(evidence_id, summary["runnable_evidence"])
        scratch = ROOT / ".work/allocator-x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
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
            required = dict(check, required_cases=["soak-1-static-pie"],
                            required_products=["soak-static-pie"], parameters={})
            path = gate.native_shadow_receipt.receipt_directory(root, check["runner"]) / "receipt.json"
            report = {"evidence": {"receipt:soak": {"receipt": required}},
                      "provenance": {"receipts": {"receipt:soak": gate.engine.file_record(path)}}}
            self.assertEqual(gate.receipt_evidence_unmet(report, {"receipt:soak": required}, root), [])
            (path.parent / "logs/soak.stdout").write_text("changed after gate collection\n")
            self.assertIn("does not match its digest", gate.receipt_evidence_unmet(
                report, {"receipt:soak": required}, root)[0])


if __name__ == "__main__":
    unittest.main()
