#!/usr/bin/env python3
"""Contracts for the fail-closed native allocator integration gate."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
SPEC = importlib.util.spec_from_file_location("x86_64_m8_gate", ROOT / "compat/allocator/x86_64_m8_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
harness = gate.harness


class M8GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pin = harness.load_pin()
        self.contract = harness.read_json(gate.CONTRACT)

    def validate(self, contract=None):
        return gate.validate_contract(self.contract if contract is None else contract, self.pin)

    def gate_record(self, contract, gate_id):
        return next(entry for entry in contract["gates"] if entry["id"] == gate_id)

    def test_checked_in_contract_names_every_m8_row(self) -> None:
        summary = self.validate()
        self.assertEqual(summary["gate_ids"], list(gate.GATE_IDS))
        self.assertIn(summary["products"]["evidence"], summary["runnable_evidence"])

    def test_missing_evidence_cannot_be_unblocked_by_editing_the_contract(self) -> None:
        unblocked = copy.deepcopy(self.contract)
        unblocked["evidence"]["consumer:lua-static"]["command"] = None
        self.gate_record(unblocked, "m8.lua")["blocked_by"] = []
        with self.assertRaisesRegex(harness.HarnessError, "missing evidence without a blocker"):
            self.validate(unblocked)

        undeclared = copy.deepcopy(self.contract)
        self.gate_record(undeclared, "m8.corpus")["evidence"].append("product:invented")
        with self.assertRaisesRegex(harness.HarnessError, "undeclared evidence"):
            self.validate(undeclared)

        foreign = copy.deepcopy(self.contract)
        foreign["evidence"]["product:loader-synthetic"]["command"] = ["python3", "x.py"]
        with self.assertRaisesRegex(harness.HarnessError, "product command"):
            self.validate(foreign)

        unused = copy.deepcopy(self.contract)
        unused["evidence"]["product:unused"] = {"command": None, "scope": "s"}
        with self.assertRaisesRegex(harness.HarnessError, "declared but unused"):
            self.validate(unused)

    def test_the_products_command_must_run_and_build_its_own_products(self) -> None:
        absent = copy.deepcopy(self.contract)
        absent["evidence"][absent["products"]["evidence"]]["command"] = None
        with self.assertRaisesRegex(harness.HarnessError, "products evidence must be runnable"):
            self.validate(absent)

        circular = copy.deepcopy(self.contract)
        circular["evidence"][circular["products"]["evidence"]]["command"].append("{dynamic_sysroot}")
        with self.assertRaisesRegex(harness.HarnessError, "cannot consume its own products"):
            self.validate(circular)

    def test_passing_runnable_evidence_never_removes_a_reviewed_blocker(self) -> None:
        contract = copy.deepcopy(self.contract)
        self.gate_record(contract, "m8.rust-std")["blocked_by"] = ["pending review"]
        summary = self.validate(contract)
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        report = gate.gate_report(contract, summary, passed)
        self.assertEqual(report["overall_status"], "unmet")
        for record in report["gates"]:
            if record["blocked_by"]:
                self.assertEqual(record["status"], "blocked")

    def test_a_fully_evidenced_unblocked_gate_passes_and_a_failed_run_fails(self) -> None:
        contract = copy.deepcopy(self.contract)
        for record in contract["evidence"].values():
            if record["command"] is None:
                record["command"] = ["scripts/dev-x86_64.sh", "stand-in"]
        for entry in contract["gates"]:
            entry["blocked_by"] = []
        summary = self.validate(contract)
        results = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        self.assertEqual(gate.gate_report(contract, summary, results)["overall_status"], "passed")
        results["product:loader-synthetic"] = {"status": "failed"}
        report = gate.gate_report(contract, summary, results)
        self.assertEqual(self.gate_record(report, "m8.dso-loader")["status"], "failed")
        del results["product:loader-synthetic"]
        report = gate.gate_report(contract, summary, results)
        self.assertEqual(self.gate_record(report, "m8.dso-loader")["status"], "blocked")


class M8ProductBindingTests(unittest.TestCase):
    PRODUCTS = {
        "evidence": "product:p", "evidence_line": "p evidence: ",
        "static_sysroot": "static-sysroot", "dynamic_sysroot": "dynamic-sysroot",
    }

    def test_the_products_directory_is_exactly_one_container_path(self) -> None:
        self.assertEqual(gate.product_directory("x\np evidence: /workspace/.work/a\n", "p evidence: "),
                         "/workspace/.work/a")
        self.assertIsNone(gate.product_directory("p evidence: /tmp/a\n", "p evidence: "))
        self.assertIsNone(gate.product_directory("p evidence: /workspace/a\np evidence: /workspace/b\n",
                                                 "p evidence: "))
        self.assertIsNone(gate.product_directory("nothing\n", "p evidence: "))

    def test_placeholders_bind_the_two_sysroots(self) -> None:
        bound = gate.bind_products(["s", "c", "--static-sysroot", "{static_sysroot}", "{dynamic_sysroot}"],
                                   self.PRODUCTS, "/workspace/.work/d")
        self.assertEqual(bound[3:], ["/workspace/.work/d/static-sysroot", "/workspace/.work/d/dynamic-sysroot"])

    def test_consumers_fail_without_products_and_run_with_them(self) -> None:
        runnable = {
            "product:p": ["scripts/dev-x86_64.sh", "produce"],
            "product:c": ["scripts/dev-x86_64.sh", "consume", "{dynamic_sysroot}"],
            "product:i": ["scripts/dev-x86_64.sh", "independent"],
        }
        calls: list[list[str]] = []

        def outcome(status, output):
            def record(command, **_kwargs):
                calls.append(list(command))
                produced = command[1] == "produce"
                return {"status": status if produced else 0, "stdout": output if produced else "", "stderr": ""}
            return record

        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            with mock.patch.object(harness, "command_record", outcome(1, "")):
                results = gate.run_evidence(runnable, self.PRODUCTS, list(runnable), Path(directory))
            self.assertEqual({key: value["status"] for key, value in results.items()},
                             {"product:p": "failed", "product:c": "failed", "product:i": "passed"})
            self.assertFalse(any(call[1] == "consume" for call in calls))

            calls.clear()
            with mock.patch.object(harness, "command_record",
                                   outcome(0, "p evidence: /workspace/.work/d\n")):
                # Selecting only the consumer still builds its products first.
                results = gate.run_evidence(runnable, self.PRODUCTS, ["product:c"], Path(directory))
            self.assertEqual(results["product:c"]["status"], "passed")
            self.assertEqual([call[1] for call in calls], ["produce", "consume"])
            self.assertEqual(calls[1][2], "/workspace/.work/d/dynamic-sysroot")
            self.assertEqual(set(results), {"product:c"})


class M8RustStdReceiptTests(unittest.TestCase):
    def test_native_shadow_receipt_binds_current_source_products_and_retained_bytes(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            work = Path(directory)
            output = work / "consumer"
            output.mkdir()
            retained = output / "consumer.log"
            retained.write_bytes(b"rust std passed\n")
            source = "a" * 64

            def container(path: Path) -> str:
                return str(gate.CONTAINER_ROOT / path.relative_to(ROOT))

            static = work / "static-sysroot"
            dynamic = work / "dynamic-sysroot"
            for root in (static, dynamic):
                (root / "share/crabc").mkdir(parents=True)
                (root / "share/crabc/manifest.json").write_text('{"allocator_backend":"native-shadow"}')
                (root / "share/crabc/libc-shared.provenance.json").write_text(
                    '{"allocator_backend":"native-shadow"}')
            state = dynamic / "share/crabc/dynamic-product-state.json"
            state.write_text(json.dumps({"allocator_backend": "native-shadow", "source_sha256": source}))
            command = ["scripts/dev-x86_64.sh", "consumer-rust-std-lto", "run",
                       "--allocator-evidence", "native-shadow",
                       "--development-static-sysroot", container(static),
                       "--development-dynamic-sysroot", container(dynamic),
                       "--output", container(output)]

            def snapshot(root: Path, mode: str):
                return {"root": str(root), "manifest": {"path": str(root / "share/crabc/manifest.json"),
                        "sha256": mode[0] * 64}, "files": {"lib/a": mode[1] * 64}}

            receipt = {
                "schema": "crabc.x86_64-consumer-rust-std-lto/v1", "gate": "consumer.rust-std-lto",
                "source_sha256": source, "passed": True, "qualifying": False,
                "allocator_evidence": "native-shadow", "cohort": None, "unmet_conditions": [],
                "frozen_gates": ["rust-std", "rust-std-dependent", "lto", "lto-native-facade"],
                "gates": {name: {"lanes": {"candidate": {"unmet": []}}} for name in
                          ("rust-std", "rust-std-dependent", "lto", "lto-native-facade")},
                "unwind": {"native-shadow": {"unmet": [], "cross_dso": {
                    "stock-std": {"unmet": []}, "build-std": {"unmet": []}}}},
                "provider_regressions": {"lanes": {name: {"unmet": []} for name in (
                    "metadata_bounds.py", "eh_frame_bounds.py", "dynamic_bounds.py",
                    "indirect_personality_bounds.py", "metadata_target_bounds.py", "frame_bounds.py")}},
                "products": {"native-shadow": {
                    "label": "native-shadow",
                    "static": {"root": container(static), "manifest": {
                        "path": container(static / "share/crabc/manifest.json"), "sha256": "s" * 64},
                        "files": {"lib/a": "t" * 64}},
                    "dynamic": {"root": container(dynamic), "manifest": {
                        "path": container(dynamic / "share/crabc/manifest.json"), "sha256": "d" * 64},
                        "files": {"lib/a": "y" * 64}}}},
                "retained_files": {container(retained): hashlib.sha256(retained.read_bytes()).hexdigest()},
            }
            path = output / "receipt.json"

            def read():
                path.write_text(json.dumps(receipt))
                with mock.patch.object(gate.consumer.owned_cleanup, "product_snapshot", snapshot):
                    return gate.read_native_shadow_receipt(command, source)

            self.assertEqual(read()["source_sha256"], source)
            receipt["source_sha256"] = "b" * 64
            with self.assertRaisesRegex(harness.HarnessError, "source"):
                read()
            receipt["source_sha256"] = source
            retained.write_bytes(b"changed\n")
            with self.assertRaisesRegex(harness.HarnessError, "retained"):
                read()
            retained.write_bytes(b"rust std passed\n")
            receipt["products"]["native-shadow"]["static"]["root"] = container(dynamic)
            with self.assertRaisesRegex(harness.HarnessError, "static product"):
                read()
            receipt["products"]["native-shadow"]["static"]["root"] = container(static)
            state.write_text(json.dumps({"allocator_backend": "native-shadow", "source_sha256": "c" * 64}))
            with self.assertRaisesRegex(harness.HarnessError, "dynamic product source"):
                read()


if __name__ == "__main__":
    unittest.main()
