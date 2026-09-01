#!/usr/bin/env python3
"""Focused fail-closed contracts for the x86 qualification manifest surface."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
GENERATOR_PATH = ROOT / "compat" / "x86_64" / "generate_qualification_manifest.py"
RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_qualification_manifest.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


qualification = load_module("generate_qualification_manifest", GENERATOR_PATH)
runner = load_module("qualification_manifest_runner", RUNNER_PATH)


class QualificationManifestTests(unittest.TestCase):
    def document(self) -> dict[str, object]:
        return json.loads(qualification.CONTRACT_PATH.read_text(encoding="utf-8"))

    def test_checked_in_contract_has_the_exact_planned_chain_and_private_admission(self) -> None:
        report = qualification.load_contract()
        self.assertEqual(
            tuple(row["id"] for row in report["promotion_chain"]),
            qualification.CHAIN,
        )
        self.assertEqual(report["incomplete_gates"], list(qualification.CHAIN))
        self.assertFalse(report["promotion_ready"])
        self.assertEqual(report["private_admission"], [
            {
                "id": "posix-abi-admission",
                "case_manifest": "compat/x86_64/qualification_posix_abi.json",
                "case_manifest_sha256": qualification.PRIVATE_ADMISSION[0][2],
                "command": ["python3", "compat/x86_64/run_qualification_posix_abi.py"],
                "non_promoting": True,
            }
        ])

    def test_private_admission_never_becomes_promotion_evidence(self) -> None:
        document = self.document()
        admission = document["private_admission"]
        assert isinstance(admission, list)
        admission[0]["non_promoting"] = False
        with self.assertRaisesRegex(
            qualification.QualificationManifestError, "explicitly non-promoting"
        ):
            qualification.validate_contract(document)

        document = self.document()
        chain = document["promotion_chain"]
        assert isinstance(chain, list)
        chain[0]["id"] = "posix-abi-admission"
        with self.assertRaisesRegex(
            qualification.QualificationManifestError, "chain order drifted"
        ):
            qualification.validate_contract(document)

    def test_order_target_oracle_purity_isolation_and_timeout_drift_fail_closed(self) -> None:
        mutations = (
            ("order", lambda row: row.__setitem__("id", "compat.posix-process"), "chain order drifted"),
            ("oracle", lambda row: row.__setitem__("oracle", "ambient-glibc"), "contract drifted"),
            ("purity", lambda row: row.__setitem__("purity", "allow-ambient-target-libc"), "contract drifted"),
            ("isolation", lambda row: row.__setitem__("isolation", "host"), "contract drifted"),
            ("timeout", lambda row: row.__setitem__("timeout_seconds", 0), "positive integer"),
        )
        for name, mutate, message in mutations:
            with self.subTest(name=name):
                document = self.document()
                chain = document["promotion_chain"]
                assert isinstance(chain, list)
                mutate(chain[0])
                with self.assertRaisesRegex(qualification.QualificationManifestError, message):
                    qualification.validate_contract(document)

    def test_completed_gate_requires_matching_case_and_receipt_hashes(self) -> None:
        document = self.document()
        chain = document["promotion_chain"]
        assert isinstance(chain, list)
        gate = chain[0]
        assert isinstance(gate, dict)
        gate["state"] = "complete"
        gate["case_manifest"] = {"path": "compat/x86_64/qualification_posix_abi.json", "sha256": "0" * 64}
        gate["receipt"] = {"path": "compat/x86_64/qualification_posix_abi.json", "sha256": "0" * 64}
        with self.assertRaisesRegex(qualification.QualificationManifestError, "case manifest hash"):
            qualification.validate_contract(document)

    def test_completed_chain_binds_native_case_and_receipt_provenance(self) -> None:
        document = self.document()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_manifest = root / "compat/x86_64/qualification_posix_abi.json"
            private_runner = root / "compat/x86_64/run_qualification_posix_abi.py"
            private_manifest.parent.mkdir(parents=True)
            private_manifest.write_bytes(qualification.CONTRACT_PATH.parent.joinpath("qualification_posix_abi.json").read_bytes())
            private_runner.write_text("raise SystemExit(0)\n", encoding="utf-8")
            case_runner = root / "runner.py"
            case_runner.write_text("raise SystemExit(0)\n", encoding="utf-8")
            contract_path = root / "compat/x86_64/qualification_manifest.json"
            contract_path.write_text(json.dumps(document), encoding="utf-8")
            chain = document["promotion_chain"]
            assert isinstance(chain, list)
            for index, gate in enumerate(chain):
                assert isinstance(gate, dict)
                gate["state"] = "complete"
                case_relative = f"compat/x86_64/cases/{index}.json"
                receipt_relative = f"compat/x86_64/receipts/{index}.json"
                case_path = root / case_relative
                receipt_path = root / receipt_relative
                case_path.parent.mkdir(parents=True, exist_ok=True)
                receipt_path.parent.mkdir(parents=True, exist_ok=True)
                case = {
                    "schema": qualification.CASE_SCHEMA,
                    "gate": gate["id"],
                    "target": qualification.TARGET,
                    "oracle": gate["oracle"],
                    "provenance": gate["provenance"],
                    "purity": gate["purity"],
                    "isolation": gate["isolation"],
                    "cases": [{
                        "id": "owned-case",
                        "command": ["python3", "runner.py"],
                        "runner_sha256": hashlib.sha256(case_runner.read_bytes()).hexdigest(),
                        "expected_stdout_line": "owned case: PASS",
                        "timeout_seconds": gate["timeout_seconds"],
                    }],
                }
                case_path.write_text(json.dumps(case), encoding="utf-8")
                case_hash = hashlib.sha256(case_path.read_bytes()).hexdigest()
                receipt = {
                    "schema": qualification.RECEIPT_SCHEMA,
                    "gate": gate["id"],
                    "target": qualification.TARGET,
                    "case_manifest_sha256": case_hash,
                    "case_count": 1,
                    "outcome": "passed",
                    "oracle": gate["oracle"],
                    "provenance": gate["provenance"],
                    "purity": gate["purity"],
                    "isolation": gate["isolation"],
                }
                receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                gate["case_manifest"] = {"path": case_relative, "sha256": case_hash}
                gate["receipt"] = {
                    "path": receipt_relative,
                    "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                }
            with patch.object(qualification, "ROOT", root), patch.object(
                qualification, "CONTRACT_PATH", contract_path
            ):
                report = qualification.validate_contract(document)
                self.assertTrue(report["promotion_ready"])
                self.assertEqual(report["completed_gate_count"], len(qualification.CHAIN))

                first_receipt = root / chain[0]["receipt"]["path"]
                receipt = json.loads(first_receipt.read_text(encoding="utf-8"))
                receipt["target"] = {**qualification.TARGET, "machine": "aarch64"}
                first_receipt.write_text(json.dumps(receipt), encoding="utf-8")
                chain[0]["receipt"]["sha256"] = hashlib.sha256(first_receipt.read_bytes()).hexdigest()
                with self.assertRaisesRegex(qualification.QualificationManifestError, "receipt target"):
                    qualification.validate_contract(document)

    def test_runner_rechecks_pinned_case_runner_bytes_before_popen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case_runner = root / "runner.py"
            case_runner.write_text("print('owned case: PASS')\n", encoding="utf-8")
            pinned_hash = hashlib.sha256(case_runner.read_bytes()).hexdigest()
            case_runner.write_text("print('forged case: PASS')\n", encoding="utf-8")
            case = {
                "id": "owned-case",
                "command": ["python3", "runner.py"],
                "runner_sha256": pinned_hash,
                "expected_stdout_line": "owned case: PASS",
                "timeout_seconds": 1,
            }
            with patch.object(qualification, "ROOT", root), patch.object(
                runner, "ROOT", root
            ), patch.object(runner.subprocess, "Popen") as popen:
                popen.side_effect = AssertionError("runner bytes must be checked before Popen")
                with self.assertRaisesRegex(runner.QualificationRunError, "runner bytes changed"):
                    runner.run_case({"id": "compat.abi-differential"}, case)
                popen.assert_not_called()

    def test_generated_manifest_is_deterministic_and_checkable(self) -> None:
        report = qualification.load_contract()
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory) / "qualification.json"
            qualification.write_or_check(generated, report, check=False)
            qualification.write_or_check(generated, report, check=True)
            generated.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(qualification.QualificationManifestError, "stale"):
                qualification.write_or_check(generated, report, check=True)

    def test_runner_refuses_planned_chain_without_starting_any_child(self) -> None:
        with patch.object(runner, "require_native_linux_x86_64") as native, patch.object(
            runner, "run_case"
        ) as run_case, patch("sys.stderr"):
            self.assertEqual(runner.main([]), 1)
        native.assert_not_called()
        run_case.assert_not_called()

    def test_runner_refuses_a_stale_generated_projection(self) -> None:
        report = qualification.load_contract()
        with patch.object(qualification, "write_or_check") as check:
            check.side_effect = qualification.QualificationManifestError("generated qualification manifest is stale")
            with self.assertRaisesRegex(qualification.QualificationManifestError, "stale"):
                runner.main(["--check-contract"])
        check.assert_called_once_with(qualification.GENERATED_PATH, report, check=True)

    def test_controlled_environment_strips_ambient_toolchain_and_runtime_overrides(self) -> None:
        overrides = {
            "CC": "poison",
            "LD_PRELOAD": "poison",
            "RUSTFLAGS": "poison",
            "MUSL_ROOT": "poison",
            "PATH": "poison",
            "PYTHONPATH": "poison",
            "PYTHONHOME": "poison",
            "BASH_ENV": "poison",
            "ENV": "poison",
        }
        with patch.dict(runner.os.environ, overrides, clear=False):
            environment = runner.controlled_environment()
        for name in overrides:
            if name != "PATH":
                self.assertNotIn(name, environment)
        self.assertNotEqual(environment["PATH"], "poison")
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["TZ"], "UTC")


if __name__ == "__main__":
    unittest.main()
