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
from unittest.mock import Mock, patch


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
        self.assertEqual(report["execution"], qualification.EXECUTION_CONTRACT)
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

    def test_runner_requires_pinned_container_inputs_and_passes_contained_tmpdir(self) -> None:
        with patch.dict(
            runner.os.environ,
            {
                "CRABC_WORK_DIR": qualification.EXECUTION_CONTRACT["work_directory"],
                "TMPDIR": qualification.EXECUTION_CONTRACT["temporary_directory"],
            },
            clear=True,
        ), patch.object(runner.Path, "is_dir", return_value=True), patch.object(
            runner.Path, "is_file", return_value=True
        ):
            runner.require_pinned_native_execution()

        environment = runner.controlled_environment()
        self.assertEqual(
            environment["CRABC_WORK_DIR"],
            qualification.EXECUTION_CONTRACT["work_directory"],
        )
        self.assertEqual(
            environment["TMPDIR"],
            qualification.EXECUTION_CONTRACT["temporary_directory"],
        )

        with patch.dict(runner.os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                runner.QualificationRunError, "pinned work directory"
            ):
                runner.require_pinned_native_execution()

    def test_runner_rejects_a_symlinked_temporary_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            external = work / "other"
            external.mkdir()
            temporary = work / "tmp"
            temporary.symlink_to(external, target_is_directory=True)
            with patch.dict(qualification.EXECUTION_CONTRACT, {
                "work_directory": str(work),
                "temporary_directory": str(temporary),
            }), patch.dict(runner.os.environ, {
                "CRABC_WORK_DIR": str(work), "TMPDIR": str(temporary),
            }, clear=True), patch.object(runner.Path, "is_file", return_value=True):
                with self.assertRaisesRegex(runner.QualificationRunError, "physical"):
                    runner.require_pinned_native_execution()

    def test_real_repository_case_receives_the_dispatcher_temporary_directory(self) -> None:
        runner_path = ROOT / "compat/x86_64/run_libc_resolver_runtime.sh"
        case = {
            "id": "static-resolver-runtime",
            "command": ["bash", "compat/x86_64/run_libc_resolver_runtime.sh"],
            "runner_sha256": hashlib.sha256(runner_path.read_bytes()).hexdigest(),
            "expected_stdout_line": "x86 static crabc-libc resolver runtime: PASS",
            "timeout_seconds": 1,
        }
        process = Mock()
        process.communicate.return_value = (
            b"x86 static crabc-libc resolver runtime: PASS\n",
            b"",
        )
        process.returncode = 0
        with patch.object(runner.subprocess, "Popen", return_value=process) as popen:
            runner.run_case({"id": "compat.resolver-network"}, case)
        self.assertEqual(
            popen.call_args.kwargs["env"]["TMPDIR"],
            qualification.EXECUTION_CONTRACT["temporary_directory"],
        )
        self.assertEqual(
            popen.call_args.args[0],
            ["bash", "compat/x86_64/run_libc_resolver_runtime.sh"],
        )

    def test_execution_boundary_drift_is_rejected(self) -> None:
        document = self.document()
        execution = document["execution"]
        assert isinstance(execution, dict)
        execution["temporary_directory"] = "/tmp"
        with self.assertRaisesRegex(
            qualification.QualificationManifestError, "execution boundary drifted"
        ):
            qualification.validate_contract(document)

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

    def test_ready_gate_requires_matching_case_hash(self) -> None:
        document = self.document()
        chain = document["promotion_chain"]
        assert isinstance(chain, list)
        gate = chain[0]
        assert isinstance(gate, dict)
        gate["state"] = "ready"
        gate["case_manifest"] = {"path": "compat/x86_64/qualification_posix_abi.json", "sha256": "0" * 64}
        with self.assertRaisesRegex(qualification.QualificationManifestError, "case manifest hash"):
            qualification.validate_contract(document)

    def test_ready_chain_binds_cases_without_claiming_execution(self) -> None:
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
                gate["state"] = "ready"
                case_relative = f"compat/x86_64/cases/{index}.json"
                case_path = root / case_relative
                case_path.parent.mkdir(parents=True, exist_ok=True)
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
                gate["case_manifest"] = {"path": case_relative, "sha256": case_hash}
            with patch.object(qualification, "ROOT", root), patch.object(
                qualification, "CONTRACT_PATH", contract_path
            ):
                report = qualification.validate_contract(document)
                self.assertFalse(report["promotion_ready"])
                self.assertEqual(report["completed_gate_count"], 0)
                self.assertEqual(report["ready_gate_count"], len(qualification.CHAIN))
                self.assertEqual(report["runnable_prefix"], list(qualification.CHAIN))

                first_case = root / chain[0]["case_manifest"]["path"]
                case = json.loads(first_case.read_text(encoding="utf-8"))
                case["target"] = {**qualification.TARGET, "machine": "aarch64"}
                first_case.write_text(json.dumps(case), encoding="utf-8")
                chain[0]["case_manifest"]["sha256"] = hashlib.sha256(first_case.read_bytes()).hexdigest()
                with self.assertRaisesRegex(qualification.QualificationManifestError, "case manifest target"):
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
