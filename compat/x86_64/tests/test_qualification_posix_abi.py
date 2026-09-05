#!/usr/bin/env python3
"""Contract tests for the private x86 POSIX/ABI admission gate."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_qualification_posix_abi.py"
SPEC = importlib.util.spec_from_file_location("qualification_posix_abi", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
qualification = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = qualification
SPEC.loader.exec_module(qualification)


class QualificationPosixAbiTests(unittest.TestCase):
    def test_checked_in_inventory_is_exact_and_uses_real_selected_runners(self) -> None:
        cases = qualification.load_contract()
        self.assertEqual(
            tuple(case.identifier for case in cases),
            tuple(record[0] for record in qualification.EXPECTED_CASES),
        )
        self.assertEqual(
            {case.family for case in cases},
            {"compat.abi-differential", "compat.posix-process"},
        )
        for case in cases:
            self.assertTrue(case.runner.is_file())
            self.assertIn("run_libc_", case.runner.name)

    def test_roster_drift_is_rejected(self) -> None:
        document = json.loads(
            qualification.CONTRACT_PATH.read_text(encoding="utf-8")
        )
        document["cases"].pop()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(
                qualification.ContractError, "case roster or order drifted"
            ):
                qualification.load_contract(path)

    def test_success_requires_one_final_exact_child_marker(self) -> None:
        case = qualification.load_contract()[0]
        qualification.validate_completed_process(
            case,
            0,
            b"build output\n" + case.expected_stdout_line + b"\n",
            b"visible build diagnostics\n",
        )
        for stdout in (
            b"",
            case.expected_stdout_line + b"\ntrailing output\n",
            case.expected_stdout_line + b"\n" + case.expected_stdout_line + b"\n",
        ):
            with self.assertRaises(qualification.EvidenceError):
                qualification.validate_completed_process(case, 0, stdout, b"")
        with self.assertRaisesRegex(qualification.EvidenceError, "exited 3"):
            qualification.validate_completed_process(
                case, 3, case.expected_stdout_line + b"\n", b"failed\n"
            )

    def test_controlled_environment_scrubs_compiler_and_runtime_overrides(self) -> None:
        overrides = {
            name: f"poison-{name}"
            for name in (
                "CC",
                "CFLAGS",
                "LDFLAGS",
                "LD_LIBRARY_PATH",
                "LD_PRELOAD",
                "CPATH",
                "C_INCLUDE_PATH",
                "GCC_EXEC_PREFIX",
                "COMPILER_PATH",
                "CARGO_TARGET_DIR",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER",
                "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER",
                "RUSTFLAGS",
            )
        }
        with patch.dict(qualification.os.environ, overrides, clear=False):
            environment = qualification.controlled_environment()
        self.assertTrue(overrides.keys().isdisjoint(environment))
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["LANG"], "C")
        self.assertEqual(environment["TZ"], "UTC")

    def test_receipt_mode_has_fixed_rust_paths_and_per_case_artifact_directory(self) -> None:
        environment = qualification.controlled_environment()
        self.assertEqual(environment["RUSTUP_HOME"], "/opt/rustup")
        self.assertEqual(environment["CARGO_HOME"], "/workspace/.work/x86_64/cargo")
        self.assertEqual(environment["PATH"].split(":")[0], "/opt/cargo/bin")

        same_object = qualification.load_contract()[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = qualification.case_artifact_directory(same_object, root)
            self.assertEqual(artifact, root / "001-same-object-static-c-abi" / "artifacts")
            self.assertIsNone(
                qualification.case_artifact_directory(qualification.load_contract()[1], root)
            )

    def test_same_object_harness_uses_checkout_tmpdir_and_can_retain_artifacts(self) -> None:
        builder = (ROOT / "compat/x86_64/run_libc_same_object_static_c_abi_differential.sh").read_text(
            encoding="utf-8"
        )
        comparator = (ROOT / "compat/x86_64/run_same_object_static_c_abi_differential.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("mktemp -d /tmp", builder)
        self.assertNotIn("mktemp -d /tmp", comparator)
        self.assertIn("CRABC_QUALIFICATION_ARTIFACT_DIR", builder)
        self.assertIn("--artifact-directory", comparator)

    def test_receipted_case_seals_its_command_logs_timing_and_source_identity(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp/qualification-receipt-case-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            case = qualification.load_contract()[1]
            process = unittest.mock.Mock()
            process.returncode = 0
            process.communicate.return_value = (case.expected_stdout_line + b"\n", b"child diagnostics\n")
            identity = {"revision": "a" * 40, "content_sha256": "b" * 64}
            with patch.object(qualification, "source_identity", return_value=identity), patch.object(
                qualification.subprocess, "Popen", return_value=process
            ):
                receipt = qualification.run_case(case, root, 2)
            assert receipt is not None
            record = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(record["command"], ["bash", str(case.runner)])
            self.assertEqual(record["source_before"], identity)
            self.assertEqual(record["source_after"], identity)
            self.assertEqual(record["outcome"], "passed")
            self.assertEqual(record["exit_status"], 0)
            self.assertEqual(record["artifacts"], None)
            self.assertEqual((root / record["stdout"]["path"]).read_bytes(), case.expected_stdout_line + b"\n")
            self.assertEqual((root / record["stderr"]["path"]).read_bytes(), b"child diagnostics\n")
            self.assertGreaterEqual(record["duration_ns"], 0)


if __name__ == "__main__":
    unittest.main()
