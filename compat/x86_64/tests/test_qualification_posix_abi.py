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


if __name__ == "__main__":
    unittest.main()
