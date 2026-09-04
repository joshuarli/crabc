#!/usr/bin/env python3
"""Regression tests for the AArch64 TLS witness evidence boundary."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "compat/allocator/tls-codegen/run.py"
SPEC = importlib.util.spec_from_file_location("crabc_tls_codegen_aarch64", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class Aarch64TlsWitnessEvidenceTests(unittest.TestCase):
    def test_probe_command_is_locked_and_offline(self) -> None:
        command = RUNNER.cargo_probe_command("cargo")

        self.assertEqual(
            command,
            [
                "cargo",
                "rustc",
                "--locked",
                "--offline",
                "-p",
                "crabc-mimalloc",
                "--lib",
                "--features",
                "tls-codegen-probe",
                "--message-format=json-render-diagnostics",
                "--",
            ],
        )


if __name__ == "__main__":
    unittest.main()
