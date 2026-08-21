"""Focused parser tests for the M7 private-thread verifier."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_m7_runtime_thread",
    ROOT / "compat" / "crabc-rs" / "verify_m7_runtime_thread.py",
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class VerifyM7RuntimeThreadTests(unittest.TestCase):
    def test_accepts_only_the_private_runtime_getter(self) -> None:
        report = VERIFY.inspect("Machine: AArch64", "                 U __crabc_runtime_v1\n")
        self.assertEqual(report["private_runtime"], "__crabc_runtime_v1")
        self.assertEqual(report["forbidden_public_symbols"], [])

    def test_rejects_public_pthread_or_errno_symbols(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden"):
            VERIFY.inspect(
                "Machine: AArch64",
                "                 U __crabc_runtime_v1\n                 U pthread_create\n",
            )
        with self.assertRaisesRegex(VERIFY.VerificationError, "private"):
            VERIFY.inspect("Machine: AArch64", "                 U pthread_join\n")


if __name__ == "__main__":
    unittest.main()
