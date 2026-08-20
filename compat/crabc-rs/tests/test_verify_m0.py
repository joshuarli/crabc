from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/crabc-rs/verify_m0.py"
SPEC = importlib.util.spec_from_file_location("verify_m0", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


class InspectionTests(unittest.TestCase):
    def test_accepts_direct_aarch64_fixture_without_public_libc_symbols(self) -> None:
        report = checker.inspect("Machine: AArch64\n", "  0: svc #0\n")
        self.assertTrue(report["direct_svc"])
        self.assertEqual(report["forbidden_public_symbols"], [])

    def test_rejects_errno_accessor_or_public_openat(self) -> None:
        with self.assertRaises(checker.VerificationError):
            checker.inspect("Machine: AArch64\n", "  0: bl <__errno_location>\n")
        with self.assertRaises(checker.VerificationError):
            checker.inspect("Machine: AArch64\n", "  0: bl <openat>\n")

    def test_rejects_non_aarch64_or_missing_svc(self) -> None:
        with self.assertRaises(checker.VerificationError):
            checker.inspect("Machine: Advanced Micro Devices X86-64\n", "  0: svc #0\n")
        with self.assertRaises(checker.VerificationError):
            checker.inspect("Machine: AArch64\n", "  0: ret\n")


if __name__ == "__main__":
    unittest.main()
