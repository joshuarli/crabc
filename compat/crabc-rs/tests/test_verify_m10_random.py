"""Focused semantic-proof tests for the M10 random-state verifier."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_m10_random", ROOT / "compat" / "crabc-rs" / "verify_m10_random.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class VerifyM10RandomTests(unittest.TestCase):
    def test_accepts_direct_aarch64_entropy_without_c_symbols(self) -> None:
        report = VERIFY.inspect(
            "Machine: AArch64",
            "mov w8, #0x116\nsvc #0\n",
            "0000000000000000 T crabc_rs_m10_random_direct_probe\n",
        )
        self.assertTrue(report["direct_svc"])
        self.assertEqual(report["direct_syscalls"], ["getrandom"])

    def test_rejects_missing_architecture_entrypoint_or_syscall(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "AArch64"):
            VERIFY.inspect("Machine: x86-64", "mov w8, #0x116\nsvc #0", "entry")
        with self.assertRaisesRegex(VERIFY.VerificationError, "entry point"):
            VERIFY.inspect("Machine: AArch64", "mov w8, #0x116\nsvc #0", "")
        with self.assertRaisesRegex(VERIFY.VerificationError, "getrandom syscall"):
            VERIFY.inspect("Machine: AArch64", "svc #0", "entry crabc_rs_m10_random_direct_probe")

    def test_rejects_c_random_and_errno_symbols(self) -> None:
        for symbol in VERIFY.FORBIDDEN_PUBLIC_SYMBOLS:
            with self.subTest(symbol=symbol):
                with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden"):
                    VERIFY.inspect(
                        "Machine: AArch64",
                        f"mov w8, #0x116\nsvc #0\nbl <{symbol}>\n",
                        "entry crabc_rs_m10_random_direct_probe",
                    )


if __name__ == "__main__":
    unittest.main()
