"""Focused semantic-proof tests for the M8 direct-fenv verifier."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_m8_fenv", ROOT / "compat" / "crabc-rs" / "verify_m8_fenv.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def direct_fpcr_fpsr_access() -> str:
    return "\n".join(
        (
            "mrs w0, fpcr",
            "mrs x1, fpsr",
            "msr fpcr, w2",
            "msr fpsr, x3",
        )
    )


class VerifyM8FenvTests(unittest.TestCase):
    def test_accepts_aarch64_direct_fpcr_fpsr_access(self) -> None:
        report = VERIFY.inspect("Machine: AArch64", direct_fpcr_fpsr_access())
        self.assertEqual(report["machine"], "AArch64")
        self.assertTrue(report["direct_fpcr_fpsr"])
        self.assertEqual(report["forbidden_public_symbols"], [])

    def test_rejects_non_aarch64_or_incomplete_direct_access(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "AArch64"):
            VERIFY.inspect("Machine: x86-64", direct_fpcr_fpsr_access())
        with self.assertRaisesRegex(VERIFY.VerificationError, "write_fpsr"):
            VERIFY.inspect("Machine: AArch64", direct_fpcr_fpsr_access().splitlines()[0])

    def test_rejects_public_c_errno_and_allocator_symbols(self) -> None:
        for symbol in ("feclearexcept", "__errno_location", "malloc", "free"):
            with self.subTest(symbol=symbol):
                with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden"):
                    VERIFY.inspect(
                        "Machine: AArch64",
                        direct_fpcr_fpsr_access(),
                        f"                 U {symbol}\n",
                    )


if __name__ == "__main__":
    unittest.main()
