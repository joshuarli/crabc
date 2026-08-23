"""Focused semantic-proof tests for the stateful-text verifier."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_stateful_text",
    ROOT / "compat" / "crabc-rs" / "verify_stateful_text.py",
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class Verify0TextStatefulTests(unittest.TestCase):
    def test_accepts_aarch64_native_entrypoint_without_forbidden_symbols(self) -> None:
        report = VERIFY.inspect(
            "Machine: AArch64",
            "",
            "0000000000000000 T crabc_rs_text_stateful_direct_probe\n",
        )
        self.assertEqual(report["machine"], "AArch64")
        self.assertTrue(report["direct_native"])
        self.assertEqual(report["forbidden_symbols"], [])

    def test_rejects_non_aarch64_or_missing_native_entrypoint(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "AArch64"):
            VERIFY.inspect(
                "Machine: x86-64",
                "",
                "0000000000000000 T crabc_rs_text_stateful_direct_probe\n",
            )
        with self.assertRaisesRegex(VERIFY.VerificationError, "entry point"):
            VERIFY.inspect("Machine: AArch64", "", "")

    def test_rejects_text_allocator_and_errno_symbols(self) -> None:
        for symbol in VERIFY.FORBIDDEN_SYMBOLS:
            with self.subTest(symbol=symbol):
                with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden"):
                    VERIFY.inspect(
                        "Machine: AArch64",
                        f"                 U {symbol}\n",
                        "0000000000000000 T crabc_rs_text_stateful_direct_probe\n",
                    )


if __name__ == "__main__":
    unittest.main()
