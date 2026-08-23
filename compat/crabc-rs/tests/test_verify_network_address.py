"""Focused semantic-proof tests for the network-byte-order verifier."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_network_address", ROOT / "compat" / "crabc-rs" / "verify_network_address.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class Verify0NetworkAddressTests(unittest.TestCase):
    def test_accepts_native_entrypoint_without_c_symbols(self) -> None:
        for probe in VERIFY.PROBES.values():
            with self.subTest(entrypoint=probe.entrypoint):
                report = VERIFY.inspect(
                    probe, "Machine: AArch64", "", f"0000000000000000 T {probe.entrypoint}\n"
                )
                self.assertTrue(report["direct_native"])

    def test_rejects_wrong_architecture_or_missing_entrypoint(self) -> None:
        probe = VERIFY.PROBES["network-address"]
        with self.assertRaisesRegex(VERIFY.VerificationError, "AArch64"):
            VERIFY.inspect(probe, "Machine: x86-64", "", probe.entrypoint)
        with self.assertRaisesRegex(VERIFY.VerificationError, "entry point"):
            VERIFY.inspect(probe, "Machine: AArch64", "", "")

    def test_rejects_c_network_and_errno_symbols(self) -> None:
        for probe in VERIFY.PROBES.values():
            for symbol in VERIFY.FORBIDDEN_SYMBOLS:
                with self.subTest(entrypoint=probe.entrypoint, symbol=symbol):
                    with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden"):
                        VERIFY.inspect(
                            probe,
                            "Machine: AArch64",
                            f"                 U {symbol}\n",
                            f"0000000000000000 T {probe.entrypoint}\n",
                        )


if __name__ == "__main__":
    unittest.main()
