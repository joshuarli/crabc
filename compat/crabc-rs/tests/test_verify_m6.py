"""Focused parser tests for the M6 direct-boundary verifier."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("verify_m6", ROOT / "compat" / "crabc-rs" / "verify_m6.py")
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def disassembly(syscalls: tuple[int, ...], symbols: tuple[str, ...] = ()) -> str:
    instructions = "\n".join(f"mov w8, #{number:#x}\nsvc #0" for number in syscalls)
    labels = "\n".join(f"<{symbol}>:" for symbol in symbols)
    return instructions + "\n" + labels


class VerifyM6Tests(unittest.TestCase):
    def test_accepts_every_required_direct_syscall(self) -> None:
        report = VERIFY.inspect("Machine: AArch64", disassembly(tuple(VERIFY.REQUIRED_SYSCALLS)))
        self.assertEqual(report["machine"], "AArch64")
        self.assertEqual(report["forbidden_public_symbols"], [])

    def test_rejects_public_c_abi_symbols(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden"):
            VERIFY.inspect(
                "Machine: AArch64",
                disassembly(tuple(VERIFY.REQUIRED_SYSCALLS), ("sigaction",)),
            )

    def test_rejects_missing_direct_syscalls(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "wait4"):
            VERIFY.inspect("Machine: AArch64", disassembly(tuple(VERIFY.REQUIRED_SYSCALLS)[:-1]))


if __name__ == "__main__":
    unittest.main()
