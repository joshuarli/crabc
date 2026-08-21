"""Focused parser tests for the M7 direct-resolver verifier."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_m7_resolver", ROOT / "compat" / "crabc-rs" / "verify_m7_resolver.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def disassembly(numbers: tuple[int, ...], symbols: tuple[str, ...] = ()) -> str:
    instructions = "\n".join(f"mov w8, #{number:#x}\nsvc #0" for number in numbers)
    labels = "\n".join(f"<{symbol}>:" for symbol in symbols)
    return instructions + "\n" + labels


class VerifyM7ResolverTests(unittest.TestCase):
    def test_accepts_every_required_direct_syscall(self) -> None:
        report = VERIFY.inspect("Machine: AArch64", disassembly(tuple(VERIFY.REQUIRED_SYSCALLS)))
        self.assertEqual(report["direct_syscalls"], list(VERIFY.REQUIRED_SYSCALLS.values()))

    def test_rejects_public_resolver_and_missing_syscall(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden"):
            VERIFY.inspect(
                "Machine: AArch64",
                disassembly(tuple(VERIFY.REQUIRED_SYSCALLS), ("getaddrinfo",)),
            )
        with self.assertRaisesRegex(VERIFY.VerificationError, "recvfrom"):
            VERIFY.inspect("Machine: AArch64", disassembly(tuple(VERIFY.REQUIRED_SYSCALLS)[:-1]))


if __name__ == "__main__":
    unittest.main()
