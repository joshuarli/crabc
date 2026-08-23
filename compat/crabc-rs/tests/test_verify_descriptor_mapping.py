from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/crabc-rs/verify_descriptor_mapping.py"
SPEC = importlib.util.spec_from_file_location("verify_descriptor_mapping", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


def direct_syscalls() -> str:
    return "\n".join(
        f"  {index * 8:02x}: mov w8, #{number:#x}\n  {index * 8 + 4:02x}: svc #0"
        for index, number in enumerate(checker.REQUIRED_SYSCALLS)
    )


class InspectionTests(unittest.TestCase):
    def test_accepts_required_descriptor_direct_aarch64_syscalls(self) -> None:
        report = checker.inspect("Machine: AArch64\n", direct_syscalls())
        self.assertTrue(report["direct_svc"])
        self.assertEqual(report["direct_syscalls"], list(checker.REQUIRED_SYSCALLS.values()))

    def test_rejects_public_abi_or_missing_descriptor_syscall(self) -> None:
        with self.assertRaises(checker.VerificationError):
            checker.inspect("Machine: AArch64\n", direct_syscalls() + "\n  80: bl <fsync>")
        with self.assertRaises(checker.VerificationError):
            checker.inspect("Machine: AArch64\n", "  0: mov w8, #0x52\n  4: svc #0\n")
