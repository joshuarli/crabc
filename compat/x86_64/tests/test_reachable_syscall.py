#!/usr/bin/env python3
"""Regression tests for exact emitted Linux syscall reachability proofs."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "check_reachable_syscall.py"
SPEC = importlib.util.spec_from_file_location("reachable_syscall", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
reachable = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reachable
SPEC.loader.exec_module(reachable)


OUTLINED_GETPID = """
0000000000401650 <getpid>:
  401650: bf 27 00 00 00        mov    $0x27,%edi
  401655: e9 e6 15 00 00        jmp    402c40 <_RNvNtNtCs97oEZ5FN6y_1c19x86_64_static_c_abi11raw_syscall8syscall0B5_>
"""

SYSCALL0_HELPER = """
0000000000402c40 <_RNvNtNtCs97oEZ5FN6y_1c19x86_64_static_c_abi11raw_syscall8syscall0B5_>:
  402c40: 48 89 f8              mov    %rdi,%rax
  402c43: 0f 05                 syscall
  402c45: c3                    ret
"""


class ReachableSyscallTests(unittest.TestCase):
    def test_outlined_wrapper_proves_its_number_reaches_the_exact_helper(self) -> None:
        proof = reachable.prove_disassemblies(
            "getpid", "27", 0, OUTLINED_GETPID, SYSCALL0_HELPER
        )
        self.assertEqual(proof.path, "outlined")
        self.assertEqual(proof.helper, "_RNvNtNtCs97oEZ5FN6y_1c19x86_64_static_c_abi11raw_syscall8syscall0B5_")

    def test_helper_with_an_unrelated_argument_register_is_rejected(self) -> None:
        wrong_helper = SYSCALL0_HELPER.replace("%rdi,%rax", "%rsi,%rax")
        with self.assertRaisesRegex(reachable.SyscallProofError, "does not move rdi into rax"):
            reachable.prove_disassemblies("getpid", "27", 0, OUTLINED_GETPID, wrong_helper)

    def test_unrelated_syscall_marker_cannot_prove_a_direct_wrapper(self) -> None:
        direct_with_marker = """
0000000000401650 <getpid>:
  401650: b8 27 00 00 00        mov    $0x27,%eax
  401655: e8 00 00 00 00        call   40165a <unrelated>
  40165a: 0f 05                 syscall
  40165c: c3                    ret
"""
        with self.assertRaisesRegex(reachable.SyscallProofError, "direct syscall path"):
            reachable.prove_disassemblies("getpid", "27", 0, direct_with_marker, "")


if __name__ == "__main__":
    unittest.main()
