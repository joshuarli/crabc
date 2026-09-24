#!/usr/bin/env python3
"""Behavior tests for the call-closure reader over parsed disassembly."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "elf_call_closure.py"
SPEC = importlib.util.spec_from_file_location("elf_call_closure", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
closure_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = closure_module
SPEC.loader.exec_module(closure_module)


def closure(text: str, *roots: str, aliases=None, exclude=(), follow_addresses=False):
    candidate = closure_module.Candidate(closure_module.parse_disassembly(text), aliases or {})
    return closure_module.closure_of(candidate, list(roots), exclude, follow_addresses)


def failures(text: str, root: str, **assertions):
    return closure_module.check(closure(text, root), **assertions)


# An outlined raw leaf: each wrapper loads its syscall number into the first C
# argument register and transfers to the shared leaf, which moves it to rax.
OUTLINED = """
0000000000401000 <getpid>:
  401000:	mov    $0x27,%edi
  401005:	jmp    401100 <c::raw_syscall::syscall0>

0000000000401010 <umask>:
  401010:	mov    %edi,%esi
  401012:	mov    $0x5f,%edi
  401017:	jmp    401120 <c::raw_syscall::syscall1>

0000000000401100 <c::raw_syscall::syscall0>:
  401100:	mov    %rdi,%rax
  401103:	syscall
  401105:	ret

0000000000401120 <c::raw_syscall::syscall1>:
  401120:	mov    %rdi,%rax
  401123:	mov    %rsi,%rdi
  401126:	syscall
  401128:	ret
"""

# The same umask with the leaf inlined.
INLINED = """
0000000000401010 <umask>:
  401010:	mov    $0x5f,%eax
  401015:	syscall
  401017:	ret
"""

BRANCHES = """
0000000000402000 <fcntl>:
  402000:	cmp    $0x1,%esi
  402003:	je     402010 <fcntl+0x10>
  402005:	mov    %rdx,%rdx
  402008:	jmp    402015 <fcntl+0x15>
  402010:	xor    %edx,%edx
  402015:	mov    $0x48,%eax
  40201a:	syscall
  40201c:	ret
"""

MASKED = """
0000000000403000 <pthread_mutex_lock>:
  403000:	mov    (%rdi),%esi
  403002:	not    %esi
  403004:	and    $0x80,%esi
  40300a:	mov    $0xca,%eax
  40300f:	xor    %r10d,%r10d
  403012:	syscall
  403014:	lock cmpxchg %edx,(%rdi)
  403018:	mov    %eax,%fs:0xfffffffffffffffc
  403020:	ret
"""

PROGRAM = """
0000000000404000 <_start>:
  404000:	mov    $0x404020,%edi
  404005:	call   404030 <<c::Plan>::run>
  40400a:	lea    0x10(%rip),%rsi        # 404040 <worker>
  404011:	call   404050 <exit>
  404016:	ret

0000000000404030 <<c::Plan>::run>:
  404030:	ret

0000000000404040 <worker>:
  404040:	call   404060 <pthread_mutex_init>
  404045:	ret

0000000000404050 <exit>:
  404050:	mov    $0xe7,%eax
  404055:	syscall

0000000000404060 <pthread_mutex_init>:
  404060:	ret
"""


class SyscallResolutionTests(unittest.TestCase):
    def test_outlined_leaf_resolves_number_and_root_argument_through_caller(self) -> None:
        events = closure(OUTLINED, "umask").syscalls
        self.assertEqual(len(events), 1)
        self.assertEqual(str(events[0].value("rax")), "0x5f")
        self.assertEqual(str(events[0].value("rdi")), "arg:rdi")

    def test_inlined_and_outlined_codegen_satisfy_the_same_assertion(self) -> None:
        for text in (OUTLINED, INLINED):
            self.assertEqual(failures(text, "umask", syscalls=["nr=0x5f,a1=arg:rdi"],
                                      syscalls_only=["0x5f"]), [])

    def test_leaf_reached_from_another_wrapper_does_not_leak_its_number(self) -> None:
        # getpid's number reaches only through getpid's own call site.
        self.assertEqual(failures(OUTLINED, "umask", syscalls_only=["0x5f"]), [])
        self.assertTrue(failures(OUTLINED, "getpid", syscalls=["nr=0x5f"]))

    def test_branch_merge_yields_each_reaching_definition(self) -> None:
        self.assertEqual(failures(BRANCHES, "fcntl", syscalls=["nr=72,a3=0", "nr=72,a3=arg:rdx"],
                                  every_syscall=["nr=72,a2=arg:rsi"]), [])

    def test_masked_operand_enumerates_its_possible_bits(self) -> None:
        self.assertEqual(failures(MASKED, "pthread_mutex_lock", syscalls=["nr=202,a2=0x80,a4=0"],
                                  every_syscall=["a2=0|0x80"]), [])

    def test_unknown_values_never_satisfy_a_required_constant(self) -> None:
        self.assertTrue(failures(MASKED, "pthread_mutex_lock", syscalls=["nr=202,a1=0"]))

    def test_bit_test_and_set_is_a_register_write(self) -> None:
        text = INLINED.replace("  401015:\tsyscall", "  401013:\tbts    %ecx,%eax\n  401015:\tsyscall")
        self.assertTrue(failures(text, "umask", syscalls=["nr=0x5f"]))

    def test_partial_register_write_knows_only_its_width(self) -> None:
        text = INLINED.replace("mov    $0x5f,%eax", "mov    $0x38,%al")
        event = closure(text, "umask").syscalls[0]
        self.assertTrue(event.value("rax").matches("0x38"))
        self.assertTrue(event.value("rax").matches("0x1238"))

    def test_unknown_syscall_number_fails_an_allow_list(self) -> None:
        text = INLINED.replace("mov    $0x5f,%eax", "mov    (%rdi),%eax")
        self.assertTrue(failures(text, "umask", syscalls_only=["0x5f"]))


class ClosureTests(unittest.TestCase):
    def test_instruction_checks_cover_the_closure(self) -> None:
        self.assertEqual(failures(MASKED, "pthread_mutex_lock", instructions=["^lock cmpxchg"]), [])
        found = failures(MASKED, "pthread_mutex_lock", no_instructions=[",%fs:"])
        self.assertEqual(len(found), 1)
        self.assertIn("403018", found[0])

    def test_bracketed_demangled_targets_are_followed(self) -> None:
        self.assertIn("<c::Plan>::run", closure(PROGRAM, "_start").names)

    def test_address_taken_functions_join_only_when_requested(self) -> None:
        self.assertNotIn("pthread_mutex_init", closure(PROGRAM, "_start").names)
        followed = closure(PROGRAM, "_start", follow_addresses=True)
        self.assertIn("pthread_mutex_init", followed.names)
        self.assertTrue(closure_module.check(followed, not_reaches=["pthread_mutex_init"]))

    def test_excluded_boundary_is_not_entered(self) -> None:
        self.assertEqual(closure_module.check(closure(PROGRAM, "_start"), syscalls=["nr=231"]), [])
        excluded = closure(PROGRAM, "_start", exclude=["exit"])
        self.assertEqual(excluded.syscalls, [])

    def test_roots_and_reach_checks_accept_any_alias(self) -> None:
        aliases = {0x401010: {"umask", "__umask"}}
        found = closure(OUTLINED, "__umask", aliases=aliases)
        self.assertIn("umask", found.names)
        with self.assertRaises(closure_module.ClosureError):
            closure(OUTLINED, "missing")


if __name__ == "__main__":
    unittest.main()
