#!/usr/bin/env python3
"""Focused contract for the x86 machine/context public-header ABI slice."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BITS_USER = ROOT / "include" / "bits" / "user.h"
BITS_HWCAP = ROOT / "include" / "bits" / "hwcap.h"
BITS_PTRACE = ROOT / "include" / "bits" / "ptrace.h"
SYS_AUXV = ROOT / "include" / "sys" / "auxv.h"
SYS_PTRACE = ROOT / "include" / "sys" / "ptrace.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_machine_context_header_abi.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "machine_context_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "machine_context_header_abi_probe.cpp"


class MachineContextHeaderAbiTests(unittest.TestCase):
    def test_machine_headers_keep_x86_and_aarch64_namespaces_separate(self) -> None:
        bits_user = BITS_USER.read_text(encoding="utf-8")
        self.assertIn("#if defined(__x86_64__)", bits_user)
        self.assertIn("struct user_fpregs_struct", bits_user)
        self.assertIn("#define ELF_NGREG 27", bits_user)
        self.assertIn("struct user {", bits_user)
        x86_user, aarch64_user = bits_user.split("#elif defined(__aarch64__)", 1)
        self.assertNotIn("_CRABC_BITS_USER_H", x86_user)
        self.assertIn("#ifndef _CRABC_BITS_USER_H", aarch64_user)
        self.assertIn("#define _CRABC_BITS_USER_H", aarch64_user)
        self.assertIn("struct user_fpsimd_struct", aarch64_user)
        self.assertIn("#define ELF_NREG 34", aarch64_user)
        self.assertTrue(aarch64_user.rstrip().endswith("#endif\n#endif"))

        auxv = SYS_AUXV.read_text(encoding="utf-8")
        self.assertIn("#include <bits/hwcap.h>", auxv)
        self.assertNotIn("#define HWCAP_FP", auxv)

        hwcap = BITS_HWCAP.read_text(encoding="utf-8")
        self.assertIn(
            "#if defined(__aarch64__)\n#ifndef _CRABC_BITS_HWCAP_H",
            hwcap,
        )
        self.assertIn("#define HWCAP_FP", hwcap)
        self.assertIn("#define HWCAP2_MTE", hwcap)

        ptrace_bits = BITS_PTRACE.read_text(encoding="utf-8")
        self.assertIn("#if defined(__x86_64__)", ptrace_bits)
        for phrase in (
            "PTRACE_GET_THREAD_AREA 25",
            "PTRACE_ARCH_PRCTL 30",
            "PTRACE_SINGLEBLOCK 33",
            "PT_STEPBLOCK PTRACE_SINGLEBLOCK",
        ):
            self.assertIn(phrase, ptrace_bits)

    def test_ptrace_preserves_generic_and_x86_extensions(self) -> None:
        ptrace = SYS_PTRACE.read_text(encoding="utf-8")
        for phrase in (
            "#include <stdint.h>",
            "#include <bits/ptrace.h>",
            "PTRACE_GETFPREGS 14",
            "PTRACE_PEEKSIGINFO 0x4209",
            "PTRACE_GET_RSEQ_CONFIGURATION 0x420f",
            "PTRACE_O_SUSPEND_SECCOMP 0x00200000",
            "PTRACE_EVENT_STOP 128",
            "struct __ptrace_peeksiginfo_args",
            "struct __ptrace_seccomp_metadata",
            "struct __ptrace_syscall_info",
            "struct __ptrace_rseq_configuration",
            "long ptrace(int, ...);",
        ):
            self.assertIn(phrase, ptrace)

    def test_probes_and_runner_close_the_c_cpp_profile_boundary(self) -> None:
        for probe in (C_PROBE.read_text(encoding="utf-8"), CXX_PROBE.read_text(encoding="utf-8")):
            for phrase in (
                "ELF_NGREG == 27",
                "sizeof(struct user_regs_struct) == 216",
                "sizeof(struct user_fpregs_struct) == 512",
                "sizeof(struct user) == 912",
                "sizeof(struct elf_prstatus) == 336",
                "sizeof(mcontext_t) == 256",
                "sizeof(ucontext_t) == 936",
                "PTRACE_GET_THREAD_AREA == 25",
                "sizeof(struct __ptrace_syscall_info) == 88",
                "HWCAP_FP",
                "HWCAP2_MTE",
                "CRABC_MACHINE_CONTEXT_EXPECT_CONTEXT",
                "CRABC_MACHINE_CONTEXT_EXPECT_GNU_BSD",
                "CRABC_MACHINE_CONTEXT_REQUIRE_CONTEXT_HIDDEN",
                "getauxval",
                "ptrace",
                "swapcontext",
            ):
                self.assertIn(phrase, probe)
            self.assertNotIn("main(", probe)

        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        runner = RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "readonly CANDIDATE_CC=/usr/bin/gcc",
            "readonly EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "-nostdinc",
            "-nostdinc++",
            "candidate trace reached pinned musl despite -nostdinc",
            "trace escaped its declared header roots",
            "bits/hwcap.h",
            "bits/ptrace.h",
            "nm --undefined-only",
            "retained a mangled machine/context reference",
            "unexpectedly exposes mcontext_t/ucontext_t",
            "hidden-context diagnostic does not name mcontext_t/ucontext_t",
        ):
            self.assertIn(phrase, runner)


if __name__ == "__main__":
    unittest.main()
