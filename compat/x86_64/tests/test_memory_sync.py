#!/usr/bin/env python3
"""Focused contract for the isolated x86 static-C `msync` evidence paths."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
LEAF = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_sync.rs"
SYSCALL = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
C_PROBE = ROOT / "compat" / "x86_64" / "libc_memory_sync_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_memory_sync_start.S"
HEADER_C = ROOT / "compat" / "x86_64" / "memory_sync_header_abi_probe.c"
HEADER_CXX = ROOT / "compat" / "x86_64" / "memory_sync_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_memory_sync_header_abi.sh"
ARTIFACT_RUNNER = ROOT / "compat" / "x86_64" / "run_libc_memory_sync.sh"


class MemorySyncEvidenceTests(unittest.TestCase):
    def test_leaf_records_owned_cancellation_and_standalone_raw_syscall(self) -> None:
        leaf = LEAF.read_text(encoding="utf-8")
        syscall = SYSCALL.read_text(encoding="utf-8")

        for phrase in (
            "src/mman/msync.c",
            "src/thread/x86_64/syscall_cp.s",
            "syscall_cp(SYS_msync",
            "before kernel validation",
            "standalone archive selections retain",
            '#[cfg(feature = "x86-owned-static-runtime")]',
            '#[cfg(not(feature = "x86-owned-static-runtime"))]',
            "super::pthread_cancel::syscall_cp",
            "msync=26",
            "file-backed shared-map writeback",
            "raw_syscall::SYS_MSYNC",
            'extern "C" fn msync',
            "raw_syscall::syscall3",
            "c_status(result)",
        ):
            self.assertIn(phrase, leaf)
        self.assertNotIn("crabc_core", leaf)
        self.assertNotIn("raw_syscall::__syscall_cp", leaf)
        self.assertIn("pub(crate) const SYS_MSYNC: i64 = 26;", syscall)

    def test_c_fixture_keeps_raw_setup_and_msync_boundary_closed(self) -> None:
        fixture = C_PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")

        for phrase in (
            "SYS_msync == 26",
            "MS_ASYNC == 1 && MS_INVALIDATE == 2 && MS_SYNC == 4",
            "raw6(SYS_mmap",
            "raw2(SYS_munmap",
            "msync(mapping, 0, 0)",
            "MS_ASYNC | MS_SYNC",
            "MS_ASYNC | MS_SYNC | MS_INVALIDATE",
            "expect_einval(mapping, 0, MS_ASYNC | MS_SYNC, 18)",
            "expect_einval((void *)(bytes + 1), 0, 0, 20)",
            "bytes + 1",
            "errno != stale_errno",
            "CRABC_MEMORY_SYNC_FREESTANDING",
            "no musl syscall_cp/pthread-cancellation",
            "file-backed shared-map writeback",
        ):
            self.assertIn(phrase, fixture)
        for phrase in (
            "arch_prctl(ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_memory_sync_probe",
            "not CRT, pthread/TLS lifecycle",
        ):
            self.assertIn(phrase, start)

    def test_header_matrix_and_artifact_runner_are_closed_and_syntactically_valid(self) -> None:
        for runner in (HEADER_RUNNER, ARTIFACT_RUNNER):
            syntax = subprocess.run(
                ["bash", "-n", str(runner)],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)
            self.assertEqual(stat.S_IMODE(runner.stat().st_mode), 0o755)

        header_c = HEADER_C.read_text(encoding="utf-8")
        header_cxx = HEADER_CXX.read_text(encoding="utf-8")
        for probe in (header_c, header_cxx):
            for phrase in (
                "MS_ASYNC == 0x1",
                "MS_INVALIDATE == 0x2",
                "MS_SYNC == 0x4",
                "msync",
            ):
                self.assertIn(phrase, probe)
        self.assertIn("every selected C profile", header_c)
        self.assertIn("every selected C/C++ profile", header_cxx)

        header_runner = HEADER_RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "EXPECTED_PROFILE_COUNT=8",
            "c-default c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "-nostdinc",
            "-nostdinc++",
            "sys/mman.h",
            "retained a mangled msync reference",
            "unconditional msync",
        ):
            self.assertIn(phrase, header_runner)

        artifact_runner = ARTIFACT_RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "run_memory_sync_header_abi.sh",
            "run_x86_msync_reference.sh",
            "libc_memory_sync_probe.c",
            "libc_memory_sync_start.S",
            "assert_named_syscall msync 1a",
            "__syscall_cp",
            "pthread_cancel",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(phrase, artifact_runner)


if __name__ == "__main__":
    unittest.main()
