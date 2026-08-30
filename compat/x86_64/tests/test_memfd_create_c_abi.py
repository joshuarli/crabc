#!/usr/bin/env python3
"""Focused contract for the private x86 static C memfd_create slice."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "mman.h"
MODULE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memfd_create.rs"
C_PROBE = ROOT / "compat" / "x86_64" / "memfd_create_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "memfd_create_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_memfd_create_header_abi.sh"
STATIC_PROBE = ROOT / "compat" / "x86_64" / "libc_memfd_create_probe.c"
STATIC_START = ROOT / "compat" / "x86_64" / "libc_memfd_create_start.S"
STATIC_RUNNER = ROOT / "compat" / "x86_64" / "run_libc_memfd_create.sh"


class MemfdCreateCAbiTests(unittest.TestCase):
    def test_project_header_keeps_memfd_create_and_mfd_values_gnu_only(self) -> None:
        header = HEADER.read_text(encoding="utf-8")

        self.assertIn(
            "#if defined(__x86_64__) && defined(_GNU_SOURCE)\n"
            "void *mremap(void *, size_t, size_t, int, ...);\n"
            "int memfd_create(const char *, unsigned);\n#endif",
            header,
        )
        self.assertIn("#define MFD_CLOEXEC 0x0001U", header)
        self.assertIn("#define MFD_ALLOW_SEALING 0x0002U", header)
        self.assertIn("#define MFD_HUGETLB 0x0004U", header)
        self.assertNotIn(
            "#if defined(__x86_64__) && (defined(_GNU_SOURCE) || "
            "defined(_BSD_SOURCE))\nint memfd_create",
            header,
        )

    def test_source_maps_one_musl_wrapper_to_one_direct_syscall_boundary(self) -> None:
        module = MODULE.read_text(encoding="utf-8")

        for phrase in (
            "src/linux/memfd_create.c",
            "memfd_create=319",
            "raw_syscall::SYS_MEMFD_CREATE",
            "raw_syscall::syscall2",
            "c_status(result)",
            "MFD_HUGETLB",
            "fcntl",
            "memfd_secret",
        ):
            self.assertIn(phrase, module)
        self.assertNotIn("syscall3(", module)
        self.assertNotIn("syscall4(", module)

    def test_header_probes_and_matrix_close_the_gnu_visibility_boundary(self) -> None:
        for probe in (C_PROBE.read_text(encoding="utf-8"), CXX_PROBE.read_text(encoding="utf-8")):
            for phrase in (
                "SYS_memfd_create == 319",
                "memfd_create",
                "MFD_CLOEXEC == 0x0001U",
                "MFD_ALLOW_SEALING == 0x0002U",
                "MFD_HUGETLB == 0x0004U",
                "CRABC_MEMFD_CREATE_REQUIRE_GNU",
                "CRABC_MEMFD_CREATE_REQUIRE_GNU_HIDDEN",
            ):
                self.assertIn(phrase, probe)
            self.assertNotIn("main(", probe)

        self.assert_runner_is_executable_and_syntactically_valid(HEADER_RUNNER)
        runner = HEADER_RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "readonly EXPECTED_PROFILE_COUNT=8",
            "readonly EXPECTED_GNU_PROFILE_COUNT=2",
            "readonly EXPECTED_GNU_HIDDEN_PROFILE_COUNT=6",
            "c-default c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "GNU_HIDDEN_PROFILES=(c-default c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)",
            "-nostdinc",
            "-nostdinc++",
            "sys/mman.h bits/mman.h sys/syscall.h bits/syscall.h",
            "C++ probe lacks C-linkage memfd_create",
            "unexpectedly exposes GNU memfd_create",
        ):
            self.assertIn(phrase, runner)

    def test_freestanding_fixture_keeps_seals_and_c_fcntl_out_of_scope(self) -> None:
        probe = STATIC_PROBE.read_text(encoding="utf-8")

        for phrase in (
            "SYS_close == 3 && SYS_memfd_create == 319",
            "249 content bytes are accepted",
            "250 content bytes with EINVAL",
            "UINT_MAX",
            "errno != EFAULT",
            "raw_close",
            "CRABC_MEMFD_CREATE_FREESTANDING",
        ):
            self.assertIn(phrase, probe)
        self.assertNotIn("F_ADD_SEALS", probe)
        self.assertNotIn("F_GET_SEALS", probe)
        self.assertNotIn("fcntl(", probe)
        self.assert_runner_is_executable_and_syntactically_valid(STATIC_RUNNER)
        self.assertIn("arch_prctl(ARCH_SET_FS", STATIC_START.read_text(encoding="utf-8"))

        runner = STATIC_RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "run_memfd_create_header_abi.sh",
            "-nostdlib -static",
            "--no-undefined",
            "assert_memfd_syscall_path",
            "memfd_secret",
            "fcntl64",
            "x86 static crabc-libc memfd_create: PASS",
        ):
            self.assertIn(phrase, runner)
        self.assertNotIn("run_x86_memfd_reference.sh", runner)

    def assert_runner_is_executable_and_syntactically_valid(self, runner: Path) -> None:
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


if __name__ == "__main__":
    unittest.main()
