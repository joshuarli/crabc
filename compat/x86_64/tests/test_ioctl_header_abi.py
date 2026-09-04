#!/usr/bin/env python3
"""Focused contract for the x86 direct public ``<sys/ioctl.h>`` ABI slice."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "ioctl.h"
BITS_HEADER = ROOT / "include" / "bits" / "ioctl.h"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_ioctl_header_abi.sh"
C_HEADER_PROBE = ROOT / "compat" / "x86_64" / "ioctl_header_abi_probe.c"
CXX_HEADER_PROBE = ROOT / "compat" / "x86_64" / "ioctl_header_abi_probe.cpp"
STATIC_SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ioctl.rs"
STATIC_RUNNER = ROOT / "compat" / "x86_64" / "run_libc_ioctl.sh"
STATIC_PROBE = ROOT / "compat" / "x86_64" / "libc_ioctl_probe.c"
STATIC_START = ROOT / "compat" / "x86_64" / "libc_ioctl_start.S"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


class IoctlHeaderAbiTests(unittest.TestCase):
    def test_direct_header_and_static_forwarder_keep_the_selected_boundary(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        bits_header = BITS_HEADER.read_text(encoding="utf-8")
        ioctl_surface = header + bits_header
        self.assertIn('#ifdef __cplusplus\nextern "C" {\n#endif', header)
        self.assertIn("int ioctl(int, int, ...);", header)
        self.assertIn("#define __NEED_struct_winsize", header)
        self.assertIn("#include <bits/alltypes.h>", header)
        for phrase in (
            "#define _IOC_READ  2U",
            "#define _IOWR(a,b,c)",
            "#define FIONREAD\t0x541B",
            "#define FIONBIO\t\t0x5421",
            "#define FIOCLEX\t\t0x5451",
            "#define FIONCLEX\t0x5450",
        ):
            self.assertIn(phrase, ioctl_surface)
        self.assertIn("#include <bits/ioctl.h>", header)
        self.assertIn("#include <bits/ioctl_fix.h>", bits_header)
        self.assertNotIn("_BITS_IOCTL_H", bits_header)

        source = STATIC_SOURCE.read_text(encoding="utf-8")
        for phrase in (
            "Selected static Linux/x86-64 C generic ioctl boundary",
            "src/misc/ioctl.c",
            "core::arch::global_asm!",
            "ioctl_no_argument",
            "ioctl_word",
            "raw_syscall::SYS_IOCTL",
            "i64::from(request)",
            "c_status(result)",
            "three-word path",
        ):
            self.assertIn(phrase, source)
        self.assertNotIn("crabc_core", source)

    def test_direct_header_retains_pinned_macro_source_forms(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        for phrase in (
            "#define SIOCSIFBRDADDR     0x891a",
            "#define SIOCGIFNETMASK     0x891b",
            "#define SIOCSIFNETMASK     0x891c",
            "#define SIOCGIFMETRIC      0x891d",
            "#define SIOCSIFMETRIC      0x891e",
            "#define SIOCGIFMEM         0x891f",
        ):
            self.assertIn(phrase, header)

    def test_header_matrix_and_static_fixture_are_closed_and_native(self) -> None:
        for probe in (
            C_HEADER_PROBE.read_text(encoding="utf-8"),
            CXX_HEADER_PROBE.read_text(encoding="utf-8"),
        ):
            for phrase in (
                "#include <sys/ioctl.h>",
                "sizeof(struct winsize) == 8",
                "int (*)(int, int, ...)",
                "_IOC_READ == 2U",
                "FIONREAD == 0x541b",
                "FIONBIO == 0x5421",
                "FIOCLEX == 0x5451",
                "FIONCLEX == 0x5450",
            ):
                self.assertIn(phrase, probe)
            self.assertNotIn("main(", probe)

        for runner in (HEADER_RUNNER, STATIC_RUNNER):
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

        header_runner = HEADER_RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "readonly CANDIDATE_CC=/usr/bin/gcc",
            "readonly EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "-nostdinc",
            "-nostdinc++",
            "candidate trace reached pinned musl despite -nostdinc",
            "trace escaped its declared header roots",
            "trace omitted ${root}/sys/ioctl.h",
        ):
            self.assertIn(phrase, header_runner)

        static_runner = STATIC_RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "run_ioctl_header_abi.sh",
            "run_musl_oracle.sh",
            "__crabc_x86_static_tls_bootstrap",
            "ioctl",
            "SYS_IOCTL",
            "FIONREAD",
            "FIONBIO",
            "FIOCLEX",
            "FIONCLEX",
            "xor %edx, %edx",
            "R_X86_64_TPOFF",
            "TLSGD|TLSLD|TLSDESC",
            "Requesting program interpreter|INTERP",
            "DT_NEEDED",
        ):
            self.assertIn(phrase, static_runner)

        probe = STATIC_PROBE.read_text(encoding="utf-8")
        for phrase in (
            "CRABC_IOCTL_FREESTANDING",
            "SYS_ioctl == 16",
            "FIONREAD",
            "FIONBIO",
            "FIOCLEX",
            "FIONCLEX",
            "errno = E2BIG",
            "ioctl(read_descriptor, FIOCLEX)",
            "ioctl(read_descriptor, FIONCLEX)",
            "ioctl(-1, FIOCLEX)",
        ):
            self.assertIn(phrase, probe)
        start = STATIC_START.read_text(encoding="utf-8")
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertNotIn("ARCH_SET_FS", start)

    def test_dispatcher_exposes_both_ioctl_gates(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for phrase in (
            "ioctl-header-abi)",
            "run_ioctl_header_abi()",
            "run_ioctl_header_abi.sh",
            "ioctl-header-abi takes no arguments",
            "libc-ioctl)",
            "run_libc_ioctl()",
            "run_libc_ioctl.sh",
            "libc-ioctl takes no arguments",
        ):
            self.assertIn(phrase, dispatcher)


if __name__ == "__main__":
    unittest.main()
