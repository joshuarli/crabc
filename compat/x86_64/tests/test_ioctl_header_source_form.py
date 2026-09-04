#!/usr/bin/env python3
"""Pinned-musl x86 and frozen-AArch64 ioctl source-form contract."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "ioctl.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_ioctl_header_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "ioctl_header_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "ioctl_header_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

X86_LITERAL_BRANCH = """\
#if defined(__x86_64__)
#define SIOCSIFBRDADDR     0x891a
#define SIOCGIFNETMASK     0x891b
#define SIOCSIFNETMASK     0x891c
#define SIOCGIFMETRIC      0x891d
#define SIOCSIFMETRIC      0x891e
#define SIOCGIFMEM         0x891f
#else
"""

FROZEN_AARCH64_LITERALS = """\
#define SIOCSIFBRDADDR 0x891A
#define SIOCGIFNETMASK 0x891B
#define SIOCSIFNETMASK 0x891C
#define SIOCGIFMETRIC 0x891D
#define SIOCSIFMETRIC 0x891E
#define SIOCGIFMEM 0x891F
#endif
"""


class IoctlHeaderSourceFormTests(unittest.TestCase):
    def test_x86_literals_match_musl_and_non_x86_literals_stay_frozen(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        self.assertIn(X86_LITERAL_BRANCH, header)
        self.assertIn(FROZEN_AARCH64_LITERALS, header)
        for name in (
            "SIOCSIFBRDADDR",
            "SIOCGIFNETMASK",
            "SIOCSIFNETMASK",
            "SIOCGIFMETRIC",
            "SIOCSIFMETRIC",
            "SIOCGIFMEM",
        ):
            self.assertEqual(header.count(f"#define {name}"), 2)

    def test_direct_c_and_cpp_probes_cover_x86_and_frozen_non_x86_branches(self) -> None:
        for probe_path in (C_PROBE, CXX_PROBE):
            probe = probe_path.read_text(encoding="utf-8")
            for required in (
                "CRABC_IOCTL_SOURCE_FORM_HEADER",
                "CRABC_IOCTL_SOURCE_FORM_SYS",
                "_BITS_IOCTL_H",
                "_IOC_NONE == 0U",
                "SIOCSIFBRDADDR == 0x891a",
            ):
                self.assertIn(required, probe)
        self.assertIn("ioctl declaration", C_PROBE.read_text(encoding="utf-8"))
        self.assertIn(
            "ioctl_source_form_signature", CXX_PROBE.read_text(encoding="utf-8")
        )
        self.assertIn(
            'extern "C" int crabc_ioctl_header_source_form_cpp',
            CXX_PROBE.read_text(encoding="utf-8"),
        )

    def test_runner_is_native_isolated_all_profile_and_freezes_aarch64(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "AARCH64_CC=/usr/bin/clang",
            "EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "bits/ioctl.h sys/ioctl.h",
            "bits/ioctl_fix.h",
            "expected_x86_surface",
            "expected_aarch64_surface",
            "-nostdinc",
            "-nostdinc++",
            "Linux/UAPI",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-I /usr/include", runner)
        self.assertNotIn("libcrabc-libc.a", runner)

        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_dispatcher_exposes_the_native_ioctl_source_form_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for required in (
            "ioctl-header-source-form)",
            "run_ioctl_header_source_form()",
            "run_ioctl_header_source_form.sh",
            "ioctl-header-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
