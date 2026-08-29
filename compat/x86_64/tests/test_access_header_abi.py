#!/usr/bin/env python3
"""Focused contract for the x86 direct public access-header ABI slice."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "unistd.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_access_header_abi.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "access_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "access_header_abi_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


class AccessHeaderAbiTests(unittest.TestCase):
    def test_unistd_uses_the_pinned_gnu_only_eaccess_gate(self) -> None:
        header = HEADER.read_text(encoding="utf-8")

        self.assertIn("int access(const char *, int);", header)
        self.assertIn("int faccessat(int, const char *, int, int);", header)
        self.assertIn(
            "#ifdef _GNU_SOURCE\nint eaccess(const char *, int);\nint euidaccess(const char *, int);\n#endif",
            header,
        )
        self.assertNotIn(
            "#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)\nint eaccess",
            header,
        )

    def test_probes_and_runner_close_the_eight_profile_access_boundary(self) -> None:
        for probe in (C_PROBE.read_text(encoding="utf-8"), CXX_PROBE.read_text(encoding="utf-8")):
            for phrase in (
                "F_OK == 0",
                "AT_FDCWD == -100",
                "AT_SYMLINK_NOFOLLOW == 0x100",
                "AT_EACCESS == 0x200",
                "access",
                "faccessat",
                "CRABC_ACCESS_REQUIRE_GNU",
                "eaccess",
                "euidaccess",
                "CRABC_ACCESS_REQUIRE_GNU_HIDDEN",
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
            "readonly EXPECTED_PROFILE_COUNT=8",
            "c-default c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "cxx17-strict) printf '%s\\n' '-U_GNU_SOURCE'",
            "-nostdinc",
            "-nostdinc++",
            "candidate trace reached pinned musl despite -nostdinc",
            "trace escaped its declared header roots",
            "trace omitted ${root}/fcntl.h",
            "trace omitted ${root}/unistd.h",
            "nm --undefined-only",
            "retained a mangled access-header reference",
            "GNU eaccess/euidaccess declarations",
        ):
            self.assertIn(phrase, runner)

    def test_dispatcher_exposes_the_direct_access_header_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for phrase in (
            "access-header-abi)",
            "run_access_header_abi()",
            "run_access_header_abi.sh",
            "access-header-abi takes no arguments",
        ):
            self.assertIn(phrase, dispatcher)


if __name__ == "__main__":
    unittest.main()
