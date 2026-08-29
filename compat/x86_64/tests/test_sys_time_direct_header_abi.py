#!/usr/bin/env python3
"""Focused contract for the x86 direct public <sys/time.h> ABI slice."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "time.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_sys_time_direct_header_abi.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "sys_time_direct_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "sys_time_direct_header_abi_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


class SysTimeDirectHeaderAbiTests(unittest.TestCase):
    def test_sys_time_preserves_the_pinned_baseline_and_cxx_linkage_boundary(self) -> None:
        header = HEADER.read_text(encoding="utf-8")

        self.assertIn('#ifdef __cplusplus\nextern "C" {\n#endif', header)
        self.assertIn("int gettimeofday(struct timeval *__restrict, void *__restrict);", header)
        self.assertIn("#define ITIMER_REAL 0", header)
        self.assertIn("struct itimerval", header)
        self.assertIn("int getitimer(int, struct itimerval *);", header)
        self.assertIn("int setitimer(int, const struct itimerval *__restrict,", header)
        self.assertIn("int utimes(const char *, const struct timeval [2]);", header)
        self.assertLess(header.index("int gettimeofday"), header.index("#if defined(_GNU_SOURCE)"))

    def test_probes_and_runner_close_the_seven_profile_direct_header_matrix(self) -> None:
        for probe in (C_PROBE.read_text(encoding="utf-8"), CXX_PROBE.read_text(encoding="utf-8")):
            for phrase in (
                "sizeof(struct itimerval) == 32",
                "itimerval, it_value) == 16",
                "ITIMER_REAL == 0",
                "gettimeofday",
                "getitimer",
                "setitimer",
                "utimes",
                "CRABC_SYS_TIME_REQUIRE_GNU_BSD",
                "futimesat",
                "timerisset",
                "CRABC_SYS_TIME_REQUIRE_GNU",
                "TIMEVAL_TO_TIMESPEC",
                "CRABC_SYS_TIME_REQUIRE_GNU_BSD_HIDDEN",
                "CRABC_SYS_TIME_REQUIRE_GNU_HIDDEN",
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
            "cxx17-strict) printf '%s\\n' '-U_GNU_SOURCE'",
            "-nostdinc",
            "-nostdinc++",
            "candidate trace reached pinned musl despite -nostdinc",
            "trace escaped its declared header roots",
            "trace omitted ${root}/sys/select.h",
            "nm --undefined-only",
            "retained a mangled sys/time reference",
            "GNU/BSD sys/time declarations",
            "GNU sys/time conversion macros",
        ):
            self.assertIn(phrase, runner)

    def test_dispatcher_exposes_the_direct_sys_time_header_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for phrase in (
            "sys-time-direct-header-abi)",
            "run_sys_time_direct_header_abi()",
            "run_sys_time_direct_header_abi.sh",
            "sys-time-direct-header-abi takes no arguments",
        ):
            self.assertIn(phrase, dispatcher)


if __name__ == "__main__":
    unittest.main()
