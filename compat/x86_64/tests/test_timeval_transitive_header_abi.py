#!/usr/bin/env python3
"""Focused contract for x86 timeval visibility through dependent headers."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "time.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_timeval_transitive_header_abi.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "timeval_transitive_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "timeval_transitive_header_abi_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


class TimevalTransitiveHeaderAbiTests(unittest.TestCase):
    def test_sys_time_exposes_the_required_timeval_dependency_before_feature_gates(self) -> None:
        header = HEADER.read_text(encoding="utf-8")

        self.assertIn("#include <features.h>\n#include <sys/select.h>\n", header)
        self.assertLess(
            header.index("#include <sys/select.h>"),
            header.index("#if defined(_XOPEN_SOURCE)"),
        )

    def test_probes_and_runner_close_the_five_by_seven_layout_matrix(self) -> None:
        for probe in (C_PROBE.read_text(encoding="utf-8"), CXX_PROBE.read_text(encoding="utf-8")):
            for phrase in (
                "CRABC_TIMEVAL_TARGET_SYS_TIME",
                "CRABC_TIMEVAL_TARGET_UTMPX",
                "CRABC_TIMEVAL_TARGET_UTMP",
                "CRABC_TIMEVAL_TARGET_LASTLOG",
                "CRABC_TIMEVAL_TARGET_SYS_TIMEX",
                "sizeof(struct timeval) == 16",
                "sizeof(struct utmpx) == 400",
                "sizeof(struct lastlog) == 296",
                "sizeof(struct timex) == 208",
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
            "readonly EXPECTED_HEADER_COUNT=5",
            "readonly EXPECTED_PROFILE_COUNT=7",
            "readonly EXPECTED_ROW_COUNT=35",
            "sys/time.h utmpx.h utmp.h lastlog.h sys/timex.h",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "cxx17-strict) printf '%s\\n' '-U_GNU_SOURCE'",
            "-nostdinc",
            "-nostdinc++",
            "candidate trace reached pinned musl despite -nostdinc",
            "trace escaped its declared header roots",
            "sys-time|sys-timex)",
            "for required_header in utmp.h utmpx.h",
            "for required_header in lastlog.h utmp.h utmpx.h",
            "not an identical",
            "required timeval dependency",
            "required public chain",
        ):
            self.assertIn(phrase, runner)

    def test_dispatcher_exposes_the_timeval_transitive_header_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for phrase in (
            "timeval-transitive-header-abi)",
            "run_timeval_transitive_header_abi()",
            "run_timeval_transitive_header_abi.sh",
            "timeval-transitive-header-abi takes no arguments",
        ):
            self.assertIn(phrase, dispatcher)


if __name__ == "__main__":
    unittest.main()
