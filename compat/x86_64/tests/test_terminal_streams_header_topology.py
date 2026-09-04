#!/usr/bin/env python3
"""Focused contract for the x86 terminal/STREAMS direct-header topology gate."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_terminal_streams_header_topology.sh"


class TerminalStreamsHeaderTopologyTests(unittest.TestCase):
    def test_runner_keeps_both_isolated_header_trees_and_all_profiles(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "-nostdinc",
            "-nostdinc++",
            "reference candidate",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "stropts-winsize sys-stropts-winsize ttydefaults-tcgetattr",
            "compile_expected_negative",
            "forbid_trace_header",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-I /usr/include", runner)

    def test_runner_is_executable_shell(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_runner_names_each_selected_direct_header_path(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for variant in (
            "stropts sys-stropts ttydefaults-direct ttydefaults-with-termios pty termios sys-termios",
            "sys/ioctl.h",
            "sys/ttydefaults.h",
            "redirecting incorrect #include <sys/termios.h> to <termios.h>",
        ):
            self.assertIn(variant, runner)

    def test_probes_make_positive_and_negative_include_contracts_explicit(self) -> None:
        c_probe = (ROOT / "compat/x86_64/terminal_streams_header_topology_probe.c").read_text(
            encoding="utf-8"
        )
        cpp_probe = (ROOT / "compat/x86_64/terminal_streams_header_topology_probe.cpp").read_text(
            encoding="utf-8"
        )
        c_negative = (
            ROOT / "compat/x86_64/terminal_streams_header_topology_negative.c"
        ).read_text(encoding="utf-8")
        cpp_negative = (
            ROOT / "compat/x86_64/terminal_streams_header_topology_negative.cpp"
        ).read_text(encoding="utf-8")
        for required in (
            "must not acquire <sys/ioctl.h> request macros",
            "must not directly include <termios.h>",
            "must retain its direct <sys/ioctl.h> dependency",
            "must not acquire a synthetic <bits/ioctl.h> guard",
            "GNU/BSD termios profile must expose CMSPAR",
            "strict POSIX/XSI termios profile must hide CMSPAR",
        ):
            self.assertIn(required, c_probe)
        self.assertIn("bits/ioctl.h", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("bits/ioctl_fix.h", RUNNER.read_text(encoding="utf-8"))
        self.assertIn('extern "C" int openpty', cpp_probe)
        self.assertIn('extern "C" int ioctl', cpp_probe)
        self.assertIn("must not acquire a synthetic <bits/ioctl.h> guard", cpp_probe)
        self.assertIn("struct winsize", c_negative)
        self.assertIn("struct winsize", cpp_negative)
        self.assertIn("tcgetattr", c_negative)
        self.assertIn("tcgetattr", cpp_negative)


if __name__ == "__main__":
    unittest.main()
