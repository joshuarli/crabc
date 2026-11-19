#!/usr/bin/env python3
"""Pinned-musl source-form and frozen-AArch64 contract for ``sys/klog.h``."""

from __future__ import annotations

import hashlib
import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "klog.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_klog_header_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "klog_header_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "klog_header_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

X86_MUSL_SHA256 = "53fe42935799f4ccb9a141f08dac71e6f9221e3de0d5703c8870997e94b45fb1"
class KlogHeaderSourceFormTests(unittest.TestCase):
    def test_both_architectures_use_pinned_musl_source(self) -> None:
        source = HEADER.read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), X86_MUSL_SHA256)
        self.assertNotIn(b"__x86_64__", source)
        self.assertNotIn(b"__aarch64__", source)

    def test_direct_probes_preserve_klogctl_and_reject_every_leaked_command_macro(self) -> None:
        c_probe = C_PROBE.read_text(encoding="utf-8")
        cpp_probe = CXX_PROBE.read_text(encoding="utf-8")
        for probe in (c_probe, cpp_probe):
            self.assertIn("#include <sys/klog.h>", probe)
            self.assertIn("_SYS_KLOG_H", probe)
            self.assertIn("klogctl", probe)
            for macro in (
                "KLOG_CLOSE",
                "KLOG_OPEN",
                "KLOG_READ",
                "KLOG_READ_ALL",
                "KLOG_READ_CLEAR",
                "KLOG_CLEAR",
                "KLOG_CONSOLE_OFF",
                "KLOG_CONSOLE_ON",
                "KLOG_CONSOLE_LEVEL",
                "KLOG_SIZE_UNREAD",
                "KLOG_SIZE_BUFFER",
            ):
                self.assertIn(macro, probe)
        self.assertIn('extern "C" int crabc_x86_klog_header_source_form_probe_cpp', cpp_probe)

    def test_runner_is_native_isolated_and_all_profile(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "-nostdinc",
            "-nostdinc++",
            "sys/klog.h",
            "KLOG_",
            "check_cxx_linkage",
            "-dM",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-I /usr/include", runner)

        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_dispatcher_exposes_the_native_header_source_form_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for required in (
            "klog-header-source-form)",
            "run_klog_header_source_form()",
            "run_klog_header_source_form.sh",
            "klog-header-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
