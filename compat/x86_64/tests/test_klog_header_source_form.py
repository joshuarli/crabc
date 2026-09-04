#!/usr/bin/env python3
"""Pinned-musl source-form and frozen-AArch64 contract for ``sys/klog.h``."""

from __future__ import annotations

import hashlib
import re
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

# Pinned musl 1.2.6 selects the first body. The second hash is the pre-slice
# file, deliberately retained byte-for-byte to keep AArch64 behavior frozen.
X86_MUSL_SHA256 = "53fe42935799f4ccb9a141f08dac71e6f9221e3de0d5703c8870997e94b45fb1"
LEGACY_SHA256 = "2cfa6c2c1ad923c64ddb4590a73378385a4162bdb68bb5414aaa0e10ed09e067"

OPEN = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef)\b")
CLOSE = re.compile(r"^\s*#\s*endif\b")
ELSE = re.compile(r"^\s*#\s*(?:else|elif)\b")


def split_x86_branch(path: Path) -> tuple[bytes, bytes]:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if not lines or lines[0] != "#if defined(__x86_64__)\n":
        raise AssertionError(f"{path} must begin with its x86 source-form branch")

    depth = 1
    x86: list[str] = []
    legacy: list[str] = []
    in_legacy = False
    for line in lines[1:]:
        if not in_legacy and ELSE.match(line) and depth == 1:
            in_legacy = True
            continue
        if in_legacy and CLOSE.match(line) and depth == 1:
            break
        if in_legacy:
            legacy.append(line)
        else:
            x86.append(line)
        if OPEN.match(line):
            depth += 1
        elif CLOSE.match(line):
            depth -= 1
    else:
        raise AssertionError(f"{path} is missing its closing x86 source-form branch")

    return "".join(x86).encode(), "".join(legacy).encode()


class KlogHeaderSourceFormTests(unittest.TestCase):
    def test_x86_form_matches_pinned_musl_and_aarch64_form_stays_frozen(self) -> None:
        x86, legacy = split_x86_branch(HEADER)
        self.assertEqual(hashlib.sha256(x86).hexdigest(), X86_MUSL_SHA256)
        self.assertEqual(hashlib.sha256(legacy).hexdigest(), LEGACY_SHA256)

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
