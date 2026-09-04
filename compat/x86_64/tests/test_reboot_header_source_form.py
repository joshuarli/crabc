#!/usr/bin/env python3
"""Pinned-musl source-form contract for the x86 ``<sys/reboot.h>`` header."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "reboot.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_reboot_header_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "reboot_header_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "reboot_header_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

X86_MARKER = "#if defined(__x86_64__) /* pinned-musl form; the AArch64 branch stays frozen */\n"
X86_MUSL_MACROS = """\
#define RB_AUTOBOOT     0x01234567
#define RB_HALT_SYSTEM  0xcdef0123
#define RB_ENABLE_CAD   0x89abcdef
#define RB_DISABLE_CAD  0
#define RB_POWER_OFF    0x4321fedc
#define RB_SW_SUSPEND   0xd000fce2
#define RB_KEXEC        0x45584543
"""


class RebootHeaderSourceFormTests(unittest.TestCase):
    def test_x86_branch_keeps_the_exact_pinned_musl_public_macro_form(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        self.assertIn(X86_MARKER, header)
        x86_form = header.split(X86_MARKER, 1)[1].split("\n#else\n", 1)[0]
        self.assertEqual(x86_form.strip(), X86_MUSL_MACROS.strip())
        self.assertNotIn("LINUX_REBOOT_", x86_form)

    def test_non_x86_branch_retains_the_frozen_legacy_reboot_surface(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        legacy_form = header.split("\n#else\n", 1)[1].split("\n#endif\n", 1)[0]
        for macro in (
            "LINUX_REBOOT_MAGIC1",
            "LINUX_REBOOT_MAGIC2",
            "LINUX_REBOOT_CMD_RESTART",
            "LINUX_REBOOT_CMD_RESTART2",
            "LINUX_REBOOT_CMD_KEXEC",
            "RB_AUTOBOOT     LINUX_REBOOT_CMD_RESTART",
            "RB_KEXEC        LINUX_REBOOT_CMD_KEXEC",
        ):
            self.assertIn(macro, legacy_form)

    def test_direct_c_and_cpp_probes_name_visibility_and_linkage_invariants(self) -> None:
        for probe_path in (C_PROBE, CXX_PROBE):
            probe = probe_path.read_text(encoding="utf-8")
            self.assertIn("#include <sys/reboot.h>", probe)
            self.assertIn("RB_AUTOBOOT == 0x01234567", probe)
            self.assertIn("RB_HALT_SYSTEM == 0xcdef0123", probe)
            self.assertIn("RB_ENABLE_CAD == 0x89abcdef", probe)
            self.assertIn("RB_DISABLE_CAD == 0", probe)
            self.assertIn("RB_POWER_OFF == 0x4321fedc", probe)
            self.assertIn("RB_SW_SUSPEND == 0xd000fce2", probe)
            self.assertIn("RB_KEXEC == 0x45584543", probe)
            self.assertIn("LINUX_REBOOT_", probe)
            self.assertIn("reboot", probe)
        self.assertIn('extern "C" int crabc_x86_reboot_header_source_form_probe_cpp', CXX_PROBE.read_text(encoding="utf-8"))

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
            "-dM",
            "LINUX_REBOOT_",
            "reboot",
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
            "reboot-header-source-form)",
            "run_reboot_header_source_form()",
            "run_reboot_header_source_form.sh",
            "reboot-header-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
