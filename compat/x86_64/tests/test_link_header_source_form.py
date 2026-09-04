#!/usr/bin/env python3
"""Focused contract for the x86 direct <link.h> source-form gate."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_link_header_source_form.sh"


class LinkHeaderSourceFormTests(unittest.TestCase):
    def test_runner_keeps_isolated_musl_and_project_header_trees(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "-nostdinc",
            "-nostdinc++",
            "bits/alltypes.h bits/link.h",
            "forbid_trace_header",
            "stddef.h",
            "dl_iterate_phdr",
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

    def test_probes_name_the_direct_visibility_and_linkage_contract(self) -> None:
        c_probe = (ROOT / "compat/x86_64/link_header_source_form_probe.c").read_text(
            encoding="utf-8"
        )
        cpp_probe = (ROOT / "compat/x86_64/link_header_source_form_probe.cpp").read_text(
            encoding="utf-8"
        )
        for probe in (c_probe, cpp_probe):
            self.assertIn("Elf_Symndx", probe)
            self.assertIn("offsetof", probe)
            self.assertIn("dl_iterate_phdr", probe)
            self.assertIn("__NEED_size_t", probe)
            self.assertIn("__NEED_uint32_t", probe)
        self.assertIn('extern "C" int crabc_x86_link_header_source_form_probe_cpp', cpp_probe)


if __name__ == "__main__":
    unittest.main()
