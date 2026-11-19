#!/usr/bin/env python3
"""Pinned-musl x86 ``cpu_set_t`` source/visibility contract for ``sched.h``."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sched.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_sched_cpu_set_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "sched_cpu_set_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "sched_cpu_set_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

X86_FORM = "typedef struct cpu_set_t { unsigned long __bits[128/sizeof(long)]; } cpu_set_t;\n"


class SchedCpuSetSourceFormTests(unittest.TestCase):
    def test_x86_cpu_set_t_uses_the_exact_pinned_musl_source_form(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        self.assertIn(X86_FORM + "\nint __sched_cpucount", header)
        self.assertEqual(header.count("typedef struct cpu_set_t"), 1)
        self.assertNotIn("__x86_64__", header)
        self.assertNotIn("__aarch64__", header)

    def test_direct_c_and_cpp_probes_pin_cpu_set_visibility_without_runtime_work(self) -> None:
        for probe_path in (C_PROBE, CXX_PROBE):
            probe = probe_path.read_text(encoding="utf-8")
            for required in (
                "#include <sched.h>",
                "CRABC_EXPECT_CPU_SET_VISIBLE",
                "CRABC_REQUIRE_CPU_SET_HIDDEN",
                "cpu_set_t",
                "CPU_SETSIZE",
                "sizeof(cpu_set_t) == 128",
                "cpu_set_t storage offset",
            ):
                self.assertIn(required, probe, probe_path.name)
            self.assertNotIn("sched_getaffinity", probe)
            self.assertNotIn("sched_setaffinity", probe)
            self.assertNotIn("CPU_ALLOC", probe)
        self.assertIn(
            'extern "C" int crabc_x86_sched_cpu_set_source_form_probe_cpp()',
            CXX_PROBE.read_text(encoding="utf-8"),
        )

    def test_runner_is_direct_native_and_uses_the_complete_matrix_profile_roster(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "COMPILER=clang",
            "EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "c11-gnu|cxx17-gnu|cxx17-strict",
            "c11-strict|c11-posix-2008|c11-xopen-700|c11-bsd",
            "CPU_SET_FORM",
            "X86_MARKER",
            "-nostdinc",
            "-nostdinc++",
            "for header in sched.h features.h bits/alltypes.h",
            "run_musl_oracle.sh",
            "compile-only",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-I /usr/include", runner)
        self.assertNotIn("sched_getaffinity", runner)
        self.assertNotIn("sched_setaffinity", runner)

        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_dispatcher_exposes_the_native_cpu_set_source_form_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for required in (
            "sched-cpu-set-source-form)",
            "run_sched_cpu_set_source_form()",
            "run_sched_cpu_set_source_form.sh",
            "sched-cpu-set-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
