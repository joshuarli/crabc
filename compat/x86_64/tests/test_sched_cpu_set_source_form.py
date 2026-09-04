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

X86_MARKER = "#if defined(__x86_64__) /* pinned-musl cpu_set_t form; the AArch64 form stays frozen */\n"
X86_FORM = "typedef struct cpu_set_t { unsigned long __bits[128/sizeof(long)]; } cpu_set_t;\n"
NON_X86_SEPARATOR = "#else /* AArch64 frozen cpu_set_t form */\n"
FROZEN_NON_X86_FORM = """\
typedef struct cpu_set_t {
    unsigned long __bits[128 / sizeof(long)];
} cpu_set_t;
"""


class SchedCpuSetSourceFormTests(unittest.TestCase):
    def test_x86_cpu_set_t_uses_the_exact_pinned_musl_source_form(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        _, marker, after_marker = header.partition(X86_MARKER)
        self.assertTrue(marker, "sched.h lacks the selected x86 cpu_set_t branch")
        x86_form, separator, after_separator = after_marker.partition(NON_X86_SEPARATOR)
        self.assertTrue(separator, "sched.h lacks the frozen non-x86 cpu_set_t branch")
        self.assertEqual(x86_form, X86_FORM)
        non_x86_form, closer, _ = after_separator.partition("#endif\n\nint __sched_cpucount")
        self.assertTrue(closer, "sched.h lacks the cpu_set_t architecture-branch closer")
        self.assertEqual(non_x86_form, FROZEN_NON_X86_FORM)

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
