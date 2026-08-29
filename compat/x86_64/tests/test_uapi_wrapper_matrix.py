#!/usr/bin/env python3
"""Focused contracts for the native x86 Linux-5.10 UAPI wrapper ABI slice."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat" / "x86_64" / "run_uapi_wrapper_matrix.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "uapi_wrappers_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "uapi_wrappers_header_abi_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


class UapiWrapperMatrixTests(unittest.TestCase):
    def test_probes_are_compile_only_selected_c_and_cxx_abi_assertions(self) -> None:
        c_probe = C_PROBE.read_text(encoding="utf-8")
        cxx_probe = CXX_PROBE.read_text(encoding="utf-8")

        for probe in (c_probe, cxx_probe):
            for header in ("<sys/kd.h>", "<sys/soundcard.h>", "<sys/vt.h>"):
                self.assertIn(f"#include {header}", probe)
            for phrase in (
                "KDGETMODE == 0x4b3b",
                "VT_OPENQRY == 0x5600",
                "VT_EVENT_UNBLANK == 4 && VT_EVENT_RESIZE == 8",
                "SNDCTL_DSP_SYNC == _SIO('P', 1)",
                "SNDCTL_DSP_SPEED == 0xc0045002U",
                "SNDCTL_DSP_GETOSPACE == 0x8010500cU",
                "struct consolefontdesc",
                "struct vt_event",
                "struct audio_buf_info",
                "struct mixer_info",
                "_IOC_SIZE(SNDCTL_DSP_GETIPTR)",
            ):
                self.assertIn(phrase, probe)
            self.assertNotIn("main(", probe)
            self.assertNotIn("#include <stdio.h>", probe)
            self.assertNotIn("VT_EVENT_MAX", probe)

        self.assertIn("_Static_assert", c_probe)
        self.assertIn("_Alignof", c_probe)
        self.assertIn("static_assert", cxx_probe)
        self.assertIn("alignof", cxx_probe)
        self.assertIn("__builtin_offsetof", cxx_probe)
        self.assertIn("#include <stddef.h>", cxx_probe)
        self.assertNotIn("#include <cstddef>", cxx_probe)

    def test_runner_has_closed_isolated_three_by_seven_matrix(self) -> None:
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
            "readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "readonly CANDIDATE_CC=/usr/bin/gcc",
            "readonly EXPECTED_HEADER_COUNT=3",
            "readonly EXPECTED_PROFILE_COUNT=7",
            "readonly EXPECTED_ROW_COUNT=21",
            "readonly -a WRAPPER_HEADERS=(sys/kd.h sys/soundcard.h sys/vt.h)",
            "readonly -a UAPI_HEADERS=(linux/kd.h linux/soundcard.h linux/vt.h)",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "run_musl_oracle.sh",
            "run_linux_5_10_uapi.sh",
            "-nostdinc",
            "-nostdinc++",
            "-u GCC_SPECS",
            "candidate trace reached pinned musl despite -nostdinc",
            "candidate trace escaped project/builtin/Linux-5.10 roots",
            "reference trace escaped musl/builtin/Linux-5.10 roots",
            "project endian.h through linux/soundcard.h",
            "PASS (%s rows; compile-only)",
        ):
            self.assertIn(phrase, runner)
        self.assertNotIn("-I /usr/include", runner)
        self.assertNotIn("--report-only", runner)

    def test_dispatcher_exposes_the_pass_required_matrix_command(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for phrase in (
            "uapi-wrapper-matrix)",
            "run_uapi_wrapper_matrix()",
            "run_uapi_wrapper_matrix",
            "run_uapi_wrapper_matrix.sh",
            "uapi-wrapper-matrix takes no arguments",
        ):
            self.assertIn(phrase, dispatcher)


if __name__ == "__main__":
    unittest.main()
