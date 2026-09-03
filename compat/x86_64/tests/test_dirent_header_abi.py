#!/usr/bin/env python3
"""Focused structural contract for the x86 pinned-musl <dirent.h> matrix."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
C_PROBE = ROOT / "compat" / "x86_64" / "dirent_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "dirent_header_abi_probe.cpp"
RUNNER = ROOT / "compat" / "x86_64" / "run_dirent_header_abi.sh"


class DirentHeaderAbiTests(unittest.TestCase):
    def test_probes_fix_the_oracle_layout_signatures_and_visibility_contract(self) -> None:
        c_probe = C_PROBE.read_text(encoding="utf-8")
        cxx_probe = CXX_PROBE.read_text(encoding="utf-8")

        for probe in (c_probe, cxx_probe):
            for phrase in (
                "sizeof(struct dirent) == 280",
                "d_ino) == 0",
                "d_off) == 8",
                "d_reclen) == 16",
                "d_type) == 18",
                "d_name) == 19",
                "sizeof(struct posix_dent) == 24",
                "sizeof(reclen_t) == 2",
                "d_fileno",
                "DT_UNKNOWN == 0",
                "DT_WHT == 14",
                "posix_getdents",
                "readdir_r",
                "alphasort",
                "scandir",
                "CRABC_DIRENT_SEEK_TELL_VISIBLE",
                "CRABC_DIRENT_SEEK_TELL_HIDDEN",
                "CRABC_DIRENT_GETDENTS_VISIBLE",
                "CRABC_DIRENT_GETDENTS_HIDDEN",
                "CRABC_DIRENT_VERSIONSORT_VISIBLE",
                "CRABC_DIRENT_VERSIONSORT_HIDDEN",
                "IFTODT",
                "DTTOIF",
                "versionsort",
                "CRABC_DIRENT_EXPECT_HIDDEN_DECLARATIONS",
                "dirent64 must stay hidden without _LARGEFILE64_SOURCE",
                "_LARGEFILE64_SOURCE must expose dirent64",
                "readdir64_r",
                "scandir64",
                "alphasort64",
                "versionsort64",
                "off64_t",
                "ino64_t",
                "getdents64",
            ):
                self.assertIn(phrase, probe)
            self.assertNotIn("main(", probe)
        self.assertIn("__builtin_types_compatible_p", c_probe)
        self.assertIn("__is_same", cxx_probe)
        self.assertIn("__attribute__((used))", cxx_probe)
        self.assertIn("header-requested C spellings", cxx_probe)

    def test_runner_keeps_the_seven_profile_raw_gcc_matrix_and_header_only_scope(self) -> None:
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
            "readonly EXPECTED_BASE_PROFILE_COUNT=7",
            "readonly EXPECTED_LARGEFILE64_PROFILE_COUNT=4",
            "EXPECTED_SEEK_TELL_VISIBLE_PROFILE_COUNT=4",
            "EXPECTED_GETDENTS_VISIBLE_PROFILE_COUNT=3",
            "EXPECTED_VERSIONSORT_VISIBLE_PROFILE_COUNT=2",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "SEEK_TELL_VISIBLE_PROFILES=(c11-gnu cxx17-gnu c11-xopen-700 c11-bsd)",
            "GETDENTS_VISIBLE_PROFILES=(c11-gnu cxx17-gnu c11-bsd)",
            "VERSIONSORT_VISIBLE_PROFILES=(c11-gnu cxx17-gnu)",
            "LARGEFILE64_PROFILES=(c11-gnu-largefile64 cxx17-gnu-largefile64 c11-strict-largefile64 cxx17-strict-largefile64)",
            "-U_GNU_SOURCE' '-D_LARGEFILE64_SOURCE",
            "-nostdinc",
            "-nostdinc++",
            "bits/alltypes.h bits/dirent.h",
            "dirent.h features.h bits/alltypes.h",
            "candidate trace unexpectedly retained $root/sys/types.h",
            "CRABC_DIRENT_EXPECT_HIDDEN_DECLARATIONS",
            "unexpectedly exposed a hidden dirent declaration",
            "nm --undefined-only",
            "does not retain requested C spelling",
            "retained a mangled dirent reference",
            "header-requested C spellings",
            "does not claim x86 directory-stream runtime or archive linkage support",
        ):
            self.assertIn(phrase, runner)


if __name__ == "__main__":
    unittest.main()
