#!/usr/bin/env python3
"""Structural contracts for the native x86 ``<ftw.h>`` profile gate."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86FtwHeaderAbiTests(unittest.TestCase):
    def test_c_and_cxx_probes_keep_the_x86_unconditional_declaration_contract(self) -> None:
        c_probe = (
            ROOT / "compat" / "x86_64" / "ftw_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "ftw_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")

        for probe in (c_probe, cxx_probe):
            for required in (
                "CRABC_FTW_REQUIRE_LARGEFILE_ALIASES",
                "#include <ftw.h>",
                "struct FTW",
                "FTW_CHDIR == 4",
                "FTW_DEPTH == 8",
                "nftw_signature",
                "crabc_nftw_reference",
            ):
                self.assertIn(required, probe)
            self.assertNotIn("CRABC_FTW_REQUIRE_FTW_HIDDEN", probe)

        self.assertIn("__builtin_types_compatible_p", c_probe)
        self.assertIn("_Static_assert", c_probe)
        self.assertIn("__is_same", cxx_probe)
        self.assertIn('extern "C" int nftw', cxx_probe)
        self.assertIn('extern "C" int ftw', cxx_probe)

    def test_runner_proves_unconditional_ftw_visibility(self) -> None:
        runner = (ROOT / "compat" / "x86_64" / "run_ftw_header_abi.sh").read_text(
            encoding="utf-8"
        )

        for required in (
            "Native Linux/x86-64 <ftw.h> ABI profile matrix",
            "readonly MUSL_ROOT=/opt/musl-1.2.6",
            "readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "readonly -a PROFILES=(c11-gnu cxx17-gnu c11-gnu-largefile cxx17-gnu-largefile c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)",
            "profile_requires_largefile_aliases",
            "_LARGEFILE64_SOURCE",
            "check_trace",
            "check_cxx_linkage",
            "C++ probe does not retain nftw's C spelling",
            "unconditional ftw visibility",
            "-c -o",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("PROJECT_FTW_VISIBLE", runner)
        self.assertNotIn("project_ftw_visible", runner)
        self.assertNotIn("frozen ftw visibility divergence", runner)
        self.assertNotIn("libcrabc-libc.a", runner)
        self.assertNotIn("run_libc_filesystem_traversal.sh", runner)


if __name__ == "__main__":
    unittest.main()
