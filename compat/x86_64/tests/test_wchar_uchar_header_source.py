#!/usr/bin/env python3
"""Source-ownership contract for x86 pinned-musl wide-character headers."""

from __future__ import annotations

import hashlib
import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WCHAR_HEADER = ROOT / "include" / "wchar.h"
UCHAR_HEADER = ROOT / "include" / "uchar.h"
WIDE_RUNNER = ROOT / "compat" / "x86_64" / "run_wide_character_header_abi.sh"
UCHAR_STATEFUL_RUNNER = ROOT / "compat" / "x86_64" / "run_uchar_stateful_header_abi.sh"
C32RTOMB_RUNNER = ROOT / "compat" / "x86_64" / "run_c32rtomb_header_abi.sh"

MUSL_WCHAR_SHA256 = "18c5adbb8fe770aeccc0a1721b03352c6a07fb8ea373a6fcdfe88be76ca5e312"
MUSL_UCHAR_SHA256 = "53230de6c8fa9309ddd35de9ee75fcaac703b72fc0422117ad492a717d3aa77d"

class WcharUcharHeaderSourceTests(unittest.TestCase):
    def test_x86_branches_are_exact_pinned_musl_sources(self) -> None:
        wchar_x86 = WCHAR_HEADER.read_text(encoding="utf-8")
        uchar_x86 = UCHAR_HEADER.read_text(encoding="utf-8")

        self.assertEqual(
            hashlib.sha256(wchar_x86.encode()).hexdigest(), MUSL_WCHAR_SHA256
        )
        self.assertEqual(
            hashlib.sha256(uchar_x86.encode()).hexdigest(), MUSL_UCHAR_SHA256
        )
        self.assertNotIn("mbstowcs", wchar_x86)
        self.assertNotIn("wcstombs", wchar_x86)
        self.assertIn(
            "#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)\n",
            wchar_x86,
        )
        self.assertIn(
            "size_t c16rtomb(char *__restrict, char16_t, mbstate_t *__restrict);\n",
            uchar_x86,
        )

    def test_aarch64_adopts_the_complete_pinned_generic_headers(self) -> None:
        for header, digest in ((WCHAR_HEADER, MUSL_WCHAR_SHA256),
                               (UCHAR_HEADER, MUSL_UCHAR_SHA256)):
            source = header.read_text(encoding="utf-8")
            self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), digest)
            self.assertNotIn("__x86_64__", source)
            self.assertNotIn("__aarch64__", source)

    def test_header_gates_remain_native_pinned_musl_evidence(self) -> None:
        for runner in (WIDE_RUNNER, UCHAR_STATEFUL_RUNNER, C32RTOMB_RUNNER):
            syntax = subprocess.run(
                ["bash", "-n", str(runner)],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)
            self.assertEqual(stat.S_IMODE(runner.stat().st_mode), 0o755)

            source = runner.read_text(encoding="utf-8")
            self.assertIn("/opt/musl-1.2.6", source)
            self.assertIn("/usr/local/bin/crabc-x86_64-musl-gcc", source)

        uchar_runner = UCHAR_STATEFUL_RUNNER.read_text(encoding="utf-8")
        self.assertIn("x86 musl branch", uchar_runner)
        self.assertIn("AArch64 fallback", uchar_runner)


if __name__ == "__main__":
    unittest.main()
