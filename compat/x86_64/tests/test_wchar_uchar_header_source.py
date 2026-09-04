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

X86_BRANCH = "#if defined(__x86_64__)\n"
OUTER_ENDIF = "#endif\n"

# Exact complete include-file digests from pinned musl 1.2.6 release commit
# 9fa28ece75d8a2191de7c5bb53bed224c5947417.  The branch includes the final
# newline of its inner include guard but excludes the outer architecture guard.
MUSL_WCHAR_SHA256 = "18c5adbb8fe770aeccc0a1721b03352c6a07fb8ea373a6fcdfe88be76ca5e312"
MUSL_UCHAR_SHA256 = "53230de6c8fa9309ddd35de9ee75fcaac703b72fc0422117ad492a717d3aa77d"

# The legacy bodies are the AArch64 fallbacks.  Pinning them prevents an x86
# ownership change from silently altering the only public crabc platform.
AARCH64_WCHAR_SHA256 = "708d44f4a155e8560f69fe7206dd386f1ca5151da79d8d7872efcb6e33904e9d"
AARCH64_UCHAR_SHA256 = "8b56af79ab200dd1afc46306d9ed510100dd169be6d4b2dd9ec31293c9f13433"


def split_header_branches(header: str, guard: str) -> tuple[str, str]:
    """Return exact x86 and AArch64 bodies from one explicit architecture fence."""

    if not header.startswith(X86_BRANCH):
        raise ValueError("header does not start with an x86 ownership branch")
    separator = f"\n#endif\n#else\n#ifndef {guard}\n"
    x86_without_guard, fallback_with_outer_guard = header[len(X86_BRANCH) :].split(
        separator, 1
    )
    x86_body = x86_without_guard + "\n#endif\n"
    fallback_with_outer_guard = f"#ifndef {guard}\n" + fallback_with_outer_guard
    if not fallback_with_outer_guard.endswith(OUTER_ENDIF):
        raise ValueError("header does not end with the outer architecture guard")
    return x86_body, fallback_with_outer_guard[: -len(OUTER_ENDIF)]


class WcharUcharHeaderSourceTests(unittest.TestCase):
    def test_x86_branches_are_exact_pinned_musl_sources(self) -> None:
        wchar_x86, _ = split_header_branches(
            WCHAR_HEADER.read_text(encoding="utf-8"), "_WCHAR_H"
        )
        uchar_x86, _ = split_header_branches(
            UCHAR_HEADER.read_text(encoding="utf-8"), "_UCHAR_H"
        )

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

    def test_aarch64_fallbacks_remain_the_legacy_complete_bodies(self) -> None:
        _, wchar_fallback = split_header_branches(
            WCHAR_HEADER.read_text(encoding="utf-8"), "_WCHAR_H"
        )
        _, uchar_fallback = split_header_branches(
            UCHAR_HEADER.read_text(encoding="utf-8"), "_UCHAR_H"
        )

        self.assertEqual(
            hashlib.sha256(wchar_fallback.encode()).hexdigest(), AARCH64_WCHAR_SHA256
        )
        self.assertEqual(
            hashlib.sha256(uchar_fallback.encode()).hexdigest(), AARCH64_UCHAR_SHA256
        )
        self.assertIn(
            "/* POSIX.1-2024 keeps wide classification in <wctype.h>, not <wchar.h>. */\n",
            wchar_fallback,
        )
        self.assertIn("size_t mbstowcs(wchar_t *, const char *, size_t);\n", wchar_fallback)
        self.assertIn("typedef unsigned int char32_t;\n", uchar_fallback)
        self.assertIn("size_t c16rtomb(char *, char16_t, mbstate_t *);\n", uchar_fallback)

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
