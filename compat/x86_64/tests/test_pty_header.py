#!/usr/bin/env python3
"""Regression for the pinned musl x86 <pty.h> source and ABI form."""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
INCLUDE = ROOT / "include"
PTY_HEADER_SHA256 = "b5a3539229b3c2f578febf901f8971518489d97ba706cdd5aa61ec536c4ffc7f"


class PtyHeaderTests(unittest.TestCase):
    def test_header_matches_pinned_musl_source_form(self) -> None:
        self.assertEqual(hashlib.sha256((INCLUDE / "pty.h").read_bytes()).hexdigest(), PTY_HEADER_SHA256)

    def test_c_and_cpp_declarations_compile_with_c_linkage(self) -> None:
        c_source = """
#include <pty.h>
int (*openpty_type)(int *, int *, char *, const struct termios *, const struct winsize *) = openpty;
int (*forkpty_type)(int *, char *, const struct termios *, const struct winsize *) = forkpty;
"""
        cpp_source = """
#include <pty.h>
extern "C" int use_openpty(int **, int *, char *, const struct termios *, const struct winsize *);
extern "C" int use_forkpty(int *, char *, const struct termios *, const struct winsize *);
static_assert(__is_same(decltype(&openpty), int (*)(int *, int *, char *, const struct termios *, const struct winsize *)));
static_assert(__is_same(decltype(&forkpty), int (*)(int *, char *, const struct termios *, const struct winsize *)));
"""
        with tempfile.TemporaryDirectory(prefix="crabc-pty-header-") as temporary:
            directory = Path(temporary)
            c_path = directory / "probe.c"
            cpp_path = directory / "probe.cpp"
            c_path.write_text(c_source, encoding="utf-8")
            cpp_path.write_text(cpp_source, encoding="utf-8")
            c_result = subprocess.run(
                ["clang", "-std=c11", "-nostdinc", "-I", str(INCLUDE), "-fsyntax-only", str(c_path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            cpp_result = subprocess.run(
                ["clang++", "-std=c++17", "-nostdinc", "-I", str(INCLUDE), "-fsyntax-only", str(cpp_path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(c_result.returncode, 0, c_result.stderr)
        self.assertEqual(cpp_result.returncode, 0, cpp_result.stderr)


if __name__ == "__main__":
    unittest.main()
