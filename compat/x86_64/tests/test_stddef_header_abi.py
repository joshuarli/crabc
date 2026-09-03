#!/usr/bin/env python3
"""Focused structural contract for the x86 pinned-musl <stddef.h> matrix."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
C_PROBE = ROOT / "compat" / "x86_64" / "stddef_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "stddef_header_abi_probe.cpp"
RUNNER = ROOT / "compat" / "x86_64" / "run_stddef_header_abi.sh"
STDDEF_HEADER = ROOT / "include" / "stddef.h"


class StddefHeaderAbiTests(unittest.TestCase):
    def test_x86_header_uses_musl_request_body_and_preserves_aarch64_fallback(self) -> None:
        header = STDDEF_HEADER.read_text(encoding="utf-8")

        self.assertTrue(header.startswith("#if defined(__x86_64__)\n"))
        for phrase in (
            "#ifndef _STDDEF_H\n",
            "#define NULL ((void*)0)\n",
            "#define __NEED_ptrdiff_t\n",
            "#define __NEED_size_t\n",
            "#define __NEED_wchar_t\n",
            "#define __NEED_max_align_t\n",
            "#include <bits/alltypes.h>\n",
            "#if __GNUC__ > 3\n",
            "#define offsetof(type, member) __builtin_offsetof(type, member)\n",
        ):
            self.assertIn(phrase, header)

        self.assertIn("#else\n\n#ifndef _CRABC_STDDEF_H\n", header)
        self.assertIn("typedef __SIZE_TYPE__ size_t;\n", header)
        self.assertIn("typedef __PTRDIFF_TYPE__ ptrdiff_t;\n", header)
        self.assertIn("typedef __WCHAR_TYPE__ wchar_t;\n", header)
        self.assertIn("__max_align_ll", header)

    def test_probes_cover_c_and_cpp_stddef_contract(self) -> None:
        c_probe = C_PROBE.read_text(encoding="utf-8")
        cxx_probe = CXX_PROBE.read_text(encoding="utf-8")

        for probe in (c_probe, cxx_probe):
            self.assertIn("#include <stddef.h>", probe)
            self.assertIn("_STDDEF_H", probe)
            self.assertIn("_CRABC_STDDEF_H", probe)
            self.assertIn("__NEED_max_align_t", probe)
            self.assertIn("sizeof(max_align_t) == 32", probe)
            self.assertIn("offsetof(", probe)
            self.assertIn("crabc_stddef_null_pointer", probe)
            self.assertNotIn("main(", probe)

        self.assertIn("_Generic", c_probe)
        self.assertIn("_Alignof", c_probe)
        self.assertIn("__is_same", cxx_probe)
        self.assertIn("decltype(NULL)", cxx_probe)
        self.assertIn("alignof", cxx_probe)

    def test_runner_is_a_closed_seven_profile_compile_only_gate(self) -> None:
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
            "readonly MUSL_ROOT=/opt/musl-1.2.6",
            "readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "readonly CANDIDATE_CC=/usr/bin/gcc",
            "readonly -a PROFILES=(c11-strict c11-posix-2008 c11-xopen-700 c11-gnu c11-bsd cxx17-strict cxx17-gnu)",
            "-nostdinc",
            "-nostdinc++",
            "-idirafter",
            "-H",
            "stddef.h bits/alltypes.h",
            "makes no claim about archive linkage nor",
            "runtime allocation behavior",
            "compile-only evidence",
            "pinned-musl/project C/C++ <stddef.h> ABI",
        ):
            self.assertIn(phrase, runner)


if __name__ == "__main__":
    unittest.main()
