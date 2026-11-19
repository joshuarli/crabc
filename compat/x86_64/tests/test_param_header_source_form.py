#!/usr/bin/env python3
"""Pinned-musl source-form contract for x86 ``<sys/param.h>``."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PARAM_HEADER = ROOT / "include" / "sys" / "param.h"
RESOURCE_HEADER = ROOT / "include" / "sys" / "resource.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_param_header_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "param_header_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "param_header_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

X86_MUSL_PARAM_FORM = """\
#ifndef _SYS_PARAM_H
#define _SYS_PARAM_H

#define MAXSYMLINKS 20
#define MAXHOSTNAMELEN 64
#define MAXNAMLEN 255
#define MAXPATHLEN 4096
#define NBBY 8
#define NGROUPS 32
#define CANBSIZ 255
#define NOFILE 256
#define NCARGS 131072
#define DEV_BSIZE 512
#define NOGROUP (-1)

#undef MIN
#undef MAX
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define __bitop(x,i,o) ((x)[(i)/8] o (1<<(i)%8))
#define setbit(x,i) __bitop(x,i,|=)
#define clrbit(x,i) __bitop(x,i,&=~)
#define isset(x,i) __bitop(x,i,&)
#define isclr(x,i) !isset(x,i)

#define howmany(n,d) (((n)+((d)-1))/(d))
#define roundup(n,d) (howmany(n,d)*(d))
#define powerof2(n) !(((n)-1) & (n))

#include <sys/resource.h>
#include <endian.h>
#include <limits.h>

#endif
"""


class ParamHeaderSourceFormTests(unittest.TestCase):
    def test_x86_param_branch_retains_the_complete_pinned_musl_source_form(self) -> None:
        header = PARAM_HEADER.read_text(encoding="utf-8")
        self.assertEqual(header, X86_MUSL_PARAM_FORM)
        self.assertNotIn("__x86_64__", header)
        self.assertNotIn("__aarch64__", header)

    def test_resource_child_selector_is_shared(self) -> None:
        header = RESOURCE_HEADER.read_text(encoding="utf-8")
        self.assertIn("#define RUSAGE_SELF 0\n#define RUSAGE_CHILDREN (-1)\n#define RUSAGE_THREAD 1", header)
        self.assertEqual(header.count("#define RUSAGE_CHILDREN"), 1)

    def test_direct_c_and_cpp_probes_cover_param_and_direct_resource_boundaries(self) -> None:
        for probe_path in (C_PROBE, CXX_PROBE):
            probe = probe_path.read_text(encoding="utf-8")
            self.assertIn("CRABC_PARAM_HEADER_SOURCE_FORM_DIRECT_RESOURCE", probe)
            self.assertIn("#include <sys/param.h>", probe)
            self.assertIn("#include <sys/resource.h>", probe)
            self.assertIn("_SYS_PARAM_H", probe)
            self.assertIn("_CRABC_SYS_PARAM_H", probe)
            self.assertIn("RUSAGE_CHILDREN == -1", probe)
            self.assertIn("setbit(bits, 9)", probe)
            self.assertIn("clrbit(bits, 9)", probe)
            self.assertIn("howmany(17, 8)", probe)
            self.assertIn("roundup(17, 8)", probe)
            self.assertIn("powerof2(8)", probe)
        self.assertIn(
            "crabc_x86_param_header_source_form_probe_cpp", CXX_PROBE.read_text(encoding="utf-8")
        )

    def test_runner_is_native_isolated_and_all_profile(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "-nostdinc",
            "-nostdinc++",
            "sys/param.h sys/resource.h endian.h limits.h",
            "CRABC_PARAM_HEADER_SOURCE_FORM_DIRECT_RESOURCE",
            "RUSAGE_CHILDREN (-1)",
            "param macro source forms differ from pinned musl",
            "direct resource macro source form differs from pinned musl",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-I /usr/include", runner)
        self.assertNotIn("libcrabc-libc.a", runner)

        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_dispatcher_exposes_the_native_source_form_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for required in (
            "param-header-source-form)",
            "run_param_header_source_form()",
            "run_param_header_source_form.sh",
            "param-header-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
