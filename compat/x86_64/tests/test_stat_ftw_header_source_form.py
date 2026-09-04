#!/usr/bin/env python3
"""Structural contract for the x86 stat/ftw source-form matrix."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_stat_ftw_header_source_form.sh"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class StatFtwHeaderSourceFormTests(unittest.TestCase):
    def test_x86_stat_branch_retains_pinned_musl_public_forms(self) -> None:
        header = (ROOT / "include/sys/stat.h").read_text(encoding="utf-8")

        for required in (
            "#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)",
            "#define S_ISCHR(mode)  (((mode) & S_IFMT) == S_IFCHR)",
            "#define S_ISBLK(mode)  (((mode) & S_IFMT) == S_IFBLK)",
            "#define S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)",
            "#define S_ISFIFO(mode) (((mode) & S_IFMT) == S_IFIFO)",
            "#define S_ISLNK(mode)  (((mode) & S_IFMT) == S_IFLNK)",
            "#define S_ISSOCK(mode) (((mode) & S_IFMT) == S_IFSOCK)",
            "int stat(const char *__restrict, struct stat *__restrict);",
            "int lstat(const char *__restrict, struct stat *__restrict);",
            "int fstatat(int, const char *__restrict, struct stat *__restrict, int);",
            "#define S_IREAD S_IRUSR",
            "#define S_IWRITE S_IWUSR",
            "#define S_IEXEC S_IXUSR",
            "#define stat64 stat",
            "#define fstatat64 fstatat",
            "#define fsblkcnt64_t fsblkcnt_t",
            "#define fsfilcnt64_t fsfilcnt_t",
            "__REDIR(stat, __stat_time64);",
        ):
            self.assertIn(required, header)

        self.assertIn(
            "#if !defined(__x86_64__) && (defined(_GNU_SOURCE) || defined(_BSD_SOURCE))",
            header,
        )
        self.assertIn("#if defined(__x86_64__) && defined(_LARGEFILE64_SOURCE)", header)

    def test_x86_bits_stat_branch_is_intentionally_unguarded(self) -> None:
        header = (ROOT / "include/bits/stat.h").read_text(encoding="utf-8")
        x86_branch, aarch64_branch = header.split("#else\n", maxsplit=1)

        self.assertTrue(x86_branch.startswith("#if defined(__x86_64__) && defined(__LP64__)\n"))
        self.assertIn(
            "/* copied from kernel definition, but with padding replaced\n"
            " * by the corresponding correctly-sized userspace types. */",
            x86_branch,
        )
        self.assertIn("unsigned int    __pad0;", x86_branch)
        self.assertNotIn("_BITS_STAT_H", x86_branch)
        self.assertIn("#ifndef _BITS_STAT_H", aarch64_branch)

    def test_ftw_source_remains_the_exact_pinned_musl_transitive_leaf(self) -> None:
        header = (ROOT / "include/ftw.h").read_text(encoding="utf-8")
        self.assertEqual(
            header,
            """#ifndef _FTW_H
#define\t_FTW_H

#ifdef __cplusplus
extern \"C\" {
#endif

#include <features.h>
#include <sys/stat.h>

#define FTW_F   1
#define FTW_D   2
#define FTW_DNR 3
#define FTW_NS  4
#define FTW_SL  5
#define FTW_DP  6
#define FTW_SLN 7

#define FTW_PHYS  1
#define FTW_MOUNT 2
#define FTW_CHDIR 4
#define FTW_DEPTH 8

struct FTW {
\tint base;
\tint level;
};

int ftw(const char *, int (*)(const char *, const struct stat *, int), int);
int nftw(const char *, int (*)(const char *, const struct stat *, int, struct FTW *), int, int);

#if defined(_LARGEFILE64_SOURCE)
#define ftw64 ftw
#define nftw64 nftw
#endif

#ifdef __cplusplus
}
#endif

#endif
""",
        )

    def test_runner_keeps_the_complete_isolated_profile_matrix(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "-nostdinc",
            "-nostdinc++",
            "c11-gnu cxx17-gnu c11-gnu-largefile cxx17-gnu-largefile c11-strict cxx17-strict c11-posix-2008 c11-xopen-700 c11-bsd",
            "check_macro_form",
            "check_legacy_aliases",
            "check_largefile_aliases",
            "extract_macro_forms",
            "check_topology",
            "bits/stat.h",
            "time.h sys/types.h fcntl.h",
            "stat/lstat/fstatat declaration forms differ from pinned musl",
            "C++ source-form probe lost C linkage",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("libcrabc-libc.a", runner)
        self.assertNotIn("run_libc_filesystem_traversal.sh", runner)

    def test_runner_is_an_executable_shell_script(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_dispatcher_exposes_the_source_form_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        self.assertIn(
            "  stat-ftw-header-source-form  verify x86 sys/stat.h through ftw.h pinned-musl source forms",
            dispatcher,
        )
        self.assertIn("    stat-ftw-header-source-form) ;;", dispatcher)
        self.assertIn("run_stat_ftw_header_source_form()", dispatcher)
        self.assertIn(
            '    stat-ftw-header-source-form)\n'
            '        [ "$#" -eq 0 ] || fail "stat-ftw-header-source-form takes no arguments"',
            dispatcher,
        )


if __name__ == "__main__":
    unittest.main()
