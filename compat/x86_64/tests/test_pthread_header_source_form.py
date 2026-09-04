#!/usr/bin/env python3
"""Focused contract for the x86 direct ``<pthread.h>`` source-form gate."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PTHREAD_HEADER = ROOT / "include" / "pthread.h"
SCHED_HEADER = ROOT / "include" / "sched.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_pthread_header_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "pthread_header_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "pthread_header_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

PTHREAD_X86_MARKER = "#if defined(__x86_64__) /* pinned-musl 1.2.6 x86-64 direct-header source form */\n"
PTHREAD_X86_END = "\n#else /* frozen AArch64 public header */\n"
SCHED_X86_MARKER = "#if defined(__x86_64__) /* pinned-musl 1.2.6 x86-64 sched_param source form */\n"
SCHED_X86_END = "\n#else /* frozen AArch64 public header */\n"


class PthreadHeaderSourceFormTests(unittest.TestCase):
    def test_x86_pthread_branch_keeps_pinned_direct_forms_and_signal_boundary(self) -> None:
        header = PTHREAD_HEADER.read_text(encoding="utf-8")
        self.assertIn(PTHREAD_X86_MARKER, header)
        x86_form = header.split(PTHREAD_X86_MARKER, 1)[1].split(PTHREAD_X86_END, 1)[0]

        for required in (
            "#include <features.h>",
            "#include <bits/alltypes.h>",
            "#include <sched.h>",
            "#include <time.h>",
            "#define __NEED_pthread_t",
            "#define __NEED_pthread_rwlock_t",
            "#define __NEED_size_t",
            "_Noreturn void pthread_exit(void *);",
            "int pthread_getschedparam(pthread_t, int *__restrict, struct sched_param *__restrict);",
            "int pthread_mutex_getprioceiling(const pthread_mutex_t *__restrict, int *__restrict);",
            "int pthread_attr_getstack(const pthread_attr_t *__restrict, void **__restrict, size_t *__restrict);",
            "int pthread_attr_setschedparam(pthread_attr_t *__restrict, const struct sched_param *__restrict);",
            "#define pthread_cleanup_push(f, x) do { struct __ptcb __cb; _pthread_cleanup_push(&__cb, f, x);",
            "#define PTHREAD_MUTEX_STALLED 0",
            "#define PTHREAD_MUTEX_ROBUST 1",
        ):
            self.assertIn(required, x86_form)
        self.assertNotIn("pthread_sigmask", x86_form)
        self.assertNotIn("pthread_kill", x86_form)
        self.assertNotIn("#include <signal.h>", x86_form)

    def test_non_x86_pthread_branch_retains_the_frozen_legacy_surface(self) -> None:
        header = PTHREAD_HEADER.read_text(encoding="utf-8")
        legacy_form = header.split(PTHREAD_X86_END, 1)[1]
        for required in (
            "#include <sys/types.h>",
            "#ifndef _PTHREAD_TYPES_DEFINED",
            "void pthread_exit(void *) __attribute__((__noreturn__));",
            "int pthread_sigmask(int, const sigset_t *__restrict, sigset_t *__restrict);",
            "int pthread_kill(pthread_t, int);",
        ):
            self.assertIn(required, legacy_form)

    def test_x86_sched_param_source_coordinate_matches_the_pinned_transitive_form(self) -> None:
        header = SCHED_HEADER.read_text(encoding="utf-8")
        self.assertIn(SCHED_X86_MARKER, header)
        x86_form = header.split(SCHED_X86_MARKER, 1)[1].split(SCHED_X86_END, 1)[0]
        self.assertIn("#if _REDIR_TIME64", x86_form)
        self.assertIn("\tstruct {\n\t\ttime_t __reserved1;\n\t\tlong __reserved2;\n\t} __reserved2[2];", x86_form)
        self.assertEqual(header.splitlines()[24], "\tstruct {")

    def test_direct_c_and_cpp_probes_name_layout_linkage_and_signal_ownership(self) -> None:
        c_probe = C_PROBE.read_text(encoding="utf-8")
        cpp_probe = CXX_PROBE.read_text(encoding="utf-8")
        for probe in (c_probe, cpp_probe):
            self.assertIn("#include <pthread.h>", probe)
            self.assertIn("#include <signal.h>", probe)
            self.assertIn("CRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_WITNESS", probe)
            self.assertIn("pthread_sigmask", probe)
            self.assertIn("pthread_kill", probe)
            self.assertIn("sizeof(struct sched_param) == 48", probe)
            self.assertIn("pthread_attr_getschedparam", probe)
        self.assertIn('extern "C" int crabc_x86_64_pthread_header_source_form_probe_cpp', cpp_probe)

    def test_runner_is_isolated_all_profile_and_header_only(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "-nostdinc",
            "-nostdinc++",
            "check_pthread_topology",
            "check_no_direct_signal_visibility",
            "assert_direct_signal_witness_hidden",
            "assert_signal_owner_witness",
            "check_frozen_aarch64_branch_syntax",
            "-U__x86_64__ -D__aarch64__",
            "pthread declaration source forms differ from pinned musl",
            "C++ probe lost unmangled",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("libcrabc-libc.a", runner)
        self.assertNotIn("run_libc_pthread", runner)

        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_dispatcher_exposes_the_native_pthread_source_form_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for required in (
            "pthread-header-source-form  verify x86 <pthread.h> pinned-musl direct source forms",
            "    pthread-header-source-form) ;;",
            "run_pthread_header_source_form()",
            "run_pthread_header_source_form.sh",
            "pthread-header-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
