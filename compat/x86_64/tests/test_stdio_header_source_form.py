#!/usr/bin/env python3
"""Pinned-musl source-form contract for x86 stdio public headers."""

from __future__ import annotations

import hashlib
import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
STDIO = ROOT / "include" / "stdio.h"
STDIO_EXT = ROOT / "include" / "stdio_ext.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_stdio_header_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "stdio_header_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "stdio_header_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

X86_MARKER = "#if defined(__x86_64__) /* pinned-musl form; the AArch64 branch stays frozen */\n"
NON_X86_SEPARATOR = "\n#else /* AArch64 frozen form */\n"
MUSL_SHA256 = {
    STDIO: "f158cf8fed586a99533f0d16de2f5e0b4678a3b5bd2aac619c1d277e7bc2811b",
    STDIO_EXT: "d16a5f865a20b7ed68803f3da8fdc5011989e6fb1ecae31049654423899e4ffd",
}
FROZEN_AARCH64_SHA256 = {
    STDIO: "81109abb8fd51d1199dbef1ffba360b458cb860b560a12af61c48a63222cfdd6",
    STDIO_EXT: "aeb3863aec4b1cf7e6813c8a73b4081ad4f2a7ced732729caa3aa2bd3a07163c",
}


def x86_and_non_x86_forms(header: Path) -> tuple[bytes, bytes]:
    source = header.read_text(encoding="utf-8")
    _, marker, rest = source.partition(X86_MARKER)
    if not marker:
        raise AssertionError(f"{header.name} lacks the x86 pinned-musl branch")
    x86_form, separator, non_x86_with_closer = rest.partition(NON_X86_SEPARATOR)
    if not separator:
        raise AssertionError(f"{header.name} lacks its frozen non-x86 branch")
    non_x86_form, closer, trailing = non_x86_with_closer.rpartition("\n#endif\n")
    if not closer or trailing:
        raise AssertionError(f"{header.name} lacks its architecture-branch closer")
    return (x86_form + "\n").encode(), (non_x86_form + "\n").encode()


class StdioHeaderSourceFormTests(unittest.TestCase):
    def test_x86_branch_is_exact_pinned_musl_and_non_x86_is_frozen(self) -> None:
        for header in (STDIO, STDIO_EXT):
            x86_form, non_x86_form = x86_and_non_x86_forms(header)
            self.assertEqual(
                hashlib.sha256(x86_form).hexdigest(), MUSL_SHA256[header], header.name
            )
            self.assertEqual(
                hashlib.sha256(non_x86_form).hexdigest(),
                FROZEN_AARCH64_SHA256[header],
                header.name,
            )

    def test_direct_c_and_cpp_probes_name_the_source_sensitive_contract(self) -> None:
        for probe_path in (C_PROBE, CXX_PROBE):
            probe = probe_path.read_text(encoding="utf-8")
            for required in (
                "#include <stdio.h>",
                "#include <stdio_ext.h>",
                "__isoc_va_list",
                "__restrict",
                "asprintf",
                "vasprintf",
                "_STDIO_EXT_H",
                "_CRABC_STDIO_EXT_H",
                "fopen64",
                "freopen64",
            ):
                self.assertIn(required, probe)
        self.assertIn(
            'extern "C" int crabc_x86_stdio_header_source_form_probe_cpp',
            CXX_PROBE.read_text(encoding="utf-8"),
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
            "__isoc_va_list",
            "asprintf",
            "_STDIO_EXT_H",
            "_CRABC_STDIO_EXT_H",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-I /usr/include", runner)

        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_dispatcher_exposes_the_native_header_source_form_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for required in (
            "stdio-header-source-form)",
            "run_stdio_header_source_form()",
            "run_stdio_header_source_form.sh",
            "stdio-header-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
