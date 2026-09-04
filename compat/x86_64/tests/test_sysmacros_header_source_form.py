#!/usr/bin/env python3
"""Pinned-musl x86 and frozen non-x86 source contract for ``sys/sysmacros.h``."""

from __future__ import annotations

import hashlib
import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "sysmacros.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_sysmacros_header_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "sysmacros_header_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "sysmacros_header_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

MUSL_X86_SHA256 = "5fda7d3b3af6553c9499ffb428c42e5d0da1e4e8627bd3c2211f4aaa7525a37e"
LEGACY_AARCH64_SHA256 = "b9ba9f11ba75e7557c3809a5539ba0633477a3d64f7ce6a21f62d16439a07519"


def split_x86_branch(path: Path) -> tuple[bytes, bytes]:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if not lines or lines[0] != "#if defined(__x86_64__)\n":
        raise AssertionError(f"{path} must begin with its x86 source-form branch")

    depth = 1
    x86: list[str] = []
    legacy: list[str] = []
    in_legacy = False
    for line in lines[1:]:
        if not in_legacy and line.startswith("#else") and depth == 1:
            in_legacy = True
            continue
        if in_legacy and line.startswith("#endif") and depth == 1:
            break
        if in_legacy:
            legacy.append(line)
        else:
            x86.append(line)
        if line.startswith(("#if", "#ifdef", "#ifndef")):
            depth += 1
        elif line.startswith("#endif"):
            depth -= 1
    else:
        raise AssertionError(f"{path} is missing its closing x86 source-form branch")
    return "".join(x86).encode(), "".join(legacy).encode()


class SysmacrosHeaderSourceFormTests(unittest.TestCase):
    def test_x86_body_matches_pinned_musl_and_non_x86_body_stays_frozen(self) -> None:
        x86, legacy = split_x86_branch(HEADER)
        self.assertEqual(hashlib.sha256(x86).hexdigest(), MUSL_X86_SHA256)
        self.assertEqual(hashlib.sha256(legacy).hexdigest(), LEGACY_AARCH64_SHA256)

    def test_direct_c_and_cpp_probes_cover_the_device_macro_round_trip(self) -> None:
        for probe_path in (C_PROBE, CXX_PROBE):
            probe = probe_path.read_text(encoding="utf-8")
            for required in (
                "#include <sys/sysmacros.h>",
                "major(makedev(0x12345U, 0x6789abU))",
                "minor(makedev(0x12345U, 0x6789abU))",
            ):
                self.assertIn(required, probe, probe_path.name)
        self.assertIn(
            'extern "C" int crabc_x86_sysmacros_header_source_form_probe_cpp()',
            CXX_PROBE.read_text(encoding="utf-8"),
        )

    def test_runner_is_native_isolated_all_profile_and_has_aarch64_freeze_proof(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "AARCH64_CC=/usr/bin/clang",
            "EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "extract_x86_branch",
            "check_exact_x86_form",
            "check_aarch64_trace",
            "expected_aarch64_surface",
            "_SYS_SYSMACROS_H|_CRABC_SYS_SYSMACROS_H|major|minor|makedev",
            "-nostdinc",
            "-nostdinc++",
            "run_musl_oracle.sh",
            "compile-only",
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

    def test_dispatcher_and_closed_runner_roster_expose_the_native_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for required in (
            "sysmacros-header-source-form)",
            "run_sysmacros_header_source_form()",
            "run_sysmacros_header_source_form.sh",
            "sysmacros-header-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
