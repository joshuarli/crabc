#!/usr/bin/env python3
"""Pinned-musl x86 and frozen non-x86 source contract for ``sys/cachectl.h``."""

from __future__ import annotations

import hashlib
import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "cachectl.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_cachectl_header_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "cachectl_header_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "cachectl_header_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

# Pinned musl has one space-only separator, prohibited by this repository's
# checked whitespace policy. The native runner permits only that exact
# non-token normalization and compares every remaining source byte.
X86_MUSL_NORMALIZED_SHA256 = "cd7adcc34c66a04704e940a602fd6e1e16d5820a9d03ab9839ebd505cc1f7489"
LEGACY_SHA256 = "7967a76590f4bf8c82a8ced76124ad0b797453248c8f83172a7e64d451d02e08"


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


class CachectlHeaderSourceFormTests(unittest.TestCase):
    def test_x86_body_matches_normalized_pinned_musl_and_non_x86_body_stays_frozen(self) -> None:
        x86, legacy = split_x86_branch(HEADER)
        self.assertNotIn(b"\n \n", x86)
        self.assertEqual(hashlib.sha256(x86).hexdigest(), X86_MUSL_NORMALIZED_SHA256)
        self.assertEqual(hashlib.sha256(legacy).hexdigest(), LEGACY_SHA256)

    def test_direct_c_and_cpp_probes_keep_the_no_provider_declarations_visible(self) -> None:
        for probe_path in (C_PROBE, CXX_PROBE):
            probe = probe_path.read_text(encoding="utf-8")
            for required in (
                "#include <sys/cachectl.h>",
                "ICACHE == 1",
                "DCACHE == 2",
                "BCACHE == 3",
                "CACHEABLE == 0",
                "UNCACHEABLE == 1",
                "cachectl",
                "cacheflush",
                "_flush_cache",
            ):
                self.assertIn(required, probe, probe_path.name)
        self.assertIn('extern "C" int crabc_x86_cachectl_header_source_form_probe_cpp()', CXX_PROBE.read_text(encoding="utf-8"))

    def test_runner_is_native_isolated_and_all_profile(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "extract_x86_branch",
            "check_exact_x86_form",
            "extract_macro_surface",
            "check_cxx_linkage",
            "_SYS_CACHECTL_H|_CRABC_SYS_CACHECTL_H|ICACHE|DCACHE|BCACHE|CACHEABLE|UNCACHEABLE",
            "-nostdinc",
            "-nostdinc++",
            "run_musl_oracle.sh",
            "oracle-declared-no-provider",
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

    def test_dispatcher_exposes_the_native_cachectl_source_form_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for required in (
            "cachectl-header-source-form)",
            "run_cachectl_header_source_form()",
            "run_cachectl_header_source_form.sh",
            "cachectl-header-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
