#!/usr/bin/env python3
"""Pinned-musl source-form and frozen-AArch64 contract for ``sys/mount.h``."""

from __future__ import annotations

import hashlib
import re
import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "mount.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_mount_header_source_form.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "mount_header_source_form_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "mount_header_source_form_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"

# Pinned musl 1.2.6 selects the first body. The second hash is the pre-slice
# file, retained byte-for-byte to keep the frozen AArch64 public surface.
X86_MUSL_SHA256 = "f217bc6987f9e420949c31ece18720d14e80b71c87be1dcfd7542d052c43d992"
LEGACY_SHA256 = "b4b5e8c98a64fcfe6205f4c180f60d06a61b5497ca857255e57f688b0c1d75be"

OPEN = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef)\b")
CLOSE = re.compile(r"^\s*#\s*endif\b")
ELSE = re.compile(r"^\s*#\s*(?:else|elif)\b")


def split_x86_branch(path: Path) -> tuple[bytes, bytes]:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if not lines or lines[0] != "#if defined(__x86_64__)\n":
        raise AssertionError(f"{path} must begin with its x86 source-form branch")

    depth = 1
    x86: list[str] = []
    legacy: list[str] = []
    in_legacy = False
    for line in lines[1:]:
        if not in_legacy and ELSE.match(line) and depth == 1:
            in_legacy = True
            continue
        if in_legacy and CLOSE.match(line) and depth == 1:
            break
        if in_legacy:
            legacy.append(line)
        else:
            x86.append(line)
        if OPEN.match(line):
            depth += 1
        elif CLOSE.match(line):
            depth -= 1
    else:
        raise AssertionError(f"{path} is missing its closing x86 source-form branch")

    return "".join(x86).encode(), "".join(legacy).encode()


class MountHeaderSourceFormTests(unittest.TestCase):
    def test_x86_form_matches_pinned_musl_and_aarch64_form_stays_frozen(self) -> None:
        x86, legacy = split_x86_branch(HEADER)
        self.assertEqual(hashlib.sha256(x86).hexdigest(), X86_MUSL_SHA256)
        self.assertEqual(hashlib.sha256(legacy).hexdigest(), LEGACY_SHA256)

    def test_direct_probes_cover_mount_macro_type_and_c_linkage(self) -> None:
        c_probe = C_PROBE.read_text(encoding="utf-8")
        cpp_probe = CXX_PROBE.read_text(encoding="utf-8")
        for probe in (c_probe, cpp_probe):
            self.assertIn("#include <sys/mount.h>", probe)
            self.assertIn("_LINUX_MOUNT_H", probe)
            self.assertIn("MS_RMT_MASK", probe)
            self.assertIn("MS_MGC_VAL", probe)
            self.assertIn("MS_MGC_MSK", probe)
            self.assertIn("umount2", probe)
        self.assertIn("unsigned int", c_probe)
        self.assertIn("unsigned int", cpp_probe)
        self.assertIn('extern "C" int crabc_x86_mount_header_source_form_probe_cpp', cpp_probe)

    def test_runner_is_native_isolated_and_all_profile(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "EXPECTED_PROFILE_COUNT=7",
            "EXPECTED_MACRO_COUNT=52",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "-nostdinc",
            "-nostdinc++",
            "sys/mount.h sys/ioctl.h",
            "/linux/mount.h",
            "check_cxx_linkage",
            "-dM",
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
            "mount-header-source-form)",
            "run_mount_header_source_form()",
            "run_mount_header_source_form.sh",
            "mount-header-source-form takes no arguments",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
