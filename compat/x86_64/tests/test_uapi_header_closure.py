#!/usr/bin/env python3
"""Focused contracts for the x86 ioctl/mount/pty UAPI header closure slice."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat" / "x86_64" / "run_uapi_header_closure.sh"
PROBES = (
    ROOT / "compat" / "x86_64" / "uapi_header_closure_probe.c",
    ROOT / "compat" / "x86_64" / "uapi_header_closure_probe.cpp",
    ROOT / "compat" / "x86_64" / "uapi_header_include_only.c",
    ROOT / "compat" / "x86_64" / "uapi_header_include_only.cpp",
)


class UapiHeaderClosureTests(unittest.TestCase):
    def test_header_edges_and_legacy_mtio_boundary_are_explicit(self) -> None:
        ioctl = (ROOT / "include/sys/ioctl.h").read_text(encoding="utf-8")
        mount = (ROOT / "include/sys/mount.h").read_text(encoding="utf-8")
        pty = (ROOT / "include/pty.h").read_text(encoding="utf-8")
        mtio = (ROOT / "include/sys/mtio.h").read_text(encoding="utf-8")
        bits = (ROOT / "include/bits/ioctl.h").read_text(encoding="utf-8")

        self.assertIn("#include <bits/ioctl.h>", ioctl)
        self.assertIn("#include <sys/ioctl.h>", mount)
        self.assertIn("#include <sys/ioctl.h>", pty)
        self.assertIn("#include <sys/ioctl.h>", mtio)
        for phrase in ("#define _IOC(", "#define _IOW(", "#define TIOCGPTN", "#define SIOCGIFINDEX"):
            self.assertIn(phrase, bits)
        for phrase in ("#define BLKROSET", "#define BLKBSZGET", "#define BLKGETSIZE64"):
            self.assertIn(phrase, mount)
        self.assertNotIn("#define _IOT(", mtio)
        self.assertNotIn("pivot_root", mount)

    def test_probes_cover_seven_profiles_and_include_variants(self) -> None:
        for probe_path in PROBES:
            probe = probe_path.read_text(encoding="utf-8")
            for variant in (
                "CRABC_UAPI_IOCTL_ONLY",
                "CRABC_UAPI_MOUNT_ONLY",
                "CRABC_UAPI_PTY_ONLY",
                "CRABC_UAPI_MTIO_ONLY",
                "CRABC_UAPI_MOUNT_IOCTL",
                "CRABC_UAPI_PTY_IOCTL",
                "CRABC_UAPI_MTIO_IOCTL",
            ):
                self.assertIn(variant, probe)
            self.assertNotIn("/usr/include", probe)

        c_probe = PROBES[0].read_text(encoding="utf-8")
        for phrase in (
            "TIOCGWINSZ == 0x5413",
            "FIOASYNC == 0x5452",
            "N_NULL == 27",
            "BLKROSET == _IO(0x12, 93)",
            "MTIOCTOP == _IOW('m', 1, struct mtop)",
            "sizeof(struct winsize) == 8",
        ):
            self.assertIn(phrase, c_probe)

    def test_runner_is_closed_and_native(self) -> None:
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
            "readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "readonly CANDIDATE_CC=/usr/bin/gcc",
            "readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)",
            "readonly -a VARIANTS=(",
            "-nostdinc",
            "-nostdinc++",
            "candidate header trace escaped project/builtin roots",
            "reference header trace escaped musl/builtin roots",
            "PASS (%s profiles; %s include variants; C/C++)",
        ):
            self.assertIn(phrase, runner)
        self.assertNotIn("-I /usr/include", runner)


if __name__ == "__main__":
    unittest.main()
