#!/usr/bin/env python3
"""Focused contract for the x86 packed public <sys/epoll.h> ABI."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "sys" / "epoll.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_epoll_header_abi.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "epoll_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "epoll_header_abi_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


class EpollHeaderAbiTests(unittest.TestCase):
    def test_x86_packs_only_the_public_epoll_event_record(self) -> None:
        header = HEADER.read_text(encoding="utf-8")

        self.assertIn("#if defined(__x86_64__) && defined(__LP64__)", header)
        self.assertIn("__attribute__((__packed__))", header)
        self.assertIn("struct epoll_event", header)
        self.assertIn("#undef __CRABC_EPOLL_EVENT_PACKED", header)

    def test_probes_and_runner_define_the_full_seven_profile_boundary(self) -> None:
        for probe in (C_PROBE.read_text(encoding="utf-8"), CXX_PROBE.read_text(encoding="utf-8")):
            self.assertIn("#include <sys/ioctl.h>", probe)
            for phrase in (
                "sizeof(struct epoll_event) == 12",
                "epoll_event, data) == 4",
                "sizeof(struct epoll_params) == 8",
                "_IOC_READ == 2U",
                "EPIOCSPARAMS == 0x40088a01U",
                "epoll_pwait",
            ):
                self.assertIn(phrase, probe)
            self.assertNotIn("main(", probe)

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
            "readonly CANDIDATE_CC=/usr/bin/gcc",
            "readonly EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "-nostdinc",
            "-nostdinc++",
            "candidate trace reached pinned musl despite -nostdinc",
            "trace escaped its declared header roots",
            "trace omitted ${root}/sys/ioctl.h",
        ):
            self.assertIn(phrase, runner)

    def test_dispatcher_exposes_the_epoll_header_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for phrase in (
            "epoll-header-abi)",
            "run_epoll_header_abi()",
            "run_epoll_header_abi.sh",
            "epoll-header-abi takes no arguments",
        ):
            self.assertIn(phrase, dispatcher)


if __name__ == "__main__":
    unittest.main()
