#!/usr/bin/env python3
"""Focused contract for x86 event-descriptor header visibility evidence."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
EVENTFD_HEADER = ROOT / "include" / "sys" / "eventfd.h"
INOTIFY_HEADER = ROOT / "include" / "sys" / "inotify.h"
FCNTL_HEADER = ROOT / "include" / "fcntl.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_event_descriptors_header_abi.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "event_descriptors_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "event_descriptors_header_abi_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


class EventDescriptorsHeaderAbiTests(unittest.TestCase):
    def test_direct_event_surface_is_unconditional_and_fcntl_boundary_is_narrow(self) -> None:
        eventfd = EVENTFD_HEADER.read_text(encoding="utf-8")
        inotify = INOTIFY_HEADER.read_text(encoding="utf-8")
        fcntl = FCNTL_HEADER.read_text(encoding="utf-8")

        for header in (eventfd, inotify):
            self.assertIn("#include <fcntl.h>", header)
            self.assertIn('#ifdef __cplusplus\nextern "C" {', header)
            self.assertNotIn("_GNU_SOURCE", header)
            self.assertNotIn("_BSD_SOURCE", header)

        for phrase in (
            "typedef uint64_t eventfd_t;",
            "#define EFD_SEMAPHORE 1",
            "int eventfd(unsigned int, int);",
            "int eventfd_read(int, eventfd_t *);",
            "int eventfd_write(int, eventfd_t);",
        ):
            self.assertIn(phrase, eventfd)
        for phrase in (
            "struct inotify_event { int wd; uint32_t mask, cookie, len; char name[]; };",
            "#define IN_ALL_EVENTS 0x00000fff",
            "#define IN_ONESHOT 0x80000000",
            "int inotify_init(void);",
            "int inotify_init1(int);",
            "int inotify_add_watch(int, const char *, uint32_t);",
            "int inotify_rm_watch(int, int);",
        ):
            self.assertIn(phrase, inotify)
        self.assertIn(
            "#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)\n#define AT_EMPTY_PATH 0x1000\n#endif",
            fcntl,
        )

    def test_probes_and_runner_close_direct_and_immediate_profile_boundaries(self) -> None:
        for probe in (C_PROBE.read_text(encoding="utf-8"), CXX_PROBE.read_text(encoding="utf-8")):
            for phrase in (
                "sizeof(eventfd_t) == 8",
                "sizeof(struct inotify_event) == 16",
                "IN_ALL_EVENTS == 0x00000fff",
                "IN_ONESHOT == 0x80000000",
                "eventfd_read",
                "eventfd_write",
                "inotify_add_watch",
                "inotify_rm_watch",
                "CRABC_EVENT_DESCRIPTOR_REQUIRE_AT_EMPTY_PATH",
                "CRABC_EVENT_DESCRIPTOR_REQUIRE_AT_EMPTY_PATH_HIDDEN",
                "AT_EMPTY_PATH == 0x1000",
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
            "readonly EXPECTED_PROFILE_COUNT=8",
            "EXPECTED_AT_EMPTY_PATH_VISIBLE_PROFILE_COUNT=4",
            "EXPECTED_AT_EMPTY_PATH_HIDDEN_PROFILE_COUNT=4",
            "c-default c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "AT_EMPTY_PATH_VISIBLE_PROFILES=(c-default c11-gnu cxx17-gnu c11-bsd)",
            "AT_EMPTY_PATH_HIDDEN_PROFILES=(c11-strict c11-posix-2008 c11-xopen-700 cxx17-strict)",
            "cxx17-strict) printf '%s\\n' '-U_GNU_SOURCE'",
            "-nostdinc",
            "-nostdinc++",
            "for header in sys/eventfd.h sys/inotify.h fcntl.h; do",
            "trace omitted ${root}/$header",
            "nm --undefined-only",
            "retained a mangled event-descriptor reference",
            "AT_EMPTY_PATH GNU/BSD",
        ):
            self.assertIn(phrase, runner)

    def test_dispatcher_exposes_the_event_descriptor_header_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for phrase in (
            "event-descriptors-header-abi)",
            "run_event_descriptors_header_abi()",
            "run_event_descriptors_header_abi.sh",
            "event-descriptors-header-abi takes no arguments",
        ):
            self.assertIn(phrase, dispatcher)


if __name__ == "__main__":
    unittest.main()
