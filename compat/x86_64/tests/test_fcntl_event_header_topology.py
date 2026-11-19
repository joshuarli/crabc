#!/usr/bin/env python3
"""Source and runner contract for x86 fcntl/event direct-header topology."""

from __future__ import annotations

import hashlib
import re
import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_fcntl_event_header_topology.sh"
C_PROBE = ROOT / "compat/x86_64/fcntl_event_header_topology_probe.c"
CXX_PROBE = ROOT / "compat/x86_64/fcntl_event_header_topology_probe.cpp"

# The first hash is the pinned musl 1.2.6 source form selected on x86.
HEADER_FORMS = {
    "include/fcntl.h": (
        "02f3c18a6cc9303d9414bbbe3f2e42d8bc7a3e210ee329323887c46111f6cad2",
        "ae7ddb0b790ea5b6a564e1125312d9cab150d1cdacfad7c9d63560a8340a5043",
    ),
    "include/sys/fcntl.h": (
        "6f3708b141d1886107e6fd6a85f00015c0a63f29b7c985f0e1026c9f3a74ad4b",
        "ddaea64e6eb0d00bac89b6d3d96ca663173379daf2fbacdd08644bcbf4020349",
    ),
    "include/semaphore.h": (
        "c20f266e552137e6827b6622f2ddf60cf09f08175cf0c34f673910cb14a0cc05",
        "956bde4bd494685233b79eb0a107dcb963c4d94a9f0d4a6afd94ae9ad6ddff98",
    ),
    "include/sys/epoll.h": (
        "bd1bd93e96a8a0d0ccdd0392118770028609e9f95ec4d0e9f733dc2d9becf581",
        "a5d76a908245cd7492df170c98d390906fb99d3451cd7522251b7252c2b094b6",
    ),
    "include/sys/eventfd.h": (
        "bd12447de1421dff8465d0ee9287562179e39b6c9e3445a7acc261641195ee59",
        "382c15cef020ceb41e5a511da6ce952a6f0ba07f71def628cb0eb46df088c75b",
    ),
    "include/sys/inotify.h": (
        "f6af7ff2154c7036457624525369affff95719e125c46e32eb910ead860a1fc4",
        "740faf6f00097995f46f5b3812ea352efb726f4df174123128030a08cdb5444a",
    ),
    "include/sys/signalfd.h": (
        "e28b65b3a5dabe0f41bec490fd139f35e3e7323f9c5260d20fc22e9f8d648308",
        "76b3c64dd3deb667f9ba40349c1c0543fb1418a44184997340ff6fc4f6fe0e46",
    ),
    "include/sys/timerfd.h": (
        "d9e9fdbc773309427ff460c7c2847aeeaa67616402fd0b56da196bfc9ac486d6",
        "2e61ce0c4588e6a6dbaa09c1e18aae9a714f18c83bce8ea080d1e5cb8e6717d4",
    ),
    "include/bits/fcntl.h": (
        "3526dbb894665ab3b155a60d730c8527edce4fa597b3d5e51364a345d0cbdaeb",
        "9e9f34f0b44545592b1023d28fdd15f058813050b14f658bb94eada7d59b8ce2",
    ),
}

class FcntlEventHeaderTopologyTests(unittest.TestCase):
    def test_x86_forms_match_pinned_musl_and_legacy_forms_remain_frozen(self) -> None:
        for relative, (x86_sha256, _legacy_sha256) in HEADER_FORMS.items():
            with self.subTest(header=relative):
                source = (ROOT / relative).read_bytes()
                if relative == "include/sys/fcntl.h":
                    prefix = b"#if defined(__x86_64__) || defined(__aarch64__)\n"
                    self.assertTrue(source.startswith(prefix))
                    self.assertTrue(source.endswith(b"#endif\n"))
                    source = source[len(prefix):-len(b"#endif\n")]
                elif relative == "include/bits/fcntl.h":
                    pattern = rb"#if defined\(__aarch64__\)\n([\s\S]*?)#else\n([\s\S]*?)#endif\n"
                    source, count = re.subn(pattern, lambda match: match.group(2), source)
                    self.assertEqual(count, 3)
                self.assertEqual(hashlib.sha256(source).hexdigest(), x86_sha256)

    def test_runner_covers_every_direct_header_and_profile_in_isolated_trees(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "CANDIDATE_CC=/usr/bin/gcc",
            "-nostdinc",
            "-nostdinc++",
            "reference candidate",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "fcntl sys-fcntl semaphore epoll eventfd inotify signalfd timerfd",
            "redirecting incorrect #include <sys/fcntl.h> to <fcntl.h>",
            "bits/fcntl.h",
            "check_cxx_symbol",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-I /usr/include", runner)

    def test_probes_name_the_shared_type_and_guard_regressions(self) -> None:
        c_probe = C_PROBE.read_text(encoding="utf-8")
        cpp_probe = CXX_PROBE.read_text(encoding="utf-8")
        for probe in (c_probe, cpp_probe):
            self.assertIn("must not acquire a synthetic bits/fcntl.h guard", probe)
            self.assertIn("must not retain a project-private guard", probe)
            self.assertIn("sem_t", probe)
        self.assertIn("int (*)(const char *, mode_t)", c_probe)
        self.assertIn("volatile int", c_probe)
        self.assertIn("redirect to <fcntl.h>", c_probe)

    def test_runner_is_executable_shell(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)


if __name__ == "__main__":
    unittest.main()
