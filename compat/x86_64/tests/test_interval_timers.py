#!/usr/bin/env python3
"""Contract for the opt-in x86 ``getitimer``/``setitimer`` ABI artifact."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "interval_timers.rs"
PROBE = ROOT / "compat" / "x86_64" / "libc_interval_timers_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_interval_timers_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_interval_timers.sh"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class IntervalTimerTests(unittest.TestCase):
    def test_opt_in_interval_timers_keep_the_default_archive_closed(self) -> None:
        for path in (SOURCE, PROBE, START, RUNNER):
            self.assertTrue(path.is_file(), f"missing interval-timer input: {path}")
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        manifest = MANIFEST.read_text(encoding="utf-8")
        static_root = STATIC_ROOT.read_text(encoding="utf-8")
        source = SOURCE.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        exports = {
            line
            for line in STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }

        self.assertIn("x86-interval-timers = []", manifest)
        self.assertIn(
            '#[cfg(feature = "x86-interval-timers")]\n'
            '#[path = "interval_timers.rs"]\n'
            "mod interval_timers;",
            static_root,
        )
        for required in (
            "pinned musl 1.2.6",
            "src/signal/getitimer.c",
            "src/signal/setitimer.c",
            "SYS_GETITIMER",
            "SYS_SETITIMER",
            'pub unsafe extern "C" fn getitimer',
            'pub unsafe extern "C" fn setitimer',
            "size_of::<Timeval>() == 16",
            "size_of::<Itimerval>() == 32",
            "process-global",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertEqual(exports & {"getitimer", "setitimer"}, set())

        for required in (
            "SYS_getitimer == 36",
            "SYS_setitimer == 38",
            "ITIMER_REAL",
            "ITIMER_VIRTUAL",
            "ITIMER_PROF",
            "CRABC_INTERVAL_TIMERS_FREESTANDING",
            "trailing_is_unchanged",
            "invalid_setting",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertIn("crabc_x86_64_interval_timers_probe", start)

        for required in (
            "x86-interval-timers",
            "assert_feature_delta",
            "--features \"$FEATURE\"",
            "-nostdlib -static",
            "assert_named_syscall getitimer 24",
            "assert_named_syscall setitimer 26",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)


if __name__ == "__main__":
    unittest.main()
