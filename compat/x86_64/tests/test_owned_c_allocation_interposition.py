#!/usr/bin/env python3
"""The interposition runner must reject matching failed target processes."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_c_allocation_interposition.sh"


class OwnedCAllocationInterpositionTests(unittest.TestCase):
    def exercise_capture(self, status: int):
        source = RUNNER.read_text(encoding="utf-8")
        start = source.index("run_in_root() {")
        end = source.index("\n}\n", start) + len("\n}\n")
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="c-allocation-capture.", dir=scratch) as raw:
            work = Path(raw)
            commands = work / "bin"
            commands.mkdir()
            # Only replace the privilege boundary. timeout, env, shell exit
            # handling and raw stream retention are the runner's real code.
            chroot = commands / "chroot"
            chroot.write_text('#!/bin/sh\nshift\nexec "$@"\n', encoding="utf-8")
            chroot.chmod(0o755)
            prefix = work / "oracle"
            script = "set -euo pipefail\n" + source[start:end] + '''
run_in_root "$1" "$2" bash -c 'printf "target output\\n"; printf "target diagnostic\\n" >&2; exit "$1"' target "$3"
printf 'accepted target\\n'
'''
            result = subprocess.run(
                ["bash", "-c", script, "capture-test", str(work), str(prefix), str(status)],
                cwd=ROOT,
                env={**os.environ, "PATH": str(commands) + os.pathsep + os.environ["PATH"]},
                capture_output=True,
                text=True,
                check=False,
            )
            streams = {
                suffix: prefix.with_suffix("." + suffix).read_text(encoding="utf-8")
                for suffix in ("stdout", "stderr", "status")
            }
        return result, streams

    def test_failed_target_stops_before_a_matching_failure_can_qualify(self) -> None:
        for status in (7, 124):
            with self.subTest(status=status):
                result, streams = self.exercise_capture(status)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("accepted target", result.stdout)
                self.assertIn("target exited", result.stderr)
                self.assertEqual(streams, {
                    "stdout": "target output\n",
                    "stderr": "target diagnostic\n",
                    "status": f"{status}\n",
                })

    def test_successful_target_retains_streams_and_continues(self) -> None:
        result, streams = self.exercise_capture(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "accepted target\n")
        self.assertEqual(streams["status"], "0\n")
        self.assertEqual(streams["stdout"], "target output\n")
        self.assertEqual(streams["stderr"], "target diagnostic\n")


if __name__ == "__main__":
    unittest.main()
