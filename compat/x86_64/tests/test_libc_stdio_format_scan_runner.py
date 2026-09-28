#!/usr/bin/env python3
"""Containment checks for the closed static stdio format/scan runner."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_libc_stdio_format_scan.sh"


class StdioFormatScanRunnerTests(unittest.TestCase):
    def test_rejects_ambient_tmpdir_before_oracle_setup(self) -> None:
        environment = os.environ.copy()
        environment["TMPDIR"] = "/tmp"
        environment["CRABC_STDIO_FORMAT_SCAN_PROFILE"] = "integer"
        result = subprocess.run(
            ["bash", str(RUNNER)], cwd=ROOT, env=environment,
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TMPDIR must be a physical checkout .work directory", result.stderr)

    def test_rejects_symlinked_checkout_tmpdir(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            link = Path(temporary) / "scratch"
            link.symlink_to(ROOT / ".work/x86_64/tmp", target_is_directory=True)
            environment = os.environ.copy()
            environment["TMPDIR"] = str(link)
            environment["CRABC_STDIO_FORMAT_SCAN_PROFILE"] = "integer"
            result = subprocess.run(
                ["bash", str(RUNNER)], cwd=ROOT, env=environment,
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TMPDIR must be a physical checkout .work directory", result.stderr)

    def test_retained_profile_has_matching_raw_streams_and_physical_inputs(self) -> None:
        raw = os.environ.get("CRABC_STDIO_FORMAT_SCAN_EVIDENCE")
        if raw is None:
            self.skipTest("set CRABC_STDIO_FORMAT_SCAN_EVIDENCE to a completed profile directory")
        work = Path(raw).resolve(strict=True)
        self.assertTrue(work.is_relative_to(ROOT / ".work"))
        for stream in ("status", "stdout", "stderr"):
            oracle = (work / f"oracle.{stream}").read_bytes()
            candidate = (work / f"candidate.{stream}").read_bytes()
            self.assertEqual(oracle, candidate, stream)
        self.assertEqual((work / "oracle.status").read_bytes(), b"0\n")
        records = (work / "source-product.sha256").read_text().splitlines()
        self.assertEqual(len(records), 8)
        for record in records:
            expected, recorded_path = record.split("  ", 1)
            self.assertTrue(recorded_path.startswith("/workspace/"))
            physical = ROOT / recorded_path.removeprefix("/workspace/")
            self.assertEqual(hashlib.sha256(physical.read_bytes()).hexdigest(), expected)


if __name__ == "__main__":
    unittest.main()
