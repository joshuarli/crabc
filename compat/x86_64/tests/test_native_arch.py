#!/usr/bin/env python3
"""The shell entry for native architecture settings works under qualification cases."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/x86_64/native_arch.py"


class NativeArchScriptTests(unittest.TestCase):
    def test_safe_path_shell_entry_reports_each_supported_machine(self) -> None:
        environment = {**os.environ, "PYTHONSAFEPATH": "1"}
        for machine, arch in (("x86_64", "x86_64"), ("arm64", "aarch64")):
            with self.subTest(machine=machine):
                output = subprocess.run(
                    [sys.executable, "-B", str(SCRIPT), machine], cwd="/", env=environment,
                    text=True, capture_output=True, check=True,
                ).stdout
                values = dict(line.split("=", 1) for line in output.splitlines())
                self.assertEqual(shlex.split(values["arch"]), [arch])
                self.assertEqual(shlex.split(values["oracle"]), [f"/usr/local/bin/crabc-{arch}-musl-gcc"])
                self.assertTrue(shlex.split(values["image"])[0].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
