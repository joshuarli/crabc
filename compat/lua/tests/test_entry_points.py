#!/usr/bin/env python3
"""The x86 Lua entry points must start under a qualification case's Python policy."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
ENTRY_POINTS = (
    "compat/lua/run_x86_static_dispatch.py",
    "compat/lua/run_x86_dynamic.py",
    "compat/lua/run_x86_dynamic_supplied.py",
    "compat/lua/source_build_admission.py",
)


class SafePathEntryPointTests(unittest.TestCase):
    def test_entry_points_import_their_siblings_with_pythonsafepath(self) -> None:
        # The ordered qualification runner starts cases with PYTHONSAFEPATH=1,
        # which omits a script's own directory from sys.path.
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONSAFEPATH": "1",
            "PYTHONNOUSERSITE": "1",
        }
        for entry in ENTRY_POINTS:
            with self.subTest(entry=entry):
                completed = subprocess.run(
                    [sys.executable, "-B", str(ROOT / entry), "--help"],
                    cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
                self.assertIn(b"usage:", completed.stdout)


if __name__ == "__main__":
    unittest.main()
