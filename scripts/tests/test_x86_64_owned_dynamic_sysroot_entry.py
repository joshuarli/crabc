"""The dynamic sysroot producer must start under a qualification case's Python policy."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"


class DynamicSysrootEntryTests(unittest.TestCase):
    def test_producer_imports_its_shared_static_module_with_pythonsafepath(self):
        # A qualification case may run this producer directly with
        # PYTHONSAFEPATH=1, which omits the script directory from sys.path.
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONSAFEPATH": "1",
            "PYTHONNOUSERSITE": "1",
        }
        completed = subprocess.run(
            [sys.executable, "-B", str(PRODUCER), "--help"],
            cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        self.assertIn(b"usage:", completed.stdout)


if __name__ == "__main__":
    unittest.main()
