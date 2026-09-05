"""Supplied-product flags must not become file operands or trigger a build."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNERS = (
    "run_owned_environment_lifecycle.sh",
    "run_owned_posix_composition.sh",
    "run_owned_credentials_profile.sh",
    "run_owned_linux_control.sh",
)


class OwnedStaticReplayArgumentsTests(unittest.TestCase):
    def test_unknown_short_options_are_usage_errors_before_product_tools_run(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            tools = Path(temporary)
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n")
            python.chmod(0o755)
            environment = {**os.environ, "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"}
            for name in RUNNERS:
                runner = ROOT / "compat/x86_64" / name
                for arguments in (("-x",), ("--static-sysroot", "-x")):
                    with self.subTest(runner=name, arguments=arguments):
                        result = subprocess.run(
                            ["bash", str(runner), *arguments], cwd=ROOT,
                            env=environment, capture_output=True, text=True,
                        )
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(
                            result.stderr,
                            f"usage: {runner} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
                        )


if __name__ == "__main__":
    unittest.main()
