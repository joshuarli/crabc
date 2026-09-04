"""The native lifecycle runner must reject scratch escapes before its oracle."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_general_loader_lifecycle.sh"


class LifecycleRunnerContainmentTests(unittest.TestCase):
    def test_invalid_scratch_never_reaches_the_oracle(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            scratch = Path(directory)
            marker = scratch / "oracle-started"
            fake_bin = scratch / "bin"
            fake_bin.mkdir()
            shell = fake_bin / "bash"
            shell.write_text('#!/bin/sh\ntouch "$ORACLE_MARKER"\nexit 88\n')
            shell.chmod(0o755)
            alias = scratch / "alias"
            alias.symlink_to(scratch, target_is_directory=True)
            environment = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}",
                               ORACLE_MARKER=str(marker))
            for temporary in (str(alias), f"{scratch}/../{scratch.name}",
                              str(scratch / "absent")):
                with self.subTest(temporary=temporary):
                    environment["TMPDIR"] = temporary
                    marker.unlink(missing_ok=True)
                    result = subprocess.run(["/bin/bash", str(RUNNER)], env=environment,
                                            capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
