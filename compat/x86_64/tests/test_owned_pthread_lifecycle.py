#!/usr/bin/env python3
"""Real installed pthread attachment on the lifecycle fixture's small stack."""

import json
import os
import resource
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / "compat/x86_64/owned_pthread_lifecycle_consumer.c"


class InstalledSmallStackAttachmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        supplied = os.environ.get("CRABC_X86_64_PTHREAD_LIFECYCLE_TEST_SYSROOT")
        if not supplied:
            raise unittest.SkipTest("requires an installed owned sysroot in the pinned image")
        cls.sysroot = Path(supplied)
        if not cls.sysroot.is_absolute() or not (cls.sysroot / "bin/crabc-cc").is_file():
            raise AssertionError("requires an absolute installed owned driver")
        scratch = ROOT / ".work/x86_64/pthread-small-stack-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(prefix="attach-", dir=scratch))

    def test_first_worker_attaches_before_callback_on_valid_16k_stack(self):
        for mode, name in (("-static", "et-exec"), ("-static-pie", "static-pie")):
            with self.subTest(mode=mode):
                work = self.work / name
                work.mkdir()
                commands = []
                for argv in (
                    [str(self.sysroot / "bin/crabc-cc"), mode,
                     "-DCRABC_PTHREAD_SMALL_STACK_ATTACH_ONLY", "-c", str(PROBE), "-o", "probe.o"],
                    [str(self.sysroot / "bin/crabc-cc"), mode, "--link-receipt", "link.receipt.json",
                     "probe.o", "-o", "candidate"],
                    ["timeout", "30", "env", "-i", str(work / "candidate")],
                ):
                    result = subprocess.run(argv, cwd=work, text=True, capture_output=True,
                                            check=False, timeout=60,
                                            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
                    commands.append({"argv": argv, "status": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr})
                    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
