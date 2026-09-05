#!/usr/bin/env python3
"""Observe the native resolver build and network-isolation boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class OwnedResolverDispatchTests(unittest.TestCase):
    def test_products_are_built_before_network_isolated_execution(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            capture = work / "docker.jsonl"
            docker = work / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']:\n"
                "    print('linux/amd64')\n"
                "elif sys.argv[1] == 'run':\n"
                "    with open(os.environ['DISPATCH_CAPTURE'], 'a') as output:\n"
                "        output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "else:\n"
                "    raise SystemExit('unexpected Docker operation')\n"
            )
            docker.chmod(0o755)
            environment = dict(os.environ)
            environment.update(
                PATH=f"{work}{os.pathsep}{os.environ['PATH']}",
                DISPATCH_CAPTURE=str(capture),
                CRABC_X86_64_WORK_DIR=str(work / "state"),
            )
            command = ["bash", str(ROOT / "scripts/dev-x86_64.sh"), "owned-resolver-network"]
            invalid = subprocess.run(command + ["unexpected"], cwd=ROOT,
                                     env=environment, capture_output=True, text=True)
            self.assertEqual(invalid.returncode, 2)
            self.assertFalse(capture.exists())
            result = subprocess.run(command, cwd=ROOT, env=environment,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr[:300])
            prepare, execute = [json.loads(line) for line in capture.read_text().splitlines()]
            self.assertNotIn("--network", prepare)
            self.assertNotIn("--cap-add=SYS_CHROOT", prepare)
            self.assertIn("/workspace/compat/resolver-network/prepare_x86_64.py", prepare)
            products = prepare[prepare.index("--output") + 1]
            self.assertTrue(products.startswith("/workspace/.work/x86_64/tmp/owned-resolver-network."))
            self.assertTrue(products.endswith("/products"))
            self.assertEqual(execute[execute.index("--network") + 1], "none")
            self.assertIn("--cap-add=SYS_CHROOT", execute)
            self.assertNotIn("--cap-add=SYS_ADMIN", execute)
            self.assertNotIn("--privileged", execute)
            self.assertIn("/workspace/compat/resolver-network/run_x86_64.py", execute)
            self.assertEqual(execute[execute.index("--static-sysroot") + 1], products + "/static-sysroot")
            self.assertEqual(execute[execute.index("--dynamic-sysroot") + 1], products + "/dynamic-sysroot")
            self.assertEqual(execute[execute.index("--extracted-static-sysroot") + 1], products + "/static-extraction/crabc-x86_64-owned-static-sysroot")
            self.assertEqual(execute[execute.index("--extracted-dynamic-sysroot") + 1], products + "/dynamic-extraction")
            self.assertEqual(execute[execute.index("--work-root") + 1], str(Path(products).parent / "execution"))
            for invocation in (prepare, execute):
                self.assertIn("TMPDIR=/workspace/.work/x86_64/tmp", invocation)


if __name__ == "__main__":
    unittest.main()
