#!/usr/bin/env python3
"""Native loader and corpus consumers execute supplied products in isolation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class OwnedLoaderCorpusDispatchTests(unittest.TestCase):
    def test_package_corpus_executes_once_with_the_exact_selection(self):
        self.check_dispatch("owned-package-corpus", "run_owned_package_corpus.sh", [
            "--dynamic-sysroot", "/workspace/.work/x86_64/supplied-dynamic",
            "--case", "tier-a-true", "--report", ".work/x86_64/corpus/report.json",
        ])

    def test_synthetic_loader_executes_once_with_the_supplied_product(self):
        self.check_dispatch("owned-loader-synthetic", "run_owned_loader_synthetic.sh", [
            "/workspace/.work/x86_64/supplied-dynamic",
        ])

    def check_dispatch(self, command_name, script, arguments):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            capture = work / "docker.jsonl"
            docker = work / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
                "elif sys.argv[1] == 'run':\n"
                "    with open(os.environ['DISPATCH_CAPTURE'], 'a') as output: output.write(json.dumps(sys.argv[1:])+'\\n')\n"
                "else: raise SystemExit('unexpected Docker operation')\n"
            )
            docker.chmod(0o755)
            environment = {**os.environ, "PATH": f"{work}{os.pathsep}{os.environ['PATH']}",
                           "DISPATCH_CAPTURE": str(capture), "CRABC_X86_64_WORK_DIR": str(work / "state")}
            command = ["bash", str(ROOT / "scripts/dev-x86_64.sh"), command_name]
            result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(capture.exists())
            result = subprocess.run(command + arguments, cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            invocations = [json.loads(line) for line in capture.read_text().splitlines()]
            self.assertEqual(len(invocations), 1, "supplied corpus products must not trigger a build")
            invocation = invocations[0]
            leaf = "/workspace/compat/x86_64/" + script
            self.assertEqual(invocation[invocation.index(leaf) + 1:], arguments)
            self.assertIn("--cap-add=SYS_CHROOT", invocation)
            self.assertEqual(invocation[invocation.index("--network") + 1], "none")
            self.assertNotIn("--cap-add=SYS_ADMIN", invocation)
            self.assertFalse(any(argument.startswith("--security-opt") for argument in invocation))


if __name__ == "__main__":
    unittest.main()
