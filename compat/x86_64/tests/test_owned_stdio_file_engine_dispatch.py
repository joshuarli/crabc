"""The FILE-engine replay alone receives the private procfs container authority."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedStdioFileEngineDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.state = self.work / "state"
        self.static = self.state / "static-product"
        self.dynamic = self.state / "dynamic-product"
        self.static.mkdir(parents=True)
        self.dynamic.mkdir()
        self.capture = self.work / "docker.jsonl"
        docker = self.work / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['DISPATCH_CAPTURE'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
            "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
            "elif sys.argv[1] != 'run': raise SystemExit('unexpected Docker operation')\n"
        )
        docker.chmod(0o755)
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("CRABC_X86_64_")}
        self.environment.update(PATH=f"{self.work}{os.pathsep}{os.environ['PATH']}",
                                DISPATCH_CAPTURE=str(self.capture), CRABC_X86_64_WORK_DIR=str(self.state))

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        self.capture.unlink(missing_ok=True)
        return subprocess.run(["bash", str(DISPATCHER), "owned-stdio-file-engine", *arguments], cwd=ROOT,
                              env=self.environment, capture_output=True, text=True, check=False)

    def test_supplied_pair_uses_only_the_existing_mount_cap_container(self) -> None:
        result = self.invoke("--static-sysroot", str(self.static), str(self.dynamic))
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [item for item in map(json.loads, self.capture.read_text().splitlines()) if item[0] == "run"]
        self.assertEqual(len(runs), 1)
        argv = runs[0]
        self.assertIn("--cap-add=SYS_CHROOT", argv)
        self.assertIn("--cap-add=SYS_ADMIN", argv)
        self.assertIn("--security-opt=apparmor=unconfined", argv)
        self.assertNotIn("--privileged", argv)
        self.assertEqual(argv[-5:], [
            "bash", "/workspace/compat/x86_64/run_owned_stdio_file_engine.sh", "--static-sysroot",
            "/workspace/.work/x86_64/static-product", "/workspace/.work/x86_64/dynamic-product",
        ])

    def test_full_supplied_pair_is_required_before_docker(self) -> None:
        for arguments in ((), (str(self.dynamic),), ("--static-sysroot", str(self.static))):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
