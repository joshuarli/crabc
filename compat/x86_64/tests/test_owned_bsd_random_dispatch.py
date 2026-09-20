"""Installed BSD random qualification retains explicit product and authority bounds."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedBsdRandomDispatchTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.state = self.work / "state"
        self.static = self.state / "static product"
        self.dynamic = self.state / "dynamic product"
        self.static.mkdir(parents=True)
        self.dynamic.mkdir()
        self.capture = self.work / "docker.jsonl"
        docker = self.work / "docker"
        docker.write_text(f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['DISPATCH_CAPTURE'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
            "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
            "elif sys.argv[1] != 'run': raise SystemExit('unexpected Docker operation')\n")
        docker.chmod(0o755)
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith("CRABC_X86_64_")}
        self.environment.update(PATH=f"{self.work}{os.pathsep}{os.environ['PATH']}",
                                DISPATCH_CAPTURE=str(self.capture), CRABC_X86_64_WORK_DIR=str(self.state))

    def invoke(self, *arguments):
        self.capture.unlink(missing_ok=True)
        return subprocess.run(["bash", str(DISPATCHER), "owned-bsd-random", *arguments],
                              cwd=ROOT, env=self.environment, capture_output=True, text=True)

    def test_installed_and_extracted_pairs_use_only_chroot_authority(self):
        for mode in ([], ["--extracted"]):
            with self.subTest(mode=mode):
                result = self.invoke(*mode, "--static-sysroot", str(self.static), str(self.dynamic))
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [a for a in map(json.loads, self.capture.read_text().splitlines()) if a[0] == "run"]
                self.assertEqual(len(runs), 1)
                argv = runs[0]
                expected = ["bash", "/workspace/compat/x86_64/run_owned_bsd_random.sh", *mode,
                            "--static-sysroot", "/workspace/.work/x86_64/static product",
                            "/workspace/.work/x86_64/dynamic product"]
                self.assertEqual(argv[-len(expected):], expected)
                self.assertIn("--cap-add=SYS_CHROOT", argv)
                self.assertNotIn("--cap-add=SYS_ADMIN", argv)
                self.assertNotIn("--privileged", argv)
                self.assertFalse(any(a.startswith("--security-opt=") for a in argv))

    def test_malformed_or_escaping_products_fail_before_docker(self):
        alias = self.state / "alias"
        alias.symlink_to(self.static, target_is_directory=True)
        cases = [(), ("--extracted",), ("--static-sysroot", str(self.static)),
                 ("--extracted", "--extracted", "--static-sysroot", str(self.static), str(self.dynamic)),
                 ("--static-sysroot", "", str(self.dynamic)),
                 ("--static-sysroot", str(self.static), "--unknown"),
                 ("--static-sysroot", str(alias), str(self.dynamic)),
                 ("--static-sysroot", str(ROOT), str(self.dynamic))]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
