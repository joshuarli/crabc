#!/usr/bin/env python3
"""Linked worktrees retain source identity inside the pinned container."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class WorktreeGitDispatchTests(unittest.TestCase):
    def test_linked_worktree_mounts_only_common_git_metadata_read_only(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            source = work / "source"
            (source / "scripts").mkdir(parents=True)
            shutil.copyfile(ROOT / "scripts/dev-x86_64.sh", source / "scripts/dev-x86_64.sh")
            def git(*arguments):
                return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *arguments],
                    cwd=source, check=True, capture_output=True, text=True)
            git("init", "-q")
            git("add", "scripts/dev-x86_64.sh")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
            linked = work / "linked"
            git("worktree", "add", "--detach", str(linked), "HEAD")
            docker = work / "docker"
            docker.write_text(f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
                "elif sys.argv[1] == 'run':\n"
                "    with open(os.environ['DISPATCH_CAPTURE'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
                "else: raise SystemExit('unexpected Docker operation')\n")
            docker.chmod(0o755)
            common = source / ".git"
            for checkout in (source, linked):
                for command in ("musl-oracle", "owned-dynamic-spawn", "owned-dynamic-sysroot",
                                "libc-interface-discovery", "libc-uts-identity", "owned-resolver-network"):
                    with self.subTest(checkout=checkout.name, command=command):
                        capture = work / f"{checkout.name}-{command}.jsonl"
                        environment = {k:v for k,v in os.environ.items() if not k.startswith("CRABC_X86_64_")}
                        environment.update(PATH=f"{work}{os.pathsep}{os.environ['PATH']}", DISPATCH_CAPTURE=str(capture))
                        result = subprocess.run(["bash", str(checkout / "scripts/dev-x86_64.sh"), command],
                            cwd=checkout, env=environment, capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        invocations = [json.loads(line) for line in capture.read_text().splitlines()]
                        self.assertTrue(invocations)
                        for args in invocations:
                            mounts = [args[i+1] for i, arg in enumerate(args[:-1]) if arg == "--volume"]
                            self.assertEqual(f"{common}:{common}:ro" in mounts, checkout == linked)
                            self.assertNotIn(f"{common}:{common}", mounts)
                            self.assertNotIn(f"{source}:{source}", mounts)
                            self.assertIn("GIT_OPTIONAL_LOCKS=0", args)


if __name__ == "__main__":
    unittest.main()
