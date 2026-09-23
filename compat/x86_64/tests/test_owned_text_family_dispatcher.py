#!/usr/bin/env python3
"""Check the text-family reader dispatches through the pinned container."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / ".work/text-family-dispatcher-tests"


class OwnedTextFamilyDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        WORK.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        repository = base / "repository"
        repository.mkdir()
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.name", "Dispatcher Test"], check=True)
        (repository / "tracked").write_text("linked worktree fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repository), "add", "tracked"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True)

        self.checkout = base / "checkout"
        subprocess.run(["git", "-C", str(repository), "worktree", "add", "-q", "--detach",
                        str(self.checkout), "HEAD"], check=True)
        scripts = self.checkout / "scripts"
        scripts.mkdir()
        shutil.copy2(ROOT / "scripts/dev-x86_64.sh", scripts / "dev-x86_64.sh")
        (self.checkout / ".work/x86_64").mkdir(parents=True)
        self.runner_log = self.checkout / ".work/x86_64/docker-arguments.json"
        binaries = self.checkout / ".work/x86_64/bin"
        binaries.mkdir()
        docker = binaries / "docker"
        docker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['DOCKER_ARGUMENT_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args[:2] == ['image', 'inspect']:\n"
            "    if '--format' in args:\n"
            "        print('linux/amd64')\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(0)\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("CRABC_X86_64_")
        }
        self.environment.update({
            "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
            "DOCKER_ARGUMENT_LOG": str(self.runner_log),
            "PYTHONDONTWRITEBYTECODE": "1",
        })

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.checkout / "scripts/dev-x86_64.sh"),
             "owned-text-math-locale-stdio-family", *arguments],
            cwd=self.checkout,
            env=self.environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def test_assemble_and_validate_use_pinned_container_and_linked_git_mount(self) -> None:
        cases = (
            ("assemble", "--family-execution", ".work/native/matrix.json", "--pthread-family",
             ".work/native/pthread.json", "--output", ".work/text family"),
            ("validate", "--receipt", ".work/text family/receipt.json"),
        )
        git_common = subprocess.check_output(
            ["git", "-C", str(self.checkout), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            text=True,
        ).strip()
        for arguments in cases:
            with self.subTest(operation=arguments[0]):
                self.runner_log.unlink(missing_ok=True)
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [json.loads(line) for line in self.runner_log.read_text(encoding="utf-8").splitlines()]
                run = next(call for call in calls if call[0] == "run")
                expected = [
                    "crabc-core-evidence:x86_64", "python3", "-B",
                    "/workspace/compat/x86_64/owned_text_math_locale_stdio_family.py", *arguments,
                ]
                self.assertEqual(run[-len(expected):], expected)
                self.assertIn("--volume", run)
                mounts = [run[index + 1] for index, value in enumerate(run[:-1]) if value == "--volume"]
                self.assertIn(f"{git_common}:{git_common}:ro", mounts)
                self.assertIn(f"{self.checkout}:/workspace", mounts)
                self.assertIn(f"{self.checkout}/.work/x86_64:/workspace/.work/x86_64", mounts)
                self.assertEqual(calls[-1][0:2], ["run", "--rm"])

    def test_missing_or_unsupported_operation_fails_before_docker(self) -> None:
        for arguments in ((), ("collect",)):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("requires assemble or validate", result.stderr)
                self.assertFalse(self.runner_log.exists())


if __name__ == "__main__":
    unittest.main()
