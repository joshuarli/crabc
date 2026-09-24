#!/usr/bin/env python3
"""The calendar component reaches its launcher with an observed image identity."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / ".work/calendar-component-dispatch-tests"
IMAGE_ID = "sha256:" + "c" * 64


class OwnedCalendarComponentDispatchTests(unittest.TestCase):
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
        (self.checkout / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/dev-x86_64.sh", self.checkout / "scripts/dev-x86_64.sh")
        self.work = self.checkout / ".work/x86_64"
        self.work.mkdir(parents=True)
        self.static = self.work / "products/static product"
        self.dynamic = self.work / "products/dynamic product"
        self.static.mkdir(parents=True)
        self.dynamic.mkdir(parents=True)
        self.log = self.work / "calls.jsonl"
        # The host-side archive retention is a producer operation; record it
        # instead of reaching the network from a dispatcher test.
        runner = self.checkout / "compat/x86_64/run_owned_calendar_component.py"
        runner.parent.mkdir(parents=True)
        runner.write_text(
            "import json, os, sys\n"
            "with open(os.environ['CALENDAR_DISPATCH_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps(['host-runner', *sys.argv[1:]]) + '\\n')\n",
            encoding="utf-8",
        )
        binaries = self.work / "bin"
        binaries.mkdir()
        docker = binaries / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['CALENDAR_DISPATCH_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps(['docker', *args]) + '\\n')\n"
            "if args[:2] == ['image', 'inspect']:\n"
            "    fmt = args[args.index('--format') + 1] if '--format' in args else ''\n"
            f"    print({IMAGE_ID!r} if fmt == '{{{{.Id}}}}' else 'linux/amd64')\n"
            "    raise SystemExit(0)\n"
            "if args[:1] != ['run']:\n"
            "    raise SystemExit('unexpected Docker operation')\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("CRABC_X86_64_")}
        self.environment.update({
            "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
            "CALENDAR_DISPATCH_LOG": str(self.log),
            "PYTHONDONTWRITEBYTECODE": "1",
        })

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        self.log.unlink(missing_ok=True)
        return subprocess.run(
            ["bash", str(self.checkout / "scripts/dev-x86_64.sh"), "owned-calendar-component", *arguments],
            cwd=self.checkout, env=self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )

    def calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_launcher_runs_by_observed_image_after_host_archive_retention(self) -> None:
        cases = (
            ((), []),
            (("--static-sysroot", str(self.static), str(self.dynamic)),
             ["--static-sysroot", "/workspace/.work/x86_64/products/static product",
              "/workspace/.work/x86_64/products/dynamic product"]),
            (("--static-sysroot", str(self.static.relative_to(self.checkout)),
              str(self.dynamic.relative_to(self.checkout))),
             ["--static-sysroot", "/workspace/.work/x86_64/products/static product",
              "/workspace/.work/x86_64/products/dynamic product"]),
        )
        for arguments, forwarded in cases:
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.calls()
                host = [call for call in calls if call[0] == "host-runner"]
                self.assertEqual(host, [["host-runner", "fetch-tzif-archives", "--output",
                                         str(self.work / "calendar-tzif-input-2025b/download")]])
                runs = [call[1:] for call in calls if call[:2] == ["docker", "run"]]
                self.assertEqual(len(runs), 1)
                run = runs[0]
                # Archive retention precedes the only containerized execution.
                self.assertLess(calls.index(["host-runner", *host[0][1:]]),
                                calls.index(["docker", *run]))
                expected = [IMAGE_ID, "bash", "/workspace/compat/x86_64/run_owned_calendar_component.sh",
                            *forwarded]
                self.assertEqual(run[-len(expected):], expected)
                self.assertIn(f"CRABC_X86_CALENDAR_IMAGE_ID={IMAGE_ID}", run)
                self.assertIn("--cap-add=SYS_CHROOT", run)
                self.assertNotIn("--privileged", run)
                self.assertFalse(any(value.startswith("--cap-add=SYS_TIME") for value in run))
                mounts = [run[index + 1] for index, value in enumerate(run[:-1]) if value == "--volume"]
                self.assertIn(f"{self.checkout}:/workspace", mounts)
                self.assertIn(f"{self.work}:/workspace/.work/x86_64", mounts)

    def test_incomplete_or_escaping_products_fail_before_any_effect(self) -> None:
        outside = Path(tempfile.mkdtemp(dir=WORK))
        self.addCleanup(shutil.rmtree, outside, True)
        for arguments in (
            (str(self.dynamic),),
            ("--static-sysroot", str(self.static)),
            ("--static-sysroot", str(self.static), str(self.dynamic), "extra"),
            ("--static-sysroot", "--dynamic", str(self.dynamic)),
            ("--static-sysroot", str(outside), str(self.dynamic)),
        ):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.log.exists() and any(
                    call[0] == "host-runner" or call[:2] == ["docker", "run"] for call in self.calls()))


if __name__ == "__main__":
    unittest.main()
