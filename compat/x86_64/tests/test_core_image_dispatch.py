#!/usr/bin/env python3
"""Native launch defaults remain pinned when the development tag moves."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("core_image", ROOT / "compat/x86_64/core_image.py")
core_image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core_image)
PIN = core_image.CORE_IMAGE_ID
TAG = "crabc-core-evidence:x86_64"
STALE = "sha256:" + "2" * 64


class CoreImageDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.log = self.work / "docker.jsonl"
        docker = self.work / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['IMAGE_DISPATCH_LOG'], 'a') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args[:2] == ['image', 'inspect']:\n"
            f"    if args[-1] == {PIN!r} and os.environ.get('PIN_MISSING'): sys.exit(1)\n"
            "    fmt = args[args.index('--format') + 1] if '--format' in args else ''\n"
            f"    print((args[-1] if args[-1].startswith('sha256:') else {STALE!r}) "
            "if fmt == '{{.Id}}' else 'linux/amd64')\n"
            "elif args[:1] not in (['run'], ['build']): sys.exit(3)\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("CRABC_X86_64_")}
        self.environment.update(
            PATH=str(self.work) + os.pathsep + os.environ["PATH"],
            IMAGE_DISPATCH_LOG=str(self.log),
            CRABC_X86_64_WORK_DIR=str(self.work),
            PYTHONDONTWRITEBYTECODE="1",
        )

    def invoke(self, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        self.log.unlink(missing_ok=True)
        return subprocess.run(["bash", str(ROOT / script), *arguments], cwd=ROOT,
                              env=self.environment, capture_output=True, text=True, timeout=30)

    def calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_runtime_default_ignores_stale_mutable_tag(self) -> None:
        result = self.invoke("scripts/dev-x86_64.sh", "core")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        runs = [call for call in calls if call[0] == "run"]
        self.assertTrue(runs)
        for run in runs:
            self.assertIn(PIN, run)
            self.assertNotIn(TAG, run)
        self.assertFalse(any(call[0] == "build" for call in calls))

    def test_missing_pin_refuses_execution_and_implicit_build(self) -> None:
        self.environment["PIN_MISSING"] = "1"
        for explicit in (False, True):
            if explicit:
                self.environment["CRABC_X86_64_CORE_IMAGE"] = PIN
            for script, arguments in (("scripts/dev-x86_64.sh", ("core",)),
                                      ("scripts/lanes/rust-check.sh", ())):
                with self.subTest(script=script, explicit=explicit):
                    result = self.invoke(script, *arguments)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("unavailable", result.stderr)
                    self.assertFalse(any(call[0] in ("run", "build") for call in self.calls()))

    def test_help_does_not_require_an_available_pin_or_docker(self) -> None:
        self.environment["PIN_MISSING"] = "1"
        result = self.invoke("scripts/dev-x86_64.sh", "--help")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stderr)
        self.assertFalse(self.log.exists())

    def test_explicit_image_selection_and_build_tag_are_preserved(self) -> None:
        for custom in (None, "crabc-core-evidence:x86_64-native-perf", "local-core:custom"):
            with self.subTest(custom=custom):
                if custom is None:
                    self.environment.pop("CRABC_X86_64_CORE_IMAGE", None)
                else:
                    self.environment["CRABC_X86_64_CORE_IMAGE"] = custom
                    result = self.invoke("scripts/dev-x86_64.sh", "core")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = self.calls()
                    self.assertTrue(any(call[:2] == ["image", "inspect"] and custom == call[-1]
                                        for call in calls))
                    runs = [call for call in calls if call[0] == "run"]
                    self.assertTrue(runs)
                    self.assertTrue(all(STALE in run and custom not in run for run in runs))
                result = self.invoke("scripts/dev-x86_64.sh", "image")
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.calls()
                self.assertEqual(len(calls), 1)
                build = calls[0]
                self.assertEqual(build[0], "build")
                self.assertEqual(build[build.index("--tag") + 1], custom or TAG)

    def test_no_argument_rust_check_uses_pin_for_every_profile(self) -> None:
        result = self.invoke("scripts/lanes/rust-check.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(len(runs), 9)
        self.assertTrue(all(PIN in run and TAG not in run for run in runs))

    def test_rust_check_respects_explicit_image_for_custom_command(self) -> None:
        custom = "local-core:custom"
        self.environment["CRABC_X86_64_CORE_IMAGE"] = custom
        result = self.invoke("scripts/lanes/rust-check.sh", "cargo", "fetch", "--locked")
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0][-4:], [custom, "cargo", "fetch", "--locked"])


if __name__ == "__main__":
    unittest.main()
