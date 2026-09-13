#!/usr/bin/env python3
"""The selection dispatcher delegates host replay to its authoritative reader."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / ".work/x86_64/native-abi-selection-dispatcher-tests"


class NativeAbiSelectionDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        WORK.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(temporary.cleanup)
        self.checkout = Path(temporary.name) / "checkout"
        scripts = self.checkout / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/dev-x86_64.sh", scripts / "dev-x86_64.sh")
        self.work = self.checkout / ".work/x86_64"
        self.work.mkdir(parents=True)
        self.runner_log = self.work / "reader-arguments.json"
        reader = self.checkout / "compat/x86_64/native_abi_selection.py"
        reader.parent.mkdir(parents=True)
        reader.write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['ABI_SELECTION_READER_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
            "raise SystemExit(int(os.environ.get('ABI_SELECTION_READER_STATUS', '0')))\n",
            encoding="utf-8",
        )
        binaries = self.work / "bin"
        binaries.mkdir()
        docker = binaries / "docker"
        docker.write_text("#!/bin/sh\necho docker-must-not-run >&2\nexit 97\n", encoding="utf-8")
        docker.chmod(0o755)
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("CRABC_X86_64_")
        }
        self.environment.update({
            "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
            "ABI_SELECTION_READER_LOG": str(self.runner_log),
            "PYTHONDONTWRITEBYTECODE": "1",
        })

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.checkout / "scripts/dev-x86_64.sh"), "native-abi-selection", *arguments],
            cwd=self.checkout,
            env=self.environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def test_each_mode_passes_exact_arguments_to_host_reader(self) -> None:
        # The reader owns physical input admission. The dispatcher must retain
        # each path and optional contract verbatim, including spaces, so it
        # cannot silently substitute a different product or evidence tree.
        inputs = [
            "--measurement-checkout", ".work/worktrees/measurement source",
            "--elf-facts", ".work/x86_64/facts/report.json",
            "--base-inventory", ".work/x86_64/inventory/report.json",
            "--static-product", ".work/x86_64/static product",
            "--dynamic-product", ".work/x86_64/dynamic product",
            "--static-preparation", ".work/x86_64/static/preparation.json",
            "--contract", "compat/x86_64/native-abi-selection.toml",
            "--declaration-report", ".work/x86_64/declarations/report.json",
            "--public-data-ordinary-link-report", ".work/x86_64/public-data/ordinary/report.json",
            "--loader-debug-abi-report", ".work/x86_64/public-data/loader/report.json",
            "--compiler-helper-aggregate-report", ".work/x86_64/compiler helper/report.json",
            "--crt-startup-report", ".work/x86_64/crt startup/report.json",
        ]
        for mode in ("build-report", "validate-report", "require-closure"):
            with self.subTest(mode=mode):
                arguments = [mode]
                if mode != "build-report":
                    arguments.append(".work/x86_64/selection/report.json")
                arguments.extend(inputs)
                if mode == "build-report":
                    arguments.extend(["--output", ".work/x86_64/new selection"])
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(self.runner_log.read_text()), arguments)

    def test_failed_replay_or_closure_is_not_converted_to_success(self) -> None:
        self.environment["ABI_SELECTION_READER_STATUS"] = "23"
        for mode in ("build-report", "validate-report", "require-closure"):
            with self.subTest(mode=mode):
                result = self.invoke(mode, "report.json")
                self.assertEqual(result.returncode, 23, result.stderr)

    def test_unknown_or_missing_mode_is_rejected_before_reader(self) -> None:
        for arguments in ((), ("collect",), ("promote",), ("--allow-incomplete",)):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.runner_log.exists())


if __name__ == "__main__":
    unittest.main()
