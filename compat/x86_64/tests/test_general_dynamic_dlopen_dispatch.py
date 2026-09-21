#!/usr/bin/env python3
"""Focused admission and authority contract for bounded dlfcn dispatch."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "scripts/dev-x86_64.sh"


class GeneralDynamicDlopenDispatchTests(unittest.TestCase):
    def dispatch(self, temporary: Path, *arguments: str) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        capture = temporary / "docker.jsonl"
        if capture.exists():
            capture.unlink()
        docker = temporary / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "arguments = sys.argv[1:]\n"
            "if arguments[:2] == ['image', 'inspect']:\n"
            "    print('linux/amd64')\n"
            "elif arguments[:1] == ['run']:\n"
            "    with open(os.environ['DISPATCH_CAPTURE'], 'a', encoding='utf-8') as stream:\n"
            "        stream.write(json.dumps(arguments) + '\\n')\n"
            "else:\n"
            "    raise SystemExit('unexpected Docker operation')\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        environment = {key: value for key, value in os.environ.items() if not key.startswith("CRABC_X86_64_")}
        environment.update(PATH=f"{temporary}{os.pathsep}{environment['PATH']}", DISPATCH_CAPTURE=str(capture))
        completed = subprocess.run(
            ["bash", str(RUNNER), "general-dynamic-dlopen", *arguments],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )
        calls = [] if not capture.exists() else [json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines()]
        return completed, calls

    def test_physical_product_and_each_entry_mode_use_only_chroot_authority(self) -> None:
        scratch = ROOT / ".work/x86_64/general-dynamic-dlopen-dispatch-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as raw_temporary:
            temporary = Path(raw_temporary)
            product = temporary / "product"
            product.mkdir()
            expected_product = "/workspace/.work/x86_64/" + product.relative_to(ROOT / ".work/x86_64").as_posix()
            for option, expected_mode in (("dynamic-pie", "--dynamic-pie"), ("dynamic-non-pie", "--dynamic-non-pie")):
                with self.subTest(option=option):
                    completed, calls = self.dispatch(temporary, "--entry-mode", option, str(product))
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(len(calls), 1)
                    command = calls[0]
                    self.assertEqual([argument for argument in command if argument.startswith("--cap-add=")], ["--cap-add=SYS_CHROOT"])
                    self.assertNotIn("--privileged", command)
                    self.assertNotIn("--security-opt", command)
                    self.assertFalse(any("SYS_ADMIN" in argument for argument in command))
                    self.assertIn(f"CRABC_GENERAL_DYNAMIC_ENTRY_MODE={expected_mode}", command)
                    self.assertIn("CRABC_GENERAL_DYNAMIC_DLOPEN_SKIP_SEARCH=1", command)
                    self.assertEqual(command[-6:], [
                        "env",
                        f"CRABC_GENERAL_DYNAMIC_ENTRY_MODE={expected_mode}",
                        "CRABC_GENERAL_DYNAMIC_DLOPEN_SKIP_SEARCH=1",
                        "bash",
                        "/workspace/compat/x86_64/run_general_dynamic_dlopen.sh",
                        expected_product,
                    ])

    def test_nonphysical_product_and_unknown_entry_mode_stop_before_docker(self) -> None:
        scratch = ROOT / ".work/x86_64/general-dynamic-dlopen-dispatch-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as raw_temporary:
            temporary = Path(raw_temporary)
            product = temporary / "product"
            product.mkdir()
            alias = temporary / "product-alias"
            alias.symlink_to(product, target_is_directory=True)
            for arguments in (("--entry-mode", "dynamic-other", str(product)), (str(alias),)):
                with self.subTest(arguments=arguments):
                    completed, calls = self.dispatch(temporary, *arguments)
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
