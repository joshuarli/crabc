"""The pthread family dispatcher accepts only a sealed POSIX receipt and fresh work."""

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


class OwnedPthreadFamilyDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/test-owned-pthread-family-dispatch"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.state = self.work / "state"
        self.state.mkdir()
        self.execution = self.state / "execution.json"
        self.execution.write_text("{}\n", encoding="utf-8")
        self.output = self.state / "pthread-family"
        self.static = self.state / "static"
        self.dynamic = self.state / "dynamic"
        self.static.mkdir()
        self.dynamic.mkdir()
        self.capture = self.work / "docker.jsonl"
        docker = self.work / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['DISPATCH_CAPTURE'], 'a') as output:\n"
            "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1:3] == ['image', 'inspect']:\n"
            "    print('linux/amd64')\n"
            "elif sys.argv[1] != 'run':\n"
            "    raise SystemExit('unexpected Docker operation')\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("CRABC_X86_64_")}
        self.environment.update(
            PATH=f"{self.work}{os.pathsep}{os.environ['PATH']}",
            DISPATCH_CAPTURE=str(self.capture),
            CRABC_X86_64_WORK_DIR=str(self.state),
        )

    def arguments(self, execution: Path | str | None = None,
                  output: Path | str | None = None, jobs: str = "2") -> list[str]:
        return ["--family-execution", str(self.execution if execution is None else execution),
                "--output", str(self.output if output is None else output), "--jobs", jobs]

    def invoke(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        self.capture.unlink(missing_ok=True)
        return subprocess.run(
            ["bash", str(DISPATCHER), "owned-pthread-family", *arguments],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, check=False,
        )

    def assert_rejected_without_mutation(self, arguments: list[str]) -> None:
        before = set(self.state.rglob("*"))
        result = self.invoke(arguments)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.capture.exists())
        self.assertEqual(set(self.state.rglob("*")), before)

    def test_sealed_input_and_fresh_output_reach_only_the_pthread_coordinator(self) -> None:
        expected = ["--family-execution", "/workspace/.work/x86_64/execution.json",
                    "--output", "/workspace/.work/x86_64/pthread-family", "--jobs", "2"]
        for arguments in (
            self.arguments(),
            self.arguments(self.execution.relative_to(ROOT), self.output.relative_to(ROOT)),
            self.arguments("/workspace/.work/x86_64/execution.json", "/workspace/.work/x86_64/pthread-family"),
            ["--jobs", "2", *self.arguments()[:-2]],
        ):
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [value for value in map(json.loads, self.capture.read_text().splitlines())
                        if value[0] == "run"]
                self.assertEqual(len(runs), 1)
                argv = runs[0]
                self.assertEqual(
                    argv[-10:],
                    ["python3", "-B", "/workspace/compat/x86_64/owned_pthread_family.py", "run", *expected],
                )
                self.assertIn("--cap-add=SYS_CHROOT", argv)
                self.assertIn("--cap-add=SYS_ADMIN", argv)
                self.assertNotIn("--privileged", argv)
                self.assertNotIn("--security-opt=seccomp=unconfined", argv)
                self.assertFalse(self.output.exists())

    def test_parser_rejects_duplicate_or_malformed_options_before_docker(self) -> None:
        valid = self.arguments()
        invalid = [
            [], valid[:-3], valid[:-1], valid + ["extra"],
            [*valid, "--jobs", "3"],
            ["--jobs", "0", *valid[:-2]],
            ["--jobs", "4", *valid[:-2]],
            ["--jobs", "x", *valid[:-2]],
            ["--family-execution", "", *valid[2:]],
            ["--output", "", *valid[4:]],
            ["--unknown", "value", *valid[2:]],
        ]
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                self.assert_rejected_without_mutation(arguments)

    def test_paths_must_be_physical_receipt_and_fresh_work_child(self) -> None:
        alias = self.state / "execution-alias.json"
        alias.symlink_to(self.execution)
        parent_alias = self.state / "alias-parent"
        parent_alias.symlink_to(self.state, target_is_directory=True)
        for input_path in (
            ROOT, self.state, alias, self.state / "missing.json", str(self.execution) + "/../execution.json",
            "/workspace/usr/execution.json", parent_alias / "execution.json",
        ):
            with self.subTest(input_path=input_path):
                self.assert_rejected_without_mutation(self.arguments(execution=input_path))
        for output in (
            self.execution, self.state, alias, parent_alias / "new", ROOT / ".work", self.work,
            self.state / "missing-parent/new", str(self.output) + "/../new", "/workspace/usr/new",
        ):
            with self.subTest(output=output):
                self.assert_rejected_without_mutation(self.arguments(output=output))

    def test_help_names_the_sealed_family_interface(self) -> None:
        result = subprocess.run(["bash", str(DISPATCHER), "--help"], env=self.environment,
                                capture_output=True, text=True, check=False)
        self.assertIn(
            "owned-pthread-family --family-execution FILE --output NEW_DIR [--jobs 1|2|3]",
            result.stderr,
        )

    def test_composition_replay_accepts_one_physical_static_dynamic_pair(self) -> None:
        valid = ["--static-sysroot", str(self.static), str(self.dynamic)]
        result = self.invoke_composition(valid)
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = [value for value in map(json.loads, self.capture.read_text().splitlines())
                if value[0] == "run"][0]
        self.assertEqual(
            argv[-5:],
            ["bash", "/workspace/compat/x86_64/run_owned_pthread_family_composition.sh", "--static-sysroot",
             "/workspace/.work/x86_64/static", "/workspace/.work/x86_64/dynamic"],
        )
        for arguments in (
            [], valid[:-1], valid + ["extra"], ["--static-sysroot", "", str(self.dynamic)],
            ["--static-sysroot", str(self.static), "-x"],
            ["--static-sysroot", str(self.execution), str(self.dynamic)],
        ):
            with self.subTest(arguments=arguments):
                before = set(self.state.rglob("*"))
                rejected = self.invoke_composition(arguments)
                self.assertEqual(rejected.returncode, 2, rejected.stderr)
                self.assertFalse(self.capture.exists())
                self.assertEqual(set(self.state.rglob("*")), before)

    def invoke_composition(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        self.capture.unlink(missing_ok=True)
        return subprocess.run(
            ["bash", str(DISPATCHER), "owned-pthread-family-composition", *arguments],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, check=False,
        )


if __name__ == "__main__":
    unittest.main()
