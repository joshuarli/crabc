"""Family receipt paths and fresh output reach only the native family runner."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedPosixFamilyDispatchTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.state = self.work / "state"
        self.state.mkdir()
        self.static = self.state / "static preparation.json"
        self.dynamic = self.state / "dynamic qualification.json"
        self.static.write_text("{}\n")
        self.dynamic.write_text("{}\n")
        self.output = self.state / "new family"
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

    def arguments(self, static=None, dynamic=None, output=None):
        return ["--static-preparation", str(self.static if static is None else static),
                "--dynamic-qualification", str(self.dynamic if dynamic is None else dynamic),
                "--output", str(self.output if output is None else output)]

    def invoke(self, arguments):
        self.capture.unlink(missing_ok=True)
        return subprocess.run(["bash", str(DISPATCHER), "owned-posix-family", *arguments],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, check=False)

    def assert_rejected_without_mutation(self, arguments):
        before = set(self.state.rglob("*"))
        result = self.invoke(arguments)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.capture.exists())
        self.assertEqual(set(self.state.rglob("*")), before)

    def test_receipts_and_fresh_output_translate_host_relative_and_container_paths(self):
        expected = self.arguments("/workspace/.work/x86_64/static preparation.json",
            "/workspace/.work/x86_64/dynamic qualification.json", "/workspace/.work/x86_64/new family")
        for arguments in (self.arguments(), self.arguments(self.static.relative_to(ROOT),
                self.dynamic.relative_to(ROOT), self.output.relative_to(ROOT)), expected,
                self.arguments()[4:] + self.arguments()[:4]):
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [a for a in map(json.loads, self.capture.read_text().splitlines()) if a[0] == "run"]
                self.assertEqual(len(runs), 1)
                argv = runs[0]
                self.assertEqual(argv[-10:], ["python3", "-B",
                    "/workspace/compat/x86_64/owned_posix_family_execution.py", "run", *expected])
                for flag in ("--cap-add=SYS_ADMIN", "--cap-add=SYS_CHROOT",
                             "--security-opt=apparmor=unconfined", "--security-opt=seccomp=unconfined"):
                    self.assertIn(flag, argv)
                for flag in ("--privileged", "--pid=host", "--ipc=host", "--userns=host"):
                    self.assertNotIn(flag, argv)
                self.assertFalse(self.output.exists())

    def test_exact_flags_reject_missing_duplicate_empty_and_option_values_before_docker(self):
        valid = self.arguments()
        invalid = [[], valid[:-2], valid[:-1], valid + ["extra"], valid + valid[:2],
                   ["--unknown", "value", *valid[2:]]]
        for offset in (0, 2, 4):
            for value in ("", "-x", "--output"):
                invalid.append([*valid[:offset + 1], value, *valid[offset + 2:]])
            invalid.append([*valid, *valid[offset:offset + 2]])
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                self.assert_rejected_without_mutation(arguments)

    def test_receipts_require_physical_regular_files_and_output_a_fresh_physical_child(self):
        alias = self.state / "alias.json"
        alias.symlink_to(self.static)
        parent_alias = self.state / "alias-parent"
        parent_alias.symlink_to(self.state, target_is_directory=True)
        for path in (ROOT, self.state, alias, self.state / "missing.json",
                     str(self.static) + "/../static preparation.json", "/workspace/usr/file",
                     parent_alias / self.static.name):
            for role in ("static", "dynamic"):
                with self.subTest(role=role, path=path):
                    self.assert_rejected_without_mutation(self.arguments(**{role: path}))
        for path in (self.static, self.state, alias, parent_alias / "fresh", ROOT / ".work",
                     self.state / "missing-parent/fresh", self.work,
                     str(self.output) + "/../fresh", "/workspace/usr/fresh"):
            with self.subTest(output=path):
                self.assert_rejected_without_mutation(self.arguments(output=path))

    def test_cargo_mount_translation_rejects_shadowed_host_paths(self):
        cargo = self.work / "cargo-cache"
        cargo.mkdir()
        receipt = cargo / "receipt.json"
        receipt.write_text("{}\n")
        self.environment["CRABC_X86_64_CORE_CARGO_VOLUME"] = str(cargo)
        for path in (receipt, "/workspace/.work/x86_64/cargo/receipt.json"):
            result = self.invoke(self.arguments(static=path, output=cargo / "fresh"))
            self.assertEqual(result.returncode, 0, result.stderr)
            argv = [a for a in map(json.loads, self.capture.read_text().splitlines()) if a[0] == "run"][0]
            self.assertEqual(argv[-6], "--static-preparation")
            self.assertEqual(argv[-5], "/workspace/.work/x86_64/cargo/receipt.json")
            self.assertEqual(argv[-1], "/workspace/.work/x86_64/cargo/fresh")
        hidden = self.state / "cargo"
        hidden.mkdir()
        (hidden / "receipt.json").write_text("{}\n")
        self.assert_rejected_without_mutation(self.arguments(static=hidden / "receipt.json"))
        self.assert_rejected_without_mutation(self.arguments(output=hidden / "fresh"))
        hidden_work = ROOT / ".work/x86_64"
        self.assert_rejected_without_mutation(self.arguments(output=hidden_work / "fresh-family"))

    def test_output_cannot_select_directories_created_by_container_setup(self):
        for name in ("target", "cargo", "tmp", "reports"):
            with self.subTest(name=name):
                self.assert_rejected_without_mutation(self.arguments(output=self.state / name))

    def test_help_names_the_complete_family_interface(self):
        result = subprocess.run(["bash", str(DISPATCHER), "--help"], env=self.environment,
            capture_output=True, text=True, check=False)
        self.assertIn("owned-posix-family --static-preparation FILE --dynamic-qualification FILE --output NEW_DIR",
            result.stderr)


if __name__ == "__main__":
    unittest.main()
