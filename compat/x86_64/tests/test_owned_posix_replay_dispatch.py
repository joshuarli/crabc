"""Supplied POSIX products reach the intended runner and container authority."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"
COMMANDS = (
    "owned-posix-filesystem", "owned-process-control", "owned-posix-signals",
    "owned-posix-composition", "owned-credentials-profile", "owned-environment-lifecycle",
    "owned-kernel-residual", "owned-linux-control", "owned-dynamic-spawn",
    "owned-process-trio", "owned-syslog", "owned-system-cancellation",
    "owned-signal-helpers", "owned-pthread-signal", "owned-posix-timers",
    "owned-dynamic-io-cancellation",
)


class OwnedPosixReplayDispatchTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.state = self.work / "state"
        self.static, self.dynamic = self.state / "static product", self.state / "dynamic product"
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
        self.environment = {k:v for k,v in os.environ.items() if not k.startswith("CRABC_X86_64_")}
        self.environment.update(PATH=f"{self.work}{os.pathsep}{os.environ['PATH']}",
                                DISPATCH_CAPTURE=str(self.capture), CRABC_X86_64_WORK_DIR=str(self.state))

    def invoke(self, command, arguments):
        self.capture.unlink(missing_ok=True)
        return subprocess.run(["bash", str(DISPATCHER), command, *arguments], cwd=ROOT,
                              env=self.environment, capture_output=True, text=True, check=False)

    def test_every_command_forwards_both_paths_and_preserves_container_authority(self):
        expected = ["--static-sysroot", "/workspace/.work/x86_64/static product", "/workspace/.work/x86_64/dynamic product"]
        variants = ([str(self.static), str(self.dynamic)],
                    [str(self.static.relative_to(ROOT)), str(self.dynamic.relative_to(ROOT))],
                    [expected[1], expected[2]])
        for command in COMMANDS:
            for static, dynamic in variants:
                with self.subTest(command=command, static=static):
                    result = self.invoke(command, ["--static-sysroot", static, dynamic])
                    self.assertEqual(result.returncode, 0, result.stderr)
                    runs = [a for a in map(json.loads, self.capture.read_text().splitlines()) if a[0] == "run"]
                    self.assertEqual(len(runs), 1)
                    argv = runs[0]
                    self.assertEqual(argv[-5:], ["bash", "/workspace/compat/x86_64/run_" + command.replace("-", "_") + ".sh", *expected])
                    self.assertEqual("--cap-add=SYS_ADMIN" in argv, command == "owned-pthread-signal")
                    self.assertEqual("--security-opt=apparmor=unconfined" in argv, command == "owned-pthread-signal")
                    self.assertEqual("--security-opt=seccomp=unconfined" in argv, command == "owned-credentials-profile")
                    self.assertEqual("--cap-add=SYS_CHROOT" in argv, command not in ("owned-posix-signals", "owned-posix-timers"))
                    self.assertNotIn("--privileged", argv)

    def test_optional_modes_and_required_pthread_dynamic_product(self):
        for command in COMMANDS:
            for arguments in ([], [str(self.dynamic)], ["--static-sysroot", str(self.static)]):
                with self.subTest(command=command, arguments=arguments):
                    result = self.invoke(command, arguments)
                    required_missing = command == "owned-pthread-signal" and arguments != [str(self.dynamic)]
                    self.assertEqual(result.returncode, 2 if required_missing else 0, result.stderr)
                    if required_missing:
                        self.assertIn("usage:", result.stderr)
                        self.assertFalse(self.capture.exists())
                    else:
                        run = [a for a in map(json.loads, self.capture.read_text().splitlines()) if a[0] == "run"][0]
                        translated = [] if not arguments else ["/workspace/.work/x86_64/dynamic product"] if len(arguments) == 1 else ["--static-sysroot", "/workspace/.work/x86_64/static product"]
                        self.assertEqual(run[-(2 + len(translated)):], ["bash", "/workspace/compat/x86_64/run_" + command.replace("-", "_") + ".sh", *translated])

    def test_malformed_arguments_fail_before_docker_or_state_creation(self):
        malformed = ([""], ["--unknown"], ["--static-sysroot"], ["--static-sysroot", ""],
                     ["--static-sysroot", "--unknown"], ["a", "b"],
                     ["--static-sysroot", "a", "--static-sysroot", "b"],
                     ["--static-sysroot", "a", ""], ["a", "--static-sysroot", "b"])
        for command in COMMANDS:
            for arguments in malformed:
                with self.subTest(command=command, arguments=arguments):
                    result = self.invoke(command, arguments)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("usage:", result.stderr)
                    self.assertFalse(self.capture.exists())
                    self.assertEqual(set(self.state.iterdir()), {self.static, self.dynamic})

    def test_product_paths_reject_escape_symlink_traversal_and_shadowed_host_state(self):
        alias = self.state / "alias"
        alias.symlink_to(self.static, target_is_directory=True)
        for path in (str(ROOT), str(alias), str(self.static) + "/../static product",
                     "/workspace/.work/../escape", "/workspace/usr/lib", str(self.work),
                     str(self.state / "missing")):
            for position in ("static", "dynamic"):
                arguments = ["--static-sysroot", path, str(self.dynamic)] if position == "static" else [path]
                with self.subTest(path=path, position=position):
                    result = self.invoke("owned-posix-composition", arguments)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertFalse(self.capture.exists())
        self.assertEqual(set(self.state.iterdir()), {self.static, self.dynamic, alias})

    def test_translation_accounts_for_cargo_override_and_unshadowed_checkout_products(self):
        cargo = self.work / "cargo-cache"
        product = cargo / "product"
        product.mkdir(parents=True)
        self.environment["CRABC_X86_64_CORE_CARGO_VOLUME"] = str(cargo)
        for argument in (str(product), "/workspace/.work/x86_64/cargo/product"):
            result = self.invoke("owned-posix-composition", [argument])
            self.assertEqual(result.returncode, 0, result.stderr)
            run = [a for a in map(json.loads, self.capture.read_text().splitlines()) if a[0] == "run"][0]
            self.assertEqual(run[-1], "/workspace/.work/x86_64/cargo/product")
        hidden = self.state / "cargo/product"
        hidden.mkdir(parents=True)
        result = self.invoke("owned-posix-composition", [str(hidden)])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("hidden", result.stderr)
        self.assertFalse(self.capture.exists())
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            result = self.invoke("owned-posix-composition", [directory])
            self.assertEqual(result.returncode, 0, result.stderr)
            run = [a for a in map(json.loads, self.capture.read_text().splitlines()) if a[0] == "run"][0]
            self.assertEqual(run[-1], "/workspace/" + Path(directory).relative_to(ROOT).as_posix())

    def test_unrelated_command_argument_contract_is_not_widened(self):
        result = self.invoke("owned-assert", ["--static-sysroot", str(self.static), str(self.dynamic)])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("owned-assert takes no arguments", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_help_describes_exact_replay_interfaces(self):
        result = self.invoke("--help", [])
        self.assertEqual(result.returncode, 2)
        for command in COMMANDS:
            suffix = "DYNAMIC_SYSROOT" if command == "owned-pthread-signal" else "[DYNAMIC_SYSROOT]"
            self.assertIn(f"{command} [--static-sysroot STATIC_SYSROOT] {suffix}", result.stderr)


if __name__ == "__main__":
    unittest.main()
