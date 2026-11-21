#!/usr/bin/env python3
"""Native launch defaults remain pinned when the development tag moves."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
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


HOST_MACHINE = subprocess.check_output(["uname", "-m"], text=True).strip()


@unittest.skipUnless(HOST_MACHINE in ("x86_64", "amd64"), "x86 image contract")
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
            "    failure = os.environ.get('IMAGE_INSPECT_FAILURE')\n"
            "    if failure:\n"
            "        print(failure, file=sys.stderr)\n"
            "        sys.exit(1)\n"
            f"    if args[-1] == {PIN!r} and os.environ.get('PIN_MISSING'):\n"
            f"        print({'Error response from daemon: No such image: ' + PIN!r}, file=sys.stderr)\n"
            "        sys.exit(1)\n"
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
                    expected_message = "unavailable" if script == "scripts/dev-x86_64.sh" else "could not inspect"
                    self.assertIn(expected_message, result.stderr)
                    self.assertFalse(any(call[0] in ("run", "build") for call in self.calls()))

    def test_rust_check_preserves_docker_inspect_failure_diagnostics(self) -> None:
        failures = (
            ("missing image", "Error response from daemon: No such image: " + PIN, None),
            ("daemon permission", None,
             "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"),
            ("daemon unavailable", None,
             "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"),
        )
        for category, missing_image, injected_error in failures:
            with self.subTest(category=category):
                self.environment.pop("IMAGE_INSPECT_FAILURE", None)
                self.environment.pop("PIN_MISSING", None)
                if missing_image is not None:
                    self.environment["PIN_MISSING"] = "1"
                else:
                    self.environment["IMAGE_INSPECT_FAILURE"] = injected_error
                result = self.invoke("scripts/lanes/rust-check.sh")
                self.assertEqual(result.returncode, 1)
                self.assertIn(missing_image or injected_error, result.stderr)
                self.assertIn("could not inspect", result.stderr)
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

    def test_c_performance_executes_the_current_pin_without_a_tag_override(self) -> None:
        product = self.work / "dynamic-product"
        product.mkdir()
        for explicit in (False, True):
            with self.subTest(explicit=explicit):
                if explicit:
                    self.environment["CRABC_X86_64_CORE_IMAGE"] = PIN
                result = self.invoke("scripts/dev-x86_64.sh", "perf-c", "plan",
                                     "--dynamic-product", str(product),
                                     "--work-dir", str(self.work / "performance-plan"))
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [call for call in self.calls() if call[0] == "run"]
                self.assertTrue(runs)
                self.assertTrue(all(PIN in run for run in runs))
                self.assertTrue(all("CRABC_PERF_DOCKER_IMAGE_ID=" + PIN in run for run in runs))
                self.assertFalse(any(call[0] == "build" for call in self.calls()))

    def test_c_performance_rejects_a_retired_tag_before_execution(self) -> None:
        product = self.work / "dynamic-product"
        product.mkdir()
        self.environment["CRABC_X86_64_CORE_IMAGE"] = "crabc-core-evidence:x86_64-native-perf"
        result = self.invoke("scripts/dev-x86_64.sh", "perf-c", "plan",
                             "--dynamic-product", str(product),
                             "--work-dir", str(self.work / "performance-plan"))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] in ("run", "build") for call in self.calls()))

    def test_rust_check_respects_explicit_image_for_custom_command(self) -> None:
        custom = "local-core:custom"
        self.environment["CRABC_X86_64_CORE_IMAGE"] = custom
        result = self.invoke("scripts/lanes/rust-check.sh", "cargo", "fetch", "--locked")
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0][-4:], [custom, "cargo", "fetch", "--locked"])

    def test_lua_supplied_cohort_is_translated_and_uses_supplied_dynamic_runner(self) -> None:
        for name in ("installed", "rebuilt", "extracted"):
            (self.work / name).mkdir()
        for name in ("preparation.json", "qualification.json", "lua.tar.gz"):
            (self.work / name).write_text("retained input")
        for kind in ("static", "dynamic"):
            with self.subTest(kind=kind):
                arguments = ["--cohort-checkout", str(ROOT),
                             "--installed-sysroot", str(self.work / "installed"),
                             "--extracted-sysroot", str(self.work / "extracted"),
                             "--archive-seed", str(self.work / "lua.tar.gz"),
                             "--work-root", str(self.work / (kind + "-output"))]
                if kind == "static":
                    arguments += ["--static-preparation", str(self.work / "preparation.json"),
                                  "--rebuilt-sysroot", str(self.work / "rebuilt")]
                else:
                    arguments += ["--cohort-receipt", str(self.work / "qualification.json")]
                result = self.invoke("scripts/dev-x86_64.sh", "lua-" + kind + "-source-build", *arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                run = next(call for call in self.calls() if call[0] == "run")
                script = "run_x86_static_dispatch.py" if kind == "static" else "run_x86_dynamic_supplied.py"
                child = run[run.index("/workspace/compat/lua/" + script):]
                self.assertEqual(child[child.index("--cohort-checkout") + 1], "/workspace")
                self.assertEqual(child[child.index("--installed-sysroot") + 1],
                                 "/workspace/.work/x86_64/installed")
                self.assertEqual(child[child.index("--work-root") + 1],
                                 "/workspace/.work/x86_64/" + kind + "-output")


@unittest.skipUnless(HOST_MACHINE in ("x86_64", "amd64"), "x86 image contract")
class InstalledRustCheckWorktreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("docker") is None:
            raise unittest.SkipTest("requires Docker and the pinned native image")
        image = subprocess.run(["docker", "image", "inspect", PIN], capture_output=True)
        if image.returncode:
            raise unittest.SkipTest("requires the pinned native image")

    def test_linked_checkout_uses_its_own_index_without_writing_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()

            def git(directory: Path, *arguments: str) -> None:
                subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=fixture",
                                "-c", "user.email=fixture@example.invalid", *arguments],
                               cwd=directory, check=True, capture_output=True)

            git(repository, "init")
            git(repository, "config", "maintenance.auto", "false")
            git(repository, "config", "gc.auto", "0")
            (repository / "main-only.txt").write_text("main index")
            git(repository, "add", "main-only.txt")
            git(repository, "commit", "--no-verify", "-m", "main fixture")
            checkout = Path(temporary) / "checkout"
            git(repository, "worktree", "add", "-b", "checker", str(checkout))
            (checkout / "branch-only.txt").write_text("linked index")
            git(checkout, "add", "branch-only.txt")
            git(checkout, "commit", "--no-verify", "-m", "linked fixture")

            def metadata() -> dict[str, str]:
                return {str(path.relative_to(repository)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in (repository / ".git").rglob("*") if path.is_file()}

            before = metadata()
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith("CRABC_X86_64_") and not key.startswith("GIT_")}
            environment["CRABC_X86_64_CORE_IMAGE"] = PIN
            result = subprocess.run([str(ROOT / "scripts/lanes/rust-check.sh"),
                                     "git", "ls-files", "--error-unmatch", "branch-only.txt"],
                                    cwd=checkout, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "branch-only.txt\n")
            self.assertEqual(metadata(), before)


@unittest.skipUnless(HOST_MACHINE in ("aarch64", "arm64"), "aarch64 image contract")
class ArmCoreImageDispatchTests(unittest.TestCase):
    def test_pinned_image_and_help(self) -> None:
        scratch = ROOT / ".work/aarch64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            directory = Path(temporary)
            log = directory / "docker.log"
            docker = directory / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "a = sys.argv[1:]\n"
                "with open(os.environ['ARM_DOCKER_LOG'], 'a') as f: f.write(json.dumps(a) + '\\n')\n"
                "if a[:2] == ['image', 'inspect']:\n"
                " if os.environ.get('ARM_PIN_MISSING'): print('missing arm pin', file=sys.stderr); sys.exit(1)\n"
                " if os.environ.get('ARM_INSPECT_ERROR'): print(os.environ['ARM_INSPECT_ERROR'], file=sys.stderr); sys.exit(1)\n"
                f" print(os.environ.get('ARM_IDENTITY', {'linux/arm64'!r}) if '--format' in a and a[a.index('--format')+1] == '{{{{.Os}}}}/{{{{.Architecture}}}}' else {core_image.AARCH64_CORE_IMAGE_ID!r})\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            environment = os.environ.copy()
            environment.update(PATH=str(directory) + os.pathsep + environment["PATH"], ARM_DOCKER_LOG=str(log))
            help_result = subprocess.run([str(ROOT / "scripts/dev-x86_64.sh"), "--help"], cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("Usage:", help_result.stdout)
            self.assertFalse(log.exists())
            missing_environment = {**environment, "ARM_PIN_MISSING": "1"}
            for script, args in (("scripts/dev-x86_64.sh", ("core",)), ("scripts/lanes/rust-check.sh", ())):
                log.unlink(missing_ok=True)
                missing = subprocess.run([str(ROOT / script), *args], cwd=ROOT, env=missing_environment, capture_output=True, text=True)
                self.assertNotEqual(missing.returncode, 0)
                self.assertIn("unavailable" if args else "could not inspect", missing.stderr)
                self.assertFalse(any(call[0] in ("run", "build") for call in (json.loads(line) for line in log.read_text().splitlines())))
            for failure in ("permission denied", "daemon unavailable"):
                log.unlink(missing_ok=True)
                bad = subprocess.run([str(ROOT / "scripts/lanes/rust-check.sh")], cwd=ROOT, env={**environment, "ARM_INSPECT_ERROR": failure}, capture_output=True, text=True)
                self.assertEqual(bad.returncode, 1)
                self.assertIn(failure, bad.stderr)
                self.assertFalse(any(call[0] in ("run", "build") for call in (json.loads(line) for line in log.read_text().splitlines())))
            log.unlink(missing_ok=True)
            bad = subprocess.run([str(ROOT / "scripts/lanes/rust-check.sh")], cwd=ROOT, env={**environment, "ARM_IDENTITY": "linux/amd64"}, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("expected linux/arm64", bad.stderr)
            self.assertFalse(any(call[0] in ("run", "build") for call in (json.loads(line) for line in log.read_text().splitlines())))
            log.unlink()
            result = subprocess.run([str(ROOT / "scripts/dev-x86_64.sh"), "core"], cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            run = next(call for call in calls if call[0] == "run")
            self.assertIn(core_image.AARCH64_CORE_IMAGE_ID, run)
            self.assertEqual(run[run.index("--platform") + 1], "linux/arm64")
            self.assertIn("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=/usr/local/bin/crabc-aarch64-mold-gcc", run)
            log.unlink()
            result = subprocess.run([str(ROOT / "scripts/dev-x86_64.sh"), "image"], cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], "build")
            self.assertEqual(calls[0][calls[0].index("--platform") + 1], "linux/arm64")
            self.assertEqual(calls[0][calls[0].index("--tag") + 1], "crabc-core-evidence:aarch64")
            self.assertEqual(calls[0][calls[0].index("--file") + 1], str(ROOT / "docker/Dockerfile.aarch64"))


if __name__ == "__main__":
    unittest.main()
