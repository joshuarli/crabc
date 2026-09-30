#!/usr/bin/env python3
"""Allocator qualification launchers preserve explicit profile selection."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("core_dispatch_fixture", ROOT / "compat/x86_64/tests/test_core_image_dispatch.py")
assert SPEC is not None and SPEC.loader is not None
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class AllocatorQualificationProfileDispatchTests(unittest.TestCase):
    invoke = fixture.CoreImageDispatchTests.invoke
    calls = fixture.CoreImageDispatchTests.calls

    def setUp(self) -> None:
        fixture.CoreImageDispatchTests.setUp(self)
        scratch = ROOT / ".work/allocator-x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.environment = {key: value for key, value in self.environment.items()
                            if not key.startswith("CRABC_ALLOCATOR_X86_64_")}
        self.environment["CRABC_ALLOCATOR_X86_64_WORK_DIR"] = temporary.name

    def runner_arguments(self, command: str, *arguments: str) -> tuple[str, list[str]]:
        result = self.invoke("compat/allocator/run-x86_64.sh", command, *arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(len(runs), 1, runs)
        call = runs[0]
        index = call.index("python3")
        return call[index + 1], call[index + 2:]

    def assert_rejected(self, command: str, *arguments: str) -> None:
        result = self.invoke("compat/allocator/run-x86_64.sh", command, *arguments)
        self.assertNotEqual(result.returncode, 0, (command, arguments))
        self.assertFalse(self.log.exists(), "invalid profile arguments reached Docker")

    def test_default_correctness_profiles_are_explicit(self) -> None:
        for command, operation, flag in (
            ("allocator-m5", [], "--qualification-profile"),
            ("allocator-m5", ["--check"], "--qualification-profile"),
            ("allocator-m10", ["--check"], "--profile"),
            ("allocator-m10", ["--build-audit"], "--profile"),
        ):
            with self.subTest(command=command, operation=operation):
                runner, arguments = self.runner_arguments(command, *operation)
                self.assertEqual(runner, "compat/allocator/x86_64_" + command.removeprefix("allocator-") + "_gate.py")
                self.assertEqual(arguments.count(flag), 1)
                index = arguments.index(flag)
                self.assertEqual(arguments[index + 1], "correctness")
                self.assertEqual(arguments[:index] + arguments[index + 2:], operation)

    def test_explicit_full_and_correctness_work_before_or_after_operation(self) -> None:
        for command, operation, flag in (
            ("allocator-m5", [], "--qualification-profile"),
            ("allocator-m5", ["--check"], "--qualification-profile"),
            ("allocator-m5", ["--gate", "m5.pointer-dispatch"], "--qualification-profile"),
            ("allocator-m10", ["--check"], "--profile"),
            ("allocator-m10", ["--build-audit"], "--profile"),
        ):
            for profile in ("full", "correctness"):
                for arguments in ([flag, profile, *operation], [*operation, flag, profile]):
                    with self.subTest(command=command, arguments=arguments):
                        _, dispatched = self.runner_arguments(command, *arguments)
                        self.assertEqual(dispatched.count(flag), 1)
                        index = dispatched.index(flag)
                        self.assertEqual(dispatched[index + 1], profile)
                        self.assertEqual(dispatched[:index] + dispatched[index + 2:], operation)

    def test_malformed_profiles_reject_before_docker(self) -> None:
        for command, flag in (("allocator-m5", "--qualification-profile"), ("allocator-m10", "--profile")):
            for arguments in (
                [flag], [flag, "unknown"], [flag, "--check"],
                ["--check", flag], ["--check", flag, "unknown"],
                ["--check", flag, "full", flag, "correctness"],
                [flag, "full", "--check", flag, "full"],
            ):
                with self.subTest(command=command, arguments=arguments):
                    self.assert_rejected(command, *arguments)

    def test_reader_tests_have_no_qualification_profile(self) -> None:
        for command, flag in (("allocator-m5", "--qualification-profile"), ("allocator-m10", "--profile")):
            runner, arguments = self.runner_arguments(command, "--reader-tests")
            self.assertEqual(runner, "compat/allocator/tests/test_x86_64_" + command.removeprefix("allocator-") + "_gate.py")
            self.assertEqual(arguments, [])
            for arguments in (["--reader-tests", flag, "correctness"], [flag, "full", "--reader-tests"]):
                with self.subTest(command=command, arguments=arguments):
                    self.assert_rejected(command, *arguments)


if __name__ == "__main__":
    unittest.main()
