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
        runs = [call for call in self.calls() if call[0] == "run" and "python3" in call]
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

    def test_integrated_products_use_core_image_without_moving_engine_execution(self) -> None:
        runner, arguments = self.runner_arguments("allocator-perf-integrated", "--full")
        self.assertEqual((runner, arguments), ("compat/allocator/perf_integrated_x86_64.py", ["--full"]))
        run = next(call for call in self.calls() if call[0] == "run" and "python3" in call)
        self.assertIn(fixture.PIN, run)
        self.assertIn("CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID=" + fixture.PIN, run)
        self.runner_arguments("allocator-perf-engine", "--reader-tests")
        run = next(call for call in self.calls() if call[0] == "run" and "python3" in call)
        self.assertNotIn(fixture.PIN, run)

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

    def test_baseline_profiles_reach_owning_readers(self) -> None:
        for command, runner, operation, flag in (
            ("allocator-m6", "m6_gate.py", ["--check"], "--qualification-profile"),
            ("allocator-m7", "x86_64_m7_gate.py", ["--check"], "--qualification-profile"),
            ("allocator-m9", "x86_64_m9_gate.py", ["--check"], "--profile"),
            ("allocator-m10", "x86_64_m10_gate.py", ["--check"], "--profile"),
        ):
            for arguments in ([flag, "baseline", *operation], [*operation, flag, "baseline"]):
                with self.subTest(command=command, arguments=arguments):
                    dispatched_runner, dispatched = self.runner_arguments(command, *arguments)
                    self.assertEqual(dispatched_runner, "compat/allocator/" + runner)
                    self.assertEqual(dispatched, [*operation, flag, "baseline"])

    def test_hardware_profiles_reject_ambiguous_or_unrelated_operations(self) -> None:
        for command, flag in (("allocator-m6", "--qualification-profile"),
                              ("allocator-m7", "--qualification-profile"),
                              ("allocator-m9", "--profile")):
            for arguments in ([flag], [flag, "unknown"],
                              [flag, "baseline", flag, "full"],
                              ["--reader-tests", flag, "baseline"]):
                with self.subTest(command=command, arguments=arguments):
                    self.assert_rejected(command, *arguments)
        self.assert_rejected("allocator-m7", "--arena-print", "--qualification-profile", "baseline")

    def test_reader_tests_have_no_qualification_profile(self) -> None:
        for command, flag in (("allocator-m5", "--qualification-profile"), ("allocator-m10", "--profile")):
            runner, arguments = self.runner_arguments(command, "--reader-tests")
            self.assertEqual(runner, "compat/allocator/tests/test_x86_64_" + command.removeprefix("allocator-") + "_gate.py")
            self.assertEqual(arguments, [])
            for arguments in (["--reader-tests", flag, "correctness"], [flag, "full", "--reader-tests"]):
                with self.subTest(command=command, arguments=arguments):
                    self.assert_rejected(command, *arguments)

    def test_operation_matrix_and_retained_readers_reach_original_gate(self) -> None:
        for operation in ([], ["--read"], ["--replay"], ["--read", "--replay"]):
            with self.subTest(operation=operation):
                runner, arguments = self.runner_arguments("allocator-m4", "--operations-matrix", *operation)
                self.assertEqual(runner, "compat/allocator/x86_64_m4_gate.py")
                self.assertEqual(arguments, ["--offline", "--operations-matrix", *operation])
                call = next(call for call in self.calls() if call[0] == "run" and "python3" in call)
                volumes = [call[index + 1] for index, value in enumerate(call) if value == "--volume"]
                if operation:
                    self.assertIn("--read-only", call)
                    self.assertEqual(call[call.index("--network") + 1], "none")
                    for destination in ("/workspace", "/workspace/.work/allocator-x86_64",
                                        "/workspace/target", "/workspace/compat/reports",
                                        "/workspace/compat/allocator/.cache"):
                        self.assertTrue(any(volume.endswith(":" + destination + ":ro") for volume in volumes),
                                        (destination, volumes))
                    writable = [volume for volume in volumes if not volume.endswith(":ro")]
                    self.assertEqual(len(writable), 2, writable)
                    self.assertEqual(writable[0].split(":")[0], writable[1].split(":")[0])
                    self.assertIn("/retained-reader.", writable[0])
                else:
                    self.assertNotIn("--read-only", call)

    def test_invalid_operation_matrix_arguments_reject_before_docker(self) -> None:
        for arguments in (["--read"], ["--replay"], ["--operations-matrix", "--check"],
                          ["--operations-matrix", "--read", "--read"],
                          ["--operations-matrix", "--replay", "--replay"],
                          ["--operations-matrix", "--gate", "m4.upstream"]):
            with self.subTest(arguments=arguments):
                self.assert_rejected("allocator-m4", *arguments)

    def test_divergence_defaults_and_explicit_profiles_reach_reader(self) -> None:
        for operation in ([], ["--check"]):
            for profile in (None, "correctness", "full"):
                for before in (True, False):
                    selected = [] if profile is None else ["--profile", profile]
                    arguments = [*selected, *operation] if before else [*operation, *selected]
                    with self.subTest(arguments=arguments):
                        runner, dispatched = self.runner_arguments("allocator-divergence-evidence", *arguments)
                        self.assertEqual(runner, "compat/allocator/divergence_evidence.py")
                        self.assertEqual(dispatched, [*operation, "--profile", profile or "correctness"])

    def test_divergence_reader_tests_and_invalid_profiles(self) -> None:
        runner, arguments = self.runner_arguments("allocator-divergence-evidence", "--reader-tests")
        self.assertEqual(runner, "compat/allocator/tests/test_divergence_evidence.py")
        self.assertEqual(arguments, [])
        for arguments in (["--profile"], ["--profile", "unknown"],
                          ["--profile", "full", "--profile", "full"],
                          ["--reader-tests", "--profile", "correctness"]):
            with self.subTest(arguments=arguments):
                self.assert_rejected("allocator-divergence-evidence", *arguments)


if __name__ == "__main__":
    unittest.main()
