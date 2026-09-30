#!/usr/bin/env python3
"""Qualification profiles reach the native runner through validated shell argv."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("core_dispatch_fixture", ROOT / "compat/x86_64/tests/test_core_image_dispatch.py")
assert SPEC is not None and SPEC.loader is not None
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class QualificationProfileDispatchTests(unittest.TestCase):
    setUp = fixture.CoreImageDispatchTests.setUp
    invoke = fixture.CoreImageDispatchTests.invoke
    calls = fixture.CoreImageDispatchTests.calls

    def runner_arguments(self, *arguments: str) -> list[str]:
        result = self.invoke("scripts/dev-x86_64.sh", "qualification-manifest", *arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(len(runs), 1, runs)
        runner = "/workspace/compat/x86_64/run_qualification_manifest.py"
        self.assertIn(runner, runs[0])
        return runs[0][runs[0].index(runner) + 1:]

    def assert_rejected(self, *arguments: str) -> None:
        result = self.invoke("scripts/dev-x86_64.sh", "qualification-manifest", *arguments)
        self.assertNotEqual(result.returncode, 0, arguments)
        self.assertFalse(self.log.exists(), "invalid profile arguments reached Docker")

    def test_default_uses_the_declared_correctness_profile(self) -> None:
        contract = json.loads((ROOT / "compat/x86_64/qualification_manifest.json").read_text())
        self.assertEqual(contract["qualification_profile"], "correctness")
        arguments = self.runner_arguments()
        self.assertIn(arguments, ([], ["--profile", "correctness"]))

    def test_explicit_profiles_survive_either_side_of_ordered_and_status_options(self) -> None:
        for profile in ("correctness", "full"):
            for operation in ([], ["--status"], ["--through", "capability.accounting"]):
                for arguments in (["--profile", profile, *operation], [*operation, "--profile", profile]):
                    with self.subTest(arguments=arguments):
                        dispatched = self.runner_arguments(*arguments)
                        self.assertEqual(dispatched.count("--profile"), 1)
                        index = dispatched.index("--profile")
                        self.assertEqual(dispatched[index + 1], profile)
                        self.assertEqual(dispatched[:index] + dispatched[index + 2:], operation)

    def test_missing_invalid_and_duplicate_profiles_reject_before_docker(self) -> None:
        for arguments in (
            ("--profile",), ("--profile", "unknown"), ("--profile", "--status"),
            ("--profile", "full", "--profile", "full"),
            ("--profile", "correctness", "--status", "--profile", "full"),
            ("--status", "--profile"), ("--status", "--profile", "unknown"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_rejected(*arguments)

    def test_profiles_cannot_change_private_admission_publication_or_receipt_validation(self) -> None:
        receipt = self.work / "receipt.json"
        receipt.write_text("{}")
        operations = (
            ["--private-admission"],
            ["--publish", "capability.accounting", "capability-accounting", str(receipt)],
            ["--validate-receipt", str(receipt)],
        )
        for operation in operations:
            for arguments in (["--profile", "full", *operation], [*operation, "--profile", "correctness"]):
                with self.subTest(arguments=arguments):
                    self.assert_rejected(*arguments)


if __name__ == "__main__":
    unittest.main()
