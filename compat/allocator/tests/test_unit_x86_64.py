#!/usr/bin/env python3
"""Execution-count boundary for the exact native allocator unit helper."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "run_unit_x86_64.py"
SPEC = importlib.util.spec_from_file_location("allocator_unit_x86_64", SOURCE)
assert SPEC is not None and SPEC.loader is not None
unit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(unit)


class ExactAllocatorUnitTests(unittest.TestCase):
    def run_result(self, code: int, output: str) -> tuple[int, str]:
        captured = io.StringIO()
        result = subprocess.CompletedProcess([], code, output)
        with patch.object(unit.subprocess, "run", return_value=result), \
                contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            status = unit.main(["os::tests::retry_suppression"])
        return status, captured.getvalue()

    def test_one_executed_case_preserves_its_raw_trace(self) -> None:
        output = "trace.retry=8\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 987 filtered out; finished in 0.02s\n"
        self.assertEqual(self.run_result(0, output), (0, output))

    def test_zero_ignored_multiple_and_missing_cases_cannot_succeed(self) -> None:
        for counts in ("0 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored",
                       "2 passed; 0 failed; 0 ignored"):
            output = f"test result: ok. {counts}; 0 measured; 987 filtered out; finished in 0.02s\n"
            with self.subTest(counts=counts):
                self.assertEqual(self.run_result(0, output)[0], 2)
        self.assertEqual(self.run_result(0, "no test summary\n")[0], 2)

    def test_compiler_failure_or_test_signal_remains_a_failure(self) -> None:
        self.assertEqual(self.run_result(101, "compiler or test failure\n"), (101, "compiler or test failure\n"))
        self.assertEqual(self.run_result(-9, ""), (137, ""))

    def test_invalid_selection_never_starts_cargo(self) -> None:
        for arguments in ([], ["os"], ["os::"], ["--ignored"], ["os::test", "extra"]):
            with self.subTest(arguments=arguments), patch.object(unit.subprocess, "run") as run, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(unit.main(arguments), 2)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
