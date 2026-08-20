"""Pure-Python contract tests for the pthread stress runner."""

from __future__ import annotations

import importlib.util
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_pthread_stress_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class BuildContractTests(unittest.TestCase):
    def test_source_is_compiled_once_and_links_use_the_object(self) -> None:
        compile_command = RUNNER.compile_command(
            ["musl-gcc"],
            Path("/workspace/tests/fixtures/pthread_stress_test.c"),
            Path("/opt/musl-1.2.6/include"),
            Path("/tmp/pthread_stress.o"),
        )
        self.assertEqual(compile_command.count("-c"), 1)
        self.assertIn("-isystem", compile_command)
        self.assertIn("-D_POSIX_C_SOURCE=200809L", compile_command)
        self.assertIn("/opt/musl-1.2.6/include", compile_command)
        self.assertIn("pthread_stress_test.c", compile_command[-3])

        reference, candidate = RUNNER.link_commands(
            ["musl-gcc"],
            Path("/tmp/pthread_stress.o"),
            Path("/tmp/pthread_stress.musl"),
            Path("/tmp/pthread_stress.crabc"),
            Path("/workspace/target/debug"),
            Path("/workspace/target/debug/libldso.so"),
        )
        self.assertNotIn("pthread_stress_test.c", reference)
        self.assertNotIn("pthread_stress_test.c", candidate)
        self.assertIn("-Wl,--dynamic-linker=/workspace/target/debug/libldso.so", candidate)
        self.assertIn("-L/workspace/target/debug", candidate)


class ComparisonTests(unittest.TestCase):
    def result(self, status: int | str = 0, stdout: bytes = b"ok\n", stderr: bytes = b""):
        return RUNNER.ProcessResult(status, stdout, stderr)

    def test_equal_completed_results_pass_without_normalization(self) -> None:
        passed, report = RUNNER.compare_results(self.result(), self.result())
        self.assertTrue(passed)
        self.assertTrue(report["comparisons"]["exit_status_match"])
        self.assertEqual(report["reference"]["stdout"]["hex"], "6f6b0a")
        self.assertEqual(report["comparisons"]["normalization"], "none")

    def test_each_status_and_stream_is_compared_exactly(self) -> None:
        reference = self.result()
        candidate = self.result(1, b"ok\n", b"diagnostic\n")
        passed, report = RUNNER.compare_results(reference, candidate)
        self.assertFalse(passed)
        self.assertFalse(report["comparisons"]["exit_status_match"])
        self.assertFalse(report["comparisons"]["stderr_match"])

    def test_matching_timeouts_do_not_claim_a_stress_pass(self) -> None:
        timeout = self.result("TIMEOUT")
        passed, report = RUNNER.compare_results(timeout, timeout)
        self.assertFalse(passed)
        self.assertTrue(report["comparisons"]["exit_status_match"])
        self.assertFalse(report["comparisons"]["completed"])

    def test_exact_pinned_musl_stdio_failure_is_a_clean_candidate_improvement(self) -> None:
        improvement = RUNNER.classify_source_improvement(
            RUNNER.MUSL_STDIO_CANCELLATION_FAILURE,
            self.result(
                RUNNER.SOURCE_SUCCESS_STATUS,
                RUNNER.SOURCE_SUCCESS_STDOUT,
                RUNNER.SOURCE_SUCCESS_STDERR,
            ),
        )
        self.assertIsNotNone(improvement)
        assert improvement is not None
        self.assertEqual(
            improvement["id"], "pthread-stress.stdio-cancellation.musl-1.2.6"
        )

    def test_stdio_failure_rule_rejects_changed_reference_or_candidate_output(self) -> None:
        reference = self.result(1, b"pthread stress FAIL 4\n", b"different\n")
        candidate = self.result(0, b"pthread stress ok\n", b"")
        self.assertIsNone(RUNNER.classify_source_improvement(reference, candidate))
        self.assertIsNone(
            RUNNER.classify_source_improvement(
                RUNNER.MUSL_STDIO_CANCELLATION_FAILURE,
                self.result(0, b"different\n", b""),
            )
        )

    def test_binary_output_snapshot_preserves_bytes(self) -> None:
        snapshot = RUNNER.stream_snapshot(b"ok\x00\xff")
        self.assertEqual(snapshot["byte_length"], 4)
        self.assertEqual(snapshot["hex"], "6f6b00ff")
        self.assertEqual(len(snapshot["sha256"]), 64)
        self.assertEqual(snapshot["encoding"], "utf-8-replaced")


class BoundsAndReportTests(unittest.TestCase):
    def test_iteration_and_timeout_bounds_are_enforced(self) -> None:
        RUNNER.validate_limits(1, RUNNER.MAX_TIMEOUT)
        RUNNER.validate_limits(RUNNER.MAX_ITERATIONS, 0.001)
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_limits(0, 1)
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_limits(RUNNER.MAX_ITERATIONS + 1, 1)
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_limits(1, math.nan)

    def test_atomic_report_replaces_destination_without_temp_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pthread-stress-report-test-") as directory:
            destination = Path(directory) / "nested" / "latest.json"
            RUNNER.atomic_write_json(destination, {"passed": True, "raw": [1, 2]})
            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                {"passed": True, "raw": [1, 2]},
            )
            self.assertEqual(list(destination.parent.glob(".*.tmp")), [])

    def test_default_source_reuses_existing_fixture(self) -> None:
        self.assertEqual(
            RUNNER.default_source(),
            Path(RUNNER.repository_root()) / "tests/fixtures/pthread_stress_test.c",
        )


if __name__ == "__main__":
    unittest.main()
