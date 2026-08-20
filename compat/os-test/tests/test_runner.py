"""Host-side contract tests for the pinned os-test runner's pure helpers."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_os_test_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class OutcomeComparisonTests(unittest.TestCase):
    def test_equal_outcomes_have_no_difference(self) -> None:
        self.assertEqual(
            RUNNER.compare_outcomes({"header.out": b"good\n"}, {"header.out": b"good\n"}),
            [],
        )

    def test_difference_preserves_raw_outcome_text(self) -> None:
        self.assertEqual(
            RUNNER.compare_outcomes({"header.out": b"good\n"}, {"header.out": b"undeclared\n"}),
            [{"case": "header.out", "musl": "good\n", "crabc": "undeclared\n"}],
        )

    def test_missing_outcome_is_a_failure(self) -> None:
        self.assertEqual(
            RUNNER.compare_outcomes({"header.out": b"good\n"}, {}),
            [{"case": "header.out", "musl": "good\n", "crabc": "missing"}],
        )

    def test_source_oracle_requires_exact_good_output(self) -> None:
        self.assertEqual(
            RUNNER.compare_source_oracle_outcomes(
                "namespace",
                {"decl.out", "missing.out", "absent.out"},
                {"decl.out": b"good\n", "missing.out": b"undeclared\n"}
            ),
            [
                {
                    "case": "absent.out",
                    "expected": "good\n",
                    "crabc": "missing",
                },
                {
                    "case": "missing.out",
                    "expected": "good\n",
                    "crabc": "undeclared\n",
                }
            ],
        )

    def test_source_oracle_allows_only_the_named_musl_scoped_header_skips(self) -> None:
        self.assertEqual(
            RUNNER.source_oracle_expected("namespace", "devctl.out"),
            b"missing_header\n",
        )
        self.assertEqual(
            RUNNER.source_oracle_expected("namespace", "time.out"), b"good\n")

    def test_basic_source_improvement_requires_exact_clean_candidate_exit(self) -> None:
        reference = {"complex/cexpl.out": b"musl diagnostic\n"}
        candidate = {"complex/cexpl.out": b"exit: 0\n"}
        differences = RUNNER.compare_outcomes(reference, candidate)
        self.assertEqual(
            RUNNER.classify_basic_source_improvements(reference, candidate, differences),
            [{
                "case": "complex/cexpl.out",
                "expected": "exit: 0\n",
                "musl": "musl diagnostic\n",
                "crabc": "exit: 0\n",
                "source_test": "basic/complex/cexpl.c",
            }],
        )

    def test_basic_source_improvement_does_not_accept_another_failure(self) -> None:
        reference = {"complex/cexpl.out": b"musl diagnostic\n"}
        candidate = {"complex/cexpl.out": b"candidate diagnostic\n"}
        differences = RUNNER.compare_outcomes(reference, candidate)
        self.assertEqual(
            RUNNER.classify_basic_source_improvements(reference, candidate, differences), []
        )

    def test_basic_source_failure_records_shared_diagnostics(self) -> None:
        self.assertEqual(
            RUNNER.basic_source_differences({"complex/cabs.out": b"diagnostic\n"}),
            [{
                "case": "complex/cabs.out",
                "expected": "exit: 0\n",
                "crabc": "diagnostic\n",
            }],
        )

    def test_basic_source_contract_requires_no_candidate_diagnostics(self) -> None:
        self.assertFalse(
            RUNNER.source_contract_passed(
                "basic", {"complex/cabs.out": b"diagnostic\n"}
            )
        )
        self.assertTrue(
            RUNNER.source_contract_passed(
                "basic", {"complex/cabs.out": b"exit: 0\n"}
            )
        )
        self.assertTrue(RUNNER.source_contract_passed("io", {}))

    def test_basic_source_contract_failure_cannot_be_green(self) -> None:
        """A shared source diagnostic remains red after differential matching."""

        candidate = {"complex/cabs.out": b"diagnostic\n"}
        reference = dict(candidate)
        differences = RUNNER.compare_outcomes(reference, candidate)
        self.assertEqual(differences, [])
        self.assertFalse(RUNNER.source_contract_passed("basic", candidate))
        # A matched make status and no accepted differences are still red.
        # This is the former false-green condition from run_profile.
        self.assertFalse(
            RUNNER.suite_result_passed(
                "basic", candidate, make_status_ok=True, unaccepted_difference_count=0
            )
        )

    def test_snapshot_records_exact_bytes_and_hash(self) -> None:
        snapshot = RUNNER.stream_snapshot(b"ok\n")
        self.assertEqual(snapshot["byte_length"], 3)
        self.assertEqual(snapshot["text"], "ok\n")
        self.assertEqual(len(snapshot["sha256"]), 64)


class ExceptionClassificationTests(unittest.TestCase):
    def test_process_exception_requires_exact_raw_outcomes(self) -> None:
        difference = {
            "case": "waitpid-pgid-empty-on-setpgid.out",
            "musl": "SIGALRM\n",
            "crabc": "exit: 1\n",
        }
        rule = RUNNER.classify_outcome_difference("process", difference)
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertEqual(rule.id, "process.waitpid-pgid-empty-on-setpgid.musl-alarm")
        report = RUNNER.exception_report(rule, raw_difference=difference)
        self.assertEqual(report["raw_difference"], difference)
        self.assertEqual(report["source"]["revision"], RUNNER.OS_TEST_REVISION)

    def test_process_exception_does_not_accept_extra_exit_text(self) -> None:
        difference = {
            "case": "waitpid-pgid-empty-on-setpgid.out",
            "musl": "SIGALRM\n",
            "crabc": "exit: 1\nextra\n",
        }
        self.assertIsNone(RUNNER.classify_outcome_difference("process", difference))

    def test_basic_make_exception_requires_same_no_main_failure(self) -> None:
        stderr = {
            "byte_length": 100,
            "sha256": "x",
            "text": (
                "musl-gcc ... dlfcn/dlclose.so\n"
                "undefined reference to `main'\n"
            ),
        }
        reports = {
            "musl": {"make_status": 2, "stderr": stderr},
            "crabc": {"make_status": 2, "stderr": stderr},
        }
        rule = RUNNER.classify_make_status_exception("basic", reports)
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertEqual(rule.id, "basic.dlfcn.dlclose.shared-no-main-link")
        accepted = RUNNER.exception_report(rule, runtime_reports=reports)
        self.assertEqual(accepted["raw_make_status"], {"musl": 2, "crabc": 2})

    def test_basic_make_exception_does_not_accept_unrelated_status_two(self) -> None:
        stderr = {"text": "dlfcn/dlclose.so: another linker failure\n"}
        reports = {
            "musl": {"make_status": 2, "stderr": stderr},
            "crabc": {"make_status": 2, "stderr": stderr},
        }
        self.assertIsNone(RUNNER.classify_make_status_exception("basic", reports))

    def test_resolved_precision_frontier_has_no_remaining_manifest_entries(self) -> None:
        self.assertEqual(RUNNER.UNRESOLVED_FRONTIER, ())

    def test_exception_manifest_scopes_are_unique(self) -> None:
        rules = (*RUNNER.MAKE_STATUS_EXCEPTIONS, *RUNNER.OUTCOME_EXCEPTIONS)
        self.assertEqual(len({rule.id for rule in rules}), len(rules))
        self.assertEqual(len({(rule.suite, rule.case) for rule in rules}), len(rules))


class MakeCommandTests(unittest.TestCase):
    def test_basic_retains_native_compiler_abi(self) -> None:
        command = RUNNER.make_command(
            "basic",
            ["musl-gcc"],
            RUNNER.Runtime("crabc", Path("/include"), "/target", "-pie"),
            Path("/work"),
        )
        self.assertIn("CFLAGS=-fPIE", command)
        self.assertNotIn("-mlong-double-64", command)

    def test_non_math_suite_retains_ordinary_cflags(self) -> None:
        command = RUNNER.make_command(
            "io",
            ["musl-gcc"],
            RUNNER.Runtime("crabc", Path("/include"), "/target", "-pie"),
            Path("/work"),
        )
        self.assertIn("CFLAGS=-fPIE", command)
        self.assertNotIn("-mlong-double-64", command)


if __name__ == "__main__":
    unittest.main()
