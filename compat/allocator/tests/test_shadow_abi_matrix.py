#!/usr/bin/env python3
"""Contract-level regressions for the paired native-shadow ABI matrix."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "shadow-abi-matrix/run.py"
SPEC = importlib.util.spec_from_file_location("crabc_shadow_abi_matrix", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class ShadowAbiMatrixContractTests(unittest.TestCase):
    def test_checked_in_contract_has_the_closed_local_trace_and_explicit_blocks(self) -> None:
        contract = RUNNER.load_contract()
        self.assertEqual(
            RUNNER.expected_trace(contract),
            [
                "free-null-preserves-errno",
                "malloc-local-content-and-errno",
                "realloc-grow-preserves-prefix-and-errno",
                "realloc-shrink-preserves-prefix-and-errno",
                "realloc-null-zero-result",
                "realloc-zero-result",
                "realloc-failure-preserves-source-and-sets-enomem",
                "free-local-preserves-errno",
            ],
        )
        self.assertEqual(
            {case["id"] for case in contract["intentionally_blocked_cases"]},
            {
                "foreign-worker-free-or-realloc",
                "owner-exit-and-post-exit-routing",
                "dso-interposition-and-static-linking",
                "address-reuse-usable-size-and-page-layout",
            },
        )

    def test_trace_parser_accepts_only_the_complete_ordered_semantic_records(self) -> None:
        contract = RUNNER.load_contract()
        expected = RUNNER.expected_trace(contract)
        expected_results = {
            case["id"]: case["expected"]["native-rust-mimalloc-shadow"]
            for case in contract["semantic_cases"]
        }
        stdout = b"".join(
            f"case={case} result={expected_results[case]}\n".encode("ascii") for case in expected
        )
        self.assertEqual(
            RUNNER.parse_trace(stdout, contract),
            [{"id": case, "result": expected_results[case]} for case in expected],
        )
        changed = RUNNER.parse_trace(stdout.replace(b"result=pass", b"result=unknown", 1), contract)
        with self.assertRaisesRegex(RUNNER.MatrixError, "recorded semantics"):
            RUNNER.validate_backend_trace(
                contract,
                RUNNER.backend_contract(contract, "native-rust-mimalloc-shadow"),
                changed,
            )
        with self.assertRaisesRegex(RUNNER.MatrixError, "semantic records"):
            RUNNER.parse_trace(
                b"".join(
                    f"case={case} result=pass\n".encode("ascii")
                    for case in reversed(expected)
                ),
                contract,
            )

    def test_contract_rejects_a_hidden_second_attempt_or_missing_blocker(self) -> None:
        contract = RUNNER.load_contract()
        changed_attempts = copy.deepcopy(contract)
        changed_attempts["execution"]["process_attempts_per_backend"] = 2
        with mock.patch.object(RUNNER, "read_json", return_value=changed_attempts), self.assertRaisesRegex(
            RUNNER.MatrixError, "execution contract drifted"
        ):
            RUNNER.load_contract()

        missing_blocker = copy.deepcopy(contract)
        missing_blocker["intentionally_blocked_cases"].pop()
        with mock.patch.object(RUNNER, "read_json", return_value=missing_blocker), self.assertRaisesRegex(
            RUNNER.MatrixError, "blocked case count drifted"
        ):
            RUNNER.load_contract()

        changed_operations = copy.deepcopy(contract)
        changed_operations["semantic_cases"][0]["operations"] = ["malloc"]
        with mock.patch.object(RUNNER, "read_json", return_value=changed_operations), self.assertRaisesRegex(
            RUNNER.MatrixError, "semantic case operations drifted"
        ):
            RUNNER.load_contract()
        self.assertEqual(RUNNER.parse_dynamic_search_paths(" 0x0 (NEEDED) Shared library: [libc.so]"), [])
        self.assertEqual(
            RUNNER.parse_dynamic_search_paths(" 0x0 (RUNPATH) Library runpath: [/unexpected]"),
            ["/unexpected"],
        )

    def test_report_base_carries_the_blocked_cases_without_turning_them_into_passes(self) -> None:
        contract = RUNNER.load_contract()
        report = RUNNER.report_base(contract)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["semantic_comparisons"], [])
        self.assertEqual(report["intentionally_blocked_cases"], contract["intentionally_blocked_cases"])
        self.assertTrue(all(case["status"] == "blocked" for case in report["intentionally_blocked_cases"]))

    def test_known_reds_are_recorded_as_differences_not_matching_passes(self) -> None:
        contract = RUNNER.load_contract()
        rows = [case for case in contract["semantic_cases"] if case["comparison"] == "known-red"]
        self.assertEqual(
            [(row["id"], row["expected"]) for row in rows],
            [
                (
                    "realloc-null-zero-result",
                    {
                        "ordinary-c-mimalloc": "freeable-misaligned-preserves-errno",
                        "native-rust-mimalloc-shadow": "freeable-aligned-preserves-errno",
                    },
                ),
                (
                    "realloc-zero-result",
                    {
                        "ordinary-c-mimalloc": "distinct-aligned-preserves-errno",
                        "native-rust-mimalloc-shadow": "distinct-misaligned-preserves-errno",
                    },
                ),
            ],
        )
        self.assertTrue(all("not an accepted" in row["reason"] for row in rows))

    def test_retained_matching_cargo_fingerprints_do_not_make_artifact_attestation_ambiguous(self) -> None:
        contract = RUNNER.load_contract()
        backend = RUNNER.backend_contract(contract, "native-rust-mimalloc-shadow")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for suffix in ("older", "newer"):
                fingerprint = target / ".fingerprint" / f"crabc-libc-{suffix}" / "lib-c.json"
                fingerprint.parent.mkdir(parents=True)
                fingerprint.write_text(
                    json.dumps({"features": '["default", "native-mimalloc-shadow"]'}),
                    encoding="utf-8",
                )
            matches = RUNNER.matching_cargo_fingerprints(target, backend)
        self.assertEqual(len(matches), 2)
        self.assertTrue(
            all(features == ["default", "native-mimalloc-shadow"] for _, features in matches)
        )


if __name__ == "__main__":
    unittest.main()
