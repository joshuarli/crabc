#!/usr/bin/env python3
"""Focused contract tests for bounded x86-64 fault-injection evidence."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "compat/allocator/x86_64_fault_evidence.py"
SPEC = importlib.util.spec_from_file_location("crabc_x86_64_fault_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class NativeBoundaryTests(unittest.TestCase):
    def test_native_gate_rejects_missing_emulated_and_foreign_evidence(self) -> None:
        with mock.patch.object(EVIDENCE.platform, "system", return_value="Linux"), mock.patch.object(
            EVIDENCE.platform, "machine", return_value="x86_64"
        ):
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "canonical native provenance"):
                    EVIDENCE.require_native_x86_64()
            with mock.patch.dict(
                os.environ,
                {"CRABC_EXECUTION_MODE": "emulated", "CRABC_HOST_ARCH": "x86_64"},
                clear=True,
            ):
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "canonical native provenance"):
                    EVIDENCE.require_native_x86_64()

        with mock.patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "x86_64"},
            clear=True,
        ), mock.patch.object(EVIDENCE.platform, "system", return_value="Linux"), mock.patch.object(
            EVIDENCE.platform, "machine", return_value="aarch64"
        ):
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "native Linux/x86-64"):
                EVIDENCE.require_native_x86_64()

    def test_native_gate_records_the_canonical_amd64_alias(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "amd64"},
            clear=True,
        ), mock.patch.object(EVIDENCE.platform, "system", return_value="Linux"), mock.patch.object(
            EVIDENCE.platform, "machine", return_value="x86_64"
        ):
            self.assertEqual(
                EVIDENCE.require_native_x86_64(),
                {"execution_mode": "native", "host_architecture": "amd64"},
            )


class CargoCommandTests(unittest.TestCase):
    def test_each_selection_is_locked_exact_target_specific_and_isolated(self) -> None:
        target_dir = Path("/tmp/private-fault-target")
        for lane in EVIDENCE.TEST_LANES:
            with self.subTest(lane=lane.identifier):
                command = EVIDENCE.cargo_test_command("cargo", lane, target_dir)
                self.assertEqual(command[:3], ["cargo", "test", "--locked"])
                self.assertEqual(command[command.index("--target") + 1], EVIDENCE.TARGET)
                self.assertEqual(command[command.index("--target-dir") + 1], str(target_dir))
                self.assertEqual(command[command.index("-p") + 1], "crabc-mimalloc")
                self.assertIn("--lib", command)
                self.assertEqual(command[command.index("--lib") + 1], lane.test_filter)
                delimiter = command.index("--")
                self.assertEqual(command[delimiter + 1 :], ["--test-threads=1", "--exact"])

    def test_fixed_selection_covers_only_the_named_four_fault_points(self) -> None:
        self.assertEqual(len(EVIDENCE.TEST_LANES), 5)
        self.assertEqual(sum(lane.expected_pass_count for lane in EVIDENCE.TEST_LANES), 5)
        self.assertEqual(EVIDENCE.FAULT_POINT_COVERAGE, ("Map", "Commit", "Unmap", "Decommit"))
        self.assertEqual(
            [lane.identifier for lane in EVIDENCE.TEST_LANES],
            [
                "native-mapping-commit-selected-ordinal",
                "metadata-map-commit-retry",
                "aligned-claim-unmap-retry",
                "aligned-claim-commit-unmap-retention",
                "external-arena-decommit-retry-state",
            ],
        )
        observed_points = {point for lane in EVIDENCE.TEST_LANES for point in lane.fault_points}
        self.assertEqual(observed_points, set(EVIDENCE.FAULT_POINT_COVERAGE))


class ReportTests(unittest.TestCase):
    def complete_lanes(self) -> list[dict[str, object]]:
        target_dir = Path("/tmp/private-fault-target")
        lanes: list[dict[str, object]] = []
        for lane in EVIDENCE.TEST_LANES:
            command = EVIDENCE.cargo_test_command("cargo", lane, target_dir)
            lanes.append(
                {
                    "id": lane.identifier,
                    "cargo_command": EVIDENCE.normalized_command(command, target_dir),
                    "fault_points": list(lane.fault_points),
                    "expected_pass_count": lane.expected_pass_count,
                    "observed": {
                        "passed": lane.expected_pass_count,
                        "failed": 0,
                        "ignored": 0,
                        "measured": 0,
                        "filtered_out": 0,
                    },
                    "source_tests": [lane.test_filter],
                    "state_preservation": list(lane.state_preservation),
                }
            )
        return lanes

    def complete_report(self) -> dict[str, object]:
        return EVIDENCE.report_from_results(
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            toolchain={
                "cargo": "cargo 1.0.0",
                "rustc_host": EVIDENCE.TARGET,
                "rustc_release": "nightly-test",
            },
            lockfile_sha256="1" * 64,
            lanes=self.complete_lanes(),
        )

    def test_report_is_private_and_explicitly_not_general_fault_or_misuse_parity(self) -> None:
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["scope"]["public_runtime_support"])
        self.assertFalse(report["scope"]["general_fault_or_misuse_parity"])
        self.assertEqual(
            report["summary"],
            {
                "expected_pass_count": 5,
                "observed_pass_count": 5,
                "lane_count": 5,
                "named_fault_points": ["Map", "Commit", "Unmap", "Decommit"],
            },
        )
        self.assertTrue(report["cargo"]["locked"])
        self.assertEqual(
            report["cargo"]["target_dir"],
            {
                "isolated": True,
                "retained": False,
                "value": "<isolated-temporary-target-dir>",
            },
        )
        exclusions = " ".join(report["exclusions"])
        self.assertIn("No public mi_*", exclusions)
        self.assertIn("No general fault-injection matrix", exclusions)
        self.assertIn("No invalid-program or misuse parity", exclusions)

    def test_report_rejects_a_broadened_fault_or_public_boundary(self) -> None:
        malformed = self.complete_report()
        malformed["scope"]["public_runtime_support"] = True
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "non-public runtime boundary"):
            EVIDENCE.validate_report(malformed)

        malformed = self.complete_report()
        malformed["scope"]["general_fault_or_misuse_parity"] = True
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "general fault/misuse parity"):
            EVIDENCE.validate_report(malformed)

    def test_report_rejects_an_unlocked_wrong_target_or_nonexact_command(self) -> None:
        malformed = self.complete_report()
        command = malformed["lanes"][0]["cargo_command"]
        command.remove("--locked")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "Cargo --locked"):
            EVIDENCE.validate_report(malformed)

        malformed = self.complete_report()
        command = malformed["lanes"][0]["cargo_command"]
        command[command.index("--target") + 1] = "aarch64-unknown-linux-musl"
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "not locked to"):
            EVIDENCE.validate_report(malformed)

        malformed = self.complete_report()
        command = malformed["lanes"][0]["cargo_command"]
        command.remove("--exact")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "serialized exact"):
            EVIDENCE.validate_report(malformed)

    def test_report_rejects_a_partial_selected_result(self) -> None:
        malformed = self.complete_report()
        malformed["lanes"][0]["observed"]["passed"] = 0
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "observed count drifted"):
            EVIDENCE.validate_report(malformed)

    def test_atomic_writer_leaves_valid_json(self) -> None:
        report = self.complete_report()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested" / "result.json"
            EVIDENCE.atomic_write_json(output, report)
            serialized = output.read_text(encoding="utf-8")
            self.assertTrue(serialized.endswith("\n"))
            self.assertIn('"status": "passed"', serialized)
            self.assertEqual(json.loads(serialized), report)


class ResultParserTests(unittest.TestCase):
    def test_parser_requires_one_clean_exact_summary(self) -> None:
        lane = EVIDENCE.TEST_LANES[0]
        output = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.01s\n"
        self.assertEqual(
            EVIDENCE.parse_test_result(output, lane),
            {
                "passed": 1,
                "failed": 0,
                "ignored": 0,
                "measured": 0,
                "filtered_out": 42,
            },
        )

    def test_parser_rejects_a_count_drift_or_multiple_test_binaries(self) -> None:
        lane = EVIDENCE.TEST_LANES[0]
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "passed 2 tests"):
            EVIDENCE.parse_test_result(
                "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                lane,
            )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "2 lib-test summaries"):
            EVIDENCE.parse_test_result(
                "\n".join(
                    [
                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                    ]
                ),
                lane,
            )


if __name__ == "__main__":
    unittest.main()
