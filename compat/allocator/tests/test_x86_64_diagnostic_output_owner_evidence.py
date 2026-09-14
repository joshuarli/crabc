#!/usr/bin/env python3
"""Focused no-execution tests for the diagnostic-output evidence reader."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "compat/allocator/x86_64_diagnostic_output_owner_evidence.py"
SPEC = importlib.util.spec_from_file_location("crabc_diagnostic_output_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class RetainedStreamReaderTests(unittest.TestCase):
    @staticmethod
    def raw_record(command: list[str], stdout: str = "", stderr: str = "") -> dict[str, object]:
        return {"command": command, "status": 0, "stdout": stdout, "stderr": stderr}

    def complete_report(self) -> dict[str, object]:
        c_runs = {
            scenario: self.raw_record(
                ["/workspace/.work/oracle/diagnostic-output-owner-c-oracle", scenario],
                f"{scenario}={':'.join(EVIDENCE.EXPECTED_TRACE[scenario])}\n",
                "early\n" if scenario == "post_init" else "",
            )
            for scenario in EVIDENCE.SCENARIOS
        }
        rust_stream = "\n".join(
            [EVIDENCE.TRACE_BEGIN]
            + [f"{scenario}={':'.join(EVIDENCE.EXPECTED_TRACE[scenario])}" for scenario in EVIDENCE.SCENARIOS]
            + [EVIDENCE.TRACE_END, ""]
        )
        source_files = [
            {"path": source, "sha256": "a" * 64}
            for source in EVIDENCE.C_SOURCE_FILES
        ]
        return {
            "c_oracle": {
                "build": self.raw_record(
                    ["/opt/musl/bin/musl-gcc", "/workspace/.work/source/mimalloc-3.5.0/src/options.c"],
                ),
                "runs": c_runs,
                "source_files": source_files,
            },
            "cargo_lock": {"path": "Cargo.lock", "sha256": "b" * 64},
            "fixture": {
                "path": "compat/allocator/x86_64_diagnostic_output_owner_oracle.c",
                "sha256": "c" * 64,
            },
            "format": 1,
            "kind": "mimalloc-x86_64-diagnostic-output-owner-evidence",
            "native_execution_provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
            "profile": EVIDENCE.PROFILE,
            "rust": self.raw_record(
                ["cargo", "test", "--locked", "--target", EVIDENCE.TARGET], rust_stream, "early\n",
            ),
            "rust_source": {"path": "crabc-mimalloc/src/diagnostic_output.rs", "sha256": "d" * 64},
            "scope": EVIDENCE.SCOPE,
            "status": "passed",
            "target": {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": EVIDENCE.TARGET,
                "system": "linux",
            },
            "upstream": EVIDENCE.PINNED_UPSTREAM,
        }

    def test_reader_reconstructs_the_trace_from_retained_raw_streams(self) -> None:
        report = self.complete_report()
        EVIDENCE.validate_report(report)
        self.assertIn("stdout", report["c_oracle"]["runs"]["enabled"])
        self.assertIn("stderr", report["rust"])
        self.assertNotIn("stdout_sha256", report["rust"])

    def test_reader_rejects_changed_raw_callback_order_without_running_a_process(self) -> None:
        report = self.complete_report()
        report["c_oracle"]["runs"]["enabled"]["stdout"] = (
            f"enabled={EVIDENCE.SELECTED_BODY}:{EVIDENCE.PREFIX}\n"
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "pinned C diagnostic-output trace drifted"):
            EVIDENCE.validate_report(report)

    def test_reader_rejects_missing_rust_stream_marker_without_running_a_process(self) -> None:
        report = copy.deepcopy(self.complete_report())
        report["rust"]["stdout"] = report["rust"]["stdout"].replace(EVIDENCE.TRACE_END, "")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "trace markers"):
            EVIDENCE.validate_report(report)

    def test_collector_owned_paths_cannot_escape_the_checkout_work_tree(self) -> None:
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "must stay under this checkout's .work"):
            EVIDENCE.require_checkout_work_path(Path("/var/empty/report.json"), "evidence report")
