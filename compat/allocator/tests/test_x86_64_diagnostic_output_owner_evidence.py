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
    def raw_record(
        command: list[str], cwd: Path, stdout: str = "", stderr: str = "",
    ) -> dict[str, object]:
        return {
            "command": command,
            "cwd": str(cwd),
            "status": 0,
            "stdout": stdout,
            "stderr": stderr,
        }

    def complete_report(self) -> dict[str, object]:
        temporary = ROOT / ".work/allocator-x86_64/diagnostic-output-owner/synthetic-receipt"
        source = temporary / "source/mimalloc-3.5.0"
        binary = temporary / "diagnostic-output-owner-c-oracle"
        target = temporary / "rust-target"
        c_runs = {
            scenario: self.raw_record(
                [str(binary), scenario],
                source,
                f"{scenario}={':'.join(EVIDENCE.EXPECTED_TRACE[scenario])}\n",
                EVIDENCE.EXPECTED_C_STDERR[scenario],
            )
            for scenario in EVIDENCE.SCENARIOS
        }
        rust_stream = "\n".join(
            [EVIDENCE.TRACE_BEGIN]
            + [f"{scenario}={':'.join(EVIDENCE.EXPECTED_TRACE[scenario])}" for scenario in EVIDENCE.SCENARIOS]
            + [EVIDENCE.TRACE_END, ""]
        )
        default_stderr = "\n".join(
            [EVIDENCE.DEFAULT_STDERR_BEGIN]
            + [
                f"{scenario}={':'.join(EVIDENCE.EXPECTED_DEFAULT_STDERR_TRACE[scenario])}"
                for scenario in EVIDENCE.SCENARIOS
            ]
            + [EVIDENCE.DEFAULT_STDERR_END, ""]
        )
        return {
            "c_oracle": {
                "build": self.raw_record(
                    EVIDENCE.c_compile_command("musl-gcc", source, binary), source,
                ),
                "runs": c_runs,
                "source_files": EVIDENCE.expected_pinned_c_source_records(),
            },
            "cargo_lock": EVIDENCE.current_file_identity(EVIDENCE.LOCKFILE),
            "fixture": EVIDENCE.current_file_identity(EVIDENCE.FIXTURE),
            "format": 1,
            "kind": "mimalloc-x86_64-diagnostic-output-owner-evidence",
            "native_execution_provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
            "profile": EVIDENCE.PROFILE,
            "rust": self.raw_record(
                EVIDENCE.rust_command("cargo", target), ROOT, rust_stream, default_stderr,
            ),
            "rust_source": EVIDENCE.current_file_identity(EVIDENCE.RUST_SOURCE),
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

    def test_reader_rejects_each_changed_authenticated_identity(self) -> None:
        mutations = {
            "fixture": lambda report: report["fixture"].__setitem__("sha256", "0" * 64),
            "Cargo.lock": lambda report: report["cargo_lock"].__setitem__("sha256", "0" * 64),
            "Rust source": lambda report: report["rust_source"].__setitem__("sha256", "0" * 64),
            "pinned C source": lambda report: report["c_oracle"]["source_files"][0].__setitem__("sha256", "0" * 64),
        }
        for name, mutate in mutations.items():
            with self.subTest(identity=name):
                report = copy.deepcopy(self.complete_report())
                mutate(report)
                with self.assertRaises(EVIDENCE.EvidenceError):
                    EVIDENCE.validate_report(report)

    def test_reader_rejects_changed_c_and_rust_commands(self) -> None:
        changed_c = self.complete_report()
        changed_c["c_oracle"]["build"]["command"][0] = "/wrong/musl-gcc"
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(changed_c)

        changed_rust = self.complete_report()
        changed_rust["rust"]["command"][0] = "/wrong/cargo"
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(changed_rust)

    def test_reader_rejects_changed_collector_owned_cwds(self) -> None:
        changed_c = self.complete_report()
        changed_c["c_oracle"]["build"]["cwd"] = str(ROOT / ".work/wrong-source")
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(changed_c)

        changed_rust = self.complete_report()
        changed_rust["rust"]["cwd"] = str(ROOT / ".work/wrong-rust-cwd")
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(changed_rust)

    def test_reader_rejects_changed_default_stderr_bytes(self) -> None:
        report = self.complete_report()
        report["c_oracle"]["runs"]["post_init"]["stderr"] = "wrong default output\n"
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(report)

    def test_reader_rejects_changed_rust_default_stderr_bytes(self) -> None:
        report = self.complete_report()
        report["rust"]["stderr"] = report["rust"]["stderr"].replace("6561726c790a", "77726f6e670a")
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(report)

    def test_collector_owned_paths_cannot_escape_the_checkout_work_tree(self) -> None:
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "must stay under this checkout's .work"):
            EVIDENCE.require_checkout_work_path(Path("/var/empty/report.json"), "evidence report")
