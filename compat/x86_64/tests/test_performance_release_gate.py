#!/usr/bin/env python3
"""The read-only runtime and facade performance.release gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat" / "x86_64"))
import performance_release_gate as gate  # noqa: E402


HOST = {"status": "uncontended", "evidence": {"load_average": [0.0, 0.0, 0.0]}}


def runtime_row(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "gate": "pass",
        "cpu": {"median_ratio": 0.8, "one_sided_95_upper": 1.0, "gate": "pass"},
        "pss_kib": {"reference": 1000, "candidate": 900, "gate": "pass"},
        "memory_peak_bytes": {"reference": 1000, "candidate": 850, "gate": "pass"},
        "syscalls": {
            "marked_region": {"reference": 0, "candidate": 0, "gate": "pass"},
            "whole_process": {"reference": 40, "candidate": 80, "gate": "pass"},
            "gate": "pass",
        },
    }
    row.update(changes)
    return row


class RuntimeThresholdTests(unittest.TestCase):
    def test_runtime_cpu_upper_bound_of_one_is_accepted(self) -> None:
        self.assertEqual(gate.runtime_row_unmet("row", 1, runtime_row()), [])

    def test_runtime_memory_floor_policy_keeps_raw_totals_and_other_bounds(self) -> None:
        cases = (
            ("allocator_live_32m", 33 << 10, 33 << 20, True, True),
            ("memcpy_128m_aligned", 257 << 10, 257 << 20, True, True),
            ("strlen_128m_aligned", 129 << 10, 2 << 20, True, False),
            ("getpid", 1000, 256 << 10, False, True),
            ("getpid", 1000, (256 << 10) + 1, False, False),
            ("allocator_live_4m", 5000, 5 << 20, False, False),
        )
        for name, pss, peak, pss_floor, peak_floor in cases:
            for increment in (0, 1):
                row = runtime_row(
                    pss_kib={"reference": pss, "candidate": pss + increment, "gate": "pass"},
                    memory_peak_bytes={"reference": peak, "candidate": peak + increment, "gate": "pass"})
                with self.subTest(name=name, increment=increment):
                    unmet = gate.runtime_row_unmet(name, 1, row)
                    self.assertEqual(any("pss_kib ratio" in item for item in unmet), not pss_floor or bool(increment))
                    self.assertEqual(any("memory_peak_bytes ratio" in item for item in unmet),
                                     not peak_floor or bool(increment))
                    self.assertEqual(row["pss_kib"]["candidate"], pss + increment)
        row = runtime_row(pss_kib={"reference": 1000, "candidate": 1000, "gate": "pass"},
                          memory_peak_bytes={"reference": 1000, "candidate": 1000, "gate": "pass"},
                          cpu={"one_sided_95_upper": 1.01, "gate": "pass"})
        self.assertEqual(len(gate.runtime_row_unmet("allocator_live_32m", 1, row)), 1)

    def test_runtime_row_names_each_violated_scorecard_rule(self) -> None:
        cases = {
            "CPU one-sided 95% upper bound 1.01": {"cpu": {"one_sided_95_upper": 1.01, "gate": "pass"}},
            "pss_kib ratio 0.9100": {"pss_kib": {"reference": 1000, "candidate": 910, "gate": "pass"}},
            "memory_peak_bytes has no nonzero reference": {
                "memory_peak_bytes": {"reference": 0, "candidate": 0, "gate": "pass"}},
            "marked_region syscalls 1 > 2R=0": {"syscalls": {
                "marked_region": {"reference": 0, "candidate": 1}, "whole_process": {"reference": 1, "candidate": 2},
                "gate": "pass"}},
            "whole_process syscalls 81 > 2R=80": {"syscalls": {
                "marked_region": {"reference": 1, "candidate": 1}, "whole_process": {"reference": 40, "candidate": 81},
                "gate": "pass"}},
            "syscalls release gate is fail": {"syscalls": {
                "marked_region": {"reference": 1, "candidate": 1}, "whole_process": {"reference": 1, "candidate": 1},
                "gate": "fail"}},
        }
        for expected, change in cases.items():
            with self.subTest(expected=expected):
                unmet = gate.runtime_row_unmet("row", 2, runtime_row(**change))
                self.assertEqual(len(unmet), 1, unmet)
                self.assertIn(f"row attempt 2: {expected}", unmet[0])


class ReceiptTests(unittest.TestCase):
    """Owner readers are replaced by fakes; the gate logic runs unchanged."""

    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="performance-release-", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.rows = {"startup": {"attempts": [runtime_row(), runtime_row(), runtime_row()]}}
        self.blockers: tuple[str, ...] = ()
        self.native_error: Exception | None = None
        cpuinfo = self.directory / "cpuinfo.raw"
        cpuinfo.write_text("processor: 0\nmodel name: Test CPU\n\n"
                           "processor: 1\nmodel name: Test CPU\n", encoding="utf-8")
        self.cpu_identity = hashlib.sha256(cpuinfo.read_bytes()).hexdigest()
        self.attempt = self.write("attempt.json", {"tools": {
            "before": {"host": {
                "kernel_release": "6.1.0-test", "allowed_affinity_before_pin": [0, 1],
                "cpuinfo_sha256": self.cpu_identity, "benchmark_cpu": 0,
            }},
            "host_cpuinfo_diagnostics": {"before": {"model_names": ["Test CPU", "Test CPU"]}},
        }})
        self.collector = self.write("collector.json", {
            "collector": {"source_revision": "a" * 40},
            "attempts": [{"report": {"path": str(self.attempt)}}],
            "uncontended_host": HOST,
        })
        self.native = self.write("native.json", {
            "mode": "full", "status": "complete-evidence", "uncontended_host": HOST,
            "diagnostics": {"allowed_affinity": [0, 1], "client_cpu": 0,
                            "cpuinfo": {"path": str(cpuinfo)}},
        })
        patcher = patch.object(gate, "_module", side_effect=self.module)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, name: str, value: object) -> Path:
        path = self.directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def module(self, directory: Path, name: str):
        del directory
        if name == "x86_64_evidence":
            def validate_collector_report(root, path):
                del root, path
                return types.SimpleNamespace(release_qualified=not self.blockers, blockers=self.blockers,
                                             scorecard={"rows": self.rows})
            return types.SimpleNamespace(
                validate_collector_report=validate_collector_report,
                SOURCE_MOUNT="/workspace",
                translate_source_path=lambda root, mount, path: Path(path),
                cpuinfo_identity_sha256=lambda raw: hashlib.sha256(raw).hexdigest(),
            )
        if name == "x86_64_runner":
            def validate_report(root, path, *, rustybench_source, rustix_source):
                del root, path, rustybench_source, rustix_source
                if self.native_error is not None:
                    raise self.native_error
            return types.SimpleNamespace(validate_report=validate_report,
                                         MODE_STATUS={"full": "complete-evidence"})
        raise AssertionError(name)

    def arguments(self, output: str = "unused") -> argparse.Namespace:
        return argparse.Namespace(
            command="evaluate", runtime_c_collector=self.collector, native_facade_report=self.native,
            rustybench_source=self.directory, rustix_source=self.directory,
            output=self.directory / output,
        )

    def receipt(self) -> dict[str, object]:
        return gate.build_receipt(gate.collect_inputs(self.arguments()))

    def details(self, receipt, identifier: str) -> list[str]:
        return next(row for row in receipt["conditions"] if row["id"] == identifier)["detail"]

    def test_release_cli_needs_no_allocator_reports(self) -> None:
        arguments = gate.parse_arguments([
            "evaluate", "--runtime-c-collector", str(self.collector),
            "--native-facade-report", str(self.native),
            "--rustybench-source", str(self.directory), "--rustix-source", str(self.directory),
            "--output", str(self.directory / "gate-cli"),
        ])
        inputs = gate.collect_inputs(arguments)
        self.assertEqual(set(inputs), {"runtime_c_collector", "native_facade"})
        self.assertNotIn("allocator_report", vars(arguments))

    def test_passing_receipt_publishes_and_rereads_while_inputs_are_unchanged(self) -> None:
        receipt = self.receipt()
        self.assertTrue(receipt["passed"], receipt["unmet"])
        self.assertEqual(receipt["schema"], "crabc.x86_64-performance-release-gate/v2")
        path = gate.write_receipt(self.directory / "gate", receipt)
        self.assertTrue(gate.validate_receipt(ROOT, path)["passed"])

    def test_changed_runtime_or_facade_input_is_rejected(self) -> None:
        path = gate.write_receipt(self.directory / "gate", self.receipt())
        self.native.write_text(json.dumps({"mode": "full", "status": "complete-evidence"}), encoding="utf-8")
        with self.assertRaisesRegex(gate.GateInputError, "inputs changed after evaluation"):
            gate.validate_receipt(ROOT, path)

    def test_failing_receipt_is_retained_but_rereads_as_named_unmet_conditions(self) -> None:
        self.blockers = ("3 rows fail a per-workload gate",)
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], ["runtime-c-scorecard"])
        path = gate.write_receipt(self.directory / "gate", receipt)
        with self.assertRaisesRegex(gate.GateInputError, "runtime-c-scorecard: collector release blocker"):
            gate.validate_receipt(ROOT, path)

    def test_native_facade_must_be_full_mode_evidence(self) -> None:
        self.write("native.json", {"mode": "smoke", "status": "bounded-implementation-smoke",
                                   "uncontended_host": HOST})
        self.assertIn("not full complete evidence", self.details(self.receipt(), "native-facade-full")[0])

    def test_both_reports_must_record_an_uncontended_host(self) -> None:
        self.write("collector.json", {})
        self.write("native.json", {"mode": "full", "status": "complete-evidence",
                                   "uncontended_host": {"status": "uncontended", "evidence": {}}})
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], ["runtime-c-uncontended-host", "native-facade-uncontended-host"])

    def test_runtime_and_facade_selected_cpu_models_must_match(self) -> None:
        attempt = json.loads(self.attempt.read_text(encoding="utf-8"))
        attempt["tools"]["before"]["host"]["benchmark_cpu"] = 1
        self.attempt.write_text(json.dumps(attempt), encoding="utf-8")
        cpuinfo = Path(json.loads(self.native.read_text(encoding="utf-8"))["diagnostics"]["cpuinfo"]["path"])
        cpuinfo.write_text("processor: 0\nmodel name: Test CPU\n\n"
                           "processor: 1\nmodel name: Other CPU\n", encoding="utf-8")
        attempt["tools"]["before"]["host"]["cpuinfo_sha256"] = hashlib.sha256(cpuinfo.read_bytes()).hexdigest()
        attempt["tools"]["host_cpuinfo_diagnostics"]["before"]["model_names"] = ["Test CPU", "Other CPU"]
        self.attempt.write_text(json.dumps(attempt), encoding="utf-8")
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], ["performance-evidence-identity"])
        self.assertTrue(any("selected CPU models differ" in detail
                            for detail in self.details(receipt, "performance-evidence-identity")))


if __name__ == "__main__":
    unittest.main()
