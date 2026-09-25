#!/usr/bin/env python3
"""The read-only performance.release gate: thresholds, hosts and receipts."""

from __future__ import annotations

import argparse
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


def runtime_row(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "gate": "pass",
        "cpu": {"median_ratio": 0.8, "one_sided_95_upper": 0.9, "gate": "pass"},
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


def allocator_metrics(**changes: object) -> dict[str, object]:
    metrics: dict[str, object] = {
        "throughput": {"suite_geometric_mean_lower_95": 0.95, "critical_lower_95": {"local": 0.9, "remote": 1.2}},
        "tail_latency": {"critical_p99_upper_95": {"local": 1.1, "remote": 0.8}},
        "memory": {
            "geometric_mean_peak_upper": {"rss": 1.05, "pss": 1.0},
            "critical_peak_upper": {"local": {"rss": 1.1, "pss": 1.0}, "remote": {"rss": 0.9, "pss": 0.9}},
        },
    }
    metrics.update(changes)
    return metrics


HOST = {"status": "uncontended", "evidence": {"load_average": [0.0, 0.0, 0.0]}}


class ThresholdTests(unittest.TestCase):
    def test_runtime_row_at_every_plan_bound_passes(self):
        self.assertEqual(gate.runtime_row_unmet("row", 1, runtime_row()), [])

    def test_runtime_row_names_each_violated_scorecard_rule(self):
        cases = {
            "CPU one-sided 95% upper bound 0.91": {"cpu": {"one_sided_95_upper": 0.91, "gate": "pass"}},
            "pss_kib ratio 0.9100": {"pss_kib": {"reference": 1000, "candidate": 910, "gate": "pass"}},
            "memory_peak_bytes has no nonzero reference": {"memory_peak_bytes": {"reference": 0, "candidate": 0, "gate": "pass"}},
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

    def test_allocator_metrics_at_every_promotion_bound_pass(self):
        self.assertEqual(gate.allocator_metric_unmet("r", allocator_metrics()), [])

    def test_allocator_metrics_name_each_violated_promotion_rule(self):
        base = allocator_metrics()
        cases = {
            "suite geometric-mean throughput lower 95% bound 0.94": {
                "throughput": {**base["throughput"], "suite_geometric_mean_lower_95": 0.94}},
            "critical local throughput lower bound 0.89": {
                "throughput": {**base["throughput"], "critical_lower_95": {"local": 0.89, "remote": 1.0}}},
            "critical remote p99 upper bound 1.11": {
                "tail_latency": {"critical_p99_upper_95": {"local": 1.0, "remote": 1.11}}},
            "geometric-mean peak PSS upper ratio 1.06": {
                "memory": {**base["memory"], "geometric_mean_peak_upper": {"rss": 1.0, "pss": 1.06}}},
            "critical local peak RSS upper ratio 1.11": {
                "memory": {**base["memory"], "critical_peak_upper": {
                    "local": {"rss": 1.11, "pss": 1.0}, "remote": {"rss": 1.0, "pss": 1.0}}}},
            "do not share one nonempty critical roster": {
                "tail_latency": {"critical_p99_upper_95": {"local": 1.0}}},
        }
        for expected, change in cases.items():
            with self.subTest(expected=expected):
                unmet = gate.allocator_metric_unmet("r", allocator_metrics(**change))
                self.assertEqual(len(unmet), 1, unmet)
                self.assertIn(expected, unmet[0])
        self.assertTrue(any("critical roster" in item for item in gate.allocator_metric_unmet("r", {})))


class ReceiptTests(unittest.TestCase):
    """Owner readers are replaced by fakes; the gate logic runs unchanged."""

    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="performance-release-", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.rows = {"startup": {"attempts": [runtime_row(), runtime_row(), runtime_row()]}}
        self.blockers: tuple[str, ...] = ()
        self.allocator_metrics = [allocator_metrics() for _ in range(3)]
        self.identities = [{"source": "a" * 40, "host": "h"}] * 3
        self.native_error: Exception | None = None
        self.allocator_reader = True
        self.collector = self.write("collector.json", {"uncontended_host": HOST})
        self.native = self.write("native.json", {"mode": "full", "status": "complete-evidence", "uncontended_host": HOST})
        self.allocator = [self.write(f"allocator-{index}.json", {"index": index, "uncontended_host": HOST})
                          for index in range(3)]
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
            return types.SimpleNamespace(validate_collector_report=validate_collector_report)
        if name == "x86_64_runner":
            def validate_report(root, path, *, rustybench_source, rustix_source):
                del root, path, rustybench_source, rustix_source
                if self.native_error is not None:
                    raise self.native_error
            return types.SimpleNamespace(validate_report=validate_report, MODE_STATUS={"full": "complete-evidence"})
        if name == "perf_engine_x86_64":
            if not self.allocator_reader:
                return types.SimpleNamespace()

            def reader(root, path):
                index = json.loads(path.read_text(encoding="utf-8"))["index"]
                return {"identity": self.identities[index], "metrics": self.allocator_metrics[index]}
            return types.SimpleNamespace(**{gate.ALLOCATOR_READER: reader})
        raise AssertionError(name)

    def arguments(self, allocator=None) -> argparse.Namespace:
        return argparse.Namespace(
            runtime_c_collector=self.collector, native_facade_report=self.native,
            rustybench_source=self.directory, rustix_source=self.directory,
            allocator_report=self.allocator if allocator is None else allocator,
        )

    def receipt(self, allocator=None) -> dict[str, object]:
        return gate.build_receipt(gate.collect_inputs(self.arguments(allocator)))

    def details(self, receipt, identifier: str) -> list[str]:
        return next(row for row in receipt["conditions"] if row["id"] == identifier)["detail"]

    def test_passing_receipts_publish_and_reread_while_their_inputs_are_unchanged(self):
        receipt = self.receipt()
        self.assertTrue(receipt["passed"], receipt["unmet"])
        path = gate.write_receipt(self.directory / "gate", receipt)
        self.assertEqual(gate.validate_receipt(ROOT, path)["passed"], True)

        self.allocator[1].write_text(json.dumps({"index": 1, "uncontended_host": HOST, "edited": True}))
        with self.assertRaisesRegex(gate.GateInputError, "inputs changed after evaluation"):
            gate.validate_receipt(ROOT, path)

    def test_receipt_that_no_longer_derives_from_its_inputs_is_rejected(self):
        path = gate.write_receipt(self.directory / "gate", self.receipt())
        self.native_error = RuntimeError("current source snapshot differs")
        with self.assertRaisesRegex(gate.GateInputError, "differs from a fresh evaluation"):
            gate.validate_receipt(ROOT, path)

    def test_failing_receipt_is_retained_but_rereads_as_named_unmet_conditions(self):
        self.blockers = ("3 of 114 rows fail a per-workload gate",)
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], ["runtime-c-scorecard"])
        path = gate.write_receipt(self.directory / "gate", receipt)
        with self.assertRaisesRegex(gate.GateInputError, "runtime-c-scorecard: collector release blocker: 3 of 114"):
            gate.validate_receipt(ROOT, path)

    def test_every_receipt_must_record_an_uncontended_host(self):
        self.write("collector.json", {})
        self.write("native.json", {"mode": "full", "status": "complete-evidence",
                                   "uncontended_host": {"status": "uncontended", "evidence": {}}})
        self.write("allocator-2.json", {"index": 2, "uncontended_host": {"status": "loaded", "evidence": {"x": 1}}})
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], [
            "runtime-c-uncontended-host", "native-facade-uncontended-host", "allocator-m9-uncontended-host"])
        self.assertEqual(len(self.details(receipt, "allocator-m9-uncontended-host")), 1)

    def test_allocator_reports_need_three_agreeing_qualified_reports_and_an_owner_reader(self):
        receipt = self.receipt(self.allocator[:2])
        self.assertIn("2 allocator report(s); M9 requires at least 3", self.details(receipt, "allocator-m9-reports"))

        self.identities = [{"source": "a" * 40, "host": "h"}] * 2 + [{"source": "a" * 40, "host": "other"}]
        self.assertIn("do not agree", self.details(self.receipt(), "allocator-m9-reports")[0])

        self.identities = [{"source": "a" * 40, "host": "h"}] * 3
        self.allocator_metrics[0] = allocator_metrics(throughput={
            "suite_geometric_mean_lower_95": 0.5, "critical_lower_95": {"local": 1.0, "remote": 1.0}})
        self.assertIn("allocator-0.json: suite geometric-mean", self.details(self.receipt(), "allocator-m9-reports")[0])

        self.allocator_reader = False
        self.assertIn("no qualified full-report reader", self.details(self.receipt(), "allocator-m9-reports")[0])

    def test_native_facade_must_be_full_mode_evidence(self):
        self.write("native.json", {"mode": "smoke", "status": "bounded-implementation-smoke", "uncontended_host": HOST})
        self.assertIn("not full complete evidence", self.details(self.receipt(), "native-facade-full")[0])

    def test_inputs_and_outputs_stay_inside_the_checkout(self):
        with self.assertRaisesRegex(gate.GateInputError, "below this checkout"):
            gate.collect_inputs(argparse.Namespace(**{**vars(self.arguments()), "runtime_c_collector": Path("/etc/passwd")}))
        with self.assertRaisesRegex(gate.GateInputError, "fresh .work directory"):
            gate.write_receipt(self.directory, self.receipt())


if __name__ == "__main__":
    unittest.main()
