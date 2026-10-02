#!/usr/bin/env python3
"""The read-only performance.release gate: thresholds, hosts and receipts."""

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


def allocator_timed_sample(index: int) -> dict[str, object]:
    batches = [{"ns": 900 + index, "cpu_ns": 700 + index, "ops": 10},
               {"ns": 1000 + index, "cpu_ns": 800 + index, "ops": 10},
               {"ns": 1100 + index, "cpu_ns": 900 + index, "ops": 10}]
    return {
        "arguments": ["ready_fd=3", "control_fd=4"], "cpus": [0], "sample_index": 0,
        "process": {"exit_memory": {"status": {"vm_hwm_kib": 1000 + index}}},
        "stdout": "".join(f"batch ns={batch['ns']} cpu_ns={batch['cpu_ns']} ops={batch['ops']}\n"
                          for batch in batches) + "ok\n",
        "batches": batches,
        "peak_state": {"smaps_rollup": {"pss_kib": 900 + index}},
    }


def allocator_memory_sample(index: int) -> dict[str, object]:
    return {
        "arguments": ["ready_fd=3", "control_fd=4"], "cpus": [0], "sample_index": 0,
        "snapshots": {"live": {"status": {"vm_hwm_kib": 1000 + index},
                               "smaps_rollup": {"pss_kib": 900 + index}}},
    }


HOST = {"status": "uncontended", "evidence": {"load_average": [0.0, 0.0, 0.0], "measurement_cpus": [0]}}
SOURCE_REVISION = "a" * 40
HOST_IDENTITY = {
    "cpu_model": "Test CPU", "kernel_release": "5.10.0-test", "allowed_cpus": [0, 1],
    "logical_cpus": 2, "measurement_cpus": [0],
}
RUSTC_VERSION = ("rustc 1.100.0-nightly (574ff7d98 2026-09-14)\n"
                 "binary: rustc\ncommit-hash: 574ff7d98bd6d037e5236a8453029173b32631fd\n"
                 "release: 1.100.0-nightly\nhost: x86_64-unknown-linux-musl\n")
CARGO_VERSION = "cargo 1.100.0-nightly (7941be6fb 2026-09-11)"


class ThresholdTests(unittest.TestCase):
    def test_runtime_memory_floor_policy_keeps_raw_totals_and_other_bounds(self):
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
                    self.assertEqual(any("memory_peak_bytes ratio" in item for item in unmet), not peak_floor or bool(increment))
                    self.assertEqual(row["pss_kib"]["candidate"], pss + increment)
        row = runtime_row(pss_kib={"reference": 1000, "candidate": 1000, "gate": "pass"},
                          memory_peak_bytes={"reference": 1000, "candidate": 1000, "gate": "pass"},
                          cpu={"one_sided_95_upper": 0.91, "gate": "pass"})
        self.assertEqual(len(gate.runtime_row_unmet("allocator_live_32m", 1, row)), 1)

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
        self.identities = [{"source": "source-seal", "host": HOST_IDENTITY}] * 3
        self.native_error: Exception | None = None
        self.allocator_reader = True
        cpuinfo = self.directory / "cpuinfo.raw"
        cpuinfo.write_text("processor: 0\nmodel name: Test CPU\n\n"
                           "processor: 1\nmodel name: Test CPU\n", encoding="utf-8")
        self.cpu_identity = hashlib.sha256(cpuinfo.read_bytes()).hexdigest()
        self.attempt = self.write("attempt.json", {"tools": {
            "before": {"host": {
                "kernel_release": HOST_IDENTITY["kernel_release"],
                "allowed_affinity_before_pin": HOST_IDENTITY["allowed_cpus"],
                "cpuinfo_sha256": self.cpu_identity,
                "benchmark_cpu": 0,
            }},
            "host_cpuinfo_diagnostics": {"before": {"model_names": [HOST_IDENTITY["cpu_model"]] * 2}},
        }})
        self.collector = self.write("collector.json", {
            "collector": {"source_revision": SOURCE_REVISION},
            "attempts": [{"report": {"path": str(self.attempt)}}],
            "uncontended_host": HOST,
        })
        rustc_stdout = self.directory / "rustc.stdout"
        rustc_stdout.write_text(RUSTC_VERSION, encoding="utf-8")
        cargo_stdout = self.directory / "cargo.stdout"
        cargo_stdout.write_text(CARGO_VERSION + "\n", encoding="utf-8")
        self.native = self.write("native.json", {
            "mode": "full", "status": "complete-evidence", "uncontended_host": HOST,
            "tools": {name: {"command": {"stdout": {"path": path.relative_to(ROOT).as_posix()}}}
                      for name, path in (("rustc", rustc_stdout), ("cargo", cargo_stdout))},
            "diagnostics": {"allowed_affinity": HOST_IDENTITY["allowed_cpus"], "client_cpu": 0,
                            "cpuinfo": {"path": str(cpuinfo)}},
        })
        self.allocator = [self.write(f"allocator-{index}.json", {
            "index": index, "uncontended_host": HOST,
            "provenance": {"git": {"head": SOURCE_REVISION}, "host": HOST_IDENTITY,
                           "tools": {"rustc": RUSTC_VERSION.strip(), "cargo": CARGO_VERSION,
                                     "musl-gcc": "pinned C compiler", "readelf": "pinned readelf"}},
            "rows": {"startup": {"cpus": [0], "lanes": {
                "pinned_c": {"samples": [allocator_timed_sample(index)]},
                "rust_engine": {"samples": [allocator_timed_sample(index)]}},
                "comparison": {"observed": index}}},
            "memory_rows": {"live": {"cpus": [0], "lanes": {
                "pinned_c": {"samples": [allocator_memory_sample(index)]},
                "rust_engine": {"samples": [allocator_memory_sample(index)]}},
                "comparison": {"observed": index}}},
        })
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
            return types.SimpleNamespace(validate_report=validate_report, MODE_STATUS={"full": "complete-evidence"})
        if name == "perf_engine_x86_64":
            if not self.allocator_reader:
                return types.SimpleNamespace()

            def reader(root, path):
                report = json.loads(path.read_text(encoding="utf-8"))
                index = report["index"]
                return {"identity": {**self.identities[index],
                                     "configuration": {"tools": report["provenance"]["tools"]}},
                        "metrics": self.allocator_metrics[index]}
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

    def select_allocator_cpu(self, cpu: int) -> None:
        self.identities = [{"source": "source-seal", "host": {**HOST_IDENTITY, "measurement_cpus": [cpu]}}] * 3
        for path in self.allocator:
            report = json.loads(path.read_text(encoding="utf-8"))
            report["provenance"]["host"]["measurement_cpus"] = [cpu]
            report["uncontended_host"]["evidence"]["measurement_cpus"] = [cpu]
            for group in ("rows", "memory_rows"):
                for row in report[group].values():
                    row["cpus"] = [cpu]
                    for lane in row["lanes"].values():
                        lane["samples"][0]["cpus"] = [cpu]
            path.write_text(json.dumps(report), encoding="utf-8")

    def set_second_cpu_model(self, model: str) -> None:
        cpuinfo = Path(json.loads(self.native.read_text(encoding="utf-8"))["diagnostics"]["cpuinfo"]["path"])
        raw = cpuinfo.read_text(encoding="utf-8").replace(
            "processor: 1\nmodel name: Test CPU", f"processor: 1\nmodel name: {model}")
        cpuinfo.write_text(raw, encoding="utf-8")
        attempt = json.loads(self.attempt.read_text(encoding="utf-8"))
        attempt["tools"]["before"]["host"]["cpuinfo_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
        attempt["tools"]["host_cpuinfo_diagnostics"]["before"]["model_names"] = ["Test CPU", model]
        self.attempt.write_text(json.dumps(attempt), encoding="utf-8")

    def test_rehashed_raw_cpuinfo_must_match_the_allocator_selected_cpu_model(self):
        self.set_second_cpu_model("Other CPU")
        self.select_allocator_cpu(1)
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], ["performance-evidence-identity"])
        self.assertTrue(any("selected CPU model differs" in detail
                            for detail in self.details(receipt, "performance-evidence-identity")))
        path = gate.write_receipt(self.directory / "gate-other-cpu-model", receipt)
        with self.assertRaisesRegex(gate.GateInputError, "selected CPU model differs"):
            gate.validate_receipt(ROOT, path)

    def test_allocator_may_use_another_cpu_with_the_same_model(self):
        self.select_allocator_cpu(1)
        self.assertTrue(self.receipt()["passed"])

    def test_mixed_model_host_can_use_the_same_nonfirst_model_for_all_measurements(self):
        self.set_second_cpu_model("Other CPU")
        attempt = json.loads(self.attempt.read_text(encoding="utf-8"))
        attempt["tools"]["before"]["host"]["benchmark_cpu"] = 1
        self.attempt.write_text(json.dumps(attempt), encoding="utf-8")
        native = json.loads(self.native.read_text(encoding="utf-8"))
        native["diagnostics"]["client_cpu"] = 1
        self.native.write_text(json.dumps(native), encoding="utf-8")
        self.select_allocator_cpu(1)
        self.assertTrue(self.receipt()["passed"])

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

    def test_passing_receipt_cannot_replace_a_replayed_condition_detail(self):
        path = gate.write_receipt(self.directory / "gate", self.receipt())
        record = json.loads(path.read_text(encoding="utf-8"))
        record["conditions"][0]["detail"] = "unverified performance evidence"
        path.write_text(json.dumps(record), encoding="utf-8")
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
        allocator = json.loads(self.allocator[2].read_text(encoding="utf-8"))
        allocator["uncontended_host"] = {"status": "loaded", "evidence": {"measurement_cpus": [0], "x": 1}}
        self.write("allocator-2.json", allocator)
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], [
            "runtime-c-uncontended-host", "native-facade-uncontended-host", "allocator-m9-uncontended-host"])
        self.assertEqual(len(self.details(receipt, "allocator-m9-uncontended-host")), 1)

    def test_allocator_reports_need_three_agreeing_qualified_reports_and_an_owner_reader(self):
        receipt = self.receipt(self.allocator[:2])
        self.assertIn("2 allocator report(s); M9 requires at least 3", self.details(receipt, "allocator-m9-reports"))

        self.identities = [{"source": "source-seal", "host": HOST_IDENTITY}] * 2 + [
            {"source": "source-seal", "host": {**HOST_IDENTITY, "cpu_model": "other"}}]
        self.assertIn("do not agree", self.details(self.receipt(), "allocator-m9-reports")[0])

        self.identities = [{"source": "source-seal", "host": HOST_IDENTITY}] * 3
        self.allocator_metrics[0] = allocator_metrics(throughput={
            "suite_geometric_mean_lower_95": 0.5, "critical_lower_95": {"local": 1.0, "remote": 1.0}})
        self.assertIn("allocator-0.json: suite geometric-mean", self.details(self.receipt(), "allocator-m9-reports")[0])

        self.allocator_reader = False
        self.assertIn("no qualified full-report reader", self.details(self.receipt(), "allocator-m9-reports")[0])

    def test_native_facade_must_be_full_mode_evidence(self):
        self.write("native.json", {"mode": "smoke", "status": "bounded-implementation-smoke", "uncontended_host": HOST})
        self.assertIn("not full complete evidence", self.details(self.receipt(), "native-facade-full")[0])

    def test_rehashed_allocator_cohort_from_other_source_or_host_is_rejected(self):
        for field, changed in (("source", "b" * 40), ("host", "Other CPU")):
            with self.subTest(field=field):
                for index, path in enumerate(self.allocator):
                    report = json.loads(path.read_text(encoding="utf-8"))
                    if field == "source":
                        report["provenance"]["git"]["head"] = changed
                    else:
                        self.identities[index] = {
                            "source": "source-seal", "host": {**HOST_IDENTITY, "cpu_model": changed}}
                        report["provenance"]["git"]["head"] = SOURCE_REVISION
                        report["provenance"]["host"]["cpu_model"] = changed
                    path.write_text(json.dumps(report), encoding="utf-8")
                receipt = self.receipt()
                self.assertFalse(receipt["passed"], receipt)
                self.assertIn("performance-evidence-identity", receipt["unmet"])
                path = gate.write_receipt(self.directory / f"gate-{field}", receipt)
                with self.assertRaisesRegex(gate.GateInputError, "performance-evidence-identity"):
                    gate.validate_receipt(ROOT, path)
                self.identities = [{"source": "source-seal", "host": HOST_IDENTITY}] * 3

    def test_rehashed_allocator_cohort_with_other_rust_tools_is_rejected(self):
        changed_versions = {
            "rustc": (RUSTC_VERSION.replace(
                "574ff7d98bd6d037e5236a8453029173b32631fd", "b" * 40).strip(),
                      "Rust compiler identity differs"),
            "cargo": ("cargo 1.99.0-nightly (different 2026-09-01)", "Cargo identity differs"),
        }
        for name, (changed, expected) in changed_versions.items():
            with self.subTest(name=name):
                for path in self.allocator:
                    report = json.loads(path.read_text(encoding="utf-8"))
                    report["provenance"]["tools"][name] = changed
                    path.write_text(json.dumps(report), encoding="utf-8")
                receipt = self.receipt()
                self.assertEqual(receipt["unmet"], ["performance-evidence-identity"])
                self.assertTrue(any(expected in detail
                                    for detail in self.details(receipt, "performance-evidence-identity")))
                path = gate.write_receipt(self.directory / f"gate-other-{name}", receipt)
                with self.assertRaisesRegex(gate.GateInputError, expected):
                    gate.validate_receipt(ROOT, path)
                for report_path in self.allocator:
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    report["provenance"]["tools"][name] = (RUSTC_VERSION.strip() if name == "rustc"
                                                            else CARGO_VERSION)
                    report_path.write_text(json.dumps(report), encoding="utf-8")

    def test_allocator_c_tools_may_differ_from_native_rust_tools(self):
        for path in self.allocator:
            report = json.loads(path.read_text(encoding="utf-8"))
            report["provenance"]["tools"]["musl-gcc"] = "different pinned C compiler"
            report["provenance"]["tools"]["readelf"] = "different pinned readelf"
            path.write_text(json.dumps(report), encoding="utf-8")
        self.assertTrue(self.receipt()["passed"])

    def test_rehashed_allocator_reports_cannot_reuse_one_raw_measurement(self):
        original = json.loads(self.allocator[0].read_text(encoding="utf-8"))
        for path in self.allocator[1:]:
            report = json.loads(path.read_text(encoding="utf-8"))
            report["rows"] = original["rows"]
            report["memory_rows"] = original["memory_rows"]
            path.write_text(json.dumps(report), encoding="utf-8")
        receipt = self.receipt()
        self.assertFalse(receipt["passed"], receipt)
        self.assertTrue(any("same raw measurements" in detail
                            for detail in self.details(receipt, "allocator-m9-reports")))

    def test_rehashed_allocator_report_cannot_hide_reused_measurements_in_descriptor_arguments(self):
        original = json.loads(self.allocator[0].read_text(encoding="utf-8"))
        copied = json.loads(self.allocator[1].read_text(encoding="utf-8"))
        for group in ("rows", "memory_rows"):
            copied[group] = json.loads(json.dumps(original[group]))
            for row in copied[group].values():
                for lane in row["lanes"].values():
                    lane["samples"][0]["arguments"] = ["ready_fd=5", "control_fd=6"]
        self.allocator[1].write_text(json.dumps(copied), encoding="utf-8")
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], ["allocator-m9-reports"])
        self.assertTrue(any("same raw measurements" in detail
                            for detail in self.details(receipt, "allocator-m9-reports")))
        path = gate.write_receipt(self.directory / "gate-reused-comparison", receipt)
        with self.assertRaisesRegex(gate.GateInputError, "same raw measurements"):
            gate.validate_receipt(ROOT, path)

    def test_independent_allocator_samples_may_have_identical_comparisons(self):
        first = json.loads(self.allocator[0].read_text(encoding="utf-8"))
        second = json.loads(self.allocator[1].read_text(encoding="utf-8"))
        for group in ("rows", "memory_rows"):
            second[group] = json.loads(json.dumps(first[group]))
        # The lower batch changes while its process median and p99 stay fixed.
        sample = second["rows"]["startup"]["lanes"]["pinned_c"]["samples"][0]
        sample["batches"][0]["ns"] -= 1
        sample["stdout"] = sample["stdout"].replace("batch ns=900 ", "batch ns=899 ", 1)
        self.allocator[1].write_text(json.dumps(second), encoding="utf-8")
        receipt = self.receipt()
        self.assertTrue(receipt["passed"], receipt["unmet"])

    def test_rehashed_allocator_row_cpus_must_be_covered_by_observed_host_cpus(self):
        report = json.loads(self.allocator[1].read_text(encoding="utf-8"))
        for group in ("rows", "memory_rows"):
            for row in report[group].values():
                row["cpus"] = [1]
                for lane in row["lanes"].values():
                    lane["samples"][0]["cpus"] = [1]
        self.allocator[1].write_text(json.dumps(report), encoding="utf-8")
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], ["allocator-m9-reports"])
        self.assertTrue(any("outside the observed host CPUs" in detail
                            for detail in self.details(receipt, "allocator-m9-reports")))

    def test_rehashed_allocator_host_cpu_identity_must_match_host_observations(self):
        self.identities = [{"source": "source-seal", "host": {**HOST_IDENTITY, "measurement_cpus": [1]}}] * 3
        for path in self.allocator:
            report = json.loads(path.read_text(encoding="utf-8"))
            report["provenance"]["host"]["measurement_cpus"] = [1]
            path.write_text(json.dumps(report), encoding="utf-8")
        receipt = self.receipt()
        self.assertEqual(receipt["unmet"], ["allocator-m9-reports"])
        self.assertTrue(any("identity CPUs differ from observed host CPUs" in detail
                            for detail in self.details(receipt, "allocator-m9-reports")))

    def test_allocator_rows_can_use_a_subset_of_the_observed_host_cpus(self):
        self.identities = [{"source": "source-seal", "host": {**HOST_IDENTITY, "measurement_cpus": [1, 0]}}] * 3
        for path in self.allocator:
            report = json.loads(path.read_text(encoding="utf-8"))
            report["provenance"]["host"]["measurement_cpus"] = [1, 0]
            report["uncontended_host"]["evidence"]["measurement_cpus"] = [1, 0]
            for group in ("rows", "memory_rows"):
                for row in report[group].values():
                    row["cpus"] = [1]
                    for lane in row["lanes"].values():
                        lane["samples"][0]["cpus"] = [1]
            path.write_text(json.dumps(report), encoding="utf-8")
        self.assertTrue(self.receipt()["passed"])

    def test_inputs_and_outputs_stay_inside_the_checkout(self):
        with self.assertRaisesRegex(gate.GateInputError, "below this checkout"):
            gate.collect_inputs(argparse.Namespace(**{**vars(self.arguments()), "runtime_c_collector": Path("/etc/passwd")}))
        with self.assertRaisesRegex(gate.GateInputError, "fresh .work directory"):
            gate.write_receipt(self.directory, self.receipt())


if __name__ == "__main__":
    unittest.main()
