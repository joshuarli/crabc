"""Reader contracts for the native x86-64 engine development performance runner.

These tests exercise the runner's pure manifest, fixture-grammar, statistics,
link-map, and summary logic. They build and measure nothing.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import os
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "perf_engine_x86_64.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_perf_engine_x86_64_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
engine = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = engine
SPEC.loader.exec_module(engine)


def timed_sample(costs: list[int], cpu_share: float = 1.0, peak_rss_kib: int = 1000,
                 peak_pss_kib: int | None = 900) -> dict[str, object]:
    sample: dict[str, object] = {
        "batches": [{"ns": cost * 100, "cpu_ns": round(cost * 100 * cpu_share), "ops": 100} for cost in costs],
        "process": {"exit_memory": {"status": {"vm_hwm_kib": peak_rss_kib}}},
    }
    if peak_pss_kib is not None:
        sample["peak_state"] = {"smaps_rollup": {"pss_kib": peak_pss_kib, "rss_kib": peak_pss_kib}}
    return sample


def architecture_row(manifest: dict, key: str) -> dict:
    name = manifest["architecture_rows"][key]
    return next(row for row in manifest["rows"] if row["name"] == name)


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = engine.load_manifest()

    def test_architecture_set_selects_the_named_rows_and_no_memory_rows(self) -> None:
        timed, memory = engine.selected_rows(self.manifest, "architecture")
        names = {row["name"] for row in timed}
        self.assertIn(self.manifest["architecture_rows"]["single_thread"], names)
        self.assertIn(self.manifest["architecture_rows"]["four_thread"], names)
        self.assertEqual(memory, [])

    def test_architecture_rows_must_match_their_worker_counts(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        architecture_row(manifest, "four_thread")["params"]["workers"] = 2
        with self.assertRaisesRegex(engine.HarnessError, "4 worker"):
            engine.validate_manifest(manifest)

    def test_architecture_rows_must_measure_one_request_size(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        architecture_row(manifest, "four_thread")["params"]["size"] += 16
        with self.assertRaisesRegex(engine.HarnessError, "one request size"):
            engine.validate_manifest(manifest)

    def test_rejects_an_unknown_workload_or_parameter(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["rows"][0]["workload"] = "fork_bomb"
        with self.assertRaisesRegex(engine.HarnessError, "unsupported workload"):
            engine.validate_manifest(manifest)
        manifest = copy.deepcopy(self.manifest)
        manifest["rows"][0]["params"]["ready_fd"] = 3
        with self.assertRaisesRegex(engine.HarnessError, "unsupported parameters"):
            engine.validate_manifest(manifest)

    def test_fixture_arguments_scale_batches_and_pin_workers(self) -> None:
        row = {"workload": "local_scaling", "params": {"size": 64, "workers": 2, "batches": 16}}
        self.assertEqual(
            engine.fixture_arguments(row, batch_divisor=4, cpus=[3, 5]),
            ["local_scaling", "batches=4", "size=64", "workers=2", "cpus=3,5"],
        )
        self.assertEqual(engine.expected_batches({"params": {"batches": 2}}, 4), 1)
        self.assertEqual(engine.row_thread_count({"workload": "remote_free", "params": {"workers": 2}}), 4)
        self.assertEqual(engine.row_thread_count({"workload": "alloc_free", "params": {"size": 1}}), 1)


class FixtureGrammarTests(unittest.TestCase):
    def test_accepts_exact_batch_records(self) -> None:
        self.assertEqual(
            engine.parse_timed_output("batch ns=10 cpu_ns=9 ops=2\nbatch ns=12 cpu_ns=12 ops=2\nok\n", expected_batches=2),
            [{"ns": 10, "cpu_ns": 9, "ops": 2}, {"ns": 12, "cpu_ns": 12, "ops": 2}],
        )

    def test_rejects_missing_ok_extra_records_and_wrong_counts(self) -> None:
        with self.assertRaisesRegex(engine.HarnessError, "terminal ok"):
            engine.parse_timed_output("batch ns=10 cpu_ns=10 ops=2\n", expected_batches=1)
        with self.assertRaisesRegex(engine.HarnessError, "unexpected record"):
            engine.parse_timed_output("pointer=0x1234\nok\n", expected_batches=0)
        with self.assertRaisesRegex(engine.HarnessError, "expected 2"):
            engine.parse_timed_output("batch ns=10 cpu_ns=10 ops=2\nok\n", expected_batches=2)
        with self.assertRaisesRegex(engine.HarnessError, "positive"):
            engine.parse_timed_output("batch ns=10 cpu_ns=0 ops=2\nok\n", expected_batches=1)
        with self.assertRaisesRegex(engine.HarnessError, "unexpected record"):
            engine.parse_timed_output("batch ns=10 ops=2\nok\n", expected_batches=1)


class StatisticsTests(unittest.TestCase):
    def test_throughput_ratio_is_inverse_cost_with_a_bootstrap_spread(self) -> None:
        c = [timed_sample([10, 10, 11]) for _ in range(5)]
        rust = [timed_sample([40, 40, 44], cpu_share=0.5) for _ in range(5)]
        comparison = engine.throughput_comparison(c, rust, seed=7)
        ratio = comparison["throughput_ratio_rust_over_c"]
        self.assertAlmostEqual(ratio["median"], 0.25)
        self.assertAlmostEqual(comparison["cpu_throughput_ratio_rust_over_c"], 0.5)
        self.assertLessEqual(ratio["bootstrap_5th_percentile"], ratio["median"])
        self.assertGreaterEqual(ratio["bootstrap_95th_percentile"], ratio["median"])

    def test_memory_ratio_is_absent_for_a_zero_reference(self) -> None:
        def sample(value: int) -> dict[str, object]:
            snapshot = {"status": {"vm_hwm_kib": value}, "smaps_rollup": {"pss_kib": value, "rss_kib": value}, "maps": {"mapping_count": value}}
            return {"snapshots": {"live": snapshot, "freed": snapshot}}

        comparison = engine.memory_comparison([sample(100)], [sample(150)], seed=1)
        self.assertAlmostEqual(comparison["peak_rss_kib"]["ratio_rust_over_c"], 1.5)
        self.assertIsNone(engine.memory_comparison([sample(0)], [sample(1)], seed=1)["live_pss_kib"]["ratio_rust_over_c"])


def measured(c_cost: float, rust_cost: float, c_cpu: float | None = None, rust_cpu: float | None = None) -> dict[str, object]:
    c_cpu = c_cost if c_cpu is None else c_cpu
    rust_cpu = rust_cost if rust_cpu is None else rust_cpu
    return {
        "status": "measured",
        "comparison": {
            "median_ns_per_op": {"pinned_c": c_cost, "rust_engine": rust_cost},
            "median_cpu_ns_per_op": {"pinned_c": c_cpu, "rust_engine": rust_cpu},
            "throughput_ratio_rust_over_c": {"median": c_cost / rust_cost},
            "cpu_throughput_ratio_rust_over_c": c_cpu / rust_cpu,
        },
    }


class SummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = engine.load_manifest()
        self.names = self.manifest["architecture_rows"]

    def test_architecture_summary_reports_ratios_and_self_scaling_without_a_verdict(self) -> None:
        # Pinned C scales with flat per-call CPU; the Rust lane serializes and
        # pays four times the CPU per call.
        rows = {
            self.names["single_thread"]: measured(10, 40, 10, 40),
            self.names["four_thread"]: measured(2.5, 40, 10, 160),
        }
        summary = engine.architecture_summary(self.manifest, rows)
        self.assertEqual(summary["status"], "measured")
        self.assertAlmostEqual(summary["single_thread_throughput_ratio_rust_over_c"]["median"], 0.25)
        self.assertEqual(summary["four_worker_wall_self_scaling"], {"pinned_c": 4.0, "rust_engine": 1.0})
        self.assertEqual(summary["four_worker_cpu_cost_growth"], {"pinned_c": 1.0, "rust_engine": 4.0})
        self.assertNotIn("verdict", json.dumps(summary))

    def test_unmeasured_architecture_rows_are_reported_as_such(self) -> None:
        rows = {self.names["single_thread"]: measured(10, 20), self.names["four_thread"]: {"status": "unavailable"}}
        self.assertEqual(engine.architecture_summary(self.manifest, rows)["status"], "not-measured")

    def test_matrix_geometric_mean_and_slowest_rows(self) -> None:
        summary = engine.matrix_summary({"a": measured(10, 20), "b": measured(10, 5), "c": {"status": "unavailable"}})
        self.assertAlmostEqual(summary["throughput_ratio_rust_over_c_geometric_mean"], 1.0)
        self.assertEqual(summary["slowest_rows"], ["a", "b"])
        self.assertEqual(summary["measured_rows"], 2)


class MeasurementFailureTests(unittest.TestCase):
    def test_a_failing_fixture_is_recorded_and_later_rows_still_run(self) -> None:
        rows = [
            {"name": "broken", "workload": "alloc_free", "params": {"size": 64, "iterations": 1, "batches": 1}},
            {"name": "unplaceable", "workload": "local_scaling", "params": {"size": 64, "workers": 4096, "batches": 1}},
        ]
        missing = Path("/nonexistent/engine-fixture")
        with tempfile.TemporaryDirectory() as directory:
            results = engine.measure_rows(
                rows, {"pinned_c": missing, "rust_engine": missing}, memory=False,
                mode={"samples": 1, "warmup_processes": 0, "batch_divisor": 1},
                cpu_pool=None, timeout=30.0, scratch=Path(directory), seed=1,
            )
        self.assertEqual(results["broken"]["status"], "failed")
        self.assertIn(results["broken"]["failed_lane"], engine.LANES)
        self.assertIn("fixture exec failure", results["broken"]["reason"])
        self.assertEqual(results["unplaceable"]["status"], "unavailable")


class LinkMapTests(unittest.TestCase):
    def test_attributes_kept_input_sections_by_owner(self) -> None:
        text = "\n".join(
            [
                "Discarded input sections",
                " .text.unused   0x0000000000000000       0x40 /b/mimalloc-src-alloc.o",
                "",
                "Linker script and memory map",
                " .text          0x0000000000401000       0x20 /b/engine-fixture-c.o",
                " .text.mi_malloc",
                "                0x0000000000401020       0x30 /b/mimalloc-src-alloc.o",
                "                0x0000000000401020                mi_malloc",
                " .rodata        0x0000000000402000       0x10 /b/mimalloc-src-options.o",
                " .text          0x0000000000403000      0x100 /usr/lib/libc.a(malloc.o)",
                " .bss           0x0000000000404000        0x8 /b/engine-c-backend.o",
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "map"
            path.write_text(text, encoding="utf-8")
            totals = engine.link_map_attribution(path, engine.c_lane_owner)
        self.assertEqual(totals["allocator"], {"text": 0x30, "rodata": 0x10, "data": 0x8})
        self.assertEqual(totals["fixture"]["text"], 0x20)
        self.assertEqual(totals["runtime"]["text"], 0x100)

    def test_rust_owner_includes_the_whole_backend_archive(self) -> None:
        self.assertEqual(engine.rust_lane_owner("/b/libcrabc_allocator_engine_rust_backend.a(core-1.o)"), "allocator")
        self.assertEqual(engine.rust_lane_owner("/b/engine-fixture-rust.o"), "fixture")


class CargoMessageTests(unittest.TestCase):
    def test_reports_each_library_rlib_once(self) -> None:
        lines = [
            json.dumps({"reason": "compiler-artifact", "target": {"name": "crabc-core"}, "filenames": ["/t/libcrabc_core-1.rlib", "/t/libcrabc_core-1.rmeta"]}),
            json.dumps({"reason": "compiler-artifact", "target": {"name": "crabc_mimalloc"}, "filenames": ["/t/libcrabc_mimalloc.rlib"]}),
            json.dumps({"reason": "build-finished", "success": True}),
            "not json",
        ]
        rlibs = engine.cargo_rlibs("\n".join(lines))
        self.assertEqual(rlibs["crabc_core"], Path("/t/libcrabc_core-1.rlib"))
        self.assertEqual(rlibs["crabc_mimalloc"], Path("/t/libcrabc_mimalloc.rlib"))

    def test_requires_the_engine_rlib(self) -> None:
        with self.assertRaisesRegex(engine.HarnessError, "crabc_mimalloc"):
            engine.cargo_rlibs("")


# ---- qualified full reports ---------------------------------------------------


def idle_window(label: str, cpus: list[int], *, busy_ticks: int = 0, load1: float = 0.0) -> dict[str, object]:
    """A /proc/stat window of 100 ticks per CPU with `busy_ticks` of user time."""

    def stat(after: bool) -> dict[str, object]:
        per_cpu = {str(cpu): [busy_ticks if after else 0, 0, 0, 100 - busy_ticks if after else 0, 0, 0, 0, 0, 0, 0]
                   for cpu in range(32)}
        total = [sum(values[index] for values in per_cpu.values()) for index in range(10)]
        return {"cpus": {"all": total, **per_cpu}, "procs_running": 1}

    return {"label": label, "elapsed_ns": 1_000_000_000, "loadavg": [f"{load1} 0.0 0.0 1/100 7", "0.0 0.0 0.0 1/100 7"],
            "stat_before": stat(False), "stat_after": stat(True), "visible_processes": 2, "active_processes": {}}


def idle_host(cpus: list[int]) -> dict[str, object]:
    frequency = {"cpus": {str(cpu): {"scaling_governor": "performance"} for cpu in cpus}, "boost": "1"}
    cgroup = {"cpu_max": "max 100000", "cpu_stat": {"nr_throttled": 0}}
    return {
        "thresholds": dict(engine.UNCONTENDED_THRESHOLDS), "measurement_cpus": cpus, "clock_ticks_per_second": 100,
        "pid_namespace": "pid:[1]", "frequency_start": frequency, "frequency_end": copy.deepcopy(frequency),
        "cgroup_start": cgroup, "cgroup_end": copy.deepcopy(cgroup),
        "windows": [idle_window("start", cpus), idle_window("row:x", cpus), idle_window("end", cpus)],
    }


def synthetic_report(rust_cost_factor: float = 1.0, peak_hook: bool = True) -> dict[str, object]:
    """A complete --full --set matrix report of the current checkout from synthetic raw samples."""

    manifest = engine.load_manifest()
    mode = manifest["modes"]["full"]
    pin = engine.shared.load_pin()
    cpus = list(range(8))
    report: dict[str, object] = {
        "schema": engine.SCHEMA, "kind": engine.KIND, "label": "synthetic", "mode": "full", "row_set": "matrix",
        "peak_hook": peak_hook, "status": "ok", "failed_rows": [],
        "native_execution_provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
        "provenance": {
            "git": {"head": "0" * 40, "clean": True, "dirty_paths": []},
            "host": {"allowed_cpus": list(range(32)), "cpu_model": "synthetic", "kernel_release": "6.1",
                     "logical_cpus": 32, "measurement_cpus": cpus, "scaling_governors": {"0": "performance"},
                     "transparent_hugepage": "always [madvise] never"},
            "tools": {"rustc": "rustc synthetic", "musl-gcc": "gcc synthetic"},
            "inputs": {**engine.sealed_inputs(), "mimalloc": {
                "archive": {"path": "archive", "bytes": 1, "sha256": pin["sha256"]},
                **{key: pin[key] for key in ("version", "tag", "revision")}}},
        },
        "rows": {}, "memory_rows": {},
    }
    timed, memory = engine.selected_rows(manifest, "matrix")
    for index, row in enumerate(timed):
        batches = engine.expected_batches(row, mode["batch_divisor"])
        lanes = {
            lane: [timed_sample([10 * factor + (sample + batch) % 3 for batch in range(batches)],
                                peak_rss_kib=1000 + sample, peak_pss_kib=900 + sample if peak_hook else None)
                   for sample in range(mode["samples"])]
            for lane, factor in (("pinned_c", 1), ("rust_engine", rust_cost_factor))
        }
        seed = 100 + index
        report["rows"][row["name"]] = {
            "status": "measured", "workload": row["workload"], "params": row["params"], "seed": seed,
            "lanes": {lane: {"samples": samples} for lane, samples in lanes.items()},
            "comparison": engine.throughput_comparison(lanes["pinned_c"], lanes["rust_engine"], seed=seed),
        }
    for index, row in enumerate(memory):
        def snapshot(value: int) -> dict[str, object]:
            return {"status": {"vm_hwm_kib": value}, "smaps_rollup": {"pss_kib": value, "rss_kib": value},
                    "maps": {"mapping_count": 10}}

        lanes = {lane: [{"snapshots": {"live": snapshot(4000 + sample), "freed": snapshot(100)}}
                        for sample in range(mode["samples"])] for lane in engine.LANES}
        seed = 500 + index
        report["memory_rows"][row["name"]] = {
            "status": "measured", "workload": row["workload"], "params": row["params"], "seed": seed,
            "lanes": {lane: {"samples": samples} for lane, samples in lanes.items()},
            "comparison": engine.memory_comparison(lanes["pinned_c"], lanes["rust_engine"], seed=seed),
        }
    report["uncontended_host"] = engine.uncontended_host_record(idle_host(cpus))
    return report


class QualifiedReportTests(unittest.TestCase):
    """The qualified full-report reader over complete synthetic raw reports."""

    def setUp(self) -> None:
        # Fewer bootstrap draws keep the full synthetic matrix fast; the
        # reader recomputes under the same count.
        patcher = patch.object(engine, "BOOTSTRAP_RESAMPLES", 24)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.report = synthetic_report()

    def write(self, report: dict[str, object]) -> Path:
        path = Path(self.directory.name) / "report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def unmet(self, report: dict[str, object]) -> list[str]:
        return engine.inspect_full_report(engine.ROOT, self.write(report))["unmet"]

    def test_a_complete_uncontended_report_returns_the_release_gate_shape(self) -> None:
        validated = engine.validate_qualified_full_report(engine.ROOT, self.write(self.report))
        roster = engine.critical_rows(engine.load_manifest())
        metrics = validated["metrics"]
        self.assertEqual(set(validated), {"identity", "metrics", "critical_rows"})
        self.assertEqual(validated["critical_rows"], roster)
        self.assertEqual(sorted(metrics["throughput"]["critical_lower_95"]), roster)
        self.assertEqual(sorted(metrics["tail_latency"]["critical_p99_upper_95"]), roster)
        self.assertEqual(sorted(metrics["memory"]["critical_peak_upper"]), roster)
        self.assertLess(abs(metrics["throughput"]["suite_geometric_mean_lower_95"] - 1.0), 0.2)
        self.assertIsNotNone(metrics["memory"]["geometric_mean_peak_upper"]["rss"])
        self.assertLess(abs(metrics["memory"]["geometric_mean_peak_upper"]["pss"] - 1.0), 0.1)
        self.assertLess(abs(metrics["memory"]["critical_peak_upper"][roster[0]]["pss"] - 1.0), 0.1)
        self.assertEqual(set(validated["identity"]), {"source", "configuration", "host"})

    def test_a_slower_rust_lane_lowers_every_throughput_bound(self) -> None:
        metrics = engine.validate_qualified_full_report(engine.ROOT, self.write(synthetic_report(2.0)))["metrics"]
        self.assertLess(metrics["throughput"]["suite_geometric_mean_lower_95"], 0.6)
        self.assertTrue(all(bound < 0.6 for bound in metrics["throughput"]["critical_lower_95"].values()))
        self.assertTrue(all(bound > 1.5 for bound in metrics["tail_latency"]["critical_p99_upper_95"].values()))

    def test_a_report_without_the_peak_hook_is_named_from_its_evidence(self) -> None:
        report = synthetic_report(peak_hook=False)
        self.assertEqual(self.unmet(report), [engine.PEAK_HOOK_GAP])
        with self.assertRaisesRegex(engine.HarnessError, "no-peak-hook"):
            engine.validate_qualified_full_report(engine.ROOT, self.write(report))
        inspected = engine.inspect_full_report(engine.ROOT, self.write(report))
        self.assertEqual(inspected["coverage"]["alloc_free_64"], ["peak_pss"])
        self.assertIsNone(inspected["metrics"]["memory"]["critical_peak_upper"]["alloc_free_64"]["pss"])
        self.assertEqual(engine.inspect_full_report(engine.ROOT, self.write(self.report))["coverage"], {})

    def test_a_sample_missing_its_peak_state_is_named(self) -> None:
        report = copy.deepcopy(self.report)
        del report["rows"]["churn_8k"]["lanes"]["rust_engine"]["samples"][3]["peak_state"]
        self.assert_named(report, "timed row churn_8k samples lack peak_pss")

    def assert_named(self, report: dict[str, object], expected: str) -> None:
        unmet = self.unmet(report)
        self.assertTrue(any(expected in item for item in unmet), unmet)

    def test_rejects_a_smoke_or_architecture_report(self) -> None:
        report = copy.deepcopy(self.report)
        report["mode"], report["row_set"] = "smoke", "architecture"
        self.assert_named(report, "not --full --set matrix")

    def test_rejects_failed_absent_and_unavailable_rows(self) -> None:
        report = copy.deepcopy(self.report)
        report["status"], report["failed_rows"] = "failed-rows", ["alloc_free_4194304"]
        report["rows"]["alloc_free_4194304"] = {"status": "failed", "reason": "fixture failed: signal 6"}
        del report["rows"]["churn_8k"]
        report["memory_rows"]["memory_churn_8k"] = {"status": "unavailable", "reason": "needs 1 CPU"}
        unmet = self.unmet(report)
        for expected in ("failed rows ['alloc_free_4194304']", "alloc_free_4194304 is failed: fixture failed",
                         "timed row churn_8k is absent", "memory row memory_churn_8k is unavailable"):
            self.assertTrue(any(expected in item for item in unmet), (expected, unmet))

    def test_rejects_a_tampered_raw_sample(self) -> None:
        report = copy.deepcopy(self.report)
        # Every raw Rust sample is edited but the stored comparison is kept.
        for sample in report["rows"]["alloc_free_64"]["lanes"]["rust_engine"]["samples"]:
            for batch in sample["batches"]:
                batch["ns"] *= 3
        self.assert_named(report, "alloc_free_64 comparison differs from a recomputation")

    def test_rejects_a_short_sample_schedule(self) -> None:
        report = copy.deepcopy(self.report)
        report["rows"]["alloc_free_64"]["lanes"]["pinned_c"]["samples"].pop()
        self.assert_named(report, "lacks the full mode's")

    def test_rejects_a_stale_source_seal_and_a_dirty_tree(self) -> None:
        report = copy.deepcopy(self.report)
        report["provenance"]["inputs"]["fixture"]["sha256"] = "0" * 64
        report["provenance"]["inputs"]["engine_sources"]["sha256"] = "1" * 64
        report["provenance"]["git"] = {"clean": False, "dirty_paths": [" M crabc-mimalloc/src/lib.rs"]}
        unmet = self.unmet(report)
        for expected in ("source seal: fixture differs", "source seal: engine_sources differs", "clean Git tree"):
            self.assertTrue(any(expected in item for item in unmet), (expected, unmet))

    def test_rejects_a_contended_host_with_its_raw_reasons(self) -> None:
        report = copy.deepcopy(self.report)
        evidence = idle_host(list(range(8)))
        evidence["windows"][0] = idle_window("start", list(range(8)), load1=37.3)
        evidence["windows"][1] = idle_window("row:x", list(range(8)), busy_ticks=60)
        report["uncontended_host"] = engine.uncontended_host_record(evidence)
        unmet = self.unmet(report)
        self.assertEqual(report["uncontended_host"]["status"], "contended")
        for expected in ("start 1-minute load average 37.3 > 1.0", "window row:x: host busy fraction 0.6",
                         "window row:x: measurement CPU 0 busy fraction 0.6"):
            self.assertTrue(any(expected in item for item in unmet), (expected, unmet))

    def test_rejects_a_host_status_its_raw_evidence_does_not_support(self) -> None:
        report = copy.deepcopy(self.report)
        report["uncontended_host"]["evidence"]["windows"][0]["loadavg"][0] = "12.0 1.0 1.0 1/10 1"
        self.assert_named(report, "differs from a reclassification")

    def test_rejects_malformed_json_and_a_foreign_reading_root(self) -> None:
        path = Path(self.directory.name) / "broken.json"
        path.write_text("{", encoding="utf-8")
        self.assertIn("unreadable JSON", engine.inspect_full_report(engine.ROOT, path)["unmet"][0])
        with self.assertRaisesRegex(engine.HarnessError, "checkout that owns this reader"):
            engine.validate_qualified_full_report(Path(self.directory.name), path)


class HostClassificationTests(unittest.TestCase):
    def test_an_idle_host_is_uncontended(self) -> None:
        self.assertEqual(engine.classify_host(idle_host([0, 1])), [])
        self.assertEqual(engine.uncontended_host_record(idle_host([0]))["status"], "uncontended")

    def test_names_governor_quota_throttling_and_competing_processes(self) -> None:
        evidence = idle_host([0, 1])
        evidence["frequency_end"]["cpus"]["1"]["scaling_governor"] = "powersave"
        evidence["cgroup_start"]["cpu_max"] = "400000 100000"
        evidence["cgroup_end"]["cpu_stat"]["nr_throttled"] = 3
        evidence["windows"][1]["active_processes"] = {"42": {"comm": "cc1", "ticks_before": 0, "ticks_after": 50}}
        reasons = engine.classify_host(evidence)
        for expected in ("do not share one governor across the run: ['performance', 'powersave']",
                         "CPU quota '400000 100000'",
                         "CPU-throttled 3 time(s)", "process 42 (cc1) used 0.500 CPU"):
            self.assertTrue(any(expected in item for item in reasons), (expected, reasons))

    def test_one_shared_powersave_governor_is_uncontended(self) -> None:
        evidence = idle_host([0, 1])
        for key in ("frequency_start", "frequency_end"):
            for values in evidence[key]["cpus"].values():
                values["scaling_governor"] = "powersave"
        self.assertEqual(engine.classify_host(evidence), [])

    def test_an_unexposed_cpufreq_interface_is_not_disqualifying(self) -> None:
        evidence = idle_host([0])
        evidence["frequency_start"]["cpus"]["0"] = {}
        evidence["frequency_end"]["cpus"]["0"] = {}
        self.assertEqual(engine.classify_host(evidence), [])

    def test_missing_edge_windows_or_other_thresholds_are_named(self) -> None:
        evidence = idle_host([0])
        evidence["windows"] = evidence["windows"][:1]
        self.assertIn("start and end", engine.classify_host(evidence)[0])
        evidence = idle_host([0])
        evidence["thresholds"]["host_busy_max"] = 0.5
        self.assertIn("other thresholds", engine.classify_host(evidence)[0])

    def test_a_live_window_reads_this_host(self) -> None:
        window = engine.contention_window("probe", 0.05)
        self.assertEqual(window["label"], "probe")
        self.assertIn("all", window["stat_after"]["cpus"])


class ExitTraceTests(unittest.TestCase):
    def test_the_exit_stop_reads_the_exec_image_peak(self) -> None:
        binary = Path("/bin/true")
        if not binary.exists():
            self.skipTest("/bin/true is absent")
        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / "out", Path(directory) / "err"
            cpu = sorted(os.sched_getaffinity(0))[0]
            try:
                pid = engine.spawn(binary, [], cpus=[cpu], stdout_path=out, stderr_path=err, trace_exit=True)
                process, _ = engine.finish_process(pid, 0, 30.0, out, err, traced=True)
            except engine.HarnessError as error:
                if "Operation not permitted" in str(error):
                    self.skipTest(f"ptrace is not permitted here: {error}")
                raise
        self.assertEqual(process["status"], {"code": 0, "kind": "exit"})
        self.assertGreater(process["exit_memory"]["status"]["vm_hwm_kib"], 0)
        self.assertIn("pss_kib", process["exit_memory"]["smaps_rollup"])


class PeakHookABTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch.object(engine, "BOOTSTRAP_RESAMPLES", 24)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_plan_pairs_every_sample_index_adjacently(self) -> None:
        plan = engine.peak_hook_plan(7, seed=3)
        self.assertEqual(len(plan), 14)
        for first, second in zip(plan[::2], plan[1::2]):
            self.assertEqual(first[1], second[1])
            self.assertEqual({first[0], second[0]}, set(engine.PEAK_HOOK_VARIANTS))

    def comparison(self, hook_factor: int) -> dict:
        hook = [timed_sample([10 * hook_factor + (index + batch) % 3 for batch in range(16)]) for index in range(9)]
        no_hook = [timed_sample([10 + (index + batch) % 3 for batch in range(16)], peak_pss_kib=None) for index in range(9)]
        return engine.peak_hook_comparison(hook, no_hook, seed=5)

    def test_identical_samples_are_consistent_with_no_effect(self) -> None:
        comparison = self.comparison(1)
        self.assertEqual(comparison["cost"]["ratio_hook_over_no_hook"]["median"], 1.0)
        self.assertEqual(len(comparison["cost"]["hook_samples"]), 9)
        summary = engine.peak_hook_summary({"r": {"lanes": {lane: {"comparison": comparison} for lane in engine.LANES}}})
        self.assertEqual(summary["rows_whose_90_percent_interval_excludes_1"],
                         {lane: {"cost": [], "batch_p99": []} for lane in engine.LANES})
        self.assertAlmostEqual(summary["median_ratio_geometric_mean"]["pinned_c"]["cost"], 1.0)

    def test_a_perturbed_variant_is_named(self) -> None:
        summary = engine.peak_hook_summary({"r": {"lanes": {"rust_engine": {"comparison": self.comparison(2)}}}})
        self.assertEqual(summary["rows_whose_90_percent_interval_excludes_1"]["rust_engine"]["cost"], ["r"])


STUB_BACKEND = """
#include <malloc.h>
#include <stdlib.h>
#include "engine-api.h"
int crabc_allocator_engine_process_init(void) { return 0; }
int crabc_allocator_engine_thread_init(void) { return 0; }
int crabc_allocator_engine_thread_done(void) { return 0; }
void *crabc_allocator_engine_malloc(size_t size) { return malloc(size); }
void crabc_allocator_engine_free(void *block) { free(block); }
void *crabc_allocator_engine_calloc(size_t count, size_t size) { return calloc(count, size); }
void *crabc_allocator_engine_realloc(void *block, size_t size) { return realloc(block, size); }
void *crabc_allocator_engine_aligned(size_t alignment, size_t size) { return aligned_alloc(alignment, size); }
size_t crabc_allocator_engine_usable_size(const void *block) { return malloc_usable_size((void *)block); }
"""


HEAP_STUB = """
#include <stdlib.h>
#include "engine-api.h"
struct node { struct node *next; };
struct crabc_allocator_engine_heap { struct node *blocks; };
struct crabc_allocator_engine_subproc { int members; };
crabc_allocator_engine_heap *crabc_allocator_engine_heap_new(void) { return calloc(1, sizeof(crabc_allocator_engine_heap)); }
void *crabc_allocator_engine_heap_malloc(crabc_allocator_engine_heap *heap, size_t size) {
  struct node *block = malloc(sizeof(struct node) + size);  /* link header, then the client bytes */
  if (block == NULL) return NULL;
  block->next = heap->blocks; heap->blocks = block; return block + 1;
}
void crabc_allocator_engine_heap_destroy(crabc_allocator_engine_heap *heap) {
  while (heap->blocks != NULL) { struct node *next = heap->blocks->next; free(heap->blocks); heap->blocks = next; }
  free(heap);
}
crabc_allocator_engine_subproc *crabc_allocator_engine_subproc_new(void) { return calloc(1, sizeof(crabc_allocator_engine_subproc)); }
int crabc_allocator_engine_subproc_add_current_thread(crabc_allocator_engine_subproc *subproc) { subproc->members++; return 0; }
void crabc_allocator_engine_subproc_destroy(crabc_allocator_engine_subproc *subproc) { free(subproc); }
"""


class FixturePeakHookTests(unittest.TestCase):
    """The real fixture's READY_PEAK pause, linked with a libc-malloc stub backend."""

    @classmethod
    def setUpClass(cls) -> None:
        compiler = next((name for name in ("musl-gcc", "cc", "gcc") if engine.shutil.which(name)), None)
        if compiler is None:
            raise unittest.SkipTest("no C compiler")
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        (root / "stub.c").write_text(STUB_BACKEND, encoding="utf-8")
        (root / "heap-stub.c").write_text(HEAP_STUB, encoding="utf-8")
        cls.binary = root / "fixture"
        cls.heap_binary = root / "heap-fixture"
        for binary, extra in ((cls.binary, []), (cls.heap_binary, [str(root / "heap-stub.c")])):
            completed = engine.subprocess.run(
                [compiler, "-std=gnu11", "-O2", "-pthread", "-I", str(engine.FIXTURE_ROOT), str(engine.FIXTURE),
                 str(root / "stub.c"), *extra, "-o", str(binary)], capture_output=True, text=True)
            if completed.returncode != 0:
                raise AssertionError(completed.stderr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def test_destruction_rows_run_with_heap_entries_and_are_unavailable_without(self) -> None:
        for workload in ("heap_destroy", "subproc_destroy"):
            row = {"workload": workload, "params": {"size": 64, "count": 2, "live": 16, "batches": 3}}
            with self.subTest(workload=workload):
                sample = self.run_row(row, peak_hook=True, binary=self.heap_binary)
                self.assertEqual([batch["ops"] for batch in sample["batches"]], [32, 32, 32])
                self.assertIn("peak_state", sample)
                with self.assertRaisesRegex(engine.HarnessError, "backend lacks the heap"):
                    self.run_row(row, peak_hook=False)

    def run_row(self, row: dict, *, peak_hook: bool, binary: Path | None = None) -> dict:
        cpus = sorted(os.sched_getaffinity(0))[: engine.row_thread_count(row)]
        if len(cpus) < engine.row_thread_count(row):
            self.skipTest("too few CPUs")
        with tempfile.TemporaryDirectory() as scratch:
            try:
                return engine.run_timed_sample(binary or self.binary, row, batch_divisor=1, cpus=cpus, timeout=60.0,
                                               scratch=Path(scratch), sample_name="s", peak_hook=peak_hook)
            except engine.HarnessError as error:
                if "Operation not permitted" in str(error):
                    self.skipTest(f"ptrace is not permitted here: {error}")
                raise

    def test_every_timed_driver_pauses_once_at_its_peak_state(self) -> None:
        rows = [
            {"workload": "alloc_batch", "params": {"size": 4096, "count": 256, "iterations": 2, "batches": 2}},
            {"workload": "realloc_grow", "params": {"size": 16, "max_size": 1 << 20, "iterations": 2, "batches": 2}},
            {"workload": "local_scaling", "params": {"size": 64, "workers": 2, "iterations": 100, "batches": 2}},
            {"workload": "churn_scaling", "params": {"live": 256, "max_size": 8192, "iterations": 100,
                                                     "batches": 2, "workers": 2, "seed": 3}},
            {"workload": "remote_free", "params": {"size": 4096, "workers": 1, "iterations": 100, "batches": 2}},
            {"workload": "thread_churn", "params": {"size": 4096, "count": 64, "workers": 2, "batches": 2}},
            {"workload": "usable_size", "params": {"size": 64, "count": 64, "iterations": 2, "batches": 2}},
        ]
        for row in rows:
            with self.subTest(workload=row["workload"]):
                sample = self.run_row(row, peak_hook=True)
                self.assertEqual(len(sample["batches"]), 2)
                self.assertGreater(sample["peak_state"]["smaps_rollup"]["pss_kib"], 0)
                self.assertGreater(sample["process"]["exit_memory"]["status"]["vm_hwm_kib"], 0)
                self.assertNotIn("peak_state", self.run_row(row, peak_hook=False))

    def test_the_ab_run_interleaves_hook_and_no_hook_processes(self) -> None:
        row = {"name": "alloc_batch_small", "workload": "alloc_batch",
               "params": {"size": 64, "count": 64, "iterations": 2, "batches": 2}}
        with tempfile.TemporaryDirectory() as scratch, patch.object(engine, "BOOTSTRAP_RESAMPLES", 8):
            try:
                rows = engine.measure_peak_hook_ab(
                    [row], {lane: self.binary for lane in engine.LANES},
                    mode={"samples": 3, "warmup_processes": 0, "batch_divisor": 1},
                    cpu_pool=None, timeout=60.0, scratch=Path(scratch), seed=9)
            except engine.HarnessError as error:
                if "Operation not permitted" in str(error):
                    self.skipTest(f"ptrace is not permitted here: {error}")
                raise
        lane = rows["alloc_batch_small"]["lanes"]["rust_engine"]
        self.assertEqual(lane["status"], "measured")
        self.assertTrue(all("peak_state" in sample for sample in lane["samples"]["hook"]))
        self.assertTrue(all("peak_state" not in sample for sample in lane["samples"]["no_hook"]))
        self.assertEqual(len(lane["sample_plan"]), 6)

    def test_the_peak_state_holds_the_batch_live_set(self) -> None:
        # The fixture touches each block's first and last byte: two resident
        # pages per 64 KiB block, so 240 more live blocks add about 1.9 MiB.
        def resident(count: int) -> int:
            row = {"workload": "alloc_batch", "params": {"size": 65536, "count": count, "iterations": 1, "batches": 1}}
            return self.run_row(row, peak_hook=True)["peak_state"]["smaps_rollup"]["rss_kib"]

        self.assertGreater(resident(256) - resident(16), 240 * 8 * 9 // 10)


if __name__ == "__main__":
    unittest.main()
