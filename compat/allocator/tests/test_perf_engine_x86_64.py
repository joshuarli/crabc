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
import unittest
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "perf_engine_x86_64.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_perf_engine_x86_64_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
engine = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = engine
SPEC.loader.exec_module(engine)


def timed_sample(costs: list[int], cpu_share: float = 1.0) -> dict[str, object]:
    return {"batches": [{"ns": cost * 100, "cpu_ns": round(cost * 100 * cpu_share), "ops": 100} for cost in costs]}


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

        comparison = engine.memory_comparison([sample(100)], [sample(150)])
        self.assertAlmostEqual(comparison["peak_rss_kib"]["ratio_rust_over_c"], 1.5)
        self.assertIsNone(engine.memory_comparison([sample(0)], [sample(1)])["live_pss_kib"]["ratio_rust_over_c"])


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


if __name__ == "__main__":
    unittest.main()
