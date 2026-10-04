#!/usr/bin/env python3
"""Reader contracts for the integrated-product allocator comparison.

Synthetic reports exercise the reader; the source seal's git view is
replaced where a test is not about it.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
sys.path.insert(0, str(ROOT / "compat/allocator/tests"))
import perf_integrated_x86_64 as integrated  # noqa: E402
from test_perf_engine_x86_64 import idle_host, timed_sample  # noqa: E402

engine = integrated.engine
PIN = engine.shared.load_pin()
# The real seal comparison, before any test replaces it.
SEAL = integrated.source_seal_unmet


def synthetic_integrated(mi_malloc_version: int = 30500, backend: str = "pinned-c-evidence") -> dict:
    manifest = integrated.load_manifest()
    samples = engine.load_manifest()["modes"]["full"]["samples"]
    rows = {row["name"]: row for row in integrated.engine_rows(manifest)}
    report = {
        "schema": integrated.SCHEMA, "kind": integrated.KIND, "mode": "full", "status": "ok", "failed_rows": [],
        "products_reused": False,
        "native_execution_provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
        "provenance": {"seal": {"objects": {}, "dirty_paths": []}},
        "c_reference": {"backend": backend, "mi_malloc_version": mi_malloc_version,
                        "upstream": {"version": PIN["version"], "revision": PIN["revision"],
                                     "archive_sha256": PIN["sha256"]}},
        "rows": {},
        "uncontended_host": engine.uncontended_host_record(idle_host([0, 1, 2, 3])),
    }
    for index, name in enumerate(integrated.row_names(manifest)):
        base = name.split("/", 1)[1]
        lanes = {lane: [timed_sample([10 + (sample + batch) % 3 for batch in range(4)], peak_rss_kib=900 + sample)
                        for sample in range(samples)] for lane in engine.LANES}
        entry = {"status": "measured", "seed": 31 + index, "lanes": {lane: {"samples": s} for lane, s in lanes.items()},
                 "comparison": engine.throughput_comparison(lanes["pinned_c"], lanes["rust_engine"], seed=31 + index)}
        if base in rows:
            entry.update(workload=rows[base]["workload"], params=rows[base]["params"])
        report["rows"][name] = entry
    return report


class IntegratedBuildTests(unittest.TestCase):
    def test_failed_fixture_output_survives_run_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            work = Path(directory)
            arguments = argparse.Namespace(full=False, label="retained-failure", reuse_products=False,
                                           cpus="0", timeout=1)
            outputs = []

            def failed_measurement(rows, binaries, *, scratch, **kwargs):
                name = rows[0]["name"]
                stdout = scratch / f"{name}.stdout"
                stderr = scratch / f"{name}.stderr"
                stdout.write_text("batch_cpu_ns=0\n", encoding="utf-8")
                stderr.write_text("fixture diagnostic\n", encoding="utf-8")
                outputs.append((stdout, stderr))
                return {name: {"status": "failed", "reason": "nonpositive batch CPU time"}}

            with ExitStack() as mocks:
                mocks.enter_context(patch.object(integrated, "WORK_ROOT", work))
                mocks.enter_context(patch.object(integrated, "REPORT_ROOT", work / "reports"))
                mocks.enter_context(patch.object(integrated, "source_seal", return_value={}))
                mocks.enter_context(patch.object(integrated, "c_reference", return_value={}))
                mocks.enter_context(patch.object(integrated, "build_products", return_value={}))
                mocks.enter_context(patch.object(integrated, "build_programs", return_value={
                    "records": {}, "binaries": {"static": {}, "dynamic": {}}, "launcher": work / "launcher"}))
                mocks.enter_context(patch.object(engine.shared, "require_native_x86_64", return_value={}))
                for name in ("git_provenance", "host_provenance", "tool_versions", "file_record"):
                    mocks.enter_context(patch.object(engine, name, return_value={}))
                mocks.enter_context(patch.object(engine, "choose_cpus", return_value=[0]))
                mocks.enter_context(patch.object(engine, "host_record_start", return_value={"windows": []}))
                mocks.enter_context(patch.object(engine, "contention_window", return_value={}))
                mocks.enter_context(patch.object(engine, "host_record_finish", return_value={}))
                mocks.enter_context(patch.object(engine, "uncontended_host_record", return_value={}))
                mocks.enter_context(patch.object(engine, "measure_rows", side_effect=failed_measurement))
                mocks.enter_context(patch.object(integrated, "measure_startup", return_value={"status": "measured"}))
                mocks.enter_context(patch.object(integrated, "integrated_unmet", return_value=["fixture failed"]))
                with self.assertRaisesRegex(integrated.HarnessError, "rows failed"):
                    integrated.run(arguments)
            report = json.loads((work / "reports/retained-failure.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "failed-rows")
            self.assertEqual(len(report["failed_rows"]), 2)
            self.assertEqual(len(outputs), 2)
            for stdout, stderr in outputs:
                self.assertEqual(stdout.read_text(encoding="utf-8"), "batch_cpu_ns=0\n")
                self.assertEqual(stderr.read_text(encoding="utf-8"), "fixture diagnostic\n")

    def test_full_preparation_settles_before_host_measurement(self) -> None:
        for full, load, expected in (
                (True, 1.13, ["products", "programs", "load", "sleep", "start"]),
                (True, engine.UNCONTENDED_START_LOAD1_MAX, ["products", "programs", "load", "start"]),
                (True, 0.1, ["products", "programs", "load", "start"]),
                (False, 1.13, ["products", "programs", "start"])):
            with self.subTest(full=full, load=load), tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
                events = []
                work = Path(directory)
                products = {kind: {lane: work / kind / lane for lane in engine.LANES}
                            for kind in ("static", "dynamic")}
                arguments = argparse.Namespace(full=full, label="settle-test", reuse_products=False,
                                               cpus="0,1,2,3", timeout=1)

                def prepared_products(*args, **kwargs):
                    events.append("products")
                    return products

                def prepared_programs(*args, **kwargs):
                    events.append("programs")
                    return {"records": {}}

                def current_load():
                    events.append("load")
                    return (load, 0.1, 0.1)

                def pause(seconds):
                    self.assertEqual(seconds, 60)
                    events.append("sleep")

                def start(cpus):
                    events.append("start")
                    raise RuntimeError("stop before workload execution")

                with ExitStack() as mocks:
                    mocks.enter_context(patch.object(integrated, "WORK_ROOT", work))
                    mocks.enter_context(patch.object(integrated, "source_seal", return_value={}))
                    mocks.enter_context(patch.object(integrated, "c_reference", return_value={}))
                    mocks.enter_context(patch.object(integrated, "build_products", side_effect=prepared_products))
                    mocks.enter_context(patch.object(integrated, "build_programs", side_effect=prepared_programs))
                    mocks.enter_context(patch.object(engine.shared, "require_native_x86_64", return_value={}))
                    for name in ("git_provenance", "host_provenance", "tool_versions", "file_record"):
                        mocks.enter_context(patch.object(engine, name, return_value={}))
                    mocks.enter_context(patch.object(engine, "choose_cpus", return_value=[0, 1, 2, 3]))
                    mocks.enter_context(patch.object(integrated.os, "getloadavg", side_effect=current_load))
                    mocks.enter_context(patch("time.sleep", side_effect=pause))
                    mocks.enter_context(patch.object(engine, "host_record_start", side_effect=start))
                    with self.assertRaisesRegex(RuntimeError, "stop before workload execution"):
                        integrated.run(arguments)
                self.assertEqual(events, expected)

    def test_selected_oracle_probe_preserves_the_engine_default_and_version_key(self) -> None:
        compiler = "/usr/local/bin/crabc-x86_64-musl-gcc"
        with patch.object(engine, "command_record", return_value={"status": 0, "stdout": "version"}) as command:
            versions = engine.tool_versions(musl_compiler=compiler)
            self.assertIn(((compiler, "--version"),), [call.args for call in command.call_args_list])
            self.assertEqual(versions["musl-gcc"], "version")
            command.reset_mock()
            engine.tool_versions()
            self.assertIn((("musl-gcc", "--version"),), [call.args for call in command.call_args_list])

    def test_startup_launcher_uses_the_core_oracle_without_an_alias(self) -> None:
        manifest = integrated.load_manifest()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            work = Path(directory)
            products = {kind: {} for kind in manifest["products"]}
            for kind in products:
                for lane in engine.LANES:
                    products[kind][lane] = work / f"product-{kind}-{lane}"
                    products[kind][lane].mkdir()

            def compile_output(command, log, *, cwd=ROOT):
                Path(command[-1]).write_bytes(b"same compiled input")

            with patch.object(integrated, "run_logged", side_effect=compile_output) as compile:
                integrated.build_programs(manifest, products, work)
            command = compile.call_args.args[0]
            self.assertEqual(command[0], "/usr/local/bin/crabc-x86_64-musl-gcc")
            self.assertIn("-static", command)
            self.assertIn("-no-pie", command)


class IntegratedReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        for target, value in ((engine, "BOOTSTRAP_RESAMPLES"), (integrated, "source_seal_unmet")):
            patcher = patch.object(target, value, 16 if value == "BOOTSTRAP_RESAMPLES" else (lambda recorded: []))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.report = synthetic_integrated()

    def test_a_complete_report_over_the_pinned_reference_qualifies(self) -> None:
        self.assertEqual(integrated.integrated_unmet(self.report), [])

    def test_the_c_reference_must_be_the_pinned_evidence_product(self) -> None:
        for report in (synthetic_integrated(30302), synthetic_integrated(backend="accepted-c")):
            unmet = integrated.integrated_unmet(report)
            self.assertEqual(len(unmet), 1, unmet)
            self.assertIn("not the pinned-c-evidence product over exact v3.5.0 (30500)", unmet[0])

    def test_covers_both_link_modes_and_the_startup_row(self) -> None:
        names = integrated.row_names(integrated.load_manifest())
        self.assertIn("static/startup_first_alloc", names)
        self.assertIn("dynamic/alloc_free_64", names)
        metrics = integrated.integrated_metrics(self.report)
        self.assertEqual(set(metrics), set(names))
        self.assertEqual(set(metrics["dynamic/startup_first_alloc"]),
                         {"throughput_lower_95", "p99_upper_95", "peak_rss_upper_95", "peak_pss_upper_95"})

    def test_names_missing_tampered_pss_less_and_reused_rows(self) -> None:
        report = copy.deepcopy(synthetic_integrated())
        del report["rows"]["static/churn_8k"]
        for sample in report["rows"]["dynamic/alloc_free_64"]["lanes"]["rust_engine"]["samples"]:
            for batch in sample["batches"]:
                batch["ns"] *= 2
        del report["rows"]["static/startup_first_alloc"]["lanes"]["pinned_c"]["samples"][0]["peak_state"]
        report["products_reused"] = True
        unmet = integrated.integrated_unmet(report)
        for expected in ("row static/churn_8k is absent", "dynamic/alloc_free_64 comparison differs",
                         "static/startup_first_alloc samples lack peak-state PSS", "did not build"):
            self.assertTrue(any(expected in item for item in unmet), (expected, unmet))

    def test_a_contended_host_is_named(self) -> None:
        report = synthetic_integrated()
        evidence = idle_host([0])
        evidence["frequency_start"]["cpus"]["0"]["scaling_governor"] = "powersave"
        report["uncontended_host"] = engine.uncontended_host_record(evidence)
        self.assertTrue(any("do not share one governor" in item for item in integrated.integrated_unmet(report)))

    def test_the_source_seal_compares_git_objects_and_dirt(self) -> None:
        current = {"objects": {"libc": "1", "crabc-mimalloc": "2"}, "dirty_paths": []}
        with patch.object(integrated, "source_seal", lambda: current):
            unmet = SEAL({"objects": {"libc": "1", "crabc-mimalloc": "3"}, "dirty_paths": [" M libc/src/lib.rs"]})
        self.assertEqual(unmet, ["measured sources were dirty: [' M libc/src/lib.rs']",
                                 "source seal: crabc-mimalloc differs from this checkout"])

    def test_the_inspector_reports_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "r.json"
            path.write_text("[", encoding="utf-8")
            self.assertIn("unreadable", integrated.inspect_integrated_report(integrated.ROOT, path)["unmet"][0])
            path.write_text(json.dumps(self.report), encoding="utf-8")
            self.assertEqual(set(integrated.validate_integrated_report(integrated.ROOT, path)), {"metrics"})
            path.write_text(json.dumps(synthetic_integrated(30302)), encoding="utf-8")
            with self.assertRaisesRegex(engine.HarnessError, "not a qualified integrated report"):
                integrated.validate_integrated_report(integrated.ROOT, path)


if __name__ == "__main__":
    unittest.main()
