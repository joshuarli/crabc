#!/usr/bin/env python3
"""Reader contracts for the integrated-product allocator comparison.

Synthetic reports exercise the reader; the source seal's git view is
replaced where a test is not about it.
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
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
        self.assertTrue(any("governor powersave" in item for item in integrated.integrated_unmet(report)))

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
