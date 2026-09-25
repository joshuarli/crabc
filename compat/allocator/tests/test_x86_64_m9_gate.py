#!/usr/bin/env python3
"""Contracts for the read-only native x86-64 Milestone 9 allocator gate.

The gate's report agreement, codegen, and correctness logic runs over fake
reader results and retained-report files; the qualified-report reader itself
is exercised by the imported ``QualifiedReportTests`` and
``HostClassificationTests`` over complete synthetic raw reports.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
sys.path.insert(0, str(ROOT / "compat/allocator/tests"))
SPEC = importlib.util.spec_from_file_location("x86_64_m9_gate", ROOT / "compat/allocator/x86_64_m9_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
engine = gate.engine

from test_perf_engine_x86_64 import (  # noqa: E402,F401
    FixturePeakHookTests, HostClassificationTests, PeakHookABTests, QualifiedReportTests)


ROSTER = ["alloc_free_64", "remote_free_1"]


def accepted(identity: dict | None = None, roster: list[str] | None = None) -> dict:
    roster = ROSTER if roster is None else roster
    return {
        "unmet": [],
        "identity": identity or {"source": {"fixture": "a"}, "configuration": {"mode": "full"}, "host": {"cpu": "x"}},
        "critical_rows": roster,
        "metrics": {
            "throughput": {"suite_geometric_mean_lower_95": 1.0, "critical_lower_95": {name: 1.0 for name in roster}},
            "tail_latency": {"critical_p99_upper_95": {name: 1.0 for name in roster}},
            "memory": {"geometric_mean_peak_upper": {"rss": 1.0, "pss": 1.0},
                       "critical_peak_upper": {name: {"rss": 1.0, "pss": 1.0} for name in roster}},
        },
    }


class GateFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.results: dict[str, dict] = {}

    def report_file(self, name: str, result: dict) -> Path:
        path = self.root / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        self.results[str(path)] = result
        return path

    def inspect(self, root: Path, path: Path) -> dict:
        self.assertEqual(root, gate.harness.ROOT)
        result = self.results[str(path)]
        if isinstance(result, Exception):
            raise result
        return copy.deepcopy(result)

    def condition(self, result: dict, identifier: str) -> dict:
        return next(row for row in result["conditions"] if row["id"] == identifier)


class AgreementTests(GateFixture):
    def evaluate(self, paths: list[Path]) -> dict:
        return gate.evaluate(paths, None, inspect=self.inspect, gate_root=self.root / "gates")

    def test_three_agreeing_accepted_reports_meet_reports_and_agreement(self) -> None:
        paths = [self.report_file(f"r{index}", accepted()) for index in range(3)]
        result = self.evaluate(paths)
        self.assertTrue(self.condition(result, "m9.qualified-reports")["met"])
        self.assertTrue(self.condition(result, "m9.agreement")["met"])
        self.assertEqual(result["overall_status"], "unmet")
        self.assertEqual([row["id"] for row in result["conditions"]], list(gate.CONDITION_IDS))

    def test_fewer_than_three_accepted_reports_are_named_with_each_refusal(self) -> None:
        paths = [
            self.report_file("good", accepted()),
            self.report_file("contended", {"unmet": ["host is not uncontended: start 1-minute load average 37.3 > 1.0"],
                                           "identity": None, "metrics": None}),
            self.report_file("raises", engine.HarnessError("report is malformed")),
        ]
        detail = self.condition(self.evaluate(paths), "m9.qualified-reports")["detail"]
        self.assertIn("1 qualified full report(s) of 3 read; M9 requires at least 3", detail[0])
        self.assertTrue(any("contended.json: host is not uncontended" in item for item in detail), detail)
        self.assertTrue(any("raises.json: HarnessError: report is malformed" in item for item in detail), detail)
        agreement = self.condition(self.evaluate(paths), "m9.agreement")["detail"]
        self.assertIn("agreement needs 3 qualified reports; 1 accepted", agreement)

    def test_each_differing_identity_part_is_named(self) -> None:
        base = accepted()
        other_host = copy.deepcopy(base)
        other_host["identity"]["host"] = {"cpu": "y"}
        other_source = copy.deepcopy(base)
        other_source["identity"]["source"] = {"fixture": "b"}
        paths = [self.report_file("a", base), self.report_file("b", other_host), self.report_file("c", other_source)]
        detail = self.condition(self.evaluate(paths), "m9.agreement")["detail"]
        self.assertTrue(any("b.json host identity differs" in item for item in detail), detail)
        self.assertTrue(any("c.json source identity differs" in item for item in detail), detail)
        self.assertFalse(any("configuration" in item for item in detail), detail)

    def test_a_differing_or_uncovered_critical_roster_is_named(self) -> None:
        narrow = accepted(roster=["alloc_free_64"])
        uncovered = accepted()
        del uncovered["metrics"]["tail_latency"]["critical_p99_upper_95"]["remote_free_1"]
        paths = [self.report_file("a", accepted()), self.report_file("b", narrow), self.report_file("c", uncovered)]
        detail = self.condition(self.evaluate(paths), "m9.agreement")["detail"]
        self.assertTrue(any("b.json critical roster differs" in item for item in detail), detail)
        self.assertTrue(any("c.json metrics do not cover exactly its critical roster" in item for item in detail), detail)

    def test_declared_missing_conditions_stay_named(self) -> None:
        result = self.evaluate([])
        for identifier in ("m9.source-convergence", "m9.integrated-products"):
            self.assertFalse(self.condition(result, identifier)["met"])
            self.assertTrue(self.condition(result, identifier)["detail"])

    def test_the_matrix_condition_comes_from_report_coverage(self) -> None:
        self.assertIn("no full report carries", self.condition(self.evaluate([]), "m9.matrix")["detail"][0])
        partial = accepted()
        partial["coverage"] = {"alloc_free_64": ["peak_pss"]}
        detail = self.condition(self.evaluate([self.report_file("p", partial)]), "m9.matrix")["detail"]
        self.assertTrue(any("p.json: alloc_free_64 lacks peak_pss" in item for item in detail), detail)
        complete = accepted()
        complete["coverage"] = {}
        self.assertTrue(self.condition(self.evaluate([self.report_file("c", complete)]), "m9.matrix")["met"])

    def test_discovery_reads_only_full_mode_reports(self) -> None:
        (self.root / "smoke.json").write_text(json.dumps({"mode": "smoke"}), encoding="utf-8")
        (self.root / "full.json").write_text(json.dumps({"mode": "full"}), encoding="utf-8")
        (self.root / "broken.json").write_text("{", encoding="utf-8")
        self.assertEqual([path.name for path in gate.discover_reports(self.root)], ["broken.json", "full.json"])
        self.assertEqual(gate.discover_reports(self.root / "absent"), [])


class CodegenTests(GateFixture):
    def codegen_report(self, **changes: object) -> dict:
        import codegen_audit_x86_64 as codegen

        report = {
            "status": "ok",
            "provenance": {"git": {"clean": True}, "inputs": {
                **engine.sealed_inputs(),
                "mimalloc": {"archive": {"sha256": engine.shared.load_pin()["sha256"]},
                             **{key: engine.shared.load_pin()[key] for key in ("version", "tag", "revision")}}}},
            "scenarios": {scenario.name: {"comparison": {region: {"rust_excess": []} for region in scenario.regions}}
                          for scenario in codegen.SCENARIOS},
        }
        report.update(changes)
        return report

    def evaluate_codegen(self, report: dict) -> dict:
        path = self.root / "codegen.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return gate.codegen_condition(path)

    def test_a_clean_current_complete_audit_is_met(self) -> None:
        self.assertTrue(self.evaluate_codegen(self.codegen_report())["met"])

    def test_rust_excess_missing_scenarios_and_stale_seal_are_named(self) -> None:
        report = self.codegen_report()
        report["scenarios"]["local_64"]["comparison"]["malloc"]["rust_excess"] = ["calls: rust 3 > pinned C 0"]
        del report["scenarios"]["calloc_64"]
        report["provenance"]["inputs"]["rust_backend"] = {"sha256": "0" * 64}
        detail = self.evaluate_codegen(report)["detail"]
        for expected in ("codegen local_64/malloc: calls: rust 3 > pinned C 0", "omits scenarios ['calloc_64']",
                         "codegen audit source seal: rust_backend differs"):
            self.assertTrue(any(expected in item for item in detail), (expected, detail))

    def test_an_absent_audit_is_named(self) -> None:
        self.assertEqual(gate.codegen_condition(None)["detail"], ["no allocator-codegen-audit report exists"])


class CorrectnessTests(GateFixture):
    def gate_report(self, name: str, status: str, mtime: float | None = None) -> None:
        path = self.root / "gates" / f"{name}-gate/report.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"overall_status": status}), encoding="utf-8")
        if mtime is not None:
            os.utime(path, (mtime, mtime))

    def test_names_missing_unmet_and_stale_gate_reports_and_m8(self) -> None:
        perf = self.root / "perf.json"
        perf.write_text("{}", encoding="utf-8")
        os.utime(perf, (2000, 2000))
        self.gate_report("m4", "passed", 3000)
        self.gate_report("m5", "unmet", 3000)
        self.gate_report("m6", "passed", 1000)
        detail = gate.correctness_condition([perf], self.root / "gates")["detail"]
        self.assertEqual(detail, [
            "allocator M8 has no gate in this launcher",
            "M5 gate report is unmet",
            "M6 gate report predates the newest qualified report",
            f"M7 gate has no retained report ({gate.harness.relative(self.root / 'gates/m7-gate/report.json')})",
        ])


if __name__ == "__main__":
    unittest.main()
