#!/usr/bin/env python3
"""Contracts for the read-only native x86-64 allocator evidence gate.

The gate's report agreement, codegen, and correctness logic runs over fake
reader results and retained-report files; the qualified-report reader itself
is exercised by the imported ``QualifiedReportTests`` and
``HostClassificationTests`` over complete synthetic raw reports.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
sys.path.insert(0, str(ROOT / "compat/allocator/tests"))
SPEC = importlib.util.spec_from_file_location("x86_64_m9_gate", ROOT / "compat/allocator/x86_64_m9_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
engine = gate.engine

from test_perf_integrated_x86_64 import IntegratedReaderTests  # noqa: E402,F401
from test_source_convergence import SourceConvergenceTests  # noqa: E402,F401
from test_divergence_evidence import DivergenceEvidenceTests  # noqa: E402,F401
from test_perf_engine_x86_64 import (  # noqa: E402,F401
    FixturePeakHookTests, HostClassificationTests, PeakHookABTests, QualifiedReportTests)


ROSTER = ["alloc_free_64", "remote_free_1"]


def integrated_reading() -> dict:
    names = gate.integrated.row_names(gate.integrated.load_manifest())
    metrics = {name: {key: 1.0 for key in ("throughput_lower_95", "p99_upper_95",
                                                "peak_rss_upper_95", "peak_pss_upper_95")} for name in names}
    return {"unmet": [], "metrics": metrics}


def accepted(identity: dict | None = None, roster: list[str] | None = None) -> dict:
    roster = ROSTER if roster is None else roster
    return {
        "unmet": [],
        "identity": identity or {"source": {"fixture": "a"}, "configuration": {"mode": "full"}, "host": {
            "cpu_model": "synthetic", "kernel_release": "6.1", "logical_cpus": 4,
            "allowed_cpus": [0, 1, 2, 3], "measurement_cpus": [0, 1, 2, 3],
            "scaling_governors": {"0": "performance"}, "transparent_hugepage": "never"}},
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
        self.directory = tempfile.TemporaryDirectory(prefix="m9-gate-", dir=ROOT / ".work")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.results: dict[str, dict] = {}
        patcher = patch.object(gate.integrated, "WORK_ROOT", self.root / "integrated-builds")
        patcher.start()
        self.addCleanup(patcher.stop)

    def report_file(self, name: str, result: dict, *, rust_product: bytes = b"rust static library") -> Path:
        path = self.root / f"{name}.json"
        product_name = "libcrabc_allocator_engine_rust_backend.a"
        artifacts = path.with_suffix(".artifacts")
        artifacts.mkdir(exist_ok=True)
        (artifacts / product_name).write_bytes(rust_product)
        product_record = {"filename": product_name, "bytes": len(rust_product),
                          "sha256": hashlib.sha256(rust_product).hexdigest()}
        path.write_text(json.dumps({
            "label": name, "attempt_marker": name,
            "lanes": {
                "shared_fixture_object_sha256": "a" * 64,
                "pinned_c": {"executable": {"artifact": {"sha256": "a" * 64}}},
                "rust_engine": {"static_library": product_record,
                                "executable": {"artifact": {"sha256": product_record["sha256"]}}},
            },
        }), encoding="utf-8")
        self.results[str(path)] = result
        return path

    def integrated_report_file(self, name: str, *, host: dict | None = None) -> Path:
        work = gate.integrated.WORK_ROOT / name
        report: dict = {"label": name, "provenance": {"host": host or accepted()["identity"]["host"]},
                        "products": {}, "programs": {}}
        manifest = gate.integrated.load_manifest()
        products: dict[str, dict[str, Path]] = {}
        for kind in ("static", "dynamic"):
            report["products"][kind] = {}
            products[kind] = {}
            for lane, backend in manifest["backends"].items():
                product = work / "products" / f"{kind}-{backend}"
                share = product / "share/crabc"
                share.mkdir(parents=True)
                product_manifest = share / "manifest.json"
                if lane == "pinned_c":
                    pin = engine.shared.load_pin()
                    evidence = {"upstream": {"version": pin["version"], "revision": pin["revision"],
                                             "archive_sha256": pin["sha256"]},
                                "mi_malloc_version": 30500, "member_sha256": "a" * 64,
                                "flag_reconstruction": {}}
                    (share / "libc-shared.provenance.json").write_text(
                        json.dumps({"pinned_c_evidence": evidence}), encoding="utf-8")
                payload = {path.relative_to(product).as_posix(): engine.sha256_file(path)
                           for path in product.rglob("*") if path.is_file()}
                product_record = {"allocator_backend": backend}
                if kind == "static":
                    product_record["installed"] = {"files": payload}
                else:
                    product_record.update(files=payload, symlinks={})
                product_manifest.write_text(json.dumps(product_record), encoding="utf-8")
                products[kind][lane] = product
                report["products"][kind][lane] = {
                    "path": engine.shared.relative(product), "manifest": engine.file_record(product_manifest)}
                program = work / "programs" / f"{kind}-{lane}"
                program.mkdir(parents=True)
                objects = {}
                for object_name in ("engine-fixture.o", "integrated-libc-backend.o"):
                    physical = program / object_name
                    physical.write_bytes(f"{kind}/{object_name}".encode())
                    objects[object_name] = engine.sha256_file(physical)
                executable = program / "program"
                executable.write_bytes(f"{kind}/{lane}/program".encode())
                report["programs"][f"{kind}/{lane}"] = {
                    "executable": engine.artifact_record(executable), "objects": objects}
                if kind == "dynamic":
                    runtime = program / "root"
                    shutil.copytree(product, runtime)
                    shutil.copy2(executable, runtime / "program")
        report["c_reference"] = gate.integrated.c_reference(products)
        launcher = work / "programs/integrated-startup-launcher"
        launcher.write_bytes(b"startup launcher")
        report["programs"]["launcher"] = engine.artifact_record(launcher)
        path = self.root / f"{name}.json"
        path.write_text(json.dumps(report), encoding="utf-8")
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
        return gate.evaluate(paths, None, inspect=self.inspect, gate_root=self.root / "gates",
                             integrated_reports=[], evaluate_convergence=lambda root: [])

    def qualified_cohort(self) -> list[dict]:
        paths = [self.report_file(f"cohort-{index}", accepted()) for index in range(3)]
        return gate.read_reports(paths, self.inspect)

    def test_three_agreeing_accepted_reports_meet_reports_and_agreement(self) -> None:
        paths = [self.report_file(f"r{index}", accepted()) for index in range(3)]
        result = self.evaluate(paths)
        self.assertTrue(self.condition(result, "m9.qualified-reports")["met"])
        self.assertTrue(self.condition(result, "m9.agreement")["met"])
        self.assertEqual(result["overall_status"], "unmet")
        self.assertEqual([row["id"] for row in result["conditions"]], list(gate.CONDITION_IDS))

    def test_repeating_one_report_path_does_not_make_three_attempts(self) -> None:
        path = self.report_file("one", accepted())
        result = self.evaluate([path, path, path])
        self.assertFalse(self.condition(result, "m9.qualified-reports")["met"])
        self.assertFalse(self.condition(result, "m9.agreement")["met"])

    def test_different_retained_products_do_not_agree(self) -> None:
        paths = [self.report_file("a", accepted()), self.report_file("b", accepted()),
                 self.report_file("c", accepted(), rust_product=b"different rust static library")]
        result = self.evaluate(paths)
        self.assertFalse(self.condition(result, "m9.agreement")["met"])

    def test_renaming_a_copied_report_does_not_make_another_attempt(self) -> None:
        first = self.report_file("a", accepted())
        copied = self.root / "b.json"
        raw = json.loads(first.read_text(encoding="utf-8"))
        raw["label"] = "b"
        copied.write_text(json.dumps(raw), encoding="utf-8")
        copied_artifacts = copied.with_suffix(".artifacts")
        copied_artifacts.mkdir()
        library = "libcrabc_allocator_engine_rust_backend.a"
        (copied_artifacts / library).write_bytes((first.with_suffix(".artifacts") / library).read_bytes())
        self.results[str(copied)] = accepted()
        third = self.report_file("c", accepted())
        result = self.evaluate([first, copied, third])
        self.assertFalse(self.condition(result, "m9.qualified-reports")["met"])
        self.assertTrue(any("raw report duplicates" in item
                            for item in self.condition(result, "m9.qualified-reports")["detail"]))

    def test_a_reader_acceptance_without_retained_product_identity_is_refused(self) -> None:
        path = self.report_file("missing", accepted())
        raw = json.loads(path.read_text(encoding="utf-8"))
        del raw["lanes"]
        path.write_text(json.dumps(raw), encoding="utf-8")
        result = self.evaluate([path])
        self.assertFalse(self.condition(result, "m9.qualified-reports")["met"])
        self.assertTrue(any("retained attempt identity is invalid" in item
                            for item in self.condition(result, "m9.qualified-reports")["detail"]))

    def test_a_missing_physical_rust_library_is_refused(self) -> None:
        path = self.report_file("missing_library", accepted())
        (path.with_suffix(".artifacts") / "libcrabc_allocator_engine_rust_backend.a").unlink()
        result = self.evaluate([path])
        self.assertTrue(any("retained attempt identity is invalid" in item
                            for item in self.condition(result, "m9.qualified-reports")["detail"]))

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

    def test_convergence_reads_current_evidence_and_integrated_reports(self) -> None:
        result = self.evaluate([])
        self.assertFalse(self.condition(result, "m9.source-convergence")["met"])
        self.assertIn("no qualified integrated-product report among 0 read",
                      self.condition(result, "m9.integrated-products")["detail"][0])
        convergence = gate.convergence_condition(lambda root: [
            {"id": "transitional", "met": False, "detail": ["src/a.c:x is partial"]},
            {"id": "pin", "met": True, "detail": "ok"}])
        self.assertTrue(any("verdict differs from the current port map" in item for item in convergence["detail"]))

    def test_forged_convergence_verdict_cannot_hide_current_divergence_evidence(self) -> None:
        condition = gate.convergence_condition(lambda root: [])
        self.assertFalse(condition["met"])
        self.assertTrue(any("heap lifecycle" in item or "src/heap.c" in item
                            for item in condition["detail"]), condition)
        self.assertTrue(any("no source/fixture/program-bound retained differential receipt" in item
                            for item in condition["detail"]), condition)

    def test_convergence_rereads_source_built_cohort_independently(self) -> None:
        paths = [self.report_file(f"cohort-{index}", accepted()) for index in range(3)]
        integrated_path = self.integrated_report_file("integrated")
        result = gate.evaluate(paths, None, inspect=self.inspect, gate_root=self.root / "gates",
                               integrated_reports=[integrated_path],
                               inspect_integrated=lambda root, path: integrated_reading(),
                               evaluate_convergence=lambda root: [])
        self.assertTrue(self.condition(result, "m9.integrated-products")["met"])
        detail = self.condition(result, "m9.source-convergence")["detail"]
        self.assertTrue(any("no qualified source-bound integrated_rows report measures" in item
                            for item in detail), detail)

    def test_status_only_differential_gate_lacks_program_identities(self) -> None:
        command = ["python3", "compat/allocator/heap_lifecycle.py"]
        contract = self.root / "differential-contract.json"
        contract.write_text(json.dumps({"evidence": {"heap": {"runner": command[1]}}}), encoding="utf-8")
        report = self.root / "gates/m6-gate/report.json"
        report.parent.mkdir(parents=True)
        report.write_text(json.dumps({"overall_status": "passed", "evidence": {
            "heap": {"runner": command[1], "status": "passed"}}}), encoding="utf-8")
        with (patch.dict(gate.CORRECTNESS_INPUTS, {"m6": ("m6_gate.py", str(contract))}, clear=True),
              patch.object(gate, "correctness_evidence_unmet", return_value=[])):
            reason = gate.convergence_differential_unmet(command, self.root / "gates", None)
        self.assertIn("lacks independently checkable C/Rust fixture and executable identities", reason)

    def test_one_accepted_integrated_report_meets_its_condition(self) -> None:
        good, bad = self.integrated_report_file("good"), self.root / "bad.json"
        results = {good: integrated_reading(), bad: {"unmet": ["host is not uncontended: x"]}}
        cohort = self.qualified_cohort()
        condition = gate.integrated_condition([bad, good], lambda root, path: results[path], cohort)
        self.assertTrue(condition["met"])
        condition = gate.integrated_condition([bad], lambda root, path: results[path], cohort)
        self.assertIn("bad.json: host is not uncontended: x", condition["detail"][1])

    def test_integrated_report_cannot_qualify_without_an_engine_report_cohort(self) -> None:
        integrated_path = self.root / "integrated.json"
        integrated_path.write_text("{}", encoding="utf-8")
        result = gate.evaluate([], None, inspect=self.inspect, gate_root=self.root / "gates",
                               integrated_reports=[integrated_path],
                               inspect_integrated=lambda root, path: integrated_reading(),
                               evaluate_convergence=lambda root: [])
        self.assertFalse(self.condition(result, "m9.integrated-products")["met"])
        self.assertTrue(any("three agreeing qualified engine reports" in item
                            for item in self.condition(result, "m9.integrated-products")["detail"]))

    def test_integrated_report_requires_the_cohort_host(self) -> None:
        host = copy.deepcopy(accepted()["identity"]["host"])
        host["cpu_model"] = "other host"
        path = self.integrated_report_file("other-host", host=host)
        condition = gate.integrated_condition([path], lambda root, path: integrated_reading(), self.qualified_cohort())
        self.assertFalse(condition["met"])
        self.assertTrue(any("host identity differs" in item for item in condition["detail"]))

    def test_integrated_report_may_use_a_subset_of_cohort_measurement_cpus(self) -> None:
        cohort = self.qualified_cohort()
        host = copy.deepcopy(cohort[0]["identity"]["host"])
        host["measurement_cpus"] = [0, 1]
        host["scaling_governors"] = {"0": "performance"}
        path = self.integrated_report_file("subset-cpus", host=host)
        condition = gate.integrated_condition([path], lambda root, path: integrated_reading(), cohort)
        self.assertTrue(condition["met"], condition)

    def test_integrated_report_requires_one_agreeing_source_cohort(self) -> None:
        cohort = self.qualified_cohort()
        cohort[-1]["identity"]["source"] = {"fixture": "different"}
        path = self.integrated_report_file("different-source-cohort")
        condition = gate.integrated_condition([path], lambda root, path: integrated_reading(), cohort)
        self.assertFalse(condition["met"])
        self.assertTrue(any("three agreeing qualified engine reports" in item for item in condition["detail"]))

    def test_integrated_reader_without_a_verdict_fails_closed(self) -> None:
        path = self.integrated_report_file("missing-verdict")
        condition = gate.integrated_condition([path], lambda root, path: {"metrics": {}}, self.qualified_cohort())
        self.assertFalse(condition["met"])
        self.assertTrue(any("reader returned no valid refusal list" in item for item in condition["detail"]))

    def test_integrated_reader_without_complete_metrics_fails_closed(self) -> None:
        path = self.integrated_report_file("missing-metrics")
        condition = gate.integrated_condition([path], lambda root, path: {"unmet": [], "metrics": {}},
                                              self.qualified_cohort())
        self.assertFalse(condition["met"])
        self.assertTrue(any("reader returned no complete row metrics" in item for item in condition["detail"]))

    def test_integrated_report_requires_physical_products_and_programs(self) -> None:
        path = self.integrated_report_file("tampered")
        work = gate.integrated.WORK_ROOT / "tampered"
        (work / "programs/static-rust_engine/program").write_bytes(b"changed binary")
        condition = gate.integrated_condition([path], lambda root, path: integrated_reading(), self.qualified_cohort())
        self.assertFalse(condition["met"])
        self.assertTrue(any("static/rust_engine program differs" in item for item in condition["detail"]))

    def test_integrated_report_rejects_changed_installed_payload_and_execution_root(self) -> None:
        path = self.integrated_report_file("changed-tree")
        work = gate.integrated.WORK_ROOT / "changed-tree"
        product = work / "products/static-native-shadow"
        (product / "unexpected.bin").write_bytes(b"unrecorded product payload")
        runtime_program = work / "programs/dynamic-rust_engine/root/program"
        runtime_program.write_bytes(b"changed runtime copy")
        condition = gate.integrated_condition([path], lambda root, path: integrated_reading(), self.qualified_cohort())
        self.assertFalse(condition["met"])
        self.assertTrue(any("static/rust_engine installed payload differs" in item for item in condition["detail"]))
        self.assertTrue(any("dynamic/rust_engine execution root differs" in item for item in condition["detail"]))

    def test_integrated_program_objects_must_be_identical_across_backends(self) -> None:
        path = self.integrated_report_file("different-objects")
        changed = gate.integrated.WORK_ROOT / "different-objects/programs/static-rust_engine/engine-fixture.o"
        changed.write_bytes(b"different fixture object")
        report = json.loads(path.read_text(encoding="utf-8"))
        report["programs"]["static/rust_engine"]["objects"]["engine-fixture.o"] = engine.sha256_file(changed)
        path.write_text(json.dumps(report), encoding="utf-8")
        condition = gate.integrated_condition([path], lambda root, path: integrated_reading(),
                                              self.qualified_cohort())
        self.assertFalse(condition["met"])
        self.assertTrue(any("static C and Rust program objects are not source-identical" in item
                            for item in condition["detail"]))

    def test_the_matrix_condition_comes_from_report_coverage(self) -> None:
        self.assertIn("no full report carries", self.condition(self.evaluate([]), "m9.matrix")["detail"][0])
        partial = accepted()
        partial["coverage"] = {"alloc_free_64": ["peak_pss"]}
        detail = self.condition(self.evaluate([self.report_file("p", partial)]), "m9.matrix")["detail"]
        self.assertTrue(any("p.json: alloc_free_64 lacks peak_pss" in item for item in detail), detail)
        complete = accepted()
        complete["coverage"] = {}
        self.assertTrue(self.condition(self.evaluate([self.report_file("c", complete)]), "m9.matrix")["met"])
        rejected = copy.deepcopy(complete)
        rejected["unmet"] = ["raw metric differs from fixture output"]
        self.assertFalse(self.condition(self.evaluate([self.report_file("r", rejected)]), "m9.matrix")["met"])

    def test_discovery_reads_only_full_mode_reports(self) -> None:
        (self.root / "smoke.json").write_text(json.dumps({"mode": "smoke"}), encoding="utf-8")
        (self.root / "full.json").write_text(json.dumps({"mode": "full"}), encoding="utf-8")
        (self.root / "broken.json").write_text("{", encoding="utf-8")
        self.assertEqual([path.name for path in gate.discover_reports(self.root)], ["broken.json", "full.json"])
        self.assertEqual(gate.discover_reports(self.root / "absent"), [])


class CodegenTests(GateFixture):
    def setUp(self) -> None:
        super().setUp()
        self.codegen = importlib.import_module("codegen_audit_x86_64")
        codegen = self.codegen

        class FixtureImage:
            def __init__(self, binary: Path, nm: str, objdump: str) -> None:
                self.instructions = {0x1000: codegen.Instruction(0x1000, "ret", "", "ret", None)}
                self.by_name = {name: (0x1000, 0x1001) for name in codegen.ENTRY_SYMBOLS}

            def function_at(self, address: int) -> str:
                return codegen.ENTRY_SYMBOLS[0] if address in self.instructions else f"<unknown:{address:#x}>"

            def function_range(self, name: str) -> tuple[int, int]:
                return self.by_name[name]

        image = patch.object(codegen, "Image", FixtureImage)
        image.start()
        self.addCleanup(image.stop)
        replay = patch.object(codegen, "trace_scenario", side_effect=lambda binary, image, scenario, scratch, cpu:
                              [codegen.Region([0x1000], {}) for _ in scenario.regions])
        replay.start()
        self.addCleanup(replay.stop)
        git = patch.object(engine, "git_provenance", return_value={"head": "fixture", "clean": True})
        git.start()
        self.addCleanup(git.stop)
        self.image = FixtureImage(self.root / "fixture", "nm", "objdump")
        self.artifacts = self.root / "codegen.artifacts"

    def codegen_report(self, **changes: object) -> dict:
        codegen = self.codegen
        self.artifacts.mkdir(exist_ok=True)
        products = {}
        for name, content in (("engine-fixture-c.o", b"shared fixture"),
                              ("engine-fixture-rust.o", b"shared fixture"),
                              ("libcrabc_allocator_engine_rust_backend.a", b"rust library"),
                              ("engine-fixture-pinned-c", b"pinned C executable"),
                              ("engine-fixture-rust-engine", b"Rust executable")):
            path = self.artifacts / name
            path.write_bytes(content)
            products[name] = engine.sha256_file(path)
        pin = engine.shared.load_pin()
        inputs = {**engine.sealed_inputs(), "mimalloc": {"archive": {"sha256": pin["sha256"]},
                                                        **{key: pin[key] for key in ("version", "tag", "revision")}}}
        source = dict(inputs, mimalloc={key: pin[key] for key in ("version", "tag", "revision")}
                      | {"archive_sha256": pin["sha256"]})
        identity = accepted()["identity"]
        identity["source"] = source
        identity["configuration"]["tools"] = {"cc": "fixture"}
        cohort = []
        for index in range(3):
            row = accepted(identity=identity)
            row["path"] = f"cohort-{index}.json"
            row["product_identity"] = {
                "shared_fixture_object": products["engine-fixture-c.o"],
                "pinned_c_executable": products["engine-fixture-pinned-c"],
                "rust_engine_static_library": products["libcrabc_allocator_engine_rust_backend.a"],
                "rust_engine_executable": products["engine-fixture-rust-engine"],
            }
            cohort.append(row)
        self.cohort = cohort
        static = {lane: {entry: codegen.static_reachability(self.image, entry)
                         for entry in codegen.ENTRY_SYMBOLS} for lane in engine.LANES}
        scenarios = {}
        for scenario in codegen.SCENARIOS:
            lanes = {}
            for lane in engine.LANES:
                lanes[lane] = {}
                for region in scenario.regions:
                    observed = codegen.Region([0x1000], {})
                    summary, listing = codegen.analyze_region(self.image, observed)
                    summary["external_vdso"] = []
                    filename = f"trace-{scenario.name}-{region}-{lane}.txt"
                    (self.artifacts / filename).write_text("\n".join(listing) + "\n", encoding="utf-8")
                    (self.artifacts / f"trace-{scenario.name}-{region}-{lane}.json").write_text(
                        json.dumps(codegen.trace_record(self.image, observed)), encoding="utf-8")
                    lanes[lane][region] = dict(summary, listing=filename)
            scenarios[scenario.name] = {
                "workload": scenario.workload, "params": dict(scenario.params), "measures": scenario.measures,
                "lanes": lanes,
                "comparison": {region: codegen.compare_regions(lanes["pinned_c"][region], lanes["rust_engine"][region])
                               for region in scenario.regions},
            }
        report = {
            "schema": codegen.SCHEMA, "kind": codegen.KIND, "label": "codegen", "status": "ok",
            "provenance": {"git": {"clean": True, "head": engine.git_provenance()["head"]},
                           "inputs": inputs, "tools": {"cc": "fixture"}},
            "lanes": {lane: {"executable": {"artifact": engine.artifact_record(
                self.artifacts / ("engine-fixture-pinned-c" if lane == "pinned_c" else "engine-fixture-rust-engine")),
                "elf": dict(engine.shared.EXPECTED_ELF), "type": "static-non-pie-exec"}}
                for lane in engine.LANES},
            "static": static, "scenarios": scenarios,
        }
        report.update(changes)
        return report

    def evaluate_codegen(self, report: dict) -> dict:
        path = self.root / "codegen.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return gate.codegen_condition(path, self.cohort)

    def test_a_clean_current_complete_audit_is_met(self) -> None:
        self.assertTrue(self.evaluate_codegen(self.codegen_report())["met"])

    def test_fabricated_trace_with_genuine_products_is_refused(self) -> None:
        report = self.codegen_report()
        scenario = report["scenarios"]["local_64"]
        forged, listing = self.codegen.analyze_region(self.image, self.codegen.Region([0x1000, 0x1000], {}))
        (self.artifacts / "trace-local_64-malloc-rust_engine.txt").write_text(
            "\n".join(listing) + "\n", encoding="utf-8")
        (self.artifacts / "trace-local_64-malloc-rust_engine.json").write_text(
            json.dumps(self.codegen.trace_record(self.image, self.codegen.Region([0x1000, 0x1000], {}))),
            encoding="utf-8")
        forged["external_vdso"] = []
        scenario["lanes"]["rust_engine"]["malloc"] = dict(forged, listing="trace-local_64-malloc-rust_engine.txt")
        scenario["comparison"]["malloc"] = self.codegen.compare_regions(
            scenario["lanes"]["pinned_c"]["malloc"], scenario["lanes"]["rust_engine"]["malloc"])
        detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("executed trace differs" in item for item in detail), detail)

    def test_fabricated_atomic_targets_with_genuine_products_are_refused(self) -> None:
        report = self.codegen_report()
        scenario = report["scenarios"]["local_64"]
        for lane in engine.LANES:
            summary = scenario["lanes"][lane]["malloc"]
            summary["atomic_rmw_targets"] = {"dynamic": 1}
            summary["atomic_rmw_non_thread_local"] = 1
        scenario["comparison"]["malloc"] = self.codegen.compare_regions(
            scenario["lanes"]["pinned_c"]["malloc"], scenario["lanes"]["rust_engine"]["malloc"])
        detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("atomic targets differ from replay" in item for item in detail), detail)

    def test_missing_raw_execution_record_is_refused(self) -> None:
        report = self.codegen_report()
        (self.artifacts / "trace-local_64-malloc-rust_engine.json").unlink()
        detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("lacks its retained raw trace" in item for item in detail), detail)

    def clock_excursion_report(self) -> tuple[dict, object]:
        self.image.instructions[0x1000] = self.codegen.Instruction(0x1000, "call", "*%rax", "call *%rax", None)
        self.image.instructions[0x1002] = self.codegen.Instruction(0x1002, "test", "%eax,%eax", "test %eax,%eax", None)
        report = self.codegen_report()
        scenario = report["scenarios"]["thread_lifecycle"]
        retained = self.codegen.Region([0x1000, 0x7F000B50, 0x7F000B54, 0x1002], {},
                                      self.codegen.VdsoImage(0x7F000000, 0x7F002000, "a" * 64, 0xB50))
        for lane in engine.LANES:
            projected, spans = self.codegen.project_region(self.image, retained)
            summary, listing = self.codegen.analyze_region(self.image, projected)
            summary["external_vdso"] = spans
            filename = f"trace-thread_lifecycle-thread_done-{lane}"
            (self.artifacts / f"{filename}.txt").write_text("\n".join(listing) + "\n", encoding="utf-8")
            (self.artifacts / f"{filename}.json").write_text(
                json.dumps(self.codegen.trace_record(self.image, retained)), encoding="utf-8")
            scenario["lanes"][lane]["thread_done"] = dict(summary, listing=f"{filename}.txt")
        scenario["comparison"]["thread_done"] = self.codegen.compare_regions(
            scenario["lanes"]["pinned_c"]["thread_done"],
            scenario["lanes"]["rust_engine"]["thread_done"])

        def replay(binary: Path, image: object, selected: object, scratch: Path, cpu: int) -> list:
            regions = [self.codegen.Region([0x1000], {}) for _ in selected.regions]
            if selected.name == "thread_lifecycle":
                regions[1] = self.codegen.Region([0x1000, 0x7F100B50, 0x7F100B60, 0x7F100B54, 0x1002], {},
                                                 self.codegen.VdsoImage(0x7F100000, 0x7F102000, "a" * 64, 0xB50))
            return regions
        return report, replay

    def test_external_clock_variation_preserves_image_cost(self) -> None:
        report, replay = self.clock_excursion_report()
        with (patch.object(self.codegen, "Image", return_value=self.image),
              patch.object(self.codegen, "trace_scenario", side_effect=replay)):
            condition = self.evaluate_codegen(report)
        self.assertTrue(condition["met"], condition["detail"])

    def test_external_clock_target_edge_cannot_be_forged(self) -> None:
        report, replay = self.clock_excursion_report()
        raw = self.artifacts / "trace-thread_lifecycle-thread_done-rust_engine.json"
        record = json.loads(raw.read_text(encoding="utf-8"))
        record["rips"][1] = 0x7F000B60
        record["vdso"]["clock_offset"] = 0xB60
        record["external_vdso"][0]["target_offset"] = 0xB60
        raw.write_text(json.dumps(record), encoding="utf-8")
        report["scenarios"]["thread_lifecycle"]["lanes"]["rust_engine"]["thread_done"][
            "external_vdso"][0]["target_offset"] = 0xB60
        with (patch.object(self.codegen, "Image", return_value=self.image),
              patch.object(self.codegen, "trace_scenario", side_effect=replay)):
            detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("external clock boundary or image differs from replay" in item
                            for item in detail), detail)

    def test_report_without_retained_codegen_products_is_refused(self) -> None:
        report = self.codegen_report()
        (self.artifacts / "engine-fixture-rust-engine").unlink()
        self.assertFalse(self.evaluate_codegen(report)["met"])

    def test_codegen_report_requires_a_qualified_engine_cohort(self) -> None:
        report = self.codegen_report()
        self.cohort = []
        detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("three agreeing qualified engine reports" in item for item in detail), detail)

    def test_rewritten_comparison_cannot_hide_structural_cost(self) -> None:
        report = self.codegen_report()
        comparison = report["scenarios"]["local_64"]["comparison"]["malloc"]
        comparison["calls"]["rust_engine"] = 3
        comparison["rust_excess"] = []
        detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("comparison differs from its lane summaries" in item for item in detail), detail)

    def test_changed_listing_and_other_cohort_product_are_refused(self) -> None:
        report = self.codegen_report()
        listing = self.artifacts / "trace-local_64-malloc-rust_engine.txt"
        listing.write_text("0x1000 crabc_allocator_engine_malloc: nop\n", encoding="utf-8")
        detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("listing differs from its executable" in item for item in detail), detail)
        listing.write_text("0x1000 crabc_allocator_engine_malloc: ret\n", encoding="utf-8")
        for member in self.cohort:
            member["product_identity"]["rust_engine_executable"] = "0" * 64
        detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("rust_engine codegen executable differs from the qualified engine product" in item
                            for item in detail), detail)

    def test_other_source_and_tool_configuration_are_refused(self) -> None:
        report = self.codegen_report()
        for member in self.cohort:
            member["identity"]["source"] = {"different": "source"}
        detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("source differs from the qualified engine reports" in item for item in detail), detail)
        for member in self.cohort:
            member["identity"]["source"] = dict(report["provenance"]["inputs"], mimalloc={
                key: report["provenance"]["inputs"]["mimalloc"][key] for key in ("version", "tag", "revision")}
                | {"archive_sha256": report["provenance"]["inputs"]["mimalloc"]["archive"]["sha256"]})
            member["identity"]["configuration"]["tools"] = {"cc": "different"}
        detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("tool configuration differs" in item for item in detail), detail)

    def test_codegen_audit_requires_the_current_clean_revision(self) -> None:
        report = self.codegen_report()
        with patch.object(engine, "git_provenance", return_value={"head": "fixture", "clean": False}):
            detail = self.evaluate_codegen(report)["detail"]
        self.assertTrue(any("clean checkout" in item for item in detail), detail)

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
    def test_corpus_receipt_reader_ignores_unrelated_run_x86_module(self) -> None:
        entry = {
            "command": ["runner", "--dynamic-sysroot", "/workspace/.work/missing-product"],
            "receipt": {"path": "/workspace/.work/missing-corpus-report.json"},
        }
        with patch.dict(sys.modules, {"run_x86": types.ModuleType("run_x86")}):
            with self.assertRaisesRegex(gate.harness.HarnessError,
                                        "corpus physical receipt reader failed"):
                gate.read_m8_receipt("product:package-corpus", entry, "")

    def test_gate_producers_record_their_raw_evidence_files(self) -> None:
        log = self.root / "gate.log"
        log.write_text("raw evidence output", encoding="utf-8")
        report = {"evidence": {"fixture": {"log": gate.harness.relative(log)}}}
        for module_name in ("x86_64_m4_gate", "x86_64_m5_gate", "m6_gate"):
            producer = importlib.import_module(module_name)
            provenance = producer.report_provenance(report)
            self.assertEqual(provenance["evidence"], {"fixture": gate.engine.file_record(log)})
            self.assertEqual(provenance["seal"]["gate"], gate.engine.file_record(Path(producer.__file__)))
            self.assertEqual(provenance["seal"]["contract"], gate.engine.file_record(producer.CONTRACT))

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
        detail = gate.correctness_condition([perf], self.root / "gates", self.root / "m8-gate/report.json")["detail"]
        self.assertEqual(detail, [
            "M4 gate report lacks current evidence provenance",
            "M5 gate report is unmet",
            "M6 gate report predates the newest qualified report",
            f"M7 gate has no retained report ({gate.harness.relative(self.root / 'gates/m7-gate/report.json')})",
            f"M8 gate has no retained report ({gate.harness.relative(self.root / 'm8-gate/report.json')})",
        ])

    def test_current_m8_report_requires_its_physical_receipts(self) -> None:
        import x86_64_m8_gate as m8

        perf = self.root / "perf.json"
        perf.write_text("{}", encoding="utf-8")
        os.utime(perf, (2000, 2000))
        for name in gate.CORRECTNESS_GATES:
            self.gate_report(name, "passed")
        report_path = self.root / "m8-gate/report.json"
        report_path.parent.mkdir(parents=True)
        contract, summary = m8.load_summary()
        source = m8.qualification.source_digest()
        product = self.root / "native-policy"
        product.mkdir()
        results = {}
        no_receipt = {"product:c-allocation-interposition", "product:stdio-allocator-interposition",
                      "product:package-corpus-input"}
        for name, canonical in summary["runnable_evidence"].items():
            log = report_path.parent / f"{name.replace(':', '-')}.log"
            log.write_text(f"native-allocator-policy evidence: {product}\n" if name == summary["products"]["evidence"]
                           else "passed\n", encoding="utf-8")
            command = (m8.bind_products(canonical, summary["products"], str(product))
                       if m8._uses_products(canonical) else canonical)
            entry = {"command": command, "log": gate.harness.relative(log), "status": "passed"}
            if name not in no_receipt:
                physical = self.root / f"{name.replace(':', '-')}.json"
                physical.write_text(json.dumps({"evidence": name}), encoding="utf-8")
                entry["receipt"] = {"path": str(physical), "sha256": engine.sha256_file(physical),
                                    "source_sha256": source}
                if name.startswith("consumer:lua-"):
                    del entry["receipt"]["source_sha256"]
                    entry["receipt"]["source_identity"] = {"revision": "fixture", "source_sha256": source}
            results[name] = entry
        report_path.write_text(json.dumps(m8.gate_report(contract, summary, results)), encoding="utf-8")
        with (patch.object(engine, "git_provenance", return_value={"head": "fixture", "clean": True}),
              patch.object(gate, "correctness_evidence_unmet", return_value=[]),
              patch.object(gate, "read_m8_receipt",
                           side_effect=lambda name, entry, output: entry["receipt"])):
            condition = gate.correctness_condition([perf], self.root / "gates", report_path)
            self.assertTrue(condition["met"], condition)
            receipt = self.root / "product-native-allocator-policy.json"
            receipt.write_text("changed", encoding="utf-8")
            detail = gate.correctness_condition([perf], self.root / "gates", report_path)["detail"]
            self.assertTrue(any("M8 gate" in item and "receipt" in item for item in detail), detail)

    def test_copied_status_only_reports_do_not_prove_current_correctness(self) -> None:
        perf = self.root / "perf.json"
        perf.write_text("{}", encoding="utf-8")
        os.utime(perf, (2000, 2000))
        for name in gate.CORRECTNESS_GATES:
            self.gate_report(name, "passed", 3000)
        detail = gate.correctness_condition([perf], self.root / "gates")["detail"]
        self.assertTrue(any("M4 gate report lacks current evidence" in item for item in detail), detail)

    def test_passing_statuses_cannot_hide_current_heap_api_conditions(self) -> None:
        import m6_gate as producer

        contract = gate.harness.read_json(producer.CONTRACT)
        path = self.root / "gates/m6-gate/report.json"
        path.parent.mkdir(parents=True)
        evidence = {}
        for name, entry in contract["evidence"].items():
            log = path.parent / f"{name.replace(':', '-')}.log"
            log.write_text("passed\n", encoding="utf-8")
            evidence[name] = {"runner": entry["runner"], "log": gate.harness.relative(log), "status": "passed"}
        summary = producer.validate_contract(contract, gate.harness.read_json(
            gate.harness.ALLOCATOR_ROOT / "api-v3.5.0.json"), gate.harness.load_pin())
        report = producer.gate_report(contract, summary, evidence)
        report["overall_status"] = "passed"
        report["unmet_required"] = []
        for row in report["gates"]:
            row["status"] = "passed"
            row["blocked_by"] = []
        with patch.object(gate.engine, "git_provenance", return_value={"head": "fixture", "clean": True}):
            report["provenance"] = producer.report_provenance(report)
            unmet = gate.correctness_evidence_unmet("m6", report, path.parent, None)
        self.assertTrue(unmet, "saved passing statuses hid the source contract's unresolved conditions")

    def test_passing_statuses_cannot_supply_a_missing_concurrency_producer(self) -> None:
        import x86_64_m5_gate as producer

        contract = gate.harness.read_json(producer.CONTRACT)
        path = self.root / "gates/m5-gate/report.json"
        path.parent.mkdir(parents=True)
        evidence = {}
        for name in contract["evidence"]:
            log = path.parent / f"{name.replace(':', '-')}.log"
            log.write_text("passed\n", encoding="utf-8")
            evidence[name] = {"log": gate.harness.relative(log), "status": "passed"}
        summary = producer.validate_contract(contract, gate.harness.load_pin(), producer.native_test_targets())
        report = producer.gate_report(contract, summary, evidence)
        report["overall_status"] = "passed"
        report["unmet_required"] = []
        for row in report["gates"]:
            row["status"] = "passed"
            row["blocked_by"] = []
            row["missing_evidence"] = []
        with patch.object(gate.engine, "git_provenance", return_value={"head": "fixture", "clean": True}):
            report["provenance"] = producer.report_provenance(report)
            unmet = gate.correctness_evidence_unmet("m5", report, path.parent, None)
        self.assertTrue(any("executed producers" in reason for reason in unmet), unmet)

    def test_current_report_requires_all_gates_and_unchanged_physical_logs(self) -> None:
        git = patch.object(gate.engine, "git_provenance", return_value={"head": "fixture", "clean": True})
        git.start()
        self.addCleanup(git.stop)
        name = "m4"
        import x86_64_m4_gate as producer

        contract = json.loads((gate.harness.ALLOCATOR_ROOT / gate.CORRECTNESS_INPUTS[name][1]).read_text(encoding="utf-8"))
        summary = producer.validate_contract(contract, gate.harness.read_json(
            gate.harness.ALLOCATOR_ROOT / "api-v3.5.0.json"), gate.harness.load_pin(),
            producer.sibling_owned_items(contract["inventory"]))
        path = self.root / "gates/m4-gate/report.json"
        path.parent.mkdir(parents=True)
        evidence = {}
        for evidence_name in {item for record in contract["gates"] for item in record["evidence"]}:
            log = path.parent / f"{evidence_name.replace(':', '-')}.log"
            log.write_text("passed", encoding="utf-8")
            command = producer.evidence_command(summary["runnable_evidence"][evidence_name],
                                                path.parent / evidence_name.replace(":", "-"))
            evidence[evidence_name] = {"command": command, "log": gate.harness.relative(log), "status": "passed"}
        source, selected_contract = (gate.harness.ALLOCATOR_ROOT / item for item in gate.CORRECTNESS_INPUTS[name])
        report = producer.gate_report(contract, summary, evidence)
        report["provenance"] = copy.deepcopy(producer.report_provenance(report))
        evidence = report["evidence"]
        path.write_text(json.dumps(report), encoding="utf-8")
        self.assertEqual(gate.correctness_evidence_unmet(name, report, path.parent, None), [])
        self.assertEqual(gate.correctness_evidence_unmet(
            name, report, path.parent.relative_to(gate.harness.ROOT), None), [])
        last_gate = report["gates"].pop()
        self.assertIn("complete passing gate roster", gate.correctness_evidence_unmet(name, report, path.parent, None)[0])
        report["gates"].append(last_gate)
        evidence_name = next(iter(evidence))
        command = evidence[evidence_name].pop("command")
        self.assertIn("lacks its executed producer",
                      gate.correctness_evidence_unmet(name, report, path.parent, None)[0])
        evidence[evidence_name]["command"] = ["python3", "different-producer.py"]
        self.assertIn("lacks its executed producer",
                      gate.correctness_evidence_unmet(name, report, path.parent, None)[0])
        evidence[evidence_name]["command"] = command
        (gate.harness.ROOT / evidence[evidence_name]["log"]).write_text("changed", encoding="utf-8")
        self.assertIn("differs from its retained raw log",
                      gate.correctness_evidence_unmet(name, report, path.parent, None)[0])
        (gate.harness.ROOT / evidence[evidence_name]["log"]).write_text("passed", encoding="utf-8")
        report["provenance"]["git"]["head"] = "old source"
        self.assertIn("current clean checkout identity",
                      gate.correctness_evidence_unmet(name, report, path.parent, None)[0])
        report["provenance"]["git"]["head"] = "fixture"
        report["provenance"]["seal"]["gate"]["sha256"] = "0" * 64
        self.assertIn("current gate and contract identity",
                      gate.correctness_evidence_unmet(name, report, path.parent, None)[0])
        report["provenance"]["seal"]["gate"] = gate.engine.file_record(source)
        os.utime(gate.harness.ROOT / evidence[evidence_name]["log"], ns=(1000, 1000))
        self.assertIn("predates the newest qualified report",
                      gate.correctness_evidence_unmet(name, report, path.parent, 2000)[0])


if __name__ == "__main__":
    unittest.main()
