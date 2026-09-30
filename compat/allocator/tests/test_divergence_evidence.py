#!/usr/bin/env python3
"""The algorithmic-divergence evidence manifest and its evaluation."""

from __future__ import annotations

import copy
import io
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
import divergence_evidence as evidence  # noqa: E402


class DivergenceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, self.port_map = evidence.load()

    def test_the_manifest_covers_exactly_the_algorithmic_rows(self) -> None:
        self.assertEqual(sorted(self.manifest["rows"]), evidence.algorithmic_rows(self.port_map))
        port_map = copy.deepcopy(self.port_map)
        next(row for row in port_map["item"] if row.get("difference_kind") == "boundary")["difference_kind"] = "algorithmic"
        with self.assertRaisesRegex(evidence.EvidenceError, "missing"):
            evidence.validate_manifest(self.manifest, port_map)

    def test_rejects_an_entry_without_both_kinds_of_evidence(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        del manifest["rows"]["src/random.c"]["performance"]
        with self.assertRaisesRegex(evidence.EvidenceError, "differential and performance"):
            evidence.validate_manifest(manifest, self.port_map)
        manifest = copy.deepcopy(self.manifest)
        manifest["rows"]["src/random.c"]["differential"] = {"command": ["python3", "absent.py"], "scope": "x"}
        with self.assertRaisesRegex(evidence.EvidenceError, "runnable"):
            evidence.validate_manifest(manifest, self.port_map)

    OS_ROW = "src/arena.c:os-fallback-commit-on-demand-initially-committed-correction"

    def rejects(self, change, expected: str, port_map=None, register: str | None = None) -> None:
        manifest = copy.deepcopy(self.manifest)
        change(manifest["rows"][self.OS_ROW])
        with self.assertRaisesRegex(evidence.EvidenceError, expected):
            evidence.validate_manifest(manifest, port_map or self.port_map, register)

    def test_not_applicable_is_admitted_only_with_its_c_defect_record(self) -> None:
        evidence.validate_manifest(self.manifest, self.port_map)
        self.assertEqual(evidence.accepted_not_applicable(self.manifest), {self.OS_ROW})
        self.rejects(lambda entry: entry.pop("c_defect"), "needs a c_defect")
        self.rejects(lambda entry: entry["c_defect"].update(source_lines=[]), "source_lines")
        self.rejects(lambda entry: entry["c_defect"].update(source_lines=["arena.c line 855"]), "source_lines")
        self.rejects(lambda entry: entry["performance"].update(not_applicable=" "), "needs a reason")
        self.rejects(lambda entry: entry.update(performance={"blocked": "x"}), "cover both")
        self.rejects(lambda entry: entry["c_defect"].update(known_difference="CRABC-MI-ABSENT"),
                     "not an accepted known-differences entry")
        self.rejects(lambda entry: entry["c_defect"].update(known_difference="CRABC-MI-RANDOM-WEAK-EXPANSION"),
                     "not carried by this row")
        register = evidence.KNOWN_DIFFERENCES.read_text(encoding="utf-8").replace(
            "`CRABC-MI-OS-ON-DEMAND-ARENA-REFUSAL` — accepted", "`CRABC-MI-OS-ON-DEMAND-ARENA-REFUSAL` — observed")
        self.rejects(lambda entry: None, "not an accepted known-differences entry", register=register)

    def test_not_applicable_is_rejected_for_a_row_that_is_not_algorithmic(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        port_map = copy.deepcopy(self.port_map)
        target = next(row for row in port_map["item"] if row.get("name") == "linux-os-reuse-contained-range-noop")
        target["difference_kind"] = "algorithmic"
        manifest["rows"]["src/os.c:linux-os-reuse-contained-range-noop"] = copy.deepcopy(manifest["rows"][self.OS_ROW])
        with self.assertRaisesRegex(evidence.EvidenceError, "not carried by this row"):
            evidence.validate_manifest(manifest, port_map)
        target["difference_kind"] = "boundary"
        with self.assertRaisesRegex(evidence.EvidenceError, "not algorithmic"):
            evidence.validate_manifest(manifest, port_map)
        reasons = evidence.not_applicable_unmet(
            "src/os.c:linux-os-reuse-contained-range-noop", manifest["rows"][self.OS_ROW], port_map,
            evidence.KNOWN_DIFFERENCES.read_text(encoding="utf-8"))
        self.assertTrue(any("only for an algorithmic row" in reason for reason in reasons), reasons)

    def test_names_owned_blocked_failed_and_unmeasured_rows(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["rows"]["src/page-map.c:mi-page-map-init-once-process-publication"] = {
            "owner": "a lane", "disposition": "port the source behavior"}
        results = {row["row"]: row for row in evidence.evaluate(
            manifest, run=lambda command: {"status": 1 if "heap_lifecycle" in command[1] else 0})}
        self.assertIn("owned by a lane", results["src/page-map.c:mi-page-map-init-once-process-publication"]["detail"][0])
        child = results["src/heap.c:child-thread-empty-non-main-heap-lifecycle"]["detail"]
        self.assertTrue(any("heap_lifecycle.py failed" in item for item in child), child)
        self.assertTrue(any("performance blocked" in item for item in child), child)
        self.assertIn("no qualified integrated report measures", results["src/random.c"]["detail"][0])
        self.assertTrue(results["src/arena.c:os-fallback-commit-on-demand-initially-committed-correction"]["met"])

    def test_correctness_defers_timing_but_keeps_every_differential(self) -> None:
        calls = []
        results = {row["row"]: row for row in evidence.evaluate(
            self.manifest, profile="correctness",
            run=lambda command: calls.append(command) or {"status": 0})}
        self.assertTrue(all(row["met"] for row in results.values()), results)
        self.assertEqual(sum("--m1" in command for command in calls), 1)
        self.assertTrue(all("performance deferred" in row["detail"][-1]
                            for row in results.values()))
        failed = {row["row"]: row for row in evidence.evaluate(
            self.manifest, profile="correctness", run=lambda command: {"status": 7})}
        self.assertFalse(failed["src/random.c"]["met"])
        self.assertIn("failed (7)", failed["src/random.c"]["detail"][0])
        owned = {"rows": {"source": {"owner": "unfinished", "disposition": "missing lifetime proof"}}}
        self.assertFalse(evidence.evaluate(owned, profile="correctness")[0]["met"])

    def test_unknown_profile_is_rejected_before_running_a_differential(self) -> None:
        run = mock.Mock(return_value={"status": 0})
        with self.assertRaisesRegex(ValueError, "unknown divergence profile"):
            evidence.evaluate(self.manifest, profile="partial", run=run)
        run.assert_not_called()

    def test_correctness_still_rejects_a_missing_differential(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        del manifest["rows"]["src/random.c"]["differential"]
        with self.assertRaisesRegex(evidence.EvidenceError, "differential and performance"):
            evidence.validate_manifest(manifest, self.port_map)

    def test_cli_profile_selection_is_closed_before_input_loading(self) -> None:
        with mock.patch.object(evidence, "load") as load, mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                evidence.main(["--profile", "partial"])
            self.assertEqual(error.exception.code, 2)
            load.assert_not_called()

    def test_correctness_cli_does_not_import_or_read_performance_reports(self) -> None:
        # Poisoning these modules proves the functional route never even
        # imports the timing readers, regardless of available report paths.
        with mock.patch.object(evidence, "load", return_value=(self.manifest, self.port_map)), \
             mock.patch.object(evidence, "run_command", return_value={"status": 0}) as run, \
             mock.patch.dict(sys.modules, {"perf_engine_x86_64": None, "perf_integrated_x86_64": None}), \
             mock.patch("sys.stdout", new=io.StringIO()) as output:
            self.assertEqual(evidence.main(["--profile", "correctness"]), 0)
            self.assertIn("performance deferred", output.getvalue())
            self.assertTrue(run.called)

    def test_default_cli_still_requires_qualified_performance(self) -> None:
        gate = mock.Mock()
        gate.discover_integrated.return_value = []
        gate.discover_reports.return_value = []
        with mock.patch.object(evidence, "load", return_value=(self.manifest, self.port_map)), \
             mock.patch.object(evidence, "run_command", return_value={"status": 0}), \
             mock.patch.dict(sys.modules, {"perf_engine_x86_64": mock.Mock(),
                                          "perf_integrated_x86_64": mock.Mock(),
                                          "x86_64_m9_gate": gate}), \
             mock.patch("sys.stdout", new=io.StringIO()) as output:
            self.assertEqual(evidence.main([]), 1)
            gate.discover_integrated.assert_called_once()
            gate.discover_reports.assert_called_once()
            self.assertIn("no qualified integrated report", output.getvalue())
            self.assertIn("performance blocked", output.getvalue())

    def test_a_qualified_integrated_measurement_and_passing_differential_meet_a_row(self) -> None:
        commands = []
        results = {row["row"]: row for row in evidence.evaluate(
            self.manifest, run=lambda command: commands.append(command) or {"status": 0},
            integrated_rows={"static/startup_first_alloc", "dynamic/startup_first_alloc"})}
        self.assertTrue(results["src/random.c"]["met"])
        self.assertEqual(sum(1 for command in commands if "--m1" in command), 1, "a shared command runs once")


if __name__ == "__main__":
    unittest.main()
