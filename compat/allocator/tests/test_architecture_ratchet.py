#!/usr/bin/env python3
"""Executable contract checks for the native-mimalloc architecture ratchet."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "compat/allocator/architecture-gate-v3.5.0.json"
SCRIPT = ROOT / "compat/allocator/architecture_ratchet.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_architecture_ratchet", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RATCHET = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RATCHET
SPEC.loader.exec_module(RATCHET)


class ArchitectureRatchetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        RATCHET.validate_manifest(cls.manifest)

    def test_checked_in_report_records_the_current_shadow_subset_as_unmet(self) -> None:
        report = RATCHET.evaluate(ROOT, MANIFEST, None)
        self.assertEqual(report["scope"]["current"], "shadow_subset")
        self.assertTrue(report["scope"]["static_analysis_cannot_close_final_gate"])
        self.assertEqual(report["selected_production"]["status"], "static-selection-confirmed")
        manifest_metadata = report["selected_production"]["libc_manifest"]
        self.assertTrue(manifest_metadata["feature_declared"])
        self.assertTrue(manifest_metadata["native_engine_dependency_declared"])
        self.assertTrue(manifest_metadata["c_oracle_dependency_declared"])
        self.assertFalse(report["summary"]["final_architecture_passed"])
        self.assertEqual(report["summary"]["gate_status"], "unmet")
        self.assertTrue(report["summary"]["static_analysis_only"])
        self.assertIn("production-general runtime/artifact evidence", report["summary"]["unmet"])
        ceilings = self.manifest["ratchet_baseline"]["static_signal_ceiling"]
        selected_source_metrics = {
            "local_hot_path_process_scheduler_ops",
            "local_hot_path_global_pagemap_leases",
            "local_operation_owner_registry_scans",
            "local_operation_client_ledger_scans",
            "remote_free_owner_registry_scans",
            "extra_control_bytes_per_live_allocation",
            "per_call_engine_park_resume",
            "exited_owner_admission_survives_thread_exit",
        }
        for name, metric in report["metrics"].items():
            self.assertLessEqual(metric["source_indicator_count"], ceilings[name])
            if name in selected_source_metrics:
                self.assertGreater(metric["source_indicator_count"], 0)
            else:
                self.assertEqual(metric["source_indicator_count"], 0)
        self.assertEqual(
            set(report["forbidden_scaffolding_compiled"]["found"]),
            {
                "exited_owner_admission_claim",
                "geometry_shaped_post_exit_route",
                "live_remote_owner_registry",
                "per_call_parked_engine",
                "post_exit_route_registry",
                "prepared_owner_exit_clients",
                "process_global_page_owner_scheduler",
            },
        )
        stress = report["unmodified_upstream_stress"]
        self.assertEqual(stress["inventory_status"], "adapted-milestone-5")
        self.assertEqual(stress["current_max_workers"], 0)
        self.assertFalse(stress["current_large_mode"])
        self.assertEqual(stress["status"], "unmet")
        self.assertEqual(report["ratchet"]["regressions"], [])

    def test_comment_only_scaffolding_is_not_treated_as_compiled(self) -> None:
        source = """\
// struct NativeLiveRemoteOwnerRegistry {}
/* struct NativePostExitRouteRegistry {} */
let description = \"struct PreparedOwnerExitClients {}\";
struct CurrentSource {};
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "runtime.rs"
            source_path.write_text(source, encoding="utf-8")
            self.assertEqual(
                RATCHET.source_matches(root, "runtime.rs", r"\bstruct\s+NativeLiveRemoteOwnerRegistry\b"),
                [],
            )
            self.assertEqual(
                RATCHET.source_matches(root, "runtime.rs", r"\bstruct\s+CurrentSource\b")[0].line,
                4,
            )

    def test_static_absence_cannot_close_the_gate_without_runtime_artifact_evidence(self) -> None:
        report = RATCHET.evaluate(ROOT, MANIFEST, None)
        synthetic = copy.deepcopy(report)
        synthetic["forbidden_scaffolding_compiled"]["compiled_from_selected_source"] = False
        synthetic["unmodified_upstream_stress"]["status"] = "verified"
        for metric in synthetic["metrics"].values():
            metric["source_indicator_count"] = 0
        self.assertEqual(
            RATCHET.gate_unmet(synthetic),
            ["production-general runtime/artifact evidence"],
        )

    def test_runtime_evidence_requires_selected_artifact_metadata_and_matching_sources(self) -> None:
        report = RATCHET.evaluate(ROOT, MANIFEST, None)
        incomplete = {
            "format": 1,
            "schema": RATCHET.RUNTIME_EVIDENCE_SCHEMA,
            "evidence_scope": "production_general",
            "selected_production": {
                "feature": report["selected_production"]["feature"],
                "source_sha256": report["selected_production"]["sources"],
            },
            "metrics": {},
        }
        with tempfile.TemporaryDirectory() as temporary:
            evidence_path = Path(temporary) / "runtime-evidence.json"
            evidence_path.write_text(json.dumps(incomplete), encoding="utf-8")
            with self.assertRaisesRegex(RATCHET.RatchetError, "does not identify a selected artifact"):
                RATCHET.load_runtime_evidence(evidence_path, report["selected_production"])

    def test_static_signal_ceiling_rejects_a_regression(self) -> None:
        regressed = copy.deepcopy(self.manifest)
        regressed["ratchet_baseline"]["static_signal_ceiling"][
            "local_hot_path_process_scheduler_ops"
        ] = 0
        signals = {name: [] for name in regressed["metrics"]}
        signals["local_hot_path_process_scheduler_ops"] = [
            RATCHET.SourceMatch("runtime.rs", 1, "page_owner_state")
        ]
        regressions = RATCHET.ratchet_regressions(regressed, signals)
        self.assertEqual(
            regressions,
            ["local_hot_path_process_scheduler_ops: 1 source indicators exceed ratchet ceiling 0"],
        )

    def test_cli_writes_a_report_but_gate_refuses_the_current_unmet_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "architecture.json"
            checked = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(ROOT), "--report", str(report), "--check"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertTrue(report.is_file())
            self.assertFalse(json.loads(report.read_text(encoding="utf-8"))["summary"]["final_architecture_passed"])
            gated = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(ROOT), "--report", str(report), "--gate"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(gated.returncode, 1)
            self.assertIn("architecture gate unmet:", gated.stderr)


if __name__ == "__main__":
    unittest.main()
