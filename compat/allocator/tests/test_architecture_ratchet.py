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
        dispatch = report["caller_identity_first_free_dispatch"]
        self.assertEqual(dispatch["status"], "forbidden")
        self.assertTrue(dispatch["caller_identity_first"])
        self.assertFalse(dispatch["final_acceptance"])
        self.assertEqual(
            dispatch["phase_a_bridge"]["marker"],
            "CRABC-MI-PHASE-A-CALLER-IDENTITY-FREE-BRIDGE",
        )
        self.assertIn("pointer-to-page", dispatch["phase_a_bridge"]["removal_condition"])
        self.assertFalse(dispatch["phase_a_bridge"]["active"])
        self.assertEqual(dispatch["phase_a_bridge"]["marker_matches"], [])
        self.assertEqual(
            report["structural_violations"],
            ["caller-identity-first native_free dispatch"],
        )
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
        expected_regressions = [
            "local_operation_owner_registry_scans: 15 source indicators exceed ratchet ceiling 14",
            "remote_free_owner_registry_scans: 17 source indicators exceed ratchet ceiling 16",
        ]
        self.assertEqual(report["ratchet"]["regressions"], expected_regressions)
        for name, metric in report["metrics"].items():
            if name in {
                "local_operation_owner_registry_scans",
                "remote_free_owner_registry_scans",
            }:
                self.assertGreater(metric["source_indicator_count"], ceilings[name])
            else:
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
        synthetic["caller_identity_first_free_dispatch"]["status"] = "no_caller_identity_dispatch"
        for metric in synthetic["metrics"].values():
            metric["source_indicator_count"] = 0
        self.assertEqual(
            RATCHET.gate_unmet(synthetic),
            ["production-general runtime/artifact evidence"],
        )

    def test_phase_a_bridge_requires_its_explicit_removal_condition(self) -> None:
        invalid = copy.deepcopy(self.manifest)
        del invalid["caller_identity_first_free_dispatch"]["phase_a_bridge"]["removal_condition"]
        with self.assertRaisesRegex(RATCHET.RatchetError, "removal_condition"):
            RATCHET.validate_manifest(invalid)

    def test_phase_a_bridge_manifest_requires_a_sole_identity_branch(self) -> None:
        invalid = copy.deepcopy(self.manifest)
        invalid["caller_identity_first_free_dispatch"]["maximum_phase_a_identity_matches"] = 2
        with self.assertRaisesRegex(RATCHET.RatchetError, "sole identity branch"):
            RATCHET.validate_manifest(invalid)

    def test_phase_a_bridge_marker_must_be_inside_and_before_its_sole_identity_branch(self) -> None:
        policy = copy.deepcopy(self.manifest)
        policy["caller_identity_first_free_dispatch"]["path"] = "runtime.rs"
        marker = policy["caller_identity_first_free_dispatch"]["phase_a_bridge"]["marker"]
        marked_before = f"""\
pub unsafe fn native_free() {{
    // {marker}
    if RUNTIME_PROCESS.is_on_initial_thread() {{}}
}}
"""
        marked_after = f"""\
pub unsafe fn native_free() {{
    if RUNTIME_PROCESS.is_on_initial_thread() {{}}
    // {marker}
}}
"""
        marker_outside_function = f"""\
// {marker}
pub unsafe fn native_free() {{
    if RUNTIME_PROCESS.is_on_initial_thread() {{}}
}}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "runtime.rs"
            source.write_text(marked_before, encoding="utf-8")
            bridge = RATCHET.caller_identity_first_free_dispatch(root, policy)
            self.assertEqual(bridge["status"], "phase_a_bridge")
            self.assertTrue(bridge["phase_a_bridge"]["active"])
            source.write_text(marked_after, encoding="utf-8")
            late_marker = RATCHET.caller_identity_first_free_dispatch(root, policy)
            self.assertEqual(late_marker["status"], "forbidden")
            self.assertTrue(late_marker["phase_a_bridge"]["marker_matches"])
            self.assertEqual(late_marker["phase_a_bridge"]["marker_matches_before_or_at_identity"], [])
            source.write_text(marker_outside_function, encoding="utf-8")
            outside_marker = RATCHET.caller_identity_first_free_dispatch(root, policy)
            self.assertEqual(outside_marker["status"], "forbidden")
            self.assertEqual(outside_marker["phase_a_bridge"]["marker_matches"], [])

    def test_structural_checker_allows_pointer_first_but_rejects_an_extra_identity_branch(self) -> None:
        policy = copy.deepcopy(self.manifest)
        policy["caller_identity_first_free_dispatch"]["path"] = "runtime.rs"
        pointer_first_source = """\
pub unsafe fn native_free() { lookup_page_for_live_client(); if RUNTIME_PROCESS.is_on_initial_thread() {} }
"""
        repeated_identity_source = """\
pub unsafe fn native_free() {
    if RUNTIME_PROCESS.is_on_initial_thread() {}
    if RUNTIME_PROCESS.is_on_initial_thread() {}
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "runtime.rs"
            source.write_text(pointer_first_source, encoding="utf-8")
            pointer_first = RATCHET.caller_identity_first_free_dispatch(root, policy)
            self.assertEqual(pointer_first["status"], "pointer_dispatch_first")
            self.assertFalse(pointer_first["structural_violation"])
            source.write_text(repeated_identity_source, encoding="utf-8")
            repeated_identity = RATCHET.caller_identity_first_free_dispatch(root, policy)
            self.assertEqual(repeated_identity["status"], "forbidden")
            self.assertTrue(repeated_identity["structural_violation"])

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
            self.assertEqual(checked.returncode, 1)
            self.assertTrue(report.is_file())
            self.assertIn("architecture structural prohibition:", checked.stderr)
            self.assertFalse(json.loads(report.read_text(encoding="utf-8"))["summary"]["final_architecture_passed"])
            gated = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(ROOT), "--report", str(report), "--gate"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(gated.returncode, 1)
            self.assertIn("architecture structural prohibition:", gated.stderr)


if __name__ == "__main__":
    unittest.main()
