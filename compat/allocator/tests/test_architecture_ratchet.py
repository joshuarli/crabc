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

        phase_bc = report["phase_bc_selected_production_reachability"]
        self.assertEqual(phase_bc["evidence_kind"], "syntactic selected-source may-reachability")
        self.assertEqual(
            {entry["function"] for entry in phase_bc["entry_points"]},
            {"native_allocate_aligned", "native_free", "native_reallocate", "native_usable_size"},
        )
        self.assertFalse(phase_bc["final_acceptance"])
        self.assertTrue(phase_bc["ratchets"]["caller_identity_first_native_free"]["matches"])
        self.assertTrue(phase_bc["ratchets"]["per_call_scheduler_park_resume"]["matches"])
        self.assertTrue(phase_bc["ratchets"]["long_pagemap_mutation_lease"]["matches"])
        self.assertTrue(phase_bc["ratchets"]["ledger_owner_registry_scans"]["matches"])
        phase_bc_ceilings = self.manifest["ratchet_baseline"][
            "phase_bc_selected_production_reachable_ceiling"
        ]
        for name, ceiling in phase_bc_ceilings.items():
            ratchet = phase_bc["ratchets"][name]
            self.assertEqual(ratchet["reachable_indicator_count"], ceiling)
            self.assertTrue(ratchet["within_ratchet_ceiling"])
            self.assertFalse(ratchet["static_final_requirement_met"])
        remote_projection = phase_bc["ratchets"]["page_local_remote_free_projection"]
        self.assertEqual(remote_projection["status"], "static-projection-only")
        self.assertFalse(remote_projection["final_acceptance"])
        self.assertEqual(set(remote_projection["pattern_counts"]), {
            "atomic_remote_push",
            "canonical_remote_block",
            "live_page_lookup",
        })
        self.assertTrue(all(count >= 1 for count in remote_projection["pattern_counts"].values()))
        self.assertIn(
            "Phase B/C caller_identity_first_native_free has selected-production-reachable indicators",
            report["summary"]["unmet"],
        )

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
        for ratchet in synthetic["phase_bc_selected_production_reachability"]["ratchets"].values():
            if ratchet["direction"] == "maximum":
                ratchet["static_final_requirement_met"] = True
            else:
                ratchet["static_projection_present"] = True
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

    def test_phase_bc_manifest_does_not_allow_a_nonzero_final_ceiling(self) -> None:
        invalid = copy.deepcopy(self.manifest)
        invalid["phase_bc_call_graph"]["ratchets"]["ledger_owner_registry_scans"][
            "final_required"
        ] = 1
        with self.assertRaisesRegex(RATCHET.RatchetError, "must retain final_required 0"):
            RATCHET.validate_manifest(invalid)

    def test_phase_bc_sources_must_participate_in_runtime_evidence_hashing(self) -> None:
        invalid = copy.deepcopy(self.manifest)
        invalid["selected_production"]["sources"].remove(
            "crabc-mimalloc/src/main_heap_page.rs"
        )
        with self.assertRaisesRegex(RATCHET.RatchetError, "absent from selected source hashing"):
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

    def test_runtime_evidence_requires_explicit_phase_bc_observations(self) -> None:
        report = RATCHET.evaluate(ROOT, MANIFEST, None)
        incomplete = {
            "format": 1,
            "schema": RATCHET.RUNTIME_EVIDENCE_SCHEMA,
            "evidence_scope": "production_general",
            "selected_production": {
                "feature": report["selected_production"]["feature"],
                "source_sha256": report["selected_production"]["sources"],
            },
            "artifact": {"path": "target/libc.so", "sha256": "0" * 64},
            "metrics": {
                name: metric["final_required"] for name, metric in report["metrics"].items()
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            evidence_path = Path(temporary) / "runtime-evidence.json"
            evidence_path.write_text(json.dumps(incomplete), encoding="utf-8")
            with self.assertRaisesRegex(RATCHET.RatchetError, "Phase-B/C"):
                RATCHET.load_runtime_evidence(
                    evidence_path,
                    report["selected_production"],
                    self.manifest,
                )

    def test_phase_bc_runtime_observation_must_match_the_required_value(self) -> None:
        required = self.manifest["phase_bc_call_graph"]["runtime_evidence_required"]
        observed = copy.deepcopy(required)
        observed["phase_c"]["native_free_pointer_first"] = False
        self.assertEqual(
            RATCHET.phase_bc_evidence_mismatches(observed, required),
            ["phase_bc.phase_c.native_free_pointer_first"],
        )

    def test_phase_bc_call_graph_excludes_unreachable_and_test_only_functions(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        phase_bc = manifest["phase_bc_call_graph"]
        phase_bc["sources"] = ["runtime.rs", "helper.rs"]
        phase_bc["entry_points"] = [
            {"path": "runtime.rs", "function": "native_free", "public": True}
        ]
        for ratchet in phase_bc["ratchets"].values():
            ratchet.pop("entry_points", None)
        phase_bc["ratchets"]["caller_identity_first_native_free"]["entry_points"] = [
            {"path": "runtime.rs", "function": "native_free", "public": True}
        ]
        runtime_source = """\
pub unsafe fn native_free() {
    pointer_projection();
    local_compatibility_bridge();
    #[cfg(feature = "native-runtime-test-audit")]
    feature_test_only_scaffolding();
}

fn pointer_projection() {
    page_map.lookup_page_for_live_client(block);
    Page::canonical_remote_block_for_live_client_at(page, block);
    remote_free::push(page, block);
}

fn local_compatibility_bridge() {
    helper_path();
}

fn unreachable_scaffolding() {
    RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire);
    NATIVE_LIVE_REMOTE_OWNER.claim_exact_client(block);
}

#[cfg(test)]
fn test_only_scaffolding() {
    parked.resume(attachment);
    access.into_mutation_lease();
}

#[cfg(feature = "native-runtime-test-audit")]
fn feature_test_only_scaffolding() {
    NATIVE_LIVE_REMOTE_OWNER.claim_exact_client(block);
}
"""
        helper_source = """\
fn helper_path() {
    RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire);
    parked.resume(attachment);
    engine.suspend();
    page_map.begin_page_lifecycle();
    NATIVE_LIVE_REMOTE_OWNER.claim_current_slot(slot);
    clients.native_client_for_block(block);
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runtime.rs").write_text(runtime_source, encoding="utf-8")
            (root / "helper.rs").write_text(helper_source, encoding="utf-8")
            report = RATCHET.phase_bc_selected_production_reachability(root, manifest)

        reachable = {(item["path"], item["function"]) for item in report["reachable_functions"]}
        self.assertEqual(
            reachable,
            {
                ("helper.rs", "helper_path"),
                ("runtime.rs", "local_compatibility_bridge"),
                ("runtime.rs", "native_free"),
                ("runtime.rs", "pointer_projection"),
            },
        )
        self.assertNotIn(("runtime.rs", "unreachable_scaffolding"), reachable)
        self.assertNotIn(("runtime.rs", "test_only_scaffolding"), reachable)
        self.assertNotIn(("runtime.rs", "feature_test_only_scaffolding"), reachable)
        self.assertEqual(
            report["ratchets"]["page_local_remote_free_projection"]["pattern_counts"],
            {"atomic_remote_push": 1, "canonical_remote_block": 1, "live_page_lookup": 1},
        )
        for name in (
            "per_call_scheduler_park_resume",
            "long_pagemap_mutation_lease",
            "ledger_owner_registry_scans",
        ):
            self.assertTrue(report["ratchets"][name]["matches"])

    def test_phase_bc_reachable_ceiling_is_a_ratchet_not_an_acceptance_threshold(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        phase_bc = manifest["phase_bc_call_graph"]
        phase_bc["sources"] = ["runtime.rs"]
        phase_bc["entry_points"] = [
            {"path": "runtime.rs", "function": "native_free", "public": True}
        ]
        for ratchet in phase_bc["ratchets"].values():
            ratchet.pop("entry_points", None)
        phase_bc["ratchets"]["caller_identity_first_native_free"]["entry_points"] = [
            {"path": "runtime.rs", "function": "native_free", "public": True}
        ]
        baseline = manifest["ratchet_baseline"]
        baseline["phase_bc_selected_production_reachable_ceiling"] = {
            "caller_identity_first_native_free": 0,
            "ledger_owner_registry_scans": 0,
            "long_pagemap_mutation_lease": 0,
            "per_call_scheduler_park_resume": 0,
        }
        baseline["phase_bc_selected_production_reachable_floor_per_pattern"] = {
            "page_local_remote_free_projection": {
                "atomic_remote_push": 1,
                "canonical_remote_block": 1,
                "live_page_lookup": 1,
            }
        }
        source = """\
pub unsafe fn native_free() {
    pointer_projection();
    forbidden_helper();
}
fn pointer_projection() {
    page_map.lookup_page_for_live_client(block);
    Page::canonical_remote_block_for_live_client_at(page, block);
    remote_free::push(page, block);
}
fn forbidden_helper() {
    NATIVE_LIVE_REMOTE_OWNER.claim_exact_client(block);
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runtime.rs").write_text(source, encoding="utf-8")
            report = RATCHET.phase_bc_selected_production_reachability(root, manifest)

        ledger = report["ratchets"]["ledger_owner_registry_scans"]
        self.assertEqual(ledger["reachable_indicator_count"], 2)
        self.assertFalse(ledger["within_ratchet_ceiling"])
        self.assertFalse(ledger["final_acceptance"])
        self.assertEqual(
            report["regressions"],
            [
                "phase_bc ledger_owner_registry_scans: 2 selected-production-reachable "
                "indicators exceed ratchet ceiling 0"
            ],
        )

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
