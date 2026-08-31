#!/usr/bin/env python3
"""Executable contract checks for the native-mimalloc architecture ratchet."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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
        self.assertIn("promotion-qualified runtime/artifact evidence", report["summary"]["unmet"])
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
        self.assertEqual(report["ratchet"]["regressions"], [])
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
        self.assertEqual(stress["current_max_workers"], 0)
        self.assertFalse(stress["current_large_mode"])
        self.assertEqual(stress["status"], "unmet")
        self.assertIsInstance(stress["reason"], str)
        self.assertTrue(stress["reason"])

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
            ["promotion-qualified runtime/artifact evidence"],
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
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "target/libc.so"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"selected production artifact")
            incomplete = {
                "format": 1,
                "schema": RATCHET.RUNTIME_EVIDENCE_SCHEMA,
                "evidence_scope": "promotion_qualified",
                "selected_production": {
                    "feature": report["selected_production"]["feature"],
                    "source_sha256": report["selected_production"]["sources"],
                },
                "artifact": {
                    "path": "target/libc.so",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                },
                "metrics": {
                    name: metric["final_required"] for name, metric in report["metrics"].items()
                },
            }
            evidence_path = root / "runtime-evidence.json"
            evidence_path.write_text(json.dumps(incomplete), encoding="utf-8")
            with self.assertRaisesRegex(RATCHET.RatchetError, "Phase-B/C"):
                RATCHET.load_runtime_evidence(
                    evidence_path,
                    report["selected_production"],
                    self.manifest,
                    root,
                )

    def test_runtime_evidence_requires_exact_final_scope_and_verified_artifact(self) -> None:
        report = RATCHET.evaluate(ROOT, MANIFEST, None)
        required_phase_bc = self.manifest["phase_bc_call_graph"]["runtime_evidence_required"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "target/libc.so"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"selected production artifact")
            evidence = {
                "format": 1,
                "schema": RATCHET.RUNTIME_EVIDENCE_SCHEMA,
                "evidence_scope": "production_general",
                "selected_production": {
                    "feature": report["selected_production"]["feature"],
                    "source_sha256": report["selected_production"]["sources"],
                },
                "artifact": {
                    "path": "target/libc.so",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                },
                "metrics": {
                    name: metric["final_required"] for name, metric in report["metrics"].items()
                },
                "phase_bc": required_phase_bc,
            }
            evidence_path = root / "runtime-evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(RATCHET.RatchetError, "exact final scope"):
                RATCHET.load_runtime_evidence(
                    evidence_path, report["selected_production"], self.manifest, root
                )

            evidence["evidence_scope"] = "promotion_qualified"
            evidence["artifact"]["sha256"] = "0" * 64
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(RATCHET.RatchetError, "artifact SHA-256 mismatch"):
                RATCHET.load_runtime_evidence(
                    evidence_path, report["selected_production"], self.manifest, root
                )

            artifact.unlink()
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(RATCHET.RatchetError, "artifact is absent"):
                RATCHET.load_runtime_evidence(
                    evidence_path, report["selected_production"], self.manifest, root
                )

    def test_runtime_performance_claims_fail_closed_without_a_real_producer_schema(self) -> None:
        report = RATCHET.evaluate(ROOT, MANIFEST, None)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "target/libc.so"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"selected production artifact")
            evidence = {
                "format": 1,
                "schema": RATCHET.RUNTIME_EVIDENCE_SCHEMA,
                "evidence_scope": "promotion_qualified",
                "selected_production": {
                    "feature": report["selected_production"]["feature"],
                    "source_sha256": report["selected_production"]["sources"],
                },
                "artifact": {
                    "path": "target/libc.so",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                },
                "metrics": {
                    name: metric["final_required"] for name, metric in report["metrics"].items()
                },
                "phase_bc": self.manifest["phase_bc_call_graph"]["runtime_evidence_required"],
            }
            evidence_path = root / "runtime-evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(RATCHET.RatchetError, "benchmark producer schema"):
                RATCHET.load_runtime_evidence(
                    evidence_path, report["selected_production"], self.manifest, root
                )
        synthetic = copy.deepcopy(report)
        synthetic["runtime_artifact_evidence"] = {
            "present": True,
            "evidence": evidence,
            "required_phase_bc": self.manifest["phase_bc_call_graph"][
                "runtime_evidence_required"
            ],
        }
        unmet = RATCHET.gate_unmet(synthetic)
        for name in RATCHET.PROMOTION_BENCHMARK_METRICS:
            self.assertIn(
                f"runtime evidence {name} lacks validated benchmark samples/provenance",
                unmet,
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
#[cfg(not(test))]
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

    def test_production_cfg_keeps_not_test_and_excludes_test_consistently(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["forbidden_scaffolding"]["patterns"] = {
            "production_only": {
                "path": "runtime.rs",
                "pattern": r"\bstruct\s+ProductionOnlyScaffold\b",
            },
            "test_only": {
                "path": "runtime.rs",
                "pattern": r"\bstruct\s+TestOnlyScaffold\b",
            },
            "disabled": {
                "path": "runtime.rs",
                "pattern": r"\bstruct\s+DisabledScaffold\b",
            },
        }
        source = """\
#[cfg(not(test))]
struct ProductionOnlyScaffold;
#[cfg(test)]
struct TestOnlyScaffold;
#[cfg(any())]
struct DisabledScaffold;
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runtime.rs").write_text(source, encoding="utf-8")
            forbidden = RATCHET.collect_forbidden_scaffolding(root, manifest)
        self.assertEqual(set(forbidden["found"]), {"production_only"})

    def test_unknown_production_cfg_fails_closed(self) -> None:
        source = """\
#[cfg(allocator_magic)]
fn hidden_or_selected() {}
"""
        with self.assertRaisesRegex(RATCHET.RatchetError, "unknown production cfg"):
            RATCHET.production_rust_source(
                source, self.manifest["phase_bc_call_graph"]["cfg_environment"]
            )

    def test_canonical_upstream_stress_complete_matrix_is_consumed(self) -> None:
        cargo_target = {
            "kind": ["cdylib", "staticlib"],
            "crate_types": ["cdylib", "staticlib"],
            "name": "c",
            "src_path": "libc/src/lib.rs",
            "edition": "2021",
            "doc": True,
            "doctest": False,
            "test": False,
        }
        cargo_profile = {
            "opt_level": "2",
            "debuginfo": 2,
            "debug_assertions": True,
            "overflow_checks": False,
            "test": False,
        }
        artifact_ids = [
            "contract",
            "upstream_archive",
            "source_member",
            "owned_sysroot_manifest",
            "owned_sysroot_purity",
            "owned_compiler",
            "selected_loader",
            "staged_canonical_loader",
            "selected_libc",
            "selected_static_libc",
            "selected_backend_build_record",
            "stress_binary",
        ]
        matrix = [
            {
                "id": f"workers-{workers}-scale-{scale}-iterations-{iterations}",
                "workers": workers,
                "scale": scale,
                "iterations": iterations,
                "arguments": [str(workers), str(scale), str(iterations)],
                "expected_stdout": f"workers={workers} scale={scale} iterations={iterations}\n",
                "expected_stderr": "",
                "expected_exit_status": 0,
            }
            for scale, iterations in ((1, 1), (2, 2))
            for workers in (1, 2, 4, 8)
        ]
        contract = {
            "format": 5,
            "schema": "crabc-mimalloc-canonical-upstream-stress",
            "upstream": {
                "project": "microsoft/mimalloc",
                "version": "3.5.0",
                "tag": "v3.5.0",
                "tag_object": "tag-object",
                "revision": self.manifest["upstream"]["revision"],
                "repository": "https://github.com/microsoft/mimalloc.git",
                "archive_source": "https://example.invalid/mimalloc.tar.gz",
                "archive_path": "cache/mimalloc.tar.gz",
                "archive_root": "mimalloc-3.5.0",
                "archive_sha256": "1" * 64,
            },
            "target_inventory": {
                "selected": "linux-aarch64-little-endian",
                "targets": [{"id": "linux-aarch64-little-endian", "status": "applicable"}],
            },
            "backend_inventory": {
                "selected": "crabc-libc-native-mimalloc-shadow",
                "backends": [{
                    "id": "crabc-libc-native-mimalloc-shadow",
                    "allocator_feature": "native-mimalloc-shadow",
                    "c_backend_fallback": False,
                    "artifact_attestation": {
                        "cargo_compiler_artifact": {
                            "build_record_format": 1,
                            "build_record_schema": "crabc-selected-libc-cargo-build",
                            "cargo_command": [
                                "cargo", "build", "-p", "crabc-libc", "--features",
                                "native-mimalloc-shadow", "--profile", "dev",
                                "--message-format=json-render-diagnostics",
                            ],
                            "package_id_suffix": "#crabc-libc@0.3.0",
                            "manifest_path": "libc/Cargo.toml",
                            "target": cargo_target,
                            "semantic_profile": "dev",
                            "profile": cargo_profile,
                            "exact_features": ["default", "native-mimalloc-shadow"],
                            "artifacts": {
                                "selected_shared_libc": "libc.so",
                                "selected_static_libc": "libc.a",
                            },
                        },
                        "exported_free_route": {
                            "symbol": "free",
                            "required_callee_suffix": "native_free>",
                            "forbidden_callee_suffix": "mi_free>",
                        },
                    },
                }],
            },
            "source_adaptation": {"kind": "upstream-preprocessor-symbol-selection-only", "patches": []},
            "execution": {
                "matrix": matrix,
                "process_attempts_per_case": 1,
                "stop_after_first_nonpass": True,
                "large_object_mode": {"status": "not-claimed"},
            },
            "capability": {
                "id": "canonical-unmodified-upstream-pthread-stress",
                "required_worker_counts": [1, 2, 4, 8],
                "evidence_scope": "shadow_subset",
                "blocked_is_failure_closed": True,
            },
            "report": {
                "format": 4,
                "schema": "crabc-mimalloc-canonical-upstream-stress-report",
                "path": "reports/upstream-stress.json",
                "fixture_elf_fields": ["dynamic_dependencies", "elf_identity", "interpreter"],
                "artifact_ids": artifact_ids,
            },
            "compile_requirements": {
                "expected_dynamic_dependencies": ["libc.so"],
                "expected_elf_identity": {
                    "class": "ELF64",
                    "endianness": "little",
                    "machine": "AArch64",
                },
                "expected_interpreter": "/lib/ld-crabc-aarch64.so.1",
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected_shared = root / "target/debug/libc.so"
            selected_static = root / "target/debug/libc.a"
            selected_build_record = (
                root / "target/compat/allocator/upstream-stress/selected-libc-build.json"
            )
            selected_shared.parent.mkdir(parents=True)
            selected_build_record.parent.mkdir(parents=True)
            selected_shared.write_bytes(b"attested shared libc")
            selected_static.write_bytes(b"attested static libc")
            selected_build_record.write_text('{"schema":"build-record"}\n', encoding="utf-8")

            def artifact_record(path: Path) -> dict[str, object]:
                payload = path.read_bytes()
                return {
                    "path": str(path.relative_to(root)),
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }

            shared_record = artifact_record(selected_shared)
            static_record = artifact_record(selected_static)
            build_record = artifact_record(selected_build_record)
            contract_path = root / "upstream-stress.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            contract_bytes = contract_path.read_bytes()
            case_results = []
            for attempt, case in enumerate(matrix, start=1):
                stdout = case["expected_stdout"].encode()
                stderr = case["expected_stderr"].encode()
                case_results.append({
                    "case": {key: case[key] for key in ("id", "workers", "scale", "iterations", "arguments")},
                    "process_attempt": attempt,
                    "state": "passed",
                    "observation": {
                        "command": ["/fixture", *case["arguments"]],
                        "kind": "process",
                        "status": 0,
                        "stdout": {"bytes": len(stdout), "sha256": hashlib.sha256(stdout).hexdigest(), "hex": stdout.hex()},
                        "stderr": {"bytes": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest(), "hex": stderr.hex()},
                    },
                })
            stress_report = {
                "format": 4,
                "schema": "crabc-mimalloc-canonical-upstream-stress-report",
                "status": "passed",
                "contract": {
                    "path": "upstream-stress.json",
                    "bytes": len(contract_bytes),
                    "sha256": hashlib.sha256(contract_bytes).hexdigest(),
                    "upstream": contract["upstream"],
                },
                "selection": {
                    "target": contract["target_inventory"]["targets"][0],
                    "backend": contract["backend_inventory"]["selected"],
                },
                "artifacts": {
                    artifact_id: (
                        shared_record if artifact_id == "selected_libc" else
                        static_record if artifact_id == "selected_static_libc" else
                        build_record if artifact_id == "selected_backend_build_record" else
                        None
                    )
                    for artifact_id in artifact_ids
                },
                "runtime": {
                    "backend_attestation": {
                        "backend": "crabc-libc-native-mimalloc-shadow",
                        "semantic_profile": "dev",
                        "cargo_features": ["default", "native-mimalloc-shadow"],
                        "build_record": build_record,
                        "compiler_artifact": {
                            "package_id": "path+file:///workspace/libc#crabc-libc@0.3.0",
                            "target": cargo_target,
                            "profile": cargo_profile,
                            "features": ["default", "native-mimalloc-shadow"],
                            "filenames": [shared_record["path"], static_record["path"]],
                            "fresh": True,
                        },
                        "artifacts": {
                            "selected_shared_libc": shared_record,
                            "selected_static_libc": static_record,
                        },
                        "exported_free": {
                            "symbol": "free",
                            "required_callee_suffix": "native_free>",
                            "forbidden_callee_suffix": "mi_free>",
                            "disassembly_sha256": "2" * 64,
                        },
                        "status": "passed",
                    },
                },
                "fixture_elf": {
                    "dynamic_dependencies": ["libc.so"],
                    "elf_identity": {
                        "class": "ELF64",
                        "endianness": "little",
                        "machine": "AArch64",
                    },
                    "interpreter": "/lib/ld-crabc-aarch64.so.1",
                },
                "dynamic_dependencies": ["libc.so"],
                "execution": {
                    "attempted": True,
                    "attempted_process_count": len(matrix),
                    "case_count": len(matrix),
                    "case_results": case_results,
                    "process_attempts_per_case": 1,
                },
                "capability": {
                    "id": contract["capability"]["id"],
                    "status": "passed",
                    "failure_closed": True,
                    "native_execution_started": True,
                    "native_execution_completed": True,
                    "passed_case_count": len(matrix),
                    "required_case_count": len(matrix),
                    "fully_verified_worker_counts": [1, 2, 4, 8],
                    "required_worker_counts": [1, 2, 4, 8],
                },
                "first_fact": {"kind": "pass", "stage": "matrix", "completed_case_count": len(matrix)},
                "upstream_pin": {
                    "archive_root": contract["upstream"]["archive_root"],
                    "repository": contract["upstream"]["repository"],
                    "revision": contract["upstream"]["revision"],
                    "sha256": contract["upstream"]["archive_sha256"],
                    "source": contract["upstream"]["archive_source"],
                    "tag": contract["upstream"]["tag"],
                    "tag_object": contract["upstream"]["tag_object"],
                    "version": contract["upstream"]["version"],
                },
            }
            report_path = root / "reports/upstream-stress.json"
            report_path.parent.mkdir()
            report_path.write_text(json.dumps(stress_report), encoding="utf-8")
            manifest = copy.deepcopy(self.manifest)
            manifest["contracts"] = {"canonical_upstream_stress": "upstream-stress.json"}
            capability = RATCHET.upstream_stress_capability(root, manifest)
            self.assertEqual(capability["status"], "verified")
            self.assertEqual(capability["current_max_workers"], 8)
            self.assertFalse(capability["current_large_mode"])

            stress_report["runtime"]["backend_attestation"]["semantic_profile"] = "test"
            report_path.write_text(json.dumps(stress_report), encoding="utf-8")
            rejected_profile = RATCHET.upstream_stress_capability(root, manifest)
            self.assertEqual(rejected_profile["status"], "unmet")
            self.assertIn("backend artifact attestation", rejected_profile["reason"])
            stress_report["runtime"]["backend_attestation"]["semantic_profile"] = "dev"

            stress_report["execution"]["case_results"][-1]["observation"]["stdout"]["hex"] = ""
            report_path.write_text(json.dumps(stress_report), encoding="utf-8")
            rejected = RATCHET.upstream_stress_capability(root, manifest)
            self.assertEqual(rejected["status"], "unmet")
            self.assertIn("byte-stream", rejected["reason"])

    def test_reports_are_published_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reports/latest.json"
            real_replace = RATCHET.os.replace
            observations = []

            def observed_replace(source: object, destination: object) -> None:
                staged = Path(source)
                destination_path = Path(destination)
                observations.append((staged.parent, destination_path.exists(), json.loads(staged.read_text())))
                real_replace(source, destination)

            with mock.patch.object(RATCHET.os, "replace", side_effect=observed_replace):
                RATCHET.write_json(path, {"status": "complete"})
            self.assertEqual(
                observations,
                [(path.parent.resolve(), False, {"status": "complete"})],
            )
            self.assertEqual(json.loads(path.read_text()), {"status": "complete"})
            self.assertEqual(list(path.parent.glob(f".{path.name}.*")), [])

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
