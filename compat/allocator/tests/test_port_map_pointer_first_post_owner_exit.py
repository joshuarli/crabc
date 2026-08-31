#!/usr/bin/env python3
"""Focused contract for the pointer-first W03 post-owner-exit mapping."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PORT_MAP_PATH = ROOT / "compat/allocator/port-map.toml"
RATCHET_PATH = ROOT / "compat/allocator/ratchet-v3.5.0.json"
RUNNER_PATH = ROOT / "compat/allocator/run.py"
RUNTIME_LIFECYCLE_PATH = ROOT / "crabc-mimalloc/src/runtime_lifecycle.rs"
RUNTIME_EXPORTS_PATH = ROOT / "crabc-mimalloc/src/lib.rs"
TICKET_ZERO_CONTRACT_PATH = ROOT / "compat/allocator/runtime-ticket-zero-test-v3.5.0.json"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_pointer_first_port_map", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class PointerFirstPostOwnerExitPortMapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.port_map = RUNNER.load_port_map()

    def record(self) -> dict[str, object]:
        return self.item(
            "src/free.c",
            "page-owned-post-owner-exit-exact-remote-claim-terminal-tail",
        )

    def item(self, upstream: str, name: str) -> dict[str, object]:
        return next(
            item
            for item in self.port_map["item"]
            if item["upstream"] == upstream and item["name"] == name
        )

    def test_w03_mapping_separates_remote_publication_from_structural_page_map_serialization(
        self,
    ) -> None:
        record = self.record()

        self.assertEqual(self.port_map["metadata"]["upstream_version"], "3.5.0")
        self.assertEqual(
            self.port_map["metadata"]["upstream_revision"],
            "18b08671c9302247bfb682286e6bf3cc1773f801",
        )
        for source_fact in (
            "mimalloc v3.5.0",
            "src/free.c:63-95",
            "mi_free_block_mt allow_collect publication",
            "371-379 mi_abandoned_page_try_free",
            "480-515 mi_free_try_collect_mt",
            "src/page.c:214-243",
            "src/arena.c:1304-1355",
            "1384-1424",
            "1285-1298",
        ):
            self.assertIn(source_fact, record["source_region"])

        mapping = record["rust_module"] + record["rust_item"]
        for rust_fact in (
            "crabc_mimalloc::remote_free",
            "crabc_mimalloc::process_page_map",
            "push_post_owner_exit_live_allocation",
            "LiveRemoteFreePublish",
            "continue_post_owner_exit_live_allocation_with_process_page_facts",
            "ProcessPageMapMutationLease::finish_after_exact_post_owner_exit_operation",
        ):
            self.assertIn(rust_fact, mapping)

        scope = record["intentional_difference"]
        for invariant in (
            "page-local remote-free CAS is the normal publication serialization",
            "does not acquire a `ProcessPageMapMutationLease`",
            "serializes exactly that structural operation",
            "neither a route access nor a route/registry owner",
            "Detached is an explicit pre-CAS NotOwnerAssociated rejection",
            "does not own `NativePostExitRouteRegistry` or `NativePostExitFreeRoute`",
            "`#[cfg(test)]` historical oracle code only",
            "not a production mapping",
        ):
            self.assertIn(invariant, scope)

        # This record must not accidentally re-adopt the legacy route surface
        # while the production deletion slice is integrated elsewhere.
        for stale_mapping in (
            "NativePostExitRouteRegistry",
            "NativePostExitFreeRoute",
            "ProcessPageMapPostExitAccess",
            "geometry_shaped_post_exit_route",
        ):
            self.assertNotIn(stale_mapping, mapping)

        self.assertTrue(record["implemented"])
        self.assertTrue(record["unit_verified"])
        self.assertFalse(record["differential_verified"])
        self.assertFalse(record["stress_verified"])
        self.assertFalse(record["performance_qualified"])

    def test_legacy_owner_exit_facades_are_retired_from_live_port_mappings(self) -> None:
        stale_mapping_names = (
            "NativePostExitRouteRegistry",
            "NativePostExitFreeRoute",
            "DetachedOwnerExitClientLedger",
            "PreparedOwnerExitClients",
            "TicketZeroOwnerExit",
        )
        historical_oracle_rows = (
            ("src/init.c", "private-lazy-ticket-zero-runtime-first-arena-page-owner"),
            ("src/theap.c", "runtime-active-session-retired-page-prepass-before-opaque-route"),
            ("src/alloc.c", "private-ticket-zero-runtime-page-owner-prefixed-c-evidence-adapter"),
            ("src/free.c", "later-main-bounded-post-exit-same-page-remote-publication"),
            ("src/arena.c", "later-main-aggregate-last-mapped-regular-post-exit-allocation-adoption"),
        )

        for upstream, name in historical_oracle_rows:
            record = self.item(upstream, name)
            self.assertEqual(
                record["implementation_scope"],
                "test-only historical oracle; not a production mapping",
            )
            self.assertIn("#[cfg(test)]", record["historical_oracle_contract"])
            self.assertIn("production", record["historical_oracle_contract"].lower())
            self.assertNotIn(
                "crabc-mimalloc/tests/native_post_exit_registry_high_water.rs",
                record["tests"],
            )

        # Production `rust_module`/`rust_item` mappings must not preserve the
        # legacy facade names. The scoped historical rows above retain that
        # provenance without being selected as production behavior.
        for record in self.port_map["item"]:
            if record.get("implementation_scope") == (
                "test-only historical oracle; not a production mapping"
            ):
                continue
            mapping = record["rust_module"] + record["rust_item"]
            for stale_mapping in stale_mapping_names:
                self.assertNotIn(stale_mapping, mapping)

        shadow = self.item(
            "src/alloc.c",
            "nondefault-crabc-libc-native-mimalloc-shadow-ordinary-boundary",
        )
        self.assertEqual(
            shadow["implementation_scope"],
            "production nondefault pointer-first PageMap boundary",
        )
        shadow_scope = shadow["production_contract"]
        for production_fact in (
            "compile-time, nondefault early-shadow lane",
            "one coherent PageMap observation",
            "only nonlocal free continuation",
            "W03",
            "B finishes only B's own owner",
            "no route, registry, exact-client ledger scan",
        ):
            self.assertIn(production_fact, shadow_scope)
        self.assertIn("#[cfg(test)]", shadow["historical_detail_scope"])
        self.assertIn("not production behavior", shadow["historical_detail_scope"])
        self.assertNotIn(
            "crabc-mimalloc/tests/native_post_exit_registry_high_water.rs",
            shadow["tests"],
        )

    def test_legacy_facade_is_cfg_test_only_and_the_adapter_oracle_is_nine_by_two(self) -> None:
        lifecycle_source = RUNTIME_LIFECYCLE_PATH.read_text(encoding="utf-8")
        for declaration in (
            "enum NativePostExitFreeRoute {",
            "struct NativePostExitRouteRegistry {",
            "enum DetachedOwnerExitClientLedger {",
            "struct PreparedOwnerExitClients {",
            "pub struct TicketZeroOwnerExitFreeRoute",
            "pub struct TicketZeroOwnerExitReclaimRoute",
        ):
            declaration_offset = lifecycle_source.index(declaration)
            self.assertIn(
                "#[cfg(test)]",
                lifecycle_source[max(0, declaration_offset - 1_024) : declaration_offset],
                declaration,
            )

        exports_source = RUNTIME_EXPORTS_PATH.read_text(encoding="utf-8")
        runtime_module_start = exports_source.index("pub mod __crabc_runtime {")
        test_only_exports_start = exports_source.index("    #[cfg(test)]", runtime_module_start)
        self.assertNotIn(
            "TicketZeroOwnerExit",
            exports_source[runtime_module_start:test_only_exports_start],
        )

        ticket_zero_contract = json.loads(TICKET_ZERO_CONTRACT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(ticket_zero_contract["expected_adapter_symbols"]), 9)
        self.assertEqual(ticket_zero_contract["fixture_invocation"]["worker_routes_per_cycle"], 2)
        self.assertNotIn(
            "crabc_ticket_zero_test_worker_owner_exit_roundtrip",
            ticket_zero_contract["expected_adapter_symbols"],
        )
        self.assertNotIn(
            "crabc_ticket_zero_test_worker_owner_exit_reclaim_roundtrip",
            ticket_zero_contract["expected_adapter_symbols"],
        )

    def test_w03_requires_the_concurrent_native_c_selection_and_reviewed_ratchet(self) -> None:
        record = self.record()
        required_evidence = {
            "crabc-mimalloc/tests/native_post_exit_failed_os_release.rs",
            "tests/fixtures/native_mimalloc_concurrent_post_exit_release_test.c",
            "tests/native_mimalloc_concurrent_post_exit_release.rs",
        }
        self.assertLessEqual(required_evidence, set(record["tests"]))

        fixture = ROOT / "tests/fixtures/native_mimalloc_concurrent_post_exit_release_test.c"
        harness = ROOT / "tests/native_mimalloc_concurrent_post_exit_release.rs"
        self.assertTrue(fixture.is_file())
        self.assertTrue(harness.is_file())
        fixture_source = fixture.read_text(encoding="utf-8")
        harness_source = harness.read_text(encoding="utf-8")
        for concurrent_fact in (
            "RELEASER_COUNT = 4",
            "OWNER_EXIT_EPOCHS = 8",
            "pthread_barrier_wait",
            "native mimalloc concurrent post-exit release ok",
        ):
            self.assertIn(concurrent_fact, fixture_source)
        self.assertIn('Command::new("musl-gcc")', harness_source)
        self.assertIn(fixture.name, harness_source)

        ratchet = json.loads(RATCHET_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            ratchet["port_map_sha256"],
            hashlib.sha256(PORT_MAP_PATH.read_bytes()).hexdigest(),
        )

    def test_live_initial_owner_releases_setup_before_disjoint_w03(self) -> None:
        record = self.item("src/free.c", "pointer-first-native-free-page-state-dispatch")
        mapping = record["rust_module"] + record["rust_item"]
        for rust_fact in (
            "ProcessPageArenaLease::page_map_for_owned_ranges",
            "PageAllocatorEngine::activate_main_static_for_owned_ranges",
        ):
            self.assertIn(rust_fact, mapping)

        scope = record["intentional_difference"]
        for invariant in (
            "short reservation/setup transition",
            "finishes that setup lease before the engine can make a client visible",
            "no global PageMap lifecycle lock merely to touch already-owned pages",
            "disjoint W03 terminal release",
        ):
            self.assertIn(invariant, scope)

        fixture = ROOT / "tests/fixtures/native_mimalloc_initial_live_owner_exit_test.c"
        harness = ROOT / "tests/native_mimalloc_initial_live_owner_exit.rs"
        self.assertTrue(fixture.is_file())
        self.assertTrue(harness.is_file())
        self.assertIn("tests/fixtures/native_mimalloc_initial_live_owner_exit_test.c", record["tests"])
        self.assertIn("tests/native_mimalloc_initial_live_owner_exit.rs", record["tests"])
        fixture_source = fixture.read_text(encoding="utf-8")
        self.assertIn("owner_worker", fixture_source)
        self.assertIn("release_worker", fixture_source)
        harness_source = harness.read_text(encoding="utf-8")
        self.assertIn("run_with_timeout", harness_source)
        self.assertIn("Duration::from_secs(5)", harness_source)


if __name__ == "__main__":
    unittest.main()
