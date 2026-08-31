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
SPEC = importlib.util.spec_from_file_location("crabc_allocator_pointer_first_port_map", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class PointerFirstPostOwnerExitPortMapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.port_map = RUNNER.load_port_map()

    def record(self) -> dict[str, object]:
        return next(
            item
            for item in self.port_map["item"]
            if item["upstream"] == "src/free.c"
            and item["name"] == "page-owned-post-owner-exit-exact-remote-claim-terminal-tail"
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
            "production registry-deletion slice",
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

    def test_w03_requires_the_concurrent_native_c_selection_and_reviewed_ratchet(self) -> None:
        record = self.record()
        required_evidence = {
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


if __name__ == "__main__":
    unittest.main()
