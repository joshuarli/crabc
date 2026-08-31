#!/usr/bin/env python3
"""Focused contract checks for the pointer-first native realloc source map."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_realloc_port_map", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class NonlocalReallocPortMapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.port_map = RUNNER.load_port_map()

    def item(self, name: str) -> dict[str, object]:
        return next(
            item
            for item in self.port_map["item"]
            if item["upstream"] == "src/alloc.c" and item["name"] == name
        )

    def test_precise_realloc_mapping_records_source_order_and_bounded_evidence(self) -> None:
        record = self.item("ordinary-reallocation-decision-and-extents")

        for source_fact in (
            "src/alloc.c:344-417",
            "mi_theap_realloc_zero_ex",
            "_mi_theap_realloc_zero",
            "mi_theap_realloc",
            "src/alloc.c:447-449",
            "mi_realloc",
        ):
            self.assertIn(source_fact, record["source_region"])
        for rust_fact in (
            "crabc_mimalloc::process_page_map",
            "crabc_mimalloc::runtime_lifecycle",
            "ProcessPageMapLease::lookup_live_allocation",
            "LiveAllocationPointer",
            "native_live_allocation_for_pointer_reallocation",
            "native_reallocate_pointer_first_local",
            "native_reallocate_pointer_first_nonlocal",
            "native_free_pointer_first_nonlocal",
            "native_reallocate_release_unpublished_replacement",
        ):
            self.assertIn(rust_fact, record["rust_module"] + record["rust_item"])

        scope = record["intentional_difference"]
        for invariant in (
            "first derives one coherent PageMap allocation observation",
            "allocates through the caller's persistent native owner",
            "Allocation failure leaves the old allocation untouched",
            "unescaped caller-local replacement is returned directly",
            "a rollback failure retains that owner",
            "not aligned-realloc",
            "invalid-pointer",
            "general differential/stress evidence",
            "M5 completion",
            "backend promotion",
        ):
            self.assertIn(invariant, scope)

        expected_evidence = {
            "crabc-mimalloc/tests/native_pointer_first_nonlocal_reallocate.rs",
            "tests/fixtures/native_mimalloc_shadow_foreign_realloc_test.c",
            "tests/native_mimalloc_shadow_abi.rs",
            "tests/fixtures/native_mimalloc_owner_exit_realloc_test.c",
            "tests/native_mimalloc_owner_exit_realloc.rs",
        }
        self.assertLessEqual(expected_evidence, set(record["tests"]))
        self.assertTrue(record["implemented"])
        self.assertTrue(record["unit_verified"])
        self.assertFalse(record["differential_verified"])
        self.assertFalse(record["stress_verified"])
        self.assertFalse(record["performance_qualified"])

    def test_shadow_boundary_no_longer_records_foreign_or_post_exit_enomem_policy(self) -> None:
        record = self.item("nondefault-crabc-libc-native-mimalloc-shadow-ordinary-boundary")
        scope = record["intentional_difference"]

        self.assertNotIn("valid detached `realloc` maps to `ENOMEM`", scope)
        self.assertNotIn("A mismatch returns `Unavailable`", scope)
        self.assertIn("successfully replaces that source at 8192 bytes", scope)
        self.assertIn("Four serialized fresh-B rounds", scope)
        self.assertIn("not broad realloc differential parity", scope)
        self.assertFalse(record["differential_verified"])
        self.assertFalse(record["stress_verified"])
        self.assertFalse(record["performance_qualified"])


if __name__ == "__main__":
    unittest.main()
