#!/usr/bin/env python3
"""Fail-closed assembly checks for the native x86 initialization M2 admission."""

from __future__ import annotations

import unittest

from test_runner import RUNNER


class NativeInitializationM2AssemblyTests(unittest.TestCase):
    def summary(self):
        return RUNNER.validate_x86_64_m2_memory_substrate_contract(
            RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT), RUNNER.load_pin()
        )

    def test_initialization_component_has_only_the_named_fragment_and_two_receipts(self) -> None:
        pin = RUNNER.load_pin()
        contract = RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT)
        summary = RUNNER.validate_x86_64_m2_memory_substrate_contract(contract, pin)
        component = next(item for item in summary["components"] if item["id"] == "initialization")
        self.assertEqual(component["native_status"], "partial")
        self.assertEqual(
            component["evidence_fragment"],
            {
                "path": RUNNER.relative(RUNNER.M2_X86_64_INITIALIZATION_FRAGMENT),
                "inventory_sha256": RUNNER.M2_X86_64_INITIALIZATION_FRAGMENT_DIGEST,
            },
        )
        self.assertEqual(
            [
                (check["id"], check["kind"], check["target"], check["expected_passed_test_count"])
                for check in component["checks"]
            ],
            [
                (
                    "initialization-tld-direct-source-matrix",
                    "c-rust-initialization-tld-source-matrix",
                    "x86_64_initialization_tld_evidence::seven_fixed_direct_tld_and_ordinary_later_main_branches",
                    7,
                ),
                (
                    "initialization-explicit-worker-recovery-lifecycle",
                    "c-rust-init-recursion-lifecycle",
                    "main_heap_thread::tests::emit_x86_64_init_recursion_teardown_c_rust_trace",
                    1,
                ),
            ],
        )
        self.assertEqual(
            [branch["id"] for branch in component["branch_matrix"]],
            [
                "detached-static-preimage",
                "normal-direct-tld-init",
                "first-main-static-tld-create",
                "later-main-tld-metadata-allocation-success",
                "later-main-tld-metadata-allocation-failure",
                "later-main-theap-metadata-list-and-root-publication-success",
                "later-main-theap-metadata-allocation-failure",
            ],
        )

    def test_direct_tld_anchor_uses_the_pinned_v350_lock_and_live_count_definitions(self) -> None:
        """Keep the direct helper bound to v3.5's actual TLD initialization body."""

        component = next(item for item in self.summary()["components"] if item["id"] == "initialization")
        definition = next(
            item for item in component["bounded_source_definitions"]
            if item["id"] == "direct-tld-initialization"
        )
        self.assertEqual(
            definition["required_definitions"],
            [
                "static mi_tld_t* mi_tld_init",
                "mi_lock_init(&tld->theaps_lock)",
                "mi_atomic_increment_relaxed(&tld->subproc->thread_count)",
            ],
        )

    def test_first_main_tld_anchor_uses_the_pinned_v350_create_call_shape(self) -> None:
        """Bind the first-main receipt to the selected v3.5 ticket and helper call."""

        component = next(item for item in self.summary()["components"] if item["id"] == "initialization")
        definition = next(
            item for item in component["bounded_source_definitions"]
            if item["id"] == "first-main-static-tld-creation"
        )
        self.assertEqual(
            definition["required_definitions"],
            [
                "static mi_tld_t* mi_tld_create",
                "mi_atomic_increment_relaxed(&subproc->thread_total_count)",
                "return mi_tld_init(tld,tseq,subproc)",
            ],
        )


if __name__ == "__main__":
    unittest.main()
