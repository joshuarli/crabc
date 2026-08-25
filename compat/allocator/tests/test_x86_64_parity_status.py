#!/usr/bin/env python3
"""Validate the target-local Linux/x86-64 mimalloc parity status contract.

The existing API inventory, port map, and ratchet intentionally remain the
AArch64 production contracts.  This test keeps the smaller x86-64 status
ledger honest without importing it into those target-specific claims.
"""

from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "compat/allocator/x86_64-parity-v3.5.0.json"
UPSTREAMS = ROOT / "compat/upstreams.toml"


class X86_64ParityStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_schema_and_explicit_non_public_boundary(self) -> None:
        self.assertEqual(
            set(self.contract),
            {
                "evidence_gates",
                "excludes",
                "facts",
                "format",
                "implementation_regressions",
                "implementation_state",
                "kind",
                "ledger_boundary",
                "native_only",
                "not_yet_covered_lanes",
                "profile",
                "public_support",
                "scope",
                "target",
                "upstream",
            },
        )
        self.assertEqual(self.contract["format"], 1)
        self.assertEqual(self.contract["kind"], "mimalloc-target-parity-status")
        self.assertEqual(self.contract["profile"], "linux-x86_64-mimalloc-parity")
        self.assertEqual(self.contract["implementation_state"], "incomplete")
        self.assertFalse(self.contract["public_support"])
        self.assertTrue(self.contract["native_only"])
        self.assertEqual(
            self.contract["excludes"],
            [
                "public crabc platform support",
                "a generic architecture portability contract",
                "allocator backend promotion",
            ],
        )

    def test_target_facts_match_the_native_x86_64_profile(self) -> None:
        target = self.contract["target"]
        self.assertEqual(
            target,
            {
                "architecture": "x86_64",
                "base_page_size_bytes": 4096,
                "endianness": "little",
                "kernel_baseline": "5.10",
                "max_vabits": 47,
                "page_map_shift": 18,
                "rust_target": "x86_64-unknown-linux-musl",
                "system": "linux",
                "tls_identity": {"offset_bytes": 0, "segment": "fs"},
            },
        )

        facts = {fact["id"]: fact for fact in self.contract["facts"]}
        self.assertEqual(
            set(facts),
            {
                "max-vabits",
                "page-map-shift",
                "base-page-size-bytes",
                "thread-pointer-identity",
            },
        )
        self.assertEqual(facts["max-vabits"]["value"], target["max_vabits"])
        self.assertEqual(facts["page-map-shift"]["value"], target["page_map_shift"])
        self.assertEqual(
            facts["base-page-size-bytes"]["value"], target["base_page_size_bytes"]
        )
        self.assertEqual(
            facts["thread-pointer-identity"]["value"], target["tls_identity"]
        )
        self.assertNotIn(
            "aarch64", facts["base-page-size-bytes"]["rust_source"]["required_text"]
        )
        self.assertEqual(
            facts["base-page-size-bytes"]["upstream_source"],
            "src/prim/unix/prim.c: native Linux x86-64 base-page observation",
        )

    def test_source_anchors_preserve_each_recorded_target_fact(self) -> None:
        for fact in self.contract["facts"]:
            source = fact["rust_source"]
            self.assertEqual(set(source), {"path", "required_text"}, fact["id"])
            path = ROOT / source["path"]
            self.assertTrue(path.is_file(), fact["id"])
            self.assertIn(source["required_text"], path.read_text(encoding="utf-8"), fact["id"])

    def test_upstream_pin_agrees_with_the_repository_pin(self) -> None:
        upstreams = tomllib.loads(UPSTREAMS.read_text(encoding="utf-8"))
        mimalloc = upstreams["mimalloc"]
        self.assertEqual(
            self.contract["upstream"],
            {
                "project": "mimalloc",
                "revision": mimalloc["revision"],
                "version": mimalloc["version"],
            },
        )

    def test_native_evidence_gates_are_target_scoped(self) -> None:
        gates = {gate["id"]: gate for gate in self.contract["evidence_gates"]}
        self.assertEqual(
            set(gates),
            {
                "native-c-oracle",
                "native-direct-rust-c-differential",
                "native-normal-engine-build-boundary",
                "native-private-test-adapter",
                "native-private-adapter-performance",
                "native-tls-codegen",
                "native-bounded-lifecycle-concurrency",
                "native-live-owner-remote-free-differential",
                "native-small-direct-remote-free-differential",
                "native-mapped-arena-same-origin-reclaim-differential",
                "native-unmapped-full-medium-reabandon-differential",
                "native-mapped-post-theap-teardown-failed-reclaim-differential",
                "native-pinned-c-release-mode-object-symbols",
                "native-release-api-mode-object-symbol-assessment",
                "native-staged-public-header-mode-linkability",
                "native-static-library-and-override-object-linkability",
                "native-bounded-fault-injection",
                "native-allocator-unit",
            },
        )
        for gate in gates.values():
            self.assertEqual(gate["state"], "available")
            self.assertTrue(gate["native_required"])
            self.assertTrue(gate["command"].startswith("./scripts/dev-amd64.sh "))
        self.assertEqual(
            gates["native-c-oracle"]["report"],
            "compat/reports/allocator/x86_64/latest.json",
        )
        self.assertEqual(
            gates["native-tls-codegen"]["report"],
            "compat/reports/allocator/tls-codegen-x86_64.json",
        )
        self.assertEqual(
            gates["native-private-test-adapter"]["report"],
            "compat/reports/allocator/x86_64/latest.json",
        )
        self.assertEqual(
            gates["native-normal-engine-build-boundary"]["report"],
            "compat/reports/allocator/x86_64/latest.json",
        )
        self.assertEqual(
            gates["native-private-adapter-performance"]["report"],
            "compat/reports/allocator/x86_64/perf/x86-private-adapter-smoke.json",
        )
        self.assertEqual(
            gates["native-bounded-lifecycle-concurrency"]["report"],
            "compat/reports/allocator/x86_64/lifecycle-concurrency.json",
        )
        self.assertEqual(
            gates["native-live-owner-remote-free-differential"]["command"],
            "./scripts/dev-amd64.sh allocator-remote-free",
        )
        self.assertEqual(
            gates["native-live-owner-remote-free-differential"]["report"],
            "compat/reports/allocator/x86_64/live-owner-remote-free.json",
        )
        self.assertEqual(
            gates["native-small-direct-remote-free-differential"]["command"],
            "./scripts/dev-amd64.sh allocator-direct-remote",
        )
        self.assertEqual(
            gates["native-small-direct-remote-free-differential"]["report"],
            "compat/reports/allocator/x86_64/small-direct-remote.json",
        )
        self.assertEqual(
            gates["native-mapped-arena-same-origin-reclaim-differential"]["command"],
            "./scripts/dev-amd64.sh allocator-mapped-reclaim",
        )
        self.assertEqual(
            gates["native-mapped-arena-same-origin-reclaim-differential"]["report"],
            "compat/reports/allocator/x86_64/mapped-reclaim.json",
        )
        self.assertEqual(
            gates["native-unmapped-full-medium-reabandon-differential"]["command"],
            "./scripts/dev-amd64.sh allocator-unmapped-reabandon",
        )
        self.assertEqual(
            gates["native-unmapped-full-medium-reabandon-differential"]["report"],
            "compat/reports/allocator/x86_64/unmapped-reabandon.json",
        )
        self.assertEqual(
            gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["command"],
            "./scripts/dev-amd64.sh allocator-mapped-post-exit",
        )
        self.assertEqual(
            gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["report"],
            "compat/reports/allocator/x86_64/mapped-post-exit.json",
        )
        self.assertEqual(
            gates["native-bounded-fault-injection"]["report"],
            "compat/reports/allocator/x86_64/fault-injection.json",
        )
        self.assertEqual(
            gates["native-pinned-c-release-mode-object-symbols"]["command"],
            "./scripts/dev-amd64.sh allocator-release-evidence",
        )
        self.assertEqual(
            gates["native-pinned-c-release-mode-object-symbols"]["report"],
            "compat/reports/allocator/x86_64/release-evidence.json",
        )
        self.assertEqual(
            gates["native-release-api-mode-object-symbol-assessment"]["command"],
            "./scripts/dev-amd64.sh allocator-api-coverage",
        )
        self.assertEqual(
            gates["native-release-api-mode-object-symbol-assessment"]["report"],
            "compat/reports/allocator/x86_64/api-native-coverage.json",
        )
        self.assertEqual(
            gates["native-staged-public-header-mode-linkability"]["command"],
            "./scripts/dev-amd64.sh allocator-header-modes",
        )
        self.assertEqual(
            gates["native-staged-public-header-mode-linkability"]["report"],
            "compat/reports/allocator/x86_64/header-mode-evidence.json",
        )
        self.assertEqual(
            gates["native-static-library-and-override-object-linkability"]["command"],
            "./scripts/dev-amd64.sh allocator-static-modes",
        )
        self.assertEqual(
            gates["native-static-library-and-override-object-linkability"]["report"],
            "compat/reports/allocator/x86_64/static-mode-evidence.json",
        )
        self.assertIn("preprocessor", gates["native-pinned-c-release-mode-object-symbols"]["claim"])
        self.assertIn("object", gates["native-pinned-c-release-mode-object-symbols"]["claim"])
        self.assertIn("default-visible", gates["native-pinned-c-release-mode-object-symbols"]["claim"])
        self.assertIn("does not claim public x86", gates["native-pinned-c-release-mode-object-symbols"]["claim"])
        self.assertIn("194 distinct source-declared C functions", gates["native-release-api-mode-object-symbol-assessment"]["claim"])
        self.assertIn("not-an-object-symbol", gates["native-release-api-mode-object-symbol-assessment"]["claim"])
        self.assertIn("does not claim declaration behavior", gates["native-release-api-mode-object-symbol-assessment"]["claim"])
        self.assertIn("five selected staged public C/C++ header forms", gates["native-staged-public-header-mode-linkability"]["claim"])
        self.assertIn("does not prove CMake configuration or installation", gates["native-staged-public-header-mode-linkability"]["claim"])
        self.assertIn("ar t", gates["native-static-library-and-override-object-linkability"]["claim"])
        self.assertIn("src/static.c", gates["native-static-library-and-override-object-linkability"]["claim"])
        self.assertIn("does not execute a consumer", gates["native-static-library-and-override-object-linkability"]["claim"])
        self.assertIn("18 address-independent values", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("real pinned-C worker pthread", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("producer_teardown_completed_before_consumer_free", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("page_map_unregistered_after_final_free", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("arena_page_bitmap_clear_after_final_free", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("arena_slice_released_after_final_free", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("does not establish general thread exit", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("public x86 support", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("AArch64 evidence", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("cpufeatures", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("no selected libc package", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("lockfile-verified", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("LLVM bitcode", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("not a staticlib/cdylib", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("private prefixed", gates["native-private-test-adapter"]["claim"])
        self.assertIn("no mi_* symbols", gates["native-private-test-adapter"]["claim"])
        self.assertIn("75-field fundamental-operation trace", gates["native-direct-rust-c-differential"]["claim"])
        self.assertIn("no-padding mi_expand", gates["native-direct-rust-c-differential"]["claim"])
        self.assertIn("NULL/nonzero", gates["native-direct-rust-c-differential"]["claim"])
        self.assertIn("mi_recalloc", gates["native-direct-rust-c-differential"]["claim"])
        self.assertIn("bounded single-thread private-adapter", gates["native-private-adapter-performance"]["claim"])
        self.assertIn("no promotion threshold", gates["native-private-adapter-performance"]["claim"])
        self.assertIn("does not qualify general mimalloc performance", gates["native-private-adapter-performance"]["claim"])
        self.assertIn("eight named private Rust lifecycle/concurrency lanes", gates["native-bounded-lifecycle-concurrency"]["claim"])
        self.assertIn("12 selected tests", gates["native-bounded-lifecycle-concurrency"]["claim"])
        self.assertIn("not general process/thread lifecycle", gates["native-bounded-lifecycle-concurrency"]["claim"])
        self.assertIn("general fault-injection or misuse parity", gates["native-bounded-lifecycle-concurrency"]["claim"])
        self.assertIn("25 address-independent values", gates["native-live-owner-remote-free-differential"]["claim"])
        self.assertIn("quiescent pthread", gates["native-live-owner-remote-free-differential"]["claim"])
        self.assertIn("_mi_page_free_collect(page, false)", gates["native-live-owner-remote-free-differential"]["claim"])
        self.assertIn("not general remote-free routing", gates["native-live-owner-remote-free-differential"]["claim"])
        self.assertIn("28 address-independent values", gates["native-small-direct-remote-free-differential"]["claim"])
        self.assertIn("small direct-cache page", gates["native-small-direct-remote-free-differential"]["claim"])
        self.assertIn("not general allocation/free routing", gates["native-small-direct-remote-free-differential"]["claim"])
        self.assertIn("eight address-independent values", gates["native-mapped-arena-same-origin-reclaim-differential"]["claim"])
        self.assertIn("same-origin mi_free reclaim", gates["native-mapped-arena-same-origin-reclaim-differential"]["claim"])
        self.assertIn("not general abandonment/adoption", gates["native-mapped-arena-same-origin-reclaim-differential"]["claim"])
        self.assertIn("13 address-independent values", gates["native-unmapped-full-medium-reabandon-differential"]["claim"])
        self.assertIn("initially-unmapped abandonment", gates["native-unmapped-full-medium-reabandon-differential"]["claim"])
        self.assertIn("synthetic private failed-reclaim tail", gates["native-unmapped-full-medium-reabandon-differential"]["claim"])
        self.assertIn("does not establish a Rust full-medium routing path", gates["native-unmapped-full-medium-reabandon-differential"]["claim"])
        self.assertIn("five named crate-private fault-injection", gates["native-bounded-fault-injection"]["claim"])
        self.assertIn("Map, Commit, Unmap, and Decommit", gates["native-bounded-fault-injection"]["claim"])
        self.assertIn("does not establish general fault-injection or misuse parity", gates["native-bounded-fault-injection"]["claim"])

    def test_native_thread_pointer_unit_is_an_implementation_regression(self) -> None:
        regressions = {
            regression["id"]: regression
            for regression in self.contract["implementation_regressions"]
        }
        self.assertEqual(set(regressions), {"native-thread-pointer-unit"})
        regression = regressions["native-thread-pointer-unit"]
        self.assertEqual(regression["state"], "available")
        self.assertTrue(regression["native_required"])
        self.assertEqual(
            regression["command"],
            "./scripts/dev-amd64.sh cargo test -p crabc-core --lib",
        )
        self.assertIn("implementation regression", regression["claim"])
        self.assertIn("not independent C-oracle", regression["claim"])
        self.assertNotIn(
            "native-thread-pointer-unit",
            {gate["id"] for gate in self.contract["evidence_gates"]},
        )

    def test_uncovered_lanes_and_aarch64_ledger_boundary_are_explicit(self) -> None:
        lanes = {lane["id"]: lane for lane in self.contract["not_yet_covered_lanes"]}
        self.assertEqual(
            set(lanes),
            {
                "public-mi-api-and-libc-integration",
                "general-thread-lifecycle-and-stress",
                "libc-backend-promotion-and-public-crabc-support",
                "performance-qualification",
            },
        )
        self.assertTrue(all(lane["state"] == "not_covered" for lane in lanes.values()))
        self.assertIn("Bounded native private-adapter", lanes["performance-qualification"]["reason"])
        self.assertIn("no whole-engine", lanes["performance-qualification"]["reason"])
        self.assertIn("Eight bounded private Rust lifecycle/concurrency lanes", lanes["general-thread-lifecycle-and-stress"]["reason"])
        self.assertIn("five bounded crate-private fault-injection", lanes["general-thread-lifecycle-and-stress"]["reason"])
        self.assertIn("25-field native C/Rust quiescent live-owner", lanes["general-thread-lifecycle-and-stress"]["reason"])
        self.assertIn("28-field real small direct-page", lanes["general-thread-lifecycle-and-stress"]["reason"])
        self.assertIn("13-field unmapped full-medium reabandon", lanes["general-thread-lifecycle-and-stress"]["reason"])
        self.assertIn("fault/misuse coverage", lanes["general-thread-lifecycle-and-stress"]["reason"])

        boundary = self.contract["ledger_boundary"]
        self.assertEqual(boundary["status"], "intentionally-not-mirrored")
        for relative_path in boundary["aarch64_contracts_not_mirrored"]:
            self.assertTrue((ROOT / relative_path).is_file(), relative_path)
        self.assertIn("falsely claim parity", boundary["reason"])


if __name__ == "__main__":
    unittest.main()
