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
DIRECT_SMALL_FULL_RETIRE_SCHEMA = (
    ROOT / "compat/allocator/x86_64-direct-small-full-retire-evidence-v3.5.0.json"
)
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

    def test_direct_small_full_regular_retire_schema_profile_is_exact(self) -> None:
        schema = json.loads(DIRECT_SMALL_FULL_RETIRE_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["profile"],
            "linux-x86_64-private-direct-small-full-regular-retire-force-release",
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
                "native-mapped-arena-allocation-time-adoption-differential",
                "native-unmapped-full-medium-reabandon-differential",
                "native-ordinary-reserved-medium-on-demand-differential",
                "native-reserved-small-direct-on-demand-differential",
                "native-aligned-overalloc-realloc-differential",
                "native-regular-small-retire-quick-collect-release-differential",
                "native-direct-small-full-regular-retire-force-release-differential",
                "native-medium-full-to-regular-retire-force-release-differential",
                "native-full-non-direct-small-force-collect-post-exit-differential",
                "native-full-direct-small-force-collect-post-exit-differential",
                "native-mapped-post-theap-teardown-failed-reclaim-differential",
                "native-retired-page-prepass-before-live-post-exit-differential",
                "native-two-live-page-aggregate-post-exit-differential",
                "native-two-client-aggregate-still-live-differential",
                "native-same-bin-two-page-aggregate-still-live-differential",
                "native-dynamic-full-medium-one-remote-force-collect-to-mapped-differential",
                "native-dynamic-full-large-one-remote-force-collect-to-mapped-differential",
                "native-dynamic-os-aligned-singleton-owner-exit-differential",
                "native-pinned-c-release-mode-object-symbols",
                "native-release-api-mode-object-symbol-assessment",
                "native-staged-public-header-mode-linkability",
                "native-static-library-and-override-object-linkability",
                "native-cmake-normal-release-shared-configure-build-install",
                "native-bounded-fault-injection",
                "native-allocator-unit",
            },
        )
        for gate in gates.values():
            self.assertEqual(gate["state"], "available")
            self.assertTrue(gate["native_required"])
            self.assertTrue(gate["command"].startswith("./compat/allocator/run-x86_64.sh "))
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
            "./compat/allocator/run-x86_64.sh allocator-remote-free",
        )
        self.assertEqual(
            gates["native-live-owner-remote-free-differential"]["report"],
            "compat/reports/allocator/x86_64/live-owner-remote-free.json",
        )
        self.assertEqual(
            gates["native-small-direct-remote-free-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-direct-remote",
        )
        self.assertEqual(
            gates["native-small-direct-remote-free-differential"]["report"],
            "compat/reports/allocator/x86_64/small-direct-remote.json",
        )
        self.assertEqual(
            gates["native-mapped-arena-same-origin-reclaim-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-mapped-reclaim",
        )
        self.assertEqual(
            gates["native-mapped-arena-same-origin-reclaim-differential"]["report"],
            "compat/reports/allocator/x86_64/mapped-reclaim.json",
        )
        self.assertEqual(
            gates["native-mapped-arena-allocation-time-adoption-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-mapped-adoption",
        )
        self.assertEqual(
            gates["native-mapped-arena-allocation-time-adoption-differential"]["report"],
            "compat/reports/allocator/x86_64/mapped-adoption.json",
        )
        self.assertEqual(
            gates["native-unmapped-full-medium-reabandon-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-unmapped-reabandon",
        )
        self.assertEqual(
            gates["native-unmapped-full-medium-reabandon-differential"]["report"],
            "compat/reports/allocator/x86_64/unmapped-reabandon.json",
        )
        self.assertEqual(
            gates["native-ordinary-reserved-medium-on-demand-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-on-demand",
        )
        self.assertEqual(
            gates["native-ordinary-reserved-medium-on-demand-differential"]["report"],
            "compat/reports/allocator/x86_64/on-demand.json",
        )
        self.assertEqual(
            gates["native-reserved-small-direct-on-demand-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-direct-on-demand",
        )
        self.assertEqual(
            gates["native-reserved-small-direct-on-demand-differential"]["report"],
            "compat/reports/allocator/x86_64/direct-on-demand.json",
        )
        self.assertEqual(
            gates["native-aligned-overalloc-realloc-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-aligned-overalloc-realloc",
        )
        self.assertEqual(
            gates["native-aligned-overalloc-realloc-differential"]["report"],
            "compat/reports/allocator/x86_64/aligned-overalloc-realloc.json",
        )
        self.assertEqual(
            gates["native-regular-small-retire-quick-collect-release-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-regular-small",
        )
        self.assertEqual(
            gates["native-regular-small-retire-quick-collect-release-differential"]["report"],
            "compat/reports/allocator/x86_64/regular-small.json",
        )
        self.assertEqual(
            gates["native-direct-small-full-regular-retire-force-release-differential"][
                "command"
            ],
            "./compat/allocator/run-x86_64.sh allocator-direct-small-full-retire",
        )
        self.assertEqual(
            gates["native-direct-small-full-regular-retire-force-release-differential"][
                "report"
            ],
            "compat/reports/allocator/x86_64/direct-small-full-retire.json",
        )
        self.assertEqual(
            gates["native-medium-full-to-regular-retire-force-release-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-medium-full-retire",
        )
        self.assertEqual(
            gates["native-medium-full-to-regular-retire-force-release-differential"]["report"],
            "compat/reports/allocator/x86_64/medium-full-retire.json",
        )
        self.assertEqual(
            gates["native-full-non-direct-small-force-collect-post-exit-differential"][
                "command"
            ],
            "./compat/allocator/run-x86_64.sh "
            "allocator-full-non-direct-small-force-collect-post-exit",
        )
        self.assertEqual(
            gates["native-full-non-direct-small-force-collect-post-exit-differential"][
                "report"
            ],
            "compat/reports/allocator/x86_64/"
            "full-non-direct-small-force-collect-post-exit.json",
        )
        self.assertEqual(
            gates["native-full-direct-small-force-collect-post-exit-differential"][
                "command"
            ],
            "./compat/allocator/run-x86_64.sh "
            "allocator-full-direct-small-force-collect-post-exit",
        )
        self.assertEqual(
            gates["native-full-direct-small-force-collect-post-exit-differential"][
                "report"
            ],
            "compat/reports/allocator/x86_64/"
            "full-direct-small-force-collect-post-exit.json",
        )
        self.assertEqual(
            gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-mapped-post-exit",
        )
        self.assertEqual(
            gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["report"],
            "compat/reports/allocator/x86_64/mapped-post-exit.json",
        )
        self.assertEqual(
            gates["native-retired-page-prepass-before-live-post-exit-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-retired-prepass",
        )
        self.assertEqual(
            gates["native-retired-page-prepass-before-live-post-exit-differential"]["report"],
            "compat/reports/allocator/x86_64/retired-prepass.json",
        )
        self.assertEqual(
            gates["native-two-live-page-aggregate-post-exit-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-aggregate-post-exit",
        )
        self.assertEqual(
            gates["native-two-live-page-aggregate-post-exit-differential"]["report"],
            "compat/reports/allocator/x86_64/aggregate-post-exit.json",
        )
        self.assertEqual(
            gates["native-two-client-aggregate-still-live-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-aggregate-still-live",
        )
        self.assertEqual(
            gates["native-two-client-aggregate-still-live-differential"]["report"],
            "compat/reports/allocator/x86_64/aggregate-still-live.json",
        )
        self.assertEqual(
            gates["native-same-bin-two-page-aggregate-still-live-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-aggregate-same-bin-still-live",
        )
        self.assertEqual(
            gates["native-same-bin-two-page-aggregate-still-live-differential"]["report"],
            "compat/reports/allocator/x86_64/aggregate-same-bin-still-live.json",
        )
        self.assertEqual(
            gates["native-dynamic-full-medium-one-remote-force-collect-to-mapped-differential"][
                "command"
            ],
            "./compat/allocator/run-x86_64.sh "
            "allocator-dynamic-full-medium-one-remote-force-collect-to-mapped",
        )
        self.assertEqual(
            gates["native-dynamic-full-medium-one-remote-force-collect-to-mapped-differential"][
                "report"
            ],
            "compat/reports/allocator/x86_64/"
            "dynamic-full-medium-one-remote-force-collect-to-mapped.json",
        )
        self.assertEqual(
            gates["native-dynamic-full-large-one-remote-force-collect-to-mapped-differential"][
                "command"
            ],
            "./compat/allocator/run-x86_64.sh "
            "allocator-dynamic-full-large-one-remote-force-collect-to-mapped",
        )
        self.assertEqual(
            gates["native-dynamic-full-large-one-remote-force-collect-to-mapped-differential"][
                "report"
            ],
            "compat/reports/allocator/x86_64/"
            "dynamic-full-large-one-remote-force-collect-to-mapped.json",
        )
        self.assertEqual(
            gates["native-dynamic-os-aligned-singleton-owner-exit-differential"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-dynamic-os-aligned-singleton",
        )
        self.assertEqual(
            gates["native-dynamic-os-aligned-singleton-owner-exit-differential"]["report"],
            "compat/reports/allocator/x86_64/dynamic-os-aligned-singleton.json",
        )
        self.assertEqual(
            gates["native-bounded-fault-injection"]["report"],
            "compat/reports/allocator/x86_64/fault-injection.json",
        )
        self.assertEqual(
            gates["native-pinned-c-release-mode-object-symbols"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-release-evidence",
        )
        self.assertEqual(
            gates["native-pinned-c-release-mode-object-symbols"]["report"],
            "compat/reports/allocator/x86_64/release-evidence.json",
        )
        self.assertEqual(
            gates["native-release-api-mode-object-symbol-assessment"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-api-coverage",
        )
        self.assertEqual(
            gates["native-release-api-mode-object-symbol-assessment"]["report"],
            "compat/reports/allocator/x86_64/api-native-coverage.json",
        )
        self.assertEqual(
            gates["native-staged-public-header-mode-linkability"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-header-modes",
        )
        self.assertEqual(
            gates["native-staged-public-header-mode-linkability"]["report"],
            "compat/reports/allocator/x86_64/header-mode-evidence.json",
        )
        self.assertEqual(
            gates["native-static-library-and-override-object-linkability"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-static-modes",
        )
        self.assertEqual(
            gates["native-static-library-and-override-object-linkability"]["report"],
            "compat/reports/allocator/x86_64/static-mode-evidence.json",
        )
        self.assertEqual(
            gates["native-cmake-normal-release-shared-configure-build-install"]["command"],
            "./compat/allocator/run-x86_64.sh allocator-cmake-modes",
        )
        self.assertEqual(
            gates["native-cmake-normal-release-shared-configure-build-install"]["report"],
            "compat/reports/allocator/x86_64/cmake-mode-evidence.json",
        )
        self.assertIn("preprocessor", gates["native-pinned-c-release-mode-object-symbols"]["claim"])
        self.assertIn("object", gates["native-pinned-c-release-mode-object-symbols"]["claim"])
        self.assertIn("default-visible", gates["native-pinned-c-release-mode-object-symbols"]["claim"])
        self.assertIn("does not claim public x86", gates["native-pinned-c-release-mode-object-symbols"]["claim"])
        self.assertIn("194 distinct source-declared C functions", gates["native-release-api-mode-object-symbol-assessment"]["claim"])
        self.assertIn("not-an-object-symbol", gates["native-release-api-mode-object-symbol-assessment"]["claim"])
        self.assertIn("does not claim declaration behavior", gates["native-release-api-mode-object-symbol-assessment"]["claim"])
        self.assertIn("six selected staged public C/C++ header forms", gates["native-staged-public-header-mode-linkability"]["claim"])
        self.assertIn("five base-header *_csize static-inline dispatch helpers", gates["native-staged-public-header-mode-linkability"]["claim"])
        self.assertIn("does not prove CMake configuration or installation", gates["native-staged-public-header-mode-linkability"]["claim"])
        self.assertIn("ar t", gates["native-static-library-and-override-object-linkability"]["claim"])
        self.assertIn("src/static.c", gates["native-static-library-and-override-object-linkability"]["claim"])
        self.assertIn("does not execute a consumer", gates["native-static-library-and-override-object-linkability"]["claim"])
        cmake = gates["native-cmake-normal-release-shared-configure-build-install"]["claim"]
        for fragment in (
            "configures, builds, and installs",
            "CMake cache values",
            "installed public-header bytes",
            "SONAME",
            "DT_NEEDED",
            "does not compile-link or execute a consumer",
            "allocator behavior or Rust implementation",
            "static/object CMake modes",
            "public x86 runtime support",
            "AArch64 status",
        ):
            self.assertIn(fragment, cmake)
        self.assertIn("18 address-independent values", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("real pinned-C worker pthread", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("producer_teardown_completed_before_consumer_free", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("page_map_unregistered_after_final_free", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("arena_page_bitmap_clear_after_final_free", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("arena_slice_released_after_final_free", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("does not establish general thread exit", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("public x86 support", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        self.assertIn("AArch64 evidence", gates["native-mapped-post-theap-teardown-failed-reclaim-differential"]["claim"])
        retired = gates["native-retired-page-prepass-before-live-post-exit-differential"]["claim"]
        for fragment in (
            "21 address-independent values",
            "real pinned-C worker local mi_free",
            "retires one medium page",
            "real mi_thread_done() and pthread join",
            "retired_page_map_unregistered_after_teardown",
            "retired_arena_page_bitmap_clear_after_teardown",
            "retired_arena_slice_released_after_teardown",
            "live_page_map_unregistered_after_final_free",
            "live_arena_page_bitmap_clear_after_final_free",
            "live_arena_slice_released_after_final_free",
            "empty route",
            "does not establish general retirement",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, retired)
        aggregate = gates["native-two-live-page-aggregate-post-exit-differential"][
            "claim"
        ]
        for fragment in (
            "25 address-independent values",
            "two distinct live nonfull medium arena pages",
            "distinct bins",
            "worker runs real mi_thread_done() and returns; the consumer calls pthread_join()",
            "both selected pages are mapped-abandoned",
            "consumer frees the second page first",
            "PageMap unregister",
            "ordinary arena-page bitmap clear",
            "exact slice-span release",
            "first remains PageMap-registered",
            "arena-bitmap-set",
            "used == 1",
            "empty route",
            "does not establish general teardown",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, aggregate)
        aggregate_still_live = gates[
            "native-two-client-aggregate-still-live-differential"
        ]["claim"]
        for fragment in (
            "46 address-independent all-1 `trace.aggregate_still_live.*` values",
            "two distinct clients on one nonfull medium arena page A",
            "one-client medium arena page B",
            "distinct bin",
            "worker runs real mi_thread_done() and returns; the consumer calls pthread_join()",
            "both selected pages are mapped-abandoned",
            "consumer frees A's first client for StillLive",
            "preserving A, B, and the route",
            "B for ReleasedPage",
            "terminally releasing only B",
            "A's second client for ReleasedAll",
            "completing the route",
            "does not establish general teardown",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, aggregate_still_live)
        aggregate_same_bin_still_live = gates[
            "native-same-bin-two-page-aggregate-still-live-differential"
        ]["claim"]
        for fragment in (
            "53 address-independent all-1 `trace.aggregate_same_bin_still_live.*` values",
            "two distinct clients on one nonfull medium arena page A",
            "one-client medium arena page B in the same bin",
            "worker fills A before it creates B",
            "then runs real mi_thread_done() and returns; the consumer calls pthread_join()",
            "same-bin queue count/link/saved-successor traversal",
            "same-bin abandoned count/bitmap transitions 2 -> 2 -> 1 -> 0",
            "consumer frees A's first client for StillLive",
            "preserving A, B, and the two-page route",
            "B for ReleasedPage",
            "terminally releasing only B",
            "A's second client for ReleasedAll",
            "completing the route",
            "does not establish general teardown",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, aggregate_same_bin_still_live)
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
        mapped_adoption = gates["native-mapped-arena-allocation-time-adoption-differential"]["claim"]
        for fragment in (
            "18 address-independent values",
            "same-origin, one-thread nonfull medium page",
            "_mi_page_abandon",
            "PageMap and ordinary arena-bitmap registration",
            "pinned C next same-heap allocation claims the exact mapped-abandoned page",
            "clears its bitmap/count",
            "restores original Theap association",
            "regular tail",
            "third live block",
            "test-only `adopt()` handoff adapter",
            "generic Rust allocation scan abandoned pages",
            "allocation-time same-origin adapter mapping",
            "not general or cross-thread abandonment/adoption",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, mapped_adoption)
        self.assertIn("13 address-independent values", gates["native-unmapped-full-medium-reabandon-differential"]["claim"])
        self.assertIn("initially-unmapped abandonment", gates["native-unmapped-full-medium-reabandon-differential"]["claim"])
        self.assertIn("bounded real full-medium post-Theap-teardown route", gates["native-unmapped-full-medium-reabandon-differential"]["claim"])
        self.assertIn("does not establish general abandonment/adoption or free routing", gates["native-unmapped-full-medium-reabandon-differential"]["claim"])
        on_demand = gates["native-ordinary-reserved-medium-on-demand-differential"]["claim"]
        for fragment in (
            "23 address-independent values",
            "only the C probe sets mi_option_page_commit_on_demand",
            "16 KiB/four-OS-page prefix",
            "second ordinary allocation commits before free-list extension",
            "reuses the same page",
            "failed direct commit and retries the same selected page",
            "does not claim C fault-injection parity",
            "Rust production option processing/API/policy",
            "fresh fallback",
            "public x86 runtime support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, on_demand)
        direct_on_demand = gates["native-reserved-small-direct-on-demand-differential"]["claim"]
        for fragment in (
            "44 address-independent values",
            "only the C probe sets mi_option_page_commit_on_demand",
            "1024-byte small direct-cache page",
            "allocation nine falls through generic queue search",
            "16 to 24 extension",
            "complete direct-cache image",
            "does not claim C fault-injection parity",
            "Rust production option processing/API/policy",
            "fresh fallback",
            "public x86 runtime support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, direct_on_demand)
        aligned_overalloc = gates["native-aligned-overalloc-realloc-differential"]["claim"]
        for fragment in (
            "29 address-independent values",
            "ordinary arena-backed 33-byte offset-aligned request",
            "64-byte alignment, offset 7",
            "interior-base recovery",
            "adjusted usable size",
            "aligned ceil-half boundary",
            "same-pointer reuse",
            "replacement preservation",
            "zeroed growth",
            "terminal PageMap/arena-page/slice release",
            "private native engine evidence only",
            "public mi_* API",
            "public x86 libc/ldso/runtime support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, aligned_overalloc)
        regular_small = gates[
            "native-regular-small-retire-quick-collect-release-differential"
        ]["claim"]
        for fragment in (
            "40 address-independent values",
            "1025-byte ordinary regular-small arena page",
            "1280-byte class, 51 blocks, one slice",
            "retire_expire == 16",
            "generic same-Theap allocation quick-collect and reuse",
            "same page",
            "force-collects the exact queue, PageMap, arena-page bit, and slice release",
            "same-thread/same-Theap private engine evidence",
            "does not establish general retirement or lifecycle",
            "remote/concurrent collection",
            "public mi_* behavior",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, regular_small)
        direct_small_full_regular = gates[
            "native-direct-small-full-regular-retire-force-release-differential"
        ]["claim"]
        for fragment in (
            "38 address-independent values",
            "1024-byte direct-small page",
            "1024-byte blocks, capacity 64, one slice",
            "full (`used == reserved`)",
            "sole ordinary regular-bin member",
            "complete rounded direct-cache range",
            "does not enter `BIN_FULL`",
            "unfull transition",
            "retire_expire == 16",
            "without detaching the regular queue or cache range",
            "source empty-page direct-cache range",
            "PageMap",
            "ordinary arena-page bitmap",
            "same-thread/same-Theap private engine evidence",
            "does not establish general retirement or lifecycle",
            "remote/concurrent collection",
            "thread exit",
            "abandonment/adoption",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, direct_small_full_regular)
        full_non_direct_small = gates[
            "native-full-non-direct-small-force-collect-post-exit-differential"
        ]["claim"]
        for fragment in (
            "25 address-independent values",
            "worker-owned arena full non-direct-small regular-bin page",
            "1032 bytes",
            "1280-byte class, 51 blocks, one slice",
            "exactly one remote mi_free",
            "real mi_thread_done and pthread_join",
            "mapped abandoned route",
            "nonfinal mapped state",
            "terminal PageMap unregister",
            "ordinary arena-page bitmap clear",
            "one-slice release",
            "bounded f329040",
            "private client-free route evidence",
            "general thread exit",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, full_non_direct_small)
        full_direct_small = gates[
            "native-full-direct-small-force-collect-post-exit-differential"
        ]["claim"]
        for fragment in (
            "28 address-independent values",
            "worker-owned arena full direct-small regular-bin page",
            "1024 bytes",
            "1024-byte class, 64 blocks, one slice",
            "complete rounded direct-cache range",
            "source anchors establish the direct-cache range update before queue detachment",
            "exactly one remote mi_free",
            "real mi_thread_done and pthread_join",
            "immediately publishes the page as mapped-abandoned",
            "preserve the mapped route",
            "unregisters the PageMap",
            "ordinary arena-page bitmap",
            "one-slice span",
            "arena_abandoned_bin_bitmap_clear_after_final_free",
            "direct-specific preflight",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, full_direct_small)
        dynamic_full_medium = gates[
            "native-dynamic-full-medium-one-remote-force-collect-to-mapped-differential"
        ]["claim"]
        for fragment in (
            "29 address-independent values",
            "sole full BIN_FULL medium arena page",
            "exactly one remote mi_free",
            "real mi_thread_done",
            "joins before the consumer's sequential frees",
            "10248",
            "12288-byte blocks",
            "capacity/reserved 42",
            "eight slices",
            "used 41",
            "dynamic abandoned bitmap/count",
            "mapped",
            "PageMap",
            "ordinary arena-page bitmap",
            "private native x86 engine evidence only",
            "general lifecycle",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, dynamic_full_medium)
        dynamic_full_large = gates[
            "native-dynamic-full-large-one-remote-force-collect-to-mapped-differential"
        ]["claim"]
        for fragment in (
            "31 address-independent values",
            "sole full BIN_FULL large arena page",
            "exactly one remote mi_free",
            "real mi_thread_done",
            "86706",
            "98304-byte blocks",
            "capacity/reserved 42",
            "64 arena slices",
            "63 PageMap-registered source page-area slices",
            "used 41",
            "PageMap-null final arena slack slice",
            "dynamic abandoned bitmap/count",
            "complete 64-slice arena span",
            "private native x86 engine evidence only",
            "general lifecycle",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, dynamic_full_large)
        dynamic_os_aligned_singleton = gates[
            "native-dynamic-os-aligned-singleton-owner-exit-differential"
        ]["claim"]
        for fragment in (
            "21 address-independent values",
            "7 bytes with 128 KiB alignment",
            "real mi_thread_done()",
            "pthread_join()s before freeing",
            "4096-byte OS singleton",
            "semantically full",
            "MI_BIN_HUGE member, not a MI_BIN_FULL member",
            "empty full queue",
            "OS-abandoned-list membership",
            "typed private owner-exit handoff",
            "general lifecycle",
            "public x86 support",
            "AArch64 evidence",
        ):
            self.assertIn(fragment, dynamic_os_aligned_singleton)
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
            "./compat/allocator/run-x86_64.sh allocator-core-unit",
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
        self.assertIn("40-field same-Theap ordinary regular-small", lanes["general-thread-lifecycle-and-stress"]["reason"])
        self.assertIn(
            "38-field same-Theap full direct-small regular-bin retire/force-release",
            lanes["general-thread-lifecycle-and-stress"]["reason"],
        )
        self.assertIn("13-field unmapped full-medium reabandon", lanes["general-thread-lifecycle-and-stress"]["reason"])
        self.assertIn("18-value same-origin allocation-time mapped-adoption", lanes["general-thread-lifecycle-and-stress"]["reason"])
        self.assertIn("fault/misuse coverage", lanes["general-thread-lifecycle-and-stress"]["reason"])

        boundary = self.contract["ledger_boundary"]
        self.assertEqual(boundary["status"], "intentionally-not-mirrored")
        for relative_path in boundary["aarch64_contracts_not_mirrored"]:
            self.assertTrue((ROOT / relative_path).is_file(), relative_path)
        self.assertIn("falsely claim parity", boundary["reason"])


if __name__ == "__main__":
    unittest.main()
