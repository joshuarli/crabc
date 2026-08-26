#!/usr/bin/env python3
"""Focused tests for the target-local x86-64 source-map ratchet."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "compat/allocator/x86_64-source-map-v3.5.0.json"
SCRIPT_PATH = ROOT / "compat/allocator/x86_64_source_map.py"
SPEC = importlib.util.spec_from_file_location("crabc_x86_64_source_map", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
SOURCE_MAP = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SOURCE_MAP
SPEC.loader.exec_module(SOURCE_MAP)


@unittest.skipUnless(
    SOURCE_MAP.DEFAULT_ARCHIVE_PATH.is_file(),
    "native allocator oracle has not populated the pinned source archive cache",
)
class X86_64SourceMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.pin = SOURCE_MAP.load_mimalloc_pin()
        cls.sources = SOURCE_MAP.read_pinned_sources(
            SOURCE_MAP.DEFAULT_ARCHIVE_PATH,
            cls.pin,
            SOURCE_MAP.source_members_from_contract(cls.contract),
        )

    def test_checked_in_contract_matches_the_verified_pinned_sources(self) -> None:
        SOURCE_MAP.validate_contract(self.contract, self.pin, self.sources)

    def test_callable_validator_returns_a_scoped_checked_result(self) -> None:
        result = SOURCE_MAP.checked_contract_result(SOURCE_MAP.DEFAULT_ARCHIVE_PATH)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["profile"], "linux-x86_64-mimalloc-engine-parity")
        self.assertEqual(result["overall_status"], "incomplete")
        self.assertEqual(result["target"], self.contract["target_context"])
        self.assertEqual(result["source_member_count"], 34)
        self.assertEqual(result["unit_count"], 34)
        self.assertEqual(result["unfinished_unit_count"], 30)
        self.assertEqual(result["status_counts"], self.contract["ratchet"]["status_counts"])
        self.assertEqual(
            result["contract"]["path"],
            "compat/allocator/x86_64-source-map-v3.5.0.json",
        )
        self.assertIn("does not establish", result["scope"])

    def test_contract_is_architecture_qualified_and_explicitly_incomplete(self) -> None:
        self.assertEqual(self.contract["format"], 1)
        self.assertEqual(self.contract["kind"], "mimalloc-x86_64-engine-source-map")
        self.assertEqual(self.contract["maturity"], "source-map-ratchet-foundation")
        self.assertEqual(
            self.contract["target_context"],
            {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": "x86_64-unknown-linux-musl",
                "system": "linux",
            },
        )
        self.assertEqual(self.contract["overall"]["status"], "incomplete")
        self.assertEqual(
            self.contract["boundary"],
            {
                "native_execution": "not-assessed",
                "public_c_api": "excluded",
                "public_runtime_integration": "excluded",
                "source_map_scope": "private-engine-evidence-only",
            },
        )
        self.assertNotIn("aarch64", json.dumps(self.contract, sort_keys=True).lower())

    def test_source_records_and_anchor_ranges_are_pinned(self) -> None:
        source_records = self.contract["source"]["members"]
        self.assertEqual(
            [record["member"] for record in source_records],
            list(SOURCE_MAP.REQUIRED_SOURCE_MEMBERS),
        )
        self.assertEqual(len(source_records), 34)
        for unit in self.contract["units"]:
            anchor = unit["source_anchor"]
            self.assertEqual(
                anchor["sha256"],
                SOURCE_MAP.sha256_bytes(
                    SOURCE_MAP.source_range(
                        self.sources[anchor["member"]],
                        anchor["start_line"],
                        anchor["end_line"],
                    )
                ),
            )

    def test_duplicate_source_member_anchor_is_rejected(self) -> None:
        malformed = copy.deepcopy(self.contract)
        duplicate = malformed["units"][1]["source_anchor"]
        duplicate["member"] = "include/mimalloc.h"
        duplicate["start_line"] = 109
        duplicate["end_line"] = 220
        duplicate["sha256"] = SOURCE_MAP.sha256_bytes(
            SOURCE_MAP.source_range(self.sources["include/mimalloc.h"], 109, 220)
        )
        with self.assertRaisesRegex(
            SOURCE_MAP.SourceMapError,
            "cover each reviewed source member exactly once",
        ):
            SOURCE_MAP.validate_contract(malformed, self.pin, self.sources)

    def test_each_status_is_present_without_upgrading_the_whole_profile(self) -> None:
        self.assertEqual(
            self.contract["ratchet"]["status_counts"],
            {
                "implemented": 1,
                "inapplicable": 3,
                "not-started": 5,
                "partial": 25,
            },
        )
        implemented = [
            unit["id"] for unit in self.contract["units"] if unit["status"] == "implemented"
        ]
        self.assertEqual(implemented, ["x86-64-width-and-bit-operations"])
        self.assertGreater(self.contract["ratchet"]["unfinished_unit_count"], 0)

    def test_ordinary_allocation_scope_records_private_expand_and_recalloc_slices(self) -> None:
        ordinary = next(
            unit for unit in self.contract["units"] if unit["id"] == "ordinary-allocation-paths"
        )
        self.assertEqual(ordinary["status"], "partial")
        self.assertIn("no-padding mi_expand", ordinary["difference"])
        self.assertIn("mi_recalloc", ordinary["difference"])
        self.assertIn("caller-managed private single-thread lifecycle", ordinary["difference"])
        self.assertLessEqual(ordinary["source_anchor"]["start_line"], 204)
        self.assertGreaterEqual(ordinary["source_anchor"]["end_line"], 483)

    def test_aligned_allocation_scope_records_bounded_overalloc_realloc_evidence(self) -> None:
        aligned = next(
            unit for unit in self.contract["units"] if unit["id"] == "aligned-allocation-paths"
        )
        self.assertEqual(aligned["status"], "partial")
        self.assertIn("29-value native x86-64 private differential", aligned["difference"])
        for evidence in (
            "compat/allocator/x86_64_aligned_overalloc_realloc_evidence.py",
            "compat/allocator/x86_64-aligned-overalloc-realloc-evidence-v3.5.0.json",
            "compat/allocator/tests/test_x86_64_aligned_overalloc_realloc_evidence.py",
        ):
            self.assertIn(evidence, aligned["evidence"])
        for fragment in (
            "33-byte offset-aligned request",
            "interior-base recovery",
            "aligned ceil-half reuse",
            "zeroed growth",
            "terminal PageMap/arena-page/slice release",
        ):
            self.assertIn(fragment, aligned["difference"])

    def test_regular_small_differential_maps_each_selected_engine_boundary(self) -> None:
        units = {
            unit["id"]: unit
            for unit in self.contract["units"]
            if unit["id"]
            in {
                "ordinary-allocation-paths",
                "local-and-remote-free",
                "arena-lifecycle",
                "page-map-lifecycle",
                "page-queue-kernels",
                "page-lifecycle",
                "thread-local-heap-lifecycle",
            }
        }
        self.assertEqual(len(units), 7)
        for unit in units.values():
            with self.subTest(unit=unit["id"]):
                self.assertEqual(unit["status"], "partial")
                self.assertIn(
                    "compat/allocator/x86_64_regular_small_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64-regular-small-evidence-v3.5.0.json",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_regular_small_evidence.py",
                    unit["evidence"],
                )
        self.assertIn("1025-byte generic request", units["ordinary-allocation-paths"]["difference"])
        self.assertIn("saved address and exact one-slice span", units["page-map-lifecycle"]["difference"])
        self.assertIn("queue stay single-member", units["page-queue-kernels"]["difference"])
        self.assertLessEqual(units["thread-local-heap-lifecycle"]["source_anchor"]["start_line"], 123)

    def test_direct_small_full_regular_retire_lane_is_limited_to_local_engine_boundaries(
        self,
    ) -> None:
        reviewed_unit_ids = {
            "ordinary-allocation-paths",
            "local-and-remote-free",
            "arena-lifecycle",
            "page-map-lifecycle",
            "page-queue-kernels",
            "page-lifecycle",
            "thread-local-heap-lifecycle",
        }
        lane_evidence = {
            "compat/allocator/tests/test_x86_64_direct_small_full_retire_evidence.py",
            "compat/allocator/x86_64-direct-small-full-retire-evidence-v3.5.0.json",
            "compat/allocator/x86_64_direct_small_full_retire_evidence.py",
        }
        units = {unit["id"]: unit for unit in self.contract["units"]}

        self.assertEqual(
            {
                unit_id
                for unit_id, unit in units.items()
                if lane_evidence <= set(unit["evidence"])
            },
            reviewed_unit_ids,
        )
        for evidence in lane_evidence:
            with self.subTest(evidence=evidence):
                self.assertEqual(
                    {
                        unit_id
                        for unit_id, unit in units.items()
                        if evidence in unit["evidence"]
                    },
                    reviewed_unit_ids,
                )
        for unit_id in reviewed_unit_ids:
            with self.subTest(unit=unit_id):
                unit = units[unit_id]
                self.assertEqual(unit["status"], "partial")
                self.assertIn("1024-byte direct-small page", unit["difference"])
                self.assertIn("ordinary regular bin", unit["difference"])
                self.assertIn("`retire_expire == 16`", unit["difference"])
                self.assertIn("`BIN_FULL`", unit["difference"])
                self.assertIn("unfull, remote, thread-exit", unit["difference"])

    def test_remote_free_scopes_record_both_bounded_native_differentials(self) -> None:
        remote = next(
            unit for unit in self.contract["units"] if unit["id"] == "local-and-remote-free"
        )
        page = next(unit for unit in self.contract["units"] if unit["id"] == "page-lifecycle")
        arena = next(unit for unit in self.contract["units"] if unit["id"] == "arena-lifecycle")
        for unit in (remote, page):
            with self.subTest(unit=unit["id"]):
                self.assertEqual(unit["status"], "partial")
                self.assertIn("25-field native C/Rust differential", unit["difference"])
                self.assertIn("28-field native C/Rust differential", unit["difference"])
                self.assertIn("8-field native C/Rust differential", unit["difference"])
                self.assertIn("13-field native C/Rust differential", unit["difference"])
                self.assertIn("18-field native C/Rust differential", unit["difference"])
                self.assertIn("21-field native C/Rust differential", unit["difference"])
                self.assertIn("25-field native C/Rust differential", unit["difference"])
                self.assertIn("46-field native C/Rust differential", unit["difference"])
                self.assertIn("53-field native C/Rust differential", unit["difference"])
                self.assertIn("40-field native C/Rust differential", unit["difference"])
                self.assertIn("1025-byte ordinary regular-small arena page", unit["difference"])
                self.assertIn("quick-collect", unit["difference"])
                self.assertIn("same-Theap", unit["difference"])
                self.assertIn(
                    "compat/allocator/x86_64_aggregate_post_exit_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64-aggregate-post-exit-evidence-v3.5.0.json",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_aggregate_post_exit_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64_aggregate_still_live_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64-aggregate-still-live-evidence-v3.5.0.json",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_aggregate_still_live_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64_aggregate_same_bin_still_live_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64-aggregate-same-bin-still-live-evidence-v3.5.0.json",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_aggregate_same_bin_still_live_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64_remote_free_evidence.py", unit["evidence"]
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_remote_free_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64_direct_remote_evidence.py", unit["evidence"]
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_direct_remote_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64_mapped_reclaim_evidence.py", unit["evidence"]
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_mapped_reclaim_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64_unmapped_reabandon_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64_mapped_post_exit_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64-mapped-post-exit-evidence-v3.5.0.json",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_mapped_post_exit_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_unmapped_reabandon_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64_retired_prepass_evidence.py", unit["evidence"]
                )
                self.assertIn(
                    "compat/allocator/x86_64-retired-prepass-evidence-v3.5.0.json",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_retired_prepass_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64_regular_small_evidence.py",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/x86_64-regular-small-evidence-v3.5.0.json",
                    unit["evidence"],
                )
                self.assertIn(
                    "compat/allocator/tests/test_x86_64_regular_small_evidence.py",
                    unit["evidence"],
                )
        self.assertLessEqual(remote["source_anchor"]["start_line"], 44)
        self.assertGreaterEqual(remote["source_anchor"]["end_line"], 515)
        self.assertLessEqual(page["source_anchor"]["start_line"], 150)
        self.assertIn("None proves general asynchronous public free routing", remote["difference"])
        self.assertIn("None proves general page routing", page["difference"])
        self.assertGreaterEqual(arena["source_anchor"]["end_line"], 1409)
        self.assertIn("mapped-abandon bitmap transition", arena["difference"])
        self.assertIn("compat/allocator/x86_64_mapped_reclaim_evidence.py", arena["evidence"])
        self.assertIn("13-field C/Rust differential", arena["difference"])
        self.assertIn("compat/allocator/x86_64_unmapped_reabandon_evidence.py", arena["evidence"])
        self.assertIn("18-field C/Rust differential", arena["difference"])
        self.assertIn("21-field C/Rust differential", arena["difference"])
        self.assertIn("25-field C/Rust differential", arena["difference"])
        self.assertIn("46-field C/Rust differential", arena["difference"])
        self.assertIn("53-field C/Rust differential", arena["difference"])
        self.assertIn("40-field C/Rust differential", arena["difference"])
        self.assertIn("ordinary regular-small arena page", arena["difference"])
        self.assertIn("ordinary arena bitmap/exact slice release", arena["difference"])
        self.assertIn("compat/allocator/x86_64_mapped_post_exit_evidence.py", arena["evidence"])
        self.assertIn("compat/allocator/x86_64_retired_prepass_evidence.py", arena["evidence"])
        self.assertIn("compat/allocator/x86_64_aggregate_post_exit_evidence.py", arena["evidence"])
        self.assertIn("compat/allocator/x86_64_aggregate_still_live_evidence.py", arena["evidence"])
        self.assertIn(
            "compat/allocator/x86_64_aggregate_same_bin_still_live_evidence.py",
            arena["evidence"],
        )
        self.assertIn(
            "compat/allocator/x86_64-aggregate-still-live-evidence-v3.5.0.json",
            arena["evidence"],
        )
        self.assertIn(
            "compat/allocator/tests/test_x86_64_aggregate_still_live_evidence.py",
            arena["evidence"],
        )
        self.assertIn(
            "compat/allocator/x86_64-aggregate-same-bin-still-live-evidence-v3.5.0.json",
            arena["evidence"],
        )
        self.assertIn(
            "compat/allocator/tests/test_x86_64_aggregate_same_bin_still_live_evidence.py",
            arena["evidence"],
        )
        self.assertIn(
            "compat/allocator/x86_64_regular_small_evidence.py", arena["evidence"]
        )
        self.assertIn(
            "compat/allocator/x86_64-regular-small-evidence-v3.5.0.json",
            arena["evidence"],
        )
        self.assertIn(
            "compat/allocator/tests/test_x86_64_regular_small_evidence.py",
            arena["evidence"],
        )
        for terminal_field in (
            "page_map_unregistered_after_final_free",
            "arena_page_bitmap_clear_after_final_free",
            "arena_slice_released_after_final_free",
        ):
            self.assertIn(terminal_field, arena["difference"])

        initialization = next(
            unit
            for unit in self.contract["units"]
            if unit["id"] == "process-and-thread-initialization"
        )
        theap = next(
            unit
            for unit in self.contract["units"]
            if unit["id"] == "thread-local-heap-lifecycle"
        )
        for unit in (initialization, theap):
            self.assertEqual(unit["status"], "partial")
            self.assertIn("18-field native differential", unit["difference"])
            self.assertIn("21-field native differential", unit["difference"])
            self.assertIn("25-field native differential", unit["difference"])
            self.assertIn("46-field native differential", unit["difference"])
            self.assertIn("53-field native differential", unit["difference"])
            self.assertIn(
                "compat/allocator/x86_64_aggregate_post_exit_evidence.py",
                unit["evidence"],
            )
            self.assertIn(
                "compat/allocator/x86_64-aggregate-post-exit-evidence-v3.5.0.json",
                unit["evidence"],
            )
            self.assertIn(
                "compat/allocator/x86_64_aggregate_still_live_evidence.py",
                unit["evidence"],
            )
            self.assertIn(
                "compat/allocator/x86_64-aggregate-still-live-evidence-v3.5.0.json",
                unit["evidence"],
            )
            self.assertIn(
                "compat/allocator/tests/test_x86_64_aggregate_still_live_evidence.py",
                unit["evidence"],
            )
            self.assertIn(
                "compat/allocator/x86_64_aggregate_same_bin_still_live_evidence.py",
                unit["evidence"],
            )
            self.assertIn(
                "compat/allocator/x86_64-aggregate-same-bin-still-live-evidence-v3.5.0.json",
                unit["evidence"],
            )
            self.assertIn(
                "compat/allocator/tests/test_x86_64_aggregate_same_bin_still_live_evidence.py",
                unit["evidence"],
            )
            self.assertIn("compat/allocator/x86_64_retired_prepass_evidence.py", unit["evidence"])
            self.assertIn(
                "compat/allocator/x86_64-retired-prepass-evidence-v3.5.0.json",
                unit["evidence"],
            )
            self.assertIn("Theap/TLD teardown", unit["difference"])
            self.assertIn("compat/allocator/x86_64_mapped_post_exit_evidence.py", unit["evidence"])

        self.assertLessEqual(theap["source_anchor"]["start_line"], 123)
        self.assertIn("40-field native differential", theap["difference"])
        self.assertIn("same-Theap 1025-byte ordinary regular-small page", theap["difference"])
        self.assertIn("generic quick-collect/same-page reuse", theap["difference"])
        self.assertIn("compat/allocator/x86_64_regular_small_evidence.py", theap["evidence"])
        self.assertIn(
            "compat/allocator/x86_64-regular-small-evidence-v3.5.0.json",
            theap["evidence"],
        )
        self.assertIn(
            "compat/allocator/tests/test_x86_64_regular_small_evidence.py",
            theap["evidence"],
        )

    def test_full_non_direct_small_post_exit_lane_is_limited_to_its_reviewed_units(self) -> None:
        reviewed_unit_ids = {
            "local-and-remote-free",
            "arena-lifecycle",
            "process-and-thread-initialization",
            "page-map-lifecycle",
            "page-queue-kernels",
            "page-lifecycle",
            "thread-local-heap-lifecycle",
        }
        lane_evidence = {
            "compat/allocator/tests/test_x86_64_full_non_direct_small_force_collect_post_exit_evidence.py",
            "compat/allocator/x86_64-full-non-direct-small-force-collect-post-exit-evidence-v3.5.0.json",
            "compat/allocator/x86_64_full_non_direct_small_force_collect_post_exit_evidence.py",
        }
        main_heap_page_source = "crabc-mimalloc/src/main_heap_page.rs"
        main_heap_page_module = "crabc_mimalloc::main_heap_page"
        units = {unit["id"]: unit for unit in self.contract["units"]}

        self.assertEqual(
            {
                unit_id
                for unit_id, unit in units.items()
                if lane_evidence <= set(unit["evidence"])
            },
            reviewed_unit_ids,
        )
        for evidence in lane_evidence:
            with self.subTest(evidence=evidence):
                self.assertEqual(
                    {
                        unit_id
                        for unit_id, unit in units.items()
                        if evidence in unit["evidence"]
                    },
                    reviewed_unit_ids,
                )
        self.assertEqual(
            {
                unit_id
                for unit_id, unit in units.items()
                if main_heap_page_source in unit["evidence"]
            },
            reviewed_unit_ids,
        )
        self.assertEqual(
            {
                unit_id
                for unit_id, unit in units.items()
                if main_heap_page_module in unit["rust_modules"]
            },
            reviewed_unit_ids,
        )
        for unit_id in reviewed_unit_ids:
            with self.subTest(unit=unit_id):
                unit = units[unit_id]
                self.assertEqual(unit["status"], "partial")
                self.assertIn("25-field native C/Rust differential", unit["difference"])
                self.assertIn("1032-byte arena full non-direct-small", unit["difference"])

    def test_full_direct_small_post_exit_lane_preserves_cache_preflight_and_mapped_force_route(
        self,
    ) -> None:
        reviewed_unit_ids = {
            "local-and-remote-free",
            "arena-lifecycle",
            "process-and-thread-initialization",
            "page-map-lifecycle",
            "page-queue-kernels",
            "page-lifecycle",
            "thread-local-heap-lifecycle",
        }
        lane_evidence = {
            "compat/allocator/tests/test_x86_64_full_direct_small_force_collect_post_exit_evidence.py",
            "compat/allocator/x86_64-full-direct-small-force-collect-post-exit-evidence-v3.5.0.json",
            "compat/allocator/x86_64_full_direct_small_force_collect_post_exit_evidence.py",
        }
        units = {unit["id"]: unit for unit in self.contract["units"]}

        self.assertEqual(
            {
                unit_id
                for unit_id, unit in units.items()
                if lane_evidence <= set(unit["evidence"])
            },
            reviewed_unit_ids,
        )
        for evidence in lane_evidence:
            with self.subTest(evidence=evidence):
                self.assertEqual(
                    {
                        unit_id
                        for unit_id, unit in units.items()
                        if evidence in unit["evidence"]
                    },
                    reviewed_unit_ids,
                )
        for unit_id in reviewed_unit_ids:
            with self.subTest(unit=unit_id):
                unit = units[unit_id]
                self.assertEqual(unit["status"], "partial")
                self.assertIn(
                    "compat/allocator/x86_64-full-direct-small-force-collect-post-exit-evidence-v3.5.0.json",
                    unit["evidence"],
                )
                self.assertIn("28-field native C/Rust differential", unit["difference"])
                self.assertIn("complete rounded direct-cache range", unit["difference"])
                self.assertIn("immediately publishes mapped abandonment", unit["difference"])
                self.assertIn("ordinary queue detached", unit["difference"])
                self.assertIn(
                    "arena_abandoned_bin_bitmap_clear_after_final_free",
                    unit["difference"],
                )

    def test_dynamic_full_medium_one_remote_lane_is_scoped_to_reviewed_units(self) -> None:
        reviewed_unit_ids = {
            "local-and-remote-free",
            "arena-lifecycle",
            "page-map-lifecycle",
            "page-queue-kernels",
            "page-lifecycle",
            "thread-local-heap-lifecycle",
        }
        lane_evidence = {
            "compat/allocator/tests/test_x86_64_dynamic_full_medium_one_remote_force_collect_to_mapped_evidence.py",
            "compat/allocator/x86_64-dynamic-full-medium-one-remote-force-collect-to-mapped-evidence-v3.5.0.json",
            "compat/allocator/x86_64_dynamic_full_medium_one_remote_force_collect_to_mapped_evidence.py",
        }
        units = {unit["id"]: unit for unit in self.contract["units"]}
        self.assertEqual(
            {
                unit_id
                for unit_id, unit in units.items()
                if lane_evidence <= set(unit["evidence"])
            },
            reviewed_unit_ids,
        )
        for unit_id in reviewed_unit_ids:
            with self.subTest(unit=unit_id):
                unit = units[unit_id]
                self.assertEqual(unit["status"], "partial")
                self.assertIn("29-field native C/Rust differential", unit["difference"])
                self.assertIn("dynamic full-medium one-remote force-collect-to-mapped route", unit["difference"])
        theap = units["thread-local-heap-lifecycle"]
        self.assertIn("exact eight-slice release", theap["difference"])
        self.assertIn("not general lifecycle", theap["difference"])

    def test_dynamic_full_large_one_remote_lane_is_scoped_to_reviewed_units(self) -> None:
        reviewed_unit_ids = {
            "local-and-remote-free",
            "arena-lifecycle",
            "page-map-lifecycle",
            "page-queue-kernels",
            "page-lifecycle",
            "thread-local-heap-lifecycle",
        }
        lane_evidence = {
            "compat/allocator/tests/test_x86_64_dynamic_full_large_one_remote_force_collect_to_mapped_evidence.py",
            "compat/allocator/x86_64-dynamic-full-large-one-remote-force-collect-to-mapped-evidence-v3.5.0.json",
            "compat/allocator/x86_64_dynamic_full_large_one_remote_force_collect_to_mapped_evidence.py",
        }
        units = {unit["id"]: unit for unit in self.contract["units"]}
        self.assertEqual(
            {
                unit_id
                for unit_id, unit in units.items()
                if lane_evidence <= set(unit["evidence"])
            },
            reviewed_unit_ids,
        )
        for unit_id in reviewed_unit_ids:
            with self.subTest(unit=unit_id):
                unit = units[unit_id]
                self.assertEqual(unit["status"], "partial")
                self.assertIn("31-field native C/Rust differential", unit["difference"])
                self.assertIn("dynamic full-large one-remote force-collect-to-mapped route", unit["difference"])
                self.assertIn("63 PageMap-registered source page-area slices", unit["difference"])
                self.assertIn("final PageMap-null arena slice is slack", unit["difference"])

    def test_dynamic_os_aligned_singleton_owner_exit_lane_is_scoped_to_reviewed_units(
        self,
    ) -> None:
        reviewed_unit_ids = {
            "aligned-allocation-paths",
            "arena-lifecycle",
            "local-and-remote-free",
            "os-allocation-policy",
            "page-map-lifecycle",
            "page-queue-kernels",
            "page-lifecycle",
            "process-and-thread-initialization",
            "thread-local-heap-lifecycle",
        }
        lane_evidence = {
            "compat/allocator/tests/test_x86_64_dynamic_os_aligned_singleton_evidence.py",
            "compat/allocator/x86_64-dynamic-os-aligned-singleton-evidence-v3.5.0.json",
            "compat/allocator/x86_64_dynamic_os_aligned_singleton_evidence.py",
        }
        units = {unit["id"]: unit for unit in self.contract["units"]}
        self.assertEqual(
            {
                unit_id
                for unit_id, unit in units.items()
                if lane_evidence <= set(unit["evidence"])
            },
            reviewed_unit_ids,
        )
        for unit_id in reviewed_unit_ids:
            with self.subTest(unit=unit_id):
                unit = units[unit_id]
                self.assertEqual(unit["status"], "partial")
                self.assertIn("21-value native C/Rust differential", unit["difference"])
                self.assertIn("semantically full", unit["difference"])
                self.assertIn("`BIN_HUGE`", unit["difference"])
                for evidence in lane_evidence:
                    self.assertIn(evidence, unit["evidence"])

        self.assertLessEqual(
            units["aligned-allocation-paths"]["source_anchor"]["start_line"], 68
        )
        self.assertLessEqual(
            units["page-queue-kernels"]["source_anchor"]["start_line"], 174
        )
        self.assertLessEqual(
            units["thread-local-heap-lifecycle"]["source_anchor"]["start_line"], 24
        )

    def test_mapped_allocation_adoption_lane_is_scoped_to_its_four_source_boundaries(
        self,
    ) -> None:
        reviewed_unit_ids = {
            "arena-lifecycle",
            "page-lifecycle",
            "page-queue-kernels",
            "tls-interface-and-thread-identity",
        }
        lane_evidence = {
            "compat/allocator/tests/test_x86_64_mapped_adoption_evidence.py",
            "compat/allocator/x86_64-mapped-adoption-evidence-v3.5.0.json",
            "compat/allocator/x86_64_mapped_adoption_evidence.py",
        }
        units = {unit["id"]: unit for unit in self.contract["units"]}
        self.assertEqual(
            {
                unit_id
                for unit_id, unit in units.items()
                if lane_evidence <= set(unit["evidence"])
            },
            reviewed_unit_ids,
        )
        for unit_id in reviewed_unit_ids:
            with self.subTest(unit=unit_id):
                unit = units[unit_id]
                self.assertEqual(unit["status"], "partial")
                self.assertIn("18-value native C/Rust differential", unit["difference"])
                for evidence in lane_evidence:
                    self.assertIn(evidence, unit["evidence"])
        self.assertEqual(
            units["arena-lifecycle"]["source_anchor"],
            {
                "member": "src/arena.c",
                "start_line": 655,
                "end_line": 1409,
                "sha256": "fdefc099be5c4b86c28fe000c94d3751046a652f94557fac3868a1be9baaab70",
            },
        )
        self.assertEqual(
            units["tls-interface-and-thread-identity"]["source_anchor"],
            {
                "member": "include/mimalloc/prim-tls.h",
                "start_line": 14,
                "end_line": 421,
                "sha256": "6ba6061a15d04e62bc3b621fe4c9d8f665a7c817384bf3369c246a58e1d75e43",
            },
        )
        self.assertIn(
            "crabc_mimalloc::dynamic_theap",
            units["tls-interface-and-thread-identity"]["rust_modules"],
        )
        self.assertIn(
            "Pinned C reaches the exact bitmap claim through its next same-heap allocation",
            units["tls-interface-and-thread-identity"]["difference"],
        )
        self.assertIn(
            "Rust explicitly invokes its test-only `adopt()` adapter",
            units["tls-interface-and-thread-identity"]["difference"],
        )
        self.assertIn(
            "does not make generic allocation scan abandoned pages",
            units["tls-interface-and-thread-identity"]["difference"],
        )

    def test_implemented_bit_scope_anchors_every_claimed_scalar_helper(self) -> None:
        unit = next(
            unit
            for unit in self.contract["units"]
            if unit["id"] == "x86-64-width-and-bit-operations"
        )
        anchor = unit["source_anchor"]
        self.assertEqual(anchor["member"], "include/mimalloc/bits.h")
        self.assertLessEqual(anchor["start_line"], 49)
        self.assertGreaterEqual(anchor["end_line"], 350)
        anchored_source = SOURCE_MAP.source_range(
            self.sources[anchor["member"]],
            anchor["start_line"],
            anchor["end_line"],
        )
        for helper in (
            b"static inline size_t mi_popcount",
            b"static inline size_t mi_ctz",
            b"static inline size_t mi_clz",
            b"static inline bool mi_bsf",
            b"static inline bool mi_bsr",
            b"static inline size_t mi_rotr",
            b"static inline size_t mi_rotl",
            b"static inline uint32_t mi_rotl32",
        ):
            self.assertIn(helper, anchored_source)

    def test_implemented_bit_scope_rejects_a_config_only_anchor(self) -> None:
        malformed = copy.deepcopy(self.contract)
        unit = next(
            unit
            for unit in malformed["units"]
            if unit["id"] == "x86-64-width-and-bit-operations"
        )
        anchor = unit["source_anchor"]
        anchor["end_line"] = 145
        anchor["sha256"] = SOURCE_MAP.sha256_bytes(
            SOURCE_MAP.source_range(self.sources[anchor["member"]], anchor["start_line"], 145)
        )
        with self.assertRaisesRegex(
            SOURCE_MAP.SourceMapError,
            "does not anchor every claimed scalar helper",
        ):
            SOURCE_MAP.validate_contract(malformed, self.pin, self.sources)

    def test_completion_claim_is_rejected(self) -> None:
        malformed = copy.deepcopy(self.contract)
        malformed["overall"]["status"] = "complete"
        with self.assertRaisesRegex(SOURCE_MAP.SourceMapError, "cannot claim x86-64 engine completion"):
            SOURCE_MAP.validate_contract(malformed, self.pin, self.sources)

    def test_unratcheted_mapping_change_is_rejected(self) -> None:
        malformed = copy.deepcopy(self.contract)
        malformed["units"][0]["difference"] += " Changed without a ratchet review."
        with self.assertRaisesRegex(SOURCE_MAP.SourceMapError, "ratchet drifted"):
            SOURCE_MAP.validate_contract(malformed, self.pin, self.sources)

    def test_unreviewed_implemented_status_is_rejected(self) -> None:
        malformed = copy.deepcopy(self.contract)
        malformed["units"][9]["status"] = "implemented"
        with self.assertRaisesRegex(SOURCE_MAP.SourceMapError, "cannot claim implemented status"):
            SOURCE_MAP.validate_contract(malformed, self.pin, self.sources)

    def test_implemented_status_downgrade_is_rejected_despite_a_recomputed_ratchet(self) -> None:
        malformed = copy.deepcopy(self.contract)
        implemented = next(
            unit
            for unit in malformed["units"]
            if unit["id"] == "x86-64-width-and-bit-operations"
        )
        implemented["status"] = "partial"
        status_counts = SOURCE_MAP.status_counts(malformed["units"])
        malformed["ratchet"]["status_counts"] = status_counts
        malformed["ratchet"]["unfinished_unit_count"] = (
            status_counts["partial"] + status_counts["not-started"]
        )
        malformed["ratchet"]["units_sha256"] = SOURCE_MAP.canonical_sha256(
            malformed["units"]
        )
        with self.assertRaisesRegex(
            SOURCE_MAP.SourceMapError,
            "implemented-status baseline changed",
        ):
            SOURCE_MAP.validate_contract(malformed, self.pin, self.sources)

    def test_unratcheted_status_model_change_is_rejected(self) -> None:
        malformed = copy.deepcopy(self.contract)
        malformed["status_model"]["partial"] += " Changed without review."
        with self.assertRaisesRegex(SOURCE_MAP.SourceMapError, "ratchet drifted"):
            SOURCE_MAP.validate_contract(malformed, self.pin, self.sources)

    def test_anchor_hash_drift_is_rejected(self) -> None:
        malformed = copy.deepcopy(self.contract)
        malformed["units"][0]["source_anchor"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(SOURCE_MAP.SourceMapError, "source anchor drifted"):
            SOURCE_MAP.validate_contract(malformed, self.pin, self.sources)

    def test_source_member_substitution_is_rejected_before_archive_access(self) -> None:
        malformed = copy.deepcopy(self.contract)
        malformed["source"]["members"][0]["member"] = "src/os.c"
        with self.assertRaisesRegex(SOURCE_MAP.SourceMapError, "source-member inventory changed"):
            SOURCE_MAP.source_members_from_contract(malformed)


if __name__ == "__main__":
    unittest.main()
