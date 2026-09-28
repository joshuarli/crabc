#!/usr/bin/env python3
"""Contracts for the fail-closed native allocator gate."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
SPEC = importlib.util.spec_from_file_location("x86_64_m7_gate", ROOT / "compat/allocator/x86_64_m7_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
harness = gate.harness


class M7GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pin = harness.load_pin()
        self.contract = harness.read_json(gate.CONTRACT)
        self.api = harness.read_json(harness.ALLOCATOR_ROOT / "api-v3.5.0.json")
        self.sibling = gate.sibling_owned_items(self.contract["inventory"])

    def validate(self, contract=None, api=None, sibling=None):
        return gate.validate_contract(
            self.contract if contract is None else contract,
            self.api if api is None else api,
            self.pin,
            self.sibling if sibling is None else sibling,
        )

    def gate_record(self, contract, gate_id):
        return next(entry for entry in contract["gates"] if entry["id"] == gate_id)

    def test_checked_in_contract_partitions_the_m7_items_and_modes(self) -> None:
        summary = self.validate()
        self.assertEqual(summary["gate_ids"], list(gate.GATE_IDS))
        self.assertEqual(sorted(summary["runnable_evidence"]), [
            "audit:default-baseline",
            "differential:adapter",
            "differential:deferred-free-callback",
            "differential:destroy-on-exit",
            "differential:diagnostic-output-owner",
            "differential:error-reporting-sites",
            "differential:option-effects",
            "differential:option-profiles",
            "differential:options-environment",
            "differential:page-max-candidates",
            "differential:reclaim-options",
            "differential:show-errors-profile",
            "differential:startup-page-map-failure",
            "differential:statistics",
            "differential:statistics-aligned-huge",
            "differential:statistics-fast-allocation",
            "differential:statistics-huge",
            "differential:statistics-huge-page-bin",
            "differential:statistics-json",
            "differential:statistics-level-one",
            "differential:statistics-level-one-output-merge",
            "differential:statistics-level-two-bins",
            "differential:statistics-level-two-page-huge",
            "differential:statistics-level-two-requested",
            "differential:statistics-page-extend",
            "differential:statistics-remote-bin",
            "differential:statistics-remote-normal",
            "differential:statistics-requested-production",
            "differential:thread-init-failure",
        ])
        # The options/environment and baseline gates have executable evidence.
        self.assertEqual(
            summary["blocked_gate_ids"],
            [gate_id for gate_id in gate.GATE_IDS if gate_id not in ("m7.options-environment", "m7.baseline")],
        )
        owned = {name for entry in self.contract["gates"] for name in entry["items"]}
        for name in ("mi_option_get", "mi_option_reset_delay", "mi_options_print_out", "mi_version",
                     "mi_register_error", "mi_stats_print_out", "mi_debug_show_arenas"):
            self.assertIn(name, owned)
        # Heap/Theap/subprocess statistics and visitation belong to M6, and
        # the declaration-only `mi_stats_merge` is inapplicable.
        for name in ("mi_heap_stats_get", "mi_heap_visit_blocks", "mi_theap_guarded_set_sample_rate",
                     "mi_stats_merge", "mi_malloc"):
            self.assertNotIn(name, owned)
        modes = {name for entry in self.contract["gates"] for name in entry["compile_time_modes"]}
        self.assertIn("MI_GUARDED", modes)
        self.assertNotIn("MI_OVERRIDE", modes)

    def test_destroy_on_exit_requires_its_physical_option_effect_evidence(self) -> None:
        summary = self.validate()
        effect = self.gate_record(self.contract, "m7.option-effects")
        self.assertIn("differential:destroy-on-exit", effect["evidence"])
        self.assertIn("differential:destroy-on-exit", summary["runnable_evidence"])

    def test_destroy_on_exit_reader_rejects_missing_physical_state(self) -> None:
        rows = "".join(f"destroy_on_exit.{index}={value}\n" for index, value in enumerate((2, 1, 0, 0, 1, 0, 1)))
        self.assertEqual(gate.destroy_on_exit_fields(rows, "destroy_on_exit", "fixture"), [2, 1, 0, 0, 1, 0, 1])
        with self.assertRaises(harness.HarnessError):
            gate.destroy_on_exit_fields(rows.replace("destroy_on_exit.6=1\n", ""), "destroy_on_exit", "fixture")

    def test_page_max_candidates_requires_discriminating_option_effect_evidence(self) -> None:
        summary = self.validate()
        effect = self.gate_record(self.contract, "m7.option-effects")
        self.assertIn("differential:page-max-candidates", effect["evidence"])
        self.assertIn("differential:page-max-candidates", summary["runnable_evidence"])

    def test_page_max_candidates_reader_requires_changed_choice_and_intact_data(self) -> None:
        first = {"case.limit": "0", "case.distinct_pages": "1", "case.selected": "first",
                 "case.first_data": "1", "case.transferred_data": "1", "case.usable": "8192"}
        transferred = {**first, "case.limit": "4", "case.selected": "transferred"}
        gate.require_page_max_candidates_choice(first, 0, "first")
        gate.require_page_max_candidates_choice(transferred, 4, "transferred")
        with self.assertRaises(harness.HarnessError):
            gate.require_page_max_candidates_choice({**transferred, "case.selected": "first"}, 4, "unchanged")
        with self.assertRaises(harness.HarnessError):
            gate.require_page_max_candidates_choice({**first, "case.transferred_data": "0"}, 0, "corrupted")

    def test_statistics_level_one_requires_source_built_differential(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-level-one", statistics["evidence"])
        self.assertIn("differential:statistics-level-one", summary["runnable_evidence"])

    def test_statistics_level_one_reader_requires_merge_and_print(self) -> None:
        trace = {"profile.level": "1", "allocation.usable": "64", "allocated.normal": "64,64,64",
                 "merged.normal": "64,64,64", "freed.normal": "64,64,0",
                 "print.live_binned": "1", "print.live_total": "1",
                 "print.freed_binned": "1", "print.freed_total": "1"}
        gate.require_statistics_level_one(trace, "fixture")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_one({**trace, "merged.normal": "0,0,0"}, "lost merge")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_one({**trace, "print.live_binned": "0"}, "missing output")

    def test_statistics_level_one_output_merge_requires_source_built_differential(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-level-one-output-merge", statistics["evidence"])
        self.assertIn("differential:statistics-level-one-output-merge", summary["runnable_evidence"])

    def test_statistics_level_one_output_merge_rejects_missing_huge_and_empty_rows(self) -> None:
        rows = {f"{scenario}.{label}": "absent" if scenario == "empty" else "  binned    : live"
                for scenario in ("empty", "normal", "huge", "mixed", "freed")
                for label in ("binned", "huge", "total")}
        rows["normal.binned"] = "  binned    : not all freed"
        rows["mixed.huge"] = "  huge      : not all freed"
        for label in ("binned", "huge", "total"):
            rows[f"freed.{label}"] = f"  {label:<10}:  ok"
        counts = {
            "normal.source_reset": "0,0,0", "normal.process": "160,320,96",
            "huge.source_reset": "0,0,0", "huge.process": "3072,4096,2048",
            "mixed.source_normal_reset": "0,0,0", "mixed.source_huge_reset": "0,0,0",
            "mixed.process_normal": "320,576,224", "mixed.process_huge": "3072,6144,2560",
            "freed.source_normal_reset": "0,0,0", "freed.source_huge_reset": "0,0,0",
            "freed.process_normal": "320,576,0", "freed.process_huge": "3072,6144,0",
        }
        trace = {"profile.level": "1", **rows, **counts}
        gate.require_statistics_level_one_output_merge(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_one_output_merge({**trace, "empty.binned": "  binned:"}, "nonempty")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_one_output_merge({**trace, "mixed.huge": "absent"}, "missing huge")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_one_output_merge({**trace, "mixed.process_normal": "160,576,224"}, "lost peak")

    def test_statistics_level_two_requested_requires_source_built_differential(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-level-two-requested", statistics["evidence"])
        self.assertIn("differential:statistics-level-two-requested", summary["runnable_evidence"])

    def test_statistics_level_two_requested_reader_rejects_missing_rows_and_merge(self) -> None:
        rows = {f"{scenario}.{label}": "absent" if scenario == "empty" else "source row"
                for scenario in ("empty", "normal", "live", "freed")
                for label in ("binned", "huge", "total", "malloc_req")}
        rows.update({f"{scenario}.blocks": "0" if scenario == "empty" else "1"
                     for scenario in ("empty", "normal", "live", "freed")})
        rows["live.malloc_req"] = rows["freed.malloc_req"] = "  malloc req: 4.1 KiB"
        counts = {
            "normal.source_requested_reset": "0,0,0", "normal.process_requested": "140,280,70",
            "normal.process_count": "2", "live.source_requested_reset": "0,0,0",
            "live.process_requested": "3070,4280,2070", "live.process_count": "2,1",
            "freed.source_requested_reset": "0,0,0", "freed.process_requested": "3070,4280,0",
        }
        trace = {"profile.level": "2", **rows, **counts}
        gate.require_statistics_level_two_requested(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_two_requested({**trace, "live.malloc_req": "absent"}, "missing row")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_two_requested({**trace, "freed.process_requested": "3070,4280,10"}, "live free")

    def test_statistics_level_two_bins_requires_source_built_differential(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-level-two-bins", statistics["evidence"])
        self.assertIn("differential:statistics-level-two-bins", summary["runnable_evidence"])

    def test_statistics_level_two_bins_reader_rejects_order_and_peak_loss(self) -> None:
        rows = {f"{scenario}.{label}": "absent" if scenario == "empty" or label == "bin9" else "  bin row: not all freed"
                for scenario in ("empty", "first", "merged", "freed")
                for label in ("bin8", "bin9", "bin40")}
        rows.update({"empty.order": "none", "first.order": "8", "merged.order": "8,40", "freed.order": "8,40",
                     "first.bin40": "absent", "freed.bin8": "  bin row:  ok", "freed.bin40": "  bin row:  ok"})
        counts = {"first.source_bin8_reset": "0,0,0", "first.process_bin8": "2,3,1",
                  "merged.source_bin8_reset": "0,0,0", "merged.source_bin40_reset": "0,0,0",
                  "merged.process_bin8": "5,8,3", "merged.process_bin40": "2,3,1",
                  "freed.source_bin8_reset": "0,0,0", "freed.source_bin40_reset": "0,0,0",
                  "freed.process_bin8": "5,8,0", "freed.process_bin40": "2,3,0"}
        trace = {"profile.level": "2", **rows, **counts}
        gate.require_statistics_level_two_bins(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_two_bins({**trace, "merged.order": "40,8"}, "wrong order")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_two_bins({**trace, "merged.process_bin8": "4,8,3"}, "lost peak")

    def test_statistics_level_two_page_huge_requires_source_built_differential(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-level-two-page-huge", statistics["evidence"])
        self.assertIn("differential:statistics-level-two-page-huge", summary["runnable_evidence"])

    def test_statistics_level_two_page_huge_reader_rejects_order_and_merge_loss(self) -> None:
        scenarios = ("empty", "huge", "live", "freed")
        labels = ("huge", "touched", "pages", "abandoned")
        trace = {f"{scenario}.{label}": "absent" if scenario == "empty" or
                 (scenario == "huge" and label != "huge") else "  row: not all freed"
                 for scenario in scenarios for label in labels}
        trace.update({"profile.level": "2", "empty.order": "none", "huge.order": "blocks",
                      "live.order": "blocks,pages", "freed.order": "blocks,pages",
                      "huge.source_reset": "0,0,0", "huge.process": "4096,8192,4096",
                      "live.source_huge_reset": "0,0,0", "live.source_pages_reset": "0,0,0",
                      "live.process_huge": "10240,20480,6144", "live.process_pages": "4,6,3",
                      "live.process_touched": "16384,24576,12288", "live.process_abandoned": "2,3,1",
                      "freed.source_huge_reset": "0,0,0", "freed.source_pages_reset": "0,0,0",
                      "freed.process_huge": "10240,20480,0", "freed.process_pages": "4,6,0",
                      "freed.process_touched": "16384,24576,0", "freed.process_abandoned": "2,3,0"})
        trace["live.touched"] = "  touched   : live"
        trace["live.pages"] = "  pages     : 3 "
        trace["live.abandoned"] = "  abandoned : 1 "
        for label in ("huge", "touched"):
            trace[f"freed.{label}"] = "  row:  ok"
        trace["freed.pages"] = "  pages     : 0 "
        trace["freed.abandoned"] = "  abandoned : 0 "
        gate.require_statistics_level_two_page_huge(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_two_page_huge({**trace, "live.order": "pages,blocks"}, "wrong order")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_two_page_huge({**trace, "live.process_huge": "6144,20480,6144"}, "lost peak")

    def test_statistics_json_requires_three_source_built_profiles(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-json", statistics["evidence"])
        self.assertIn("differential:statistics-json", summary["runnable_evidence"])

    def test_statistics_json_reader_rejects_truncation_and_lost_fields(self) -> None:
        trace = {
            "profile.level": "2", "json.grown": "1", "json.version": "1",
            "json.mimalloc_version": "1", "json.process": "1", "json.chunk_bins": "1",
            "json.hash": "123456789abcdef0", "json.pages": "6,4,3",
            "json.malloc_normal": "320,160,96", "json.malloc_huge": "8192,4096,2048",
            "json.malloc_requested": "280,140,70", "json.malloc_bins.bin8": "5,4,2,128,65536",
            "json.page_bins.bin8": "3,2,1,128,65536",
            "fixed.sufficient.result": "1", "fixed.sufficient.complete": "1",
            "fixed.sufficient.guard": "1",
            "zero_size.grown": "1", "zero_size.caller_intact": "1",
            "null_buffer.grown": "1", "invalid.version": "1",
            "invalid.caller_intact": "1", "invalid.null_image": "1",
            "get.grown": "1", "get.version": "1", "get.short": "0",
            "get.short.prefix": "7b0a00", "get.short.guard": "1",
        }
        for name, prefix in (("one", "00"), ("two", "7b00"), ("three", "7b0a00"),
                             ("sixtyfour", "7b0a202022737461")):
            trace[f"fixed.{name}.result"] = "0"
            trace[f"fixed.{name}.prefix"] = prefix
            trace[f"fixed.{name}.guard"] = "1"
        gate.require_statistics_json(trace, 2, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_json({**trace, "fixed.sufficient.result": "0"}, 2, "lost full output")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_json({**trace, "json.malloc_requested": "0,0,0"}, 2, "lost field")

    def test_statistics_page_extension_requires_source_built_producer(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-page-extend", statistics["evidence"])
        self.assertIn("differential:statistics-page-extend", summary["runnable_evidence"])

    def test_statistics_page_extension_reader_rejects_missing_touched_bytes(self) -> None:
        trace = {"profile.level": "1", "allocation.usable": "64",
                 "allocated.pages_extended": "1", "allocated.page_committed": "8192,8192,8192",
                 "allocated.pages": "1,1,1", "freed.pages_extended": "1",
                 "freed.page_committed": "8192,8192,8192"}
        gate.require_statistics_page_extend(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_page_extend({**trace, "allocated.page_committed": "0,0,0"}, "missing bytes")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_page_extend({**trace, "allocated.pages_extended": "0"}, "missing event")

    def test_statistics_huge_requires_source_built_producer(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-huge", statistics["evidence"])
        self.assertIn("differential:statistics-huge", summary["runnable_evidence"])

    def test_statistics_huge_reader_rejects_lost_nonlocal_free(self) -> None:
        trace = {"profile.level": "1", "allocation.usable": "589824",
                 "allocated.huge": "589824,589824,589824", "allocated.huge_count": "1",
                 "allocated.normal": "0", "freed.huge": "589824,589824,0",
                 "freed.huge_count": "1"}
        gate.require_statistics_huge(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_huge({**trace, "freed.huge": "589824,589824,589824"}, "lost free")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_huge({**trace, "allocated.huge_count": "0"}, "lost event")

    def test_statistics_huge_page_bin_requires_source_built_producer(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-huge-page-bin", statistics["evidence"])
        self.assertIn("differential:statistics-huge-page-bin", summary["runnable_evidence"])

    def test_statistics_huge_page_bin_reader_rejects_lost_release_or_worker_merge(self) -> None:
        trace = {
            "profile.level": "2", "request": "524289", "usable": "589824",
            "disallow_os_alloc": "1", "disallow_arena_alloc": "0",
            "allocated.mapped": "1", "worker.mapped": "1",
            "before.arena": "1076166656,3,1", "allocated.arena": "1076166656,3,1",
            "terminal.arena": "1076166656,3,1",
        }
        fields = ("huge", "requested", "normal", "huge_bin", "huge_page_bin", "pages",
                  "huge_count", "normal_count")
        stages = {
            "allocated": ("589824,589824,589824", "0,0,0", "0,0,0", "0,0,0",
                          "1,1,1", "1,1,1", "1", "0"),
            "merged": ("589824,589824,589824", "0,0,0", "0,0,0", "0,0,0",
                       "1,1,1", "1,1,1", "1", "0"),
            "freed": ("589824,589824,0", "8,8,8", "8,8,0", "0,0,0",
                      "1,1,0", "2,1,0", "1", "1"),
            "terminal": ("589824,589824,0", "8,8,8", "8,8,0", "0,0,0",
                         "1,1,0", "2,1,0", "1", "1"),
        }
        for stage, values in stages.items():
            trace.update({f"{stage}.{field}": value for field, value in zip(fields, values)})
        gate.require_statistics_huge_page_bin(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_huge_page_bin({**trace, "freed.huge_page_bin": "1,1,1"},
                                                  "lost huge page release")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_huge_page_bin({**trace, "terminal.huge": "589824,589824,589824"},
                                                  "lost huge free")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_huge_page_bin({**trace, "freed.requested": "0,0,0"},
                                                  "lost worker merge")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_huge_page_bin({**trace, "allocated.arena": "1076166656,4,1"},
                                                  "unexpected OS mapping")

    def test_statistics_remote_normal_requires_source_built_producer(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-remote-normal", statistics["evidence"])
        self.assertIn("differential:statistics-remote-normal", summary["runnable_evidence"])

    def test_statistics_remote_normal_reader_rejects_lost_worker_delta(self) -> None:
        worker_row = "  binned    :     8           8         -64                                not all freed"
        trace = {"profile.level": "1", "warm.usable": "8", "target.usable": "64",
                 "allocated.normal": "64,64,64", "freed.normal": "72,72,0",
                 "worker.binned.hex": worker_row.encode("ascii").hex()}
        gate.require_statistics_remote_normal(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_normal({**trace, "freed.normal": "72,72,64"}, "lost free")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_normal({**trace,
                "worker.binned.hex": worker_row.replace("-64", "  0").encode("ascii").hex()}, "lost worker current")

    def test_statistics_remote_bin_requires_source_built_producer(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-remote-bin", statistics["evidence"])
        self.assertIn("differential:statistics-remote-bin", summary["runnable_evidence"])

    def test_statistics_remote_bin_reader_rejects_lost_worker_free(self) -> None:
        worker_bin = "  bin S    8:    64   B      64   B     -64   B      64   B       1        not all freed"
        worker_requested = "  malloc req:    64   B"
        medium_worker_bin = "  bin M   44:    32.1 KiB    32.1 KiB   -32.1 KiB    32.1 KiB      1        not all freed"
        medium_worker_requested = "  malloc req:    32.1 KiB"
        trace = {
            "profile.level": "2", "warm.usable": "64", "target.usable": "64", "target.bin": "8",
            "allocated.bin": "1,1,1", "allocated.requested": "64,64,64",
            "allocated.normal": "64,64,64", "allocated.normal_count": "1",
            "main_merged.bin": "1,1,1", "main_merged.requested": "64,64,64",
            "main_merged.normal": "64,64,64", "main_merged.normal_count": "1",
            "freed.bin": "2,2,0", "freed.requested": "128,128,128",
            "freed.normal": "128,128,0", "freed.normal_count": "2",
            "worker.bin.hex": worker_bin.encode("ascii").hex(),
            "worker.requested.hex": worker_requested.encode("ascii").hex(),
            "medium.warm.usable": "32768", "medium.target.usable": "32768",
            "medium.target.bin": "44", "medium.disallow_os_alloc": "1",
            "medium.disallow_arena_alloc": "0", "medium.target.mapped": "1",
            "medium.survivor.mapped": "1", "medium.survivor.data": "1",
            "medium.before.arena": "1076166656,4,1",
            "medium.allocated.arena": "1076166656,4,1",
            "medium.terminal.arena": "1076166656,4,1",
            "medium.allocated.bin": "2,2,2", "medium.allocated.requested": "65536,65536,65536",
            "medium.allocated.normal": "65536,65408,65536", "medium.allocated.normal_count": "2",
            "medium.allocated.page_bin": "1,1,1",
            "medium.merged.bin": "2,2,2", "medium.merged.requested": "65536,65536,65536",
            "medium.merged.normal": "65536,65408,65536", "medium.merged.normal_count": "2",
            "medium.merged.page_bin": "1,1,1",
            "medium.freed.bin": "3,3,1", "medium.freed.requested": "98304,98304,98304",
            "medium.freed.normal": "98304,98176,32768", "medium.freed.normal_count": "3",
            "medium.freed.page_bin": "2,2,1",
            "medium.collected.bin": "3,3,1", "medium.collected.requested": "98304,98304,98304",
            "medium.collected.normal": "98304,98176,32768", "medium.collected.normal_count": "3",
            "medium.collected.page_bin": "2,2,1",
            "medium.terminal.bin": "3,3,0", "medium.terminal.requested": "98304,98304,98304",
            "medium.terminal.normal": "98304,98176,0", "medium.terminal.normal_count": "3",
            "medium.terminal.page_bin": "2,2,0",
            "worker.medium.bin.hex": medium_worker_bin.encode("ascii").hex(),
            "worker.medium.requested.hex": medium_worker_requested.encode("ascii").hex(),
        }
        gate.require_statistics_remote_bin(trace, "complete")
        gate.require_statistics_remote_bin({**trace,
            "medium.before.arena": "1076166656,3,1",
            "medium.allocated.arena": "1076166656,3,1",
            "medium.terminal.arena": "1076166656,3,1"}, "different startup mmap history")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_bin({**trace, "freed.bin": "2,2,1"}, "lost process free")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_bin({**trace,
                "worker.bin.hex": worker_bin.replace("-64", "  0").encode("ascii").hex()}, "lost worker free")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_bin({**trace, "freed.requested": "128,128,64"}, "lost requested record")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_bin({**trace, "medium.freed.bin": "3,3,2"}, "lost medium remote free")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_bin({**trace, "medium.terminal.page_bin": "2,2,1"}, "lost medium release")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_bin({**trace, "medium.survivor.mapped": "0"}, "lost medium mapping")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_bin({**trace, "medium.allocated.arena": "1076166656,5,1"},
                                               "unexpected OS allocation")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_remote_bin({**trace, "medium.disallow_os_alloc": "0"},
                                               "arena policy not selected")

    def test_statistics_aligned_huge_requires_source_built_producer(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-aligned-huge", statistics["evidence"])
        self.assertIn("differential:statistics-aligned-huge", summary["runnable_evidence"])

    def test_statistics_requested_production_requires_source_built_profile(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-requested-production", statistics["evidence"])
        self.assertIn("differential:statistics-requested-production", summary["runnable_evidence"])

    def test_statistics_requested_production_reader_rejects_missing_free_and_merge(self) -> None:
        trace = {
            "profile.level": "2", "ordinary.request": "63", "ordinary.usable": "64",
            "ordinary.bin": "8", "aligned.request": "100", "aligned.usable": "4096",
            "aligned.bin": "32", "aligned.pointer": "1",
        }
        stages = {
            "ordinary": ("63,63,63", "1,1,1", "0,0,0", 1, 0),
            "ordinary_merged": ("63,63,63", "1,1,1", "0,0,0", 1, 0),
            "aligned": ("1088,1088,1088", "1,1,1", "1,1,1", 2, 1),
            "aligned_merged": ("1088,1088,1088", "1,1,1", "1,1,1", 2, 1),
            "ordinary_freed": ("1088,1088,1088", "1,1,0", "1,1,1", 2, 1),
            "aligned_freed": ("1088,1088,1088", "1,1,0", "1,1,0", 2, 1),
            "final_merged": ("1088,1088,1088", "1,1,0", "1,1,0", 2, 1),
        }
        for stage, values in stages.items():
            for field, value in zip(("requested", "ordinary_bin", "aligned_bin",
                                     "normal_count", "huge_count"), values):
                trace[f"{stage}.{field}"] = str(value)
        gate.require_statistics_requested_production(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_requested_production(
                {**trace, "ordinary_freed.ordinary_bin": "1,1,1"}, "missing free")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_requested_production(
                {**trace, "ordinary_merged.requested": "0,0,0"}, "missing merge")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_requested_production(
                {**trace, "final_merged.requested": "1088,1088,0"}, "lost requested current")

    def test_statistics_fast_allocation_requires_source_built_profile(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-fast-allocation", statistics["evidence"])
        self.assertIn("differential:statistics-fast-allocation", summary["runnable_evidence"])

    def test_statistics_fast_allocation_reader_rejects_wrong_page_or_producer(self) -> None:
        trace = {"profile.level": "2"}
        for case, size, bin_index in (("direct64", 64, 8), ("small8192", 8192, 36),
                                      ("medium32768", 32768, 44)):
            trace.update({f"{case}.request": str(size), f"{case}.usable": str(size),
                          f"{case}.bin_index": str(bin_index), f"{case}.zero_all": "1",
                          f"{case}.distinct": "1"})
            for stage in ("allocated", "merged", "freed", "final_merged"):
                live = stage in ("allocated", "merged")
                trace.update({f"{case}.{stage}.requested": f"{size},{size},{size}",
                              f"{case}.{stage}.bin": f"1,0,{int(live)}",
                              f"{case}.{stage}.normal_count": "1",
                              f"{case}.{stage}.page_bin_current": "0",
                              f"{case}.{stage}.searches": "0",
                              f"{case}.{stage}.extensions": "0"})
        gate.require_statistics_fast_allocation(trace, "complete")
        for field, value in (("direct64.allocated.requested", "0,0,0"),
                             ("small8192.allocated.searches", "1"),
                             ("medium32768.freed.bin", "1,0,1"),
                             ("medium32768.zero_all", "0")):
            with self.assertRaises(harness.HarnessError):
                gate.require_statistics_fast_allocation({**trace, field: value}, "changed trace")

    def test_statistics_aligned_huge_reader_rejects_lost_units_and_merge(self) -> None:
        row = "  huge      :   578.2 KiB   578.2 KiB   578.2 KiB                          not all freed"
        trace = {"profile.level": "1", "allocation.aligned": "1", "allocation.usable": "589824",
                 "allocated.huge": "589824,589824,589824", "allocated.huge_count": "1",
                 "merged.huge": "589824,589824,589824", "merged.huge_count": "1",
                 "freed.huge": "589824,589824,0", "freed.huge_count": "1",
                 "thread.live_huge": "1", "thread.live_huge.hex": row.encode("ascii").hex(),
                 "warning.count": "0"}
        gate.require_statistics_aligned_huge(trace, "complete")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_aligned_huge({**trace,
                "thread.live_huge.hex": row.replace("KiB", "Ki ").encode("ascii").hex()}, "lost units")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_aligned_huge({**trace, "merged.huge": "0,0,0"}, "lost merge")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_aligned_huge({**trace, "warning.count": "1"}, "extra warning")

    def test_default_artifact_reader_rejects_changed_build_or_cpu(self) -> None:
        with harness.temporary_directory("m7-baseline-reader-") as name:
            target = Path(name) / "target"
            artifact = target / gate.RUST_TARGET / "release/libcrabc_mimalloc_native_mi_adapter.a"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"!<arch>\ncompiled archive")
            ir = target / gate.RUST_TARGET / "release/build/crabc-mimalloc-native-mi-adapter/x/out/adapter.ll"
            ir.parent.mkdir(parents=True)
            ir.write_text('target triple = "x86_64-unknown-linux-musl"\n'
                          'attributes #0 = { "target-cpu"="x86-64" }\n')
            record = {
                "reason": "compiler-artifact", "target": {"name": "crabc_mimalloc_native_mi_adapter",
                "kind": ["staticlib"]}, "profile": {"opt_level": "3", "debuginfo": 0,
                "debug_assertions": False, "overflow_checks": False, "test": False},
                "features": [], "filenames": [str(artifact)],
            }
            allocator = copy.deepcopy(record)
            allocator["target"] = {"name": "crabc_mimalloc", "kind": ["lib"]}
            output = json.dumps(record) + "\n" + json.dumps(allocator)
            self.assertEqual(gate.audit_default_baseline_artifact(output, target)["target_cpu"], "x86-64")
            changed = copy.deepcopy(record)
            changed["features"] = ["mi-show-errors"]
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(json.dumps(changed) + "\n" + json.dumps(allocator), target)
            changed = copy.deepcopy(record)
            changed["profile"]["debug_assertions"] = True
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(json.dumps(changed) + "\n" + json.dumps(allocator), target)
            changed = copy.deepcopy(allocator)
            changed["features"] = ["mi-show-errors"]
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(json.dumps(record) + "\n" + json.dumps(changed), target)
            ir.write_text(ir.read_text().replace('"x86-64"', '"x86-64-v3"'))
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(output, target)
            ir.write_text('target triple = "x86_64-unknown-linux-musl"\n'
                          'attributes #0 = { "target-cpu"="x86-64" "target-features"="+avx2" }\n')
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(output, target)
            ir.write_text('target triple = "x86_64-unknown-linux-musl"\n'
                          'attributes #0 = { "target-cpu"="x86-64" }\n')
            artifact.write_bytes(b"changed artifact")
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(output, target)

    def test_default_configuration_reader_rejects_changed_release_image(self) -> None:
        baseline = "debug level : 0\nsecure level: 0\nmem tracking: none\nfree: aligned, page size: 256\n"
        self.assertEqual(gate.audit_default_baseline_configuration(baseline, baseline), baseline)
        with self.assertRaises(harness.HarnessError):
            gate.audit_default_baseline_configuration(baseline, baseline.replace("secure level: 0", "secure level: 1"))

    def test_an_omitted_or_doubly_owned_item_or_mode_is_rejected(self) -> None:
        omitted = copy.deepcopy(self.contract)
        self.gate_record(omitted, "m7.callbacks")["items"].remove("mi_register_error")
        with self.assertRaisesRegex(harness.HarnessError, "omit applicable inventory items"):
            self.validate(omitted)

        doubled = copy.deepcopy(self.contract)
        self.gate_record(doubled, "m7.statistics")["items"].append("mi_option_get")
        with self.assertRaisesRegex(harness.HarnessError, "owned by both"):
            self.validate(doubled)

        mode_omitted = copy.deepcopy(self.contract)
        self.gate_record(mode_omitted, "m7.secure")["compile_time_modes"].remove("MI_SECURE_FULL")
        with self.assertRaisesRegex(harness.HarnessError, "omit applicable inventory modes"):
            self.validate(mode_omitted)

    def test_a_new_applicable_authority_entry_breaks_closure(self) -> None:
        api = copy.deepcopy(self.api)
        extra = copy.deepcopy(next(item for item in api["items"] if item["name"] == "mi_option_get"))
        extra["name"] = "mi_option_get_ex"
        api["items"].append(extra)
        with self.assertRaisesRegex(harness.HarnessError, "mi_option_get_ex"):
            self.validate(api=api)

        api = copy.deepcopy(self.api)
        extra = copy.deepcopy(next(mode for mode in api["compile_time_modes"] if mode["name"] == "MI_SECURE"))
        extra["name"] = "MI_SECURE_EXTRA"
        api["compile_time_modes"].append(extra)
        with self.assertRaisesRegex(harness.HarnessError, "MI_SECURE_EXTRA"):
            self.validate(api=api)

    def test_an_item_another_milestone_owns_is_rejected(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "another milestone owns"):
            self.validate(sibling={**self.sibling, "mi_option_get": "compat/allocator/m6-gate-v3.5.0.json"})

        overlapping = copy.deepcopy(self.contract)
        overlapping["inventory"]["additional_items"].append("mi_heap_stats_get")
        with self.assertRaisesRegex(harness.HarnessError, "another milestone owns"):
            self.validate(overlapping)

    def test_an_item_exported_by_libc_or_outside_the_adapter_is_rejected(self) -> None:
        for field, value, message in (
            ("crabc_libc_exported", True, "libc exports"),
            ("adapter_surface", "source-only", "outside the test-c-api-adapter-only"),
        ):
            api = copy.deepcopy(self.api)
            next(item for item in api["items"] if item["name"] == "mi_stats_get")[field] = value
            with self.assertRaisesRegex(harness.HarnessError, message):
                self.validate(api=api)
        exporting = copy.deepcopy(self.contract)
        exporting["inventory"]["abi_boundary"]["crabc_libc_exported"] = True
        with self.assertRaisesRegex(harness.HarnessError, "out of libc"):
            self.validate(exporting)

    def test_inapplicable_or_unselected_ownership_is_rejected(self) -> None:
        inapplicable = copy.deepcopy(self.contract)
        inapplicable["inventory"]["additional_items"].append("mi_collect_reduce")
        with self.assertRaisesRegex(harness.HarnessError, "not applicable"):
            self.validate(inapplicable)

        unowned = copy.deepcopy(self.contract)
        self.gate_record(unowned, "m7.debug")["compile_time_modes"].append("MI_OVERRIDE")
        with self.assertRaisesRegex(harness.HarnessError, "unselected mode"):
            self.validate(unowned)

        itemless = copy.deepcopy(self.contract)
        self.gate_record(itemless, "m7.baseline")["compile_time_modes"].append("MI_GUARDED")
        with self.assertRaisesRegex(harness.HarnessError, "cross-cutting"):
            self.validate(itemless)

    def test_missing_evidence_cannot_be_unblocked_by_editing_the_contract(self) -> None:
        unblocked = copy.deepcopy(self.contract)
        self.gate_record(unblocked, "m7.visitation")["blocked_by"] = []
        with self.assertRaisesRegex(harness.HarnessError, "missing evidence without a blocker"):
            self.validate(unblocked)

        undeclared = copy.deepcopy(self.contract)
        self.gate_record(undeclared, "m7.guarded")["evidence"].append("differential:invented")
        with self.assertRaisesRegex(harness.HarnessError, "undeclared evidence"):
            self.validate(undeclared)

        absent_runner = copy.deepcopy(self.contract)
        absent_runner["evidence"]["differential:statistics"]["command"] = ["python3", "compat/allocator/absent.py"]
        with self.assertRaisesRegex(harness.HarnessError, "absent runner"):
            self.validate(absent_runner)

    def test_passing_runnable_evidence_never_removes_a_reviewed_blocker(self) -> None:
        summary = self.validate()
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        report = gate.gate_report(self.contract, summary, passed)
        self.assertEqual(report["overall_status"], "unmet")
        self.assertEqual(report["unmet_required"], summary["blocked_gate_ids"])
        callbacks = self.gate_record(report, "m7.callbacks")
        self.assertEqual(callbacks["status"], "blocked")
        self.assertTrue(all(status == "passed" for status in callbacks["evidence"].values()))
        self.assertEqual(self.gate_record(report, "m7.options-environment")["status"], "passed")

    def test_a_fully_evidenced_unblocked_gate_passes_and_a_failed_run_fails(self) -> None:
        contract = copy.deepcopy(self.contract)
        for record in contract["evidence"].values():
            record["command"] = ["python3", "compat/allocator/x86_64_m7_gate.py"]
        for entry in contract["gates"]:
            entry["blocked_by"] = []
        summary = self.validate(contract)
        results = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        self.assertEqual(gate.gate_report(contract, summary, results)["overall_status"], "passed")
        results["differential:error-reporting-sites"] = {"status": "failed"}
        report = gate.gate_report(contract, summary, results)
        self.assertEqual(report["overall_status"], "unmet")
        self.assertEqual(self.gate_record(report, "m7.callbacks")["status"], "failed")


    def test_evidence_commands_bind_only_their_fresh_scratch_directory(self) -> None:
        command = self.contract["evidence"]["differential:diagnostic-output-owner"]["command"]
        bound = gate.evidence_command(command, Path("/scratch/run"))
        self.assertIn("/scratch/run/diagnostic-output-owner.json", bound)
        self.assertEqual(gate.evidence_command(["python3", "x.py"], Path("/s")), ["python3", "x.py"])


class M7OptionsTraceTests(unittest.TestCase):
    def trace(self, *, drop: str | None = None) -> str:
        lines = [gate.OPTIONS_TRACE_BEGIN, "options.count=1", "options.descriptor.0=show_errors,-,0"]
        for scenario in gate.OPTIONS_SCENARIOS:
            lines += [
                f"scenario.{scenario}.environment=",
                f"scenario.{scenario}.messages=",
                f"scenario.{scenario}.option.show_errors=0,1,0",
                f"scenario.{scenario}.lazy_messages=",
            ]
        for scenario in gate.OPTIONS_ERROR_SCENARIOS:
            lines += [f"error.{scenario}.environment=", f"error.{scenario}.results=0/0/12",
                      f"error.{scenario}.messages="]
        for scenario in gate.OPTIONS_RECURSION_SCENARIOS:
            lines += [f"recursion.{scenario}.{suffix}=" for suffix in (
                "environment", "init.messages", "init.verbose", "final_verbose",
                "direct.messages", "direct.verbose")]
        lines += ["api.print=7631", gate.OPTIONS_TRACE_END]
        return "\n".join(line for line in lines if line != drop) + "\n"

    def test_a_trace_missing_a_scenario_or_descriptor_record_is_rejected(self) -> None:
        gate.require_complete_options_trace(gate.parse_options_trace(self.trace(), "trace"), "trace")
        # libtest prints the test name before captured stdout on the same line.
        libtest = "running 1 test\ntest tests::trace ... " + self.trace() + "ok\n"
        self.assertEqual(gate.parse_options_trace(libtest, "Rust"), gate.parse_options_trace(self.trace(), "C"))
        for drop in ("scenario.guarded_boolean.messages=", "scenario.cap.option.show_errors=0,1,0",
                     "error.capped.results=0/0/12", "recursion.invalid_verbose.init.verbose="):
            with self.assertRaisesRegex(harness.HarnessError, "lacks"):
                gate.require_complete_options_trace(
                    gate.parse_options_trace(self.trace(drop=drop), "trace"), "trace"
                )

    def test_a_single_differing_key_fails_the_comparison(self) -> None:
        c_trace = gate.parse_options_trace(self.trace(), "C")
        gate.compare_options_traces(c_trace, dict(c_trace))
        rust_trace = {**c_trace, "scenario.empty.option.show_errors": "1,2,1"}
        with self.assertRaisesRegex(harness.HarnessError, "scenario.empty.option.show_errors"):
            gate.compare_options_traces(c_trace, rust_trace)
        with self.assertRaisesRegex(harness.HarnessError, "repeated trace key"):
            gate.parse_options_trace(self.trace().replace("api.print=7631", "api.print=1\napi.print=2"), "C")


class M7ErrorSitesTraceTests(unittest.TestCase):
    def test_a_trace_missing_a_request_record_is_rejected(self) -> None:
        trace = {
            f"error_site.{case}.{suffix}": "0"
            for case in gate.ERROR_SITE_CASES for suffix in ("messages", "deferred", "null", "errno")
        }
        trace["error_site.startup.messages"] = ""
        gate.require_complete_error_sites_trace(trace, "trace")
        del trace["error_site.worker_malloc_too_large.errno"]
        with self.assertRaisesRegex(harness.HarnessError, "worker_malloc_too_large.errno"):
            gate.require_complete_error_sites_trace(trace, "trace")


class M7OptionEffectsTraceTests(unittest.TestCase):
    def trace(self, *, drop: str | None = None) -> str:
        lines = [gate.OPTION_EFFECTS_TRACE_BEGIN]
        lines += [f"{family}.0=1" for family in gate.OPTION_EFFECT_FAMILIES if family != drop]
        lines.append(gate.OPTION_EFFECTS_TRACE_END)
        return "\n".join(lines) + "\n"

    def parse(self, output: str) -> dict[str, str]:
        return gate.parse_options_trace(
            output, "trace", gate.OPTION_EFFECTS_TRACE_BEGIN, gate.OPTION_EFFECTS_TRACE_END
        )

    def test_a_trace_missing_a_decision_family_is_rejected(self) -> None:
        gate.require_complete_option_effects_trace(self.parse(self.trace()), "trace")
        with self.assertRaisesRegex(harness.HarnessError, "arena_reserve"):
            gate.require_complete_option_effects_trace(self.parse(self.trace(drop="arena_reserve")), "trace")

    def test_the_options_markers_do_not_delimit_an_effects_trace(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "markers"):
            gate.parse_options_trace(self.trace(), "trace")


if __name__ == "__main__":
    unittest.main()
