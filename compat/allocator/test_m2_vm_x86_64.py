#!/usr/bin/env python3
"""Host-only contract regressions for the native x86 M2 VM producer."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from m2_vm_x86_64 import (
    ALIGNED_OVERMAP_C_TRACE_KEYS,
    ALIGNED_OVERMAP_RUST_TRACE_KEYS,
    ALIGNED_OVERMAP_TRACE_BEGIN,
    ALIGNED_OVERMAP_TRACE_END,
    ARENA_OWNED_EVENT_FIELD_COUNT,
    ARENA_OWNED_RUST_INLINE_PREFIX,
    CHECK_IDS,
    TRACE_KEYS,
    load_fragment,
    parse_aligned_overmap_trace,
    parse_arena_owned_purge_trace,
    parse_trace,
)


ROOT = Path(__file__).resolve().parents[2]
FRAGMENT = ROOT / "compat/allocator/m2-vm-x86_64-v3.5.0.fragment.json"
ARENA_OWNED_FIXTURE = ROOT / "compat/allocator/m2_arena_owned_x86_64.c"


LARGE_ONLY_TRACE_KEYS = (
    "m2.vm.large_only.first_one_gib_then_two_mib_same_claim_terminal_enomem",
    "m2.vm.large_only.second_only_two_mib_after_sticky_unavailable",
    "m2.vm.large_only.all_raw_maps_are_huge_and_no_regular_owner",
    "m2.vm.large_only.terminal_failures_leave_statistics_and_owners_unpublished",
)

THP_DIRECT_POLICY_TRACE_KEYS = (
    "m2.vm.thp_direct.allow_enabled_zero_calls_and_continues",
    "m2.vm.thp_direct.query_perm_get_only_disabled_and_continues",
    "m2.vm.thp_direct.query_inval_get_only_disabled_and_continues",
    "m2.vm.thp_direct.query_nonzero_one_get_only_disabled_and_continues",
    "m2.vm.thp_direct.query_nonzero_three_get_only_disabled_and_continues",
    "m2.vm.thp_direct.set_success_exact_get_set_disabled_and_continues",
    "m2.vm.thp_direct.set_perm_exact_get_set_disabled_and_continues",
    "m2.vm.thp_direct.set_inval_exact_get_set_disabled_and_continues",
)


EXPECTED_CHECK_IDS = (
    "native-vm-fixed-lifecycle-differential",
    "source-policy-lazy-environment-retry",
    "normal-release-aligned-hint-cursor-random-and-cas-matrix",
    "normal-release-large-page-retry-suppression-and-ordinary-fallback",
    "large-only-one-gib-failure-no-regular-owner",
    "thp-direct-policy-outcome-matrix",
    "process-main-thp-policy-owner-traversal",
    "runtime-source-environment-thp-ready-configuration-admission",
    "aligned-hint-source-profile-and-direct-caller-matrix",
    "aligned-overmap-cleanup-c-rust-boundary-matrix",
    "process-policy-first-arena-clean-primary-fallback",
    "process-policy-first-arena-retained-cleanup-statistics",
    "process-policy-ticket-zero-live-random",
    "aligned-map-direct-cleanup-owner",
    "aligned-map-prefix-cleanup-owner",
    "aligned-map-suffix-cleanup-owner",
    "aligned-map-complete-trim-sequence",
    "reset-advice-retry-snapshot",
    "aligned-map-os-page-claim-owner",
    "aligned-map-process-os-page-suffix-terminal-owner",
    "aligned-map-metadata-owner",
    "aligned-map-process-arena-owner",
    "normal-os-offset-full-provenance-and-release-retry",
    "process-offset-prefix-decommit-advisory-owner",
    "normal-no-callback-purge-policy-range-matrix",
    "normal-os-good-size-and-base-provenance",
    "normal-os-offset-zero-delegation-and-geometry",
    "normal-os-aligned-failure-owner",
    "normal-os-source-reservation-caller",
    "linux-os-reuse-contained-range-noop",
    "fixed-no-option-numa-cache-and-current-node-normalization",
    "native-protection-owner-and-retry",
    "normal-page-extension-direct-commit-failure-and-retry",
)


def valid_aligned_overmap_trace(keys: tuple[str, ...]) -> str:
    return "\n".join(
        [ALIGNED_OVERMAP_TRACE_BEGIN]
        + [f"{key}=1" for key in keys]
        + [ALIGNED_OVERMAP_TRACE_END]
    )


def valid_trace() -> str:
    values = {
        "m2.vm.config.page_size": 4096,
        "m2.vm.config.large_page_size": 2 * 1024 * 1024,
        "m2.vm.config.alloc_granularity": 4096,
        "m2.vm.config.has_overcommit": 1,
        "m2.vm.config.has_partial_free": 1,
        "m2.vm.config.has_virtual_reserve": 1,
        "m2.vm.config.has_transparent_huge_pages": 0,
        "m2.vm.reserved.initially_committed": 0,
        "m2.vm.normal.good_size": 8192,
        "m2.vm.aligned.alignment": 65536,
        "m2.vm.aligned.good_size": 4096,
        "m2.vm.offset.good_size": 69632,
        "m2.vm.policy.first_arena_size": 128 * 1024 * 1024,
    }
    values.update({key: 1 for key in TRACE_KEYS if key not in values})
    return "\n".join(
        ["CRABC_MI_M2_VM_TRACE_BEGIN"]
        + [f"{key}={values[key]}" for key in TRACE_KEYS]
        + ["CRABC_MI_M2_VM_TRACE_END"]
    )


class NativeM2VmTraceTests(unittest.TestCase):
    def test_complete_address_free_trace_is_accepted(self) -> None:
        trace = parse_trace(valid_trace(), source="test")
        self.assertEqual(tuple(trace), TRACE_KEYS)

    def test_large_only_terminal_failure_record_is_finite_and_fail_closed(self) -> None:
        good = valid_trace()
        self.assertEqual(
            parse_trace(good, source="test"),
            parse_trace(valid_trace(), source="test"),
        )
        for malformed in (
            good.replace(f"{LARGE_ONLY_TRACE_KEYS[0]}=1\n", "", 1),
            good.replace(
                f"{LARGE_ONLY_TRACE_KEYS[0]}=1",
                f"{LARGE_ONLY_TRACE_KEYS[0]}=1\n{LARGE_ONLY_TRACE_KEYS[0]}=1",
                1,
            ),
            good.replace(
                f"{LARGE_ONLY_TRACE_KEYS[0]}=1\n{LARGE_ONLY_TRACE_KEYS[1]}=1",
                f"{LARGE_ONLY_TRACE_KEYS[1]}=1\n{LARGE_ONLY_TRACE_KEYS[0]}=1",
                1,
            ),
            good.replace(f"{LARGE_ONLY_TRACE_KEYS[0]}=1", f"{LARGE_ONLY_TRACE_KEYS[0]}=0", 1),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_trace(malformed, source="test")

    def test_thp_direct_policy_matrix_is_finite_and_fail_closed(self) -> None:
        good = valid_trace()
        malformed = []
        for key in THP_DIRECT_POLICY_TRACE_KEYS:
            malformed.extend((
                good.replace(f"{key}=1\n", "", 1),
                good.replace(f"{key}=1", f"{key}=1\n{key}=1", 1),
                good.replace(f"{key}=1", f"{key}=0", 1),
            ))
        malformed.append(
            good.replace(
                f"{THP_DIRECT_POLICY_TRACE_KEYS[0]}=1\n{THP_DIRECT_POLICY_TRACE_KEYS[1]}=1",
                f"{THP_DIRECT_POLICY_TRACE_KEYS[1]}=1\n{THP_DIRECT_POLICY_TRACE_KEYS[0]}=1",
                1,
            )
        )
        for output in malformed:
            with self.subTest(malformed=output), self.assertRaises(ValueError):
                parse_trace(output, source="test")

    def test_aligned_overmap_sides_remain_separate_and_fail_closed(self) -> None:
        c_trace = valid_aligned_overmap_trace(ALIGNED_OVERMAP_C_TRACE_KEYS)
        rust_trace = valid_aligned_overmap_trace(ALIGNED_OVERMAP_RUST_TRACE_KEYS)
        self.assertEqual(
            parse_aligned_overmap_trace(
                c_trace, source="C", expected_keys=ALIGNED_OVERMAP_C_TRACE_KEYS
            ),
            {key: 1 for key in ALIGNED_OVERMAP_C_TRACE_KEYS},
        )
        self.assertEqual(
            parse_aligned_overmap_trace(
                rust_trace, source="Rust", expected_keys=ALIGNED_OVERMAP_RUST_TRACE_KEYS
            ),
            {key: 1 for key in ALIGNED_OVERMAP_RUST_TRACE_KEYS},
        )
        for malformed in (
            c_trace.replace(
                f"{ALIGNED_OVERMAP_C_TRACE_KEYS[0]}=1\n", "", 1
            ),
            c_trace.replace(
                f"{ALIGNED_OVERMAP_C_TRACE_KEYS[0]}=1",
                f"{ALIGNED_OVERMAP_C_TRACE_KEYS[0]}=0",
                1,
            ),
            c_trace.replace(
                f"{ALIGNED_OVERMAP_C_TRACE_KEYS[0]}=1",
                f"{ALIGNED_OVERMAP_RUST_TRACE_KEYS[0]}=1",
                1,
            ),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_aligned_overmap_trace(
                    malformed, source="C", expected_keys=ALIGNED_OVERMAP_C_TRACE_KEYS
                )

    def test_missing_duplicate_unknown_and_unmet_relations_fail_closed(self) -> None:
        good = valid_trace()
        malformed = (
            good.replace("m2.vm.normal.good_size=8192\n", ""),
            good.replace(
                "m2.vm.normal.good_size=8192\n",
                "m2.vm.normal.good_size=8192\nm2.vm.normal.good_size=8192\n",
            ),
            good.replace("m2.vm.normal.good_size=8192", "m2.vm.normal.client_pointer=8192"),
            good.replace("m2.vm.reserved.release_success=1", "m2.vm.reserved.release_success=0"),
            good.replace("m2.vm.config.has_transparent_huge_pages=0", "m2.vm.config.has_transparent_huge_pages=1"),
        )
        for output in malformed:
            with self.subTest(output=output), self.assertRaises(ValueError):
                parse_trace(output, source="test")


class NativeM2ArenaEventFixtureTests(unittest.TestCase):
    def test_delayed_purge_fixture_leaves_source_preloading_before_free(self) -> None:
        fixture = ARENA_OWNED_FIXTURE.read_text(encoding="utf-8")
        self.assertIn("  _mi_auto_process_init();\n", fixture)
        self.assertNotIn("  mi_process_init();\n", fixture)

    def test_arena_event_reader_accepts_only_exact_inline_libtest_first_field(self) -> None:
        values = tuple(range(ARENA_OWNED_EVENT_FIELD_COUNT))
        rust_stream = "\n".join(
            ["running 1 test", f"{ARENA_OWNED_RUST_INLINE_PREFIX}m2.arena.purge.0=0"]
            + [f"m2.arena.purge.{index}={index}" for index in range(1, len(values))]
            + ["ok"]
        )
        self.assertEqual(
            parse_arena_owned_purge_trace(rust_stream, source="Rust"), values
        )
        for malformed in (
            rust_stream.replace(ARENA_OWNED_RUST_INLINE_PREFIX, "test other ... ", 1),
            rust_stream.replace("m2.arena.purge.1=1", "m2.arena.purge.2=1", 1),
            rust_stream.replace("m2.arena.purge.0=0", "m2.arena.purge.0=0x0", 1),
            rust_stream.replace("m2.arena.purge.0=0", "m2.arena.purge.0=00", 1),
            rust_stream.replace("m2.arena.purge.0=0", "m2.arena.purge.0=-0", 1),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_arena_owned_purge_trace(malformed, source="Rust")


class NativeM2VmFragmentTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/allocator-x86_64/test-m2-vm-host"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.fragment = json.loads(FRAGMENT.read_text(encoding="utf-8"))

    def write_fragment(self, fragment: dict) -> Path:
        path = Path(self.temporary.name) / "fragment.json"
        path.write_text(json.dumps(fragment), encoding="utf-8")
        return path

    def test_checked_fragment_preserves_the_complete_branch_matrix(self) -> None:
        loaded = load_fragment(self.write_fragment(self.fragment))
        self.assertEqual(loaded["component"]["completion_status"], "partial")
        self.assertEqual(CHECK_IDS, EXPECTED_CHECK_IDS)
        self.assertEqual(
            tuple(check["id"] for check in loaded["component"]["checks"]),
            EXPECTED_CHECK_IDS,
        )
        self.assertIn(
            "aligned-overmap-cleanup-c-rust-boundary-matrix",
            [check["id"] for check in loaded["component"]["checks"]],
        )
        self.assertEqual(len(loaded["component"]["branch_matrix"]), 14)

    def test_deleting_or_reclassifying_a_required_open_branch_fails(self) -> None:
        branch_id = "huge-page-and-numa-placement"
        deleted = copy.deepcopy(self.fragment)
        deleted_branch_index = next(
            index
            for index, branch in enumerate(deleted["component"]["branch_matrix"])
            if branch["id"] == branch_id
        )
        del deleted["component"]["branch_matrix"][deleted_branch_index]
        reclassified = copy.deepcopy(self.fragment)
        target = next(
            branch
            for branch in reclassified["component"]["branch_matrix"]
            if branch["id"] == branch_id
        )
        target["disposition"] = "qualified-fixed-profile"
        target["missing_conditions"] = []
        for fragment in (deleted, reclassified):
            with self.subTest(fragment=fragment), self.assertRaisesRegex(ValueError, "branch"):
                load_fragment(self.write_fragment(fragment))

    def test_missing_huge_hint_numa_or_failure_frontier_fails(self) -> None:
        for word in ("huge", "hint", "NUMA", "failure"):
            fragment = copy.deepcopy(self.fragment)
            fragment["component"]["remaining_conditions"] = [
                condition for condition in fragment["component"]["remaining_conditions"]
                if word.lower() not in condition.lower()
            ]
            with self.subTest(word=word), self.assertRaisesRegex(ValueError, "remaining conditions"):
                load_fragment(self.write_fragment(fragment))

    def test_thp_branch_cannot_drop_its_child_evidence_or_open_frontier(self) -> None:
        dropped_evidence = copy.deepcopy(self.fragment)
        dropped_evidence["component"]["branch_matrix"][2]["evidence_check_ids"] = []
        promoted = copy.deepcopy(self.fragment)
        promoted["component"]["branch_matrix"][2]["disposition"] = "qualified-fixed-profile"
        promoted["component"]["branch_matrix"][2]["missing_conditions"] = []
        for fragment in (dropped_evidence, promoted):
            with self.subTest(fragment=fragment), self.assertRaisesRegex(ValueError, "THP"):
                load_fragment(self.write_fragment(fragment))

    def test_thp_direct_policy_definition_and_check_cannot_be_dropped(self) -> None:
        dropped_definition = copy.deepcopy(self.fragment)
        definitions = dropped_definition["component"]["bounded_source_definitions"]
        definitions[:] = [
            definition
            for definition in definitions
            if definition["id"] != "unix-thp-disable-process-policy"
        ]
        dropped_check = copy.deepcopy(self.fragment)
        checks = dropped_check["component"]["checks"]
        checks[:] = [
            check
            for check in checks
            if check["id"] != "thp-direct-policy-outcome-matrix"
        ]
        dropped_owner_check = copy.deepcopy(self.fragment)
        checks = dropped_owner_check["component"]["checks"]
        checks[:] = [
            check
            for check in checks
            if check["id"] != "process-main-thp-policy-owner-traversal"
        ]
        dropped_runtime_environment_check = copy.deepcopy(self.fragment)
        checks = dropped_runtime_environment_check["component"]["checks"]
        checks[:] = [
            check
            for check in checks
            if check["id"] != "runtime-source-environment-thp-ready-configuration-admission"
        ]
        raw_nonzero_removed = copy.deepcopy(self.fragment)
        thp_branch = raw_nonzero_removed["component"]["branch_matrix"][2]
        thp_branch["source_scope"] = thp_branch["source_scope"].replace(
            "raw nonzero 3", "removed raw nonzero representative"
        )
        thp_branch["source_scope"] = thp_branch["source_scope"].replace(
            "Raw nonzero 3", "Removed raw nonzero representative"
        )
        phantom_diagnostics = copy.deepcopy(self.fragment)
        thp_branch = phantom_diagnostics["component"]["branch_matrix"][2]
        thp_branch["missing_conditions"] = [
            "Diagnostics remain unqualified despite the selected source branch"
        ]
        for fragment in (
            dropped_definition,
            dropped_check,
            dropped_owner_check,
            dropped_runtime_environment_check,
            raw_nonzero_removed,
            phantom_diagnostics,
        ):
            with self.subTest(fragment=fragment), self.assertRaises(ValueError):
                load_fragment(self.write_fragment(fragment))

    def test_large_only_branch_cannot_drop_its_evidence_or_open_frontier(self) -> None:
        dropped_evidence = copy.deepcopy(self.fragment)
        route = dropped_evidence["component"]["branch_matrix"][8]
        route["evidence_check_ids"].remove("large-only-one-gib-failure-no-regular-owner")
        dropped_frontier = copy.deepcopy(self.fragment)
        route = dropped_frontier["component"]["branch_matrix"][8]
        route["missing_conditions"] = [
            condition.replace("large_only/MAP_HUGE_1GB", "removed-large-only-route")
            for condition in route["missing_conditions"]
        ]
        for fragment in (dropped_evidence, dropped_frontier):
            with self.subTest(fragment=fragment), self.assertRaisesRegex(ValueError, "large-only"):
                load_fragment(self.write_fragment(fragment))


if __name__ == "__main__":
    unittest.main()
