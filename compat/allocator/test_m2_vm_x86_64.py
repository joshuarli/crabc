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

from m2_vm_x86_64 import TRACE_KEYS, load_fragment, parse_trace


ROOT = Path(__file__).resolve().parents[2]
FRAGMENT = ROOT / "compat/allocator/m2-vm-x86_64-v3.5.0.fragment.json"


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


class NativeM2VmFragmentTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/tmp"
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
        self.assertEqual(len(loaded["component"]["checks"]), 17)
        self.assertEqual(len(loaded["component"]["branch_matrix"]), 13)

    def test_deleting_or_reclassifying_a_required_open_branch_fails(self) -> None:
        deleted = copy.deepcopy(self.fragment)
        del deleted["component"]["branch_matrix"][7]
        reclassified = copy.deepcopy(self.fragment)
        reclassified["component"]["branch_matrix"][7]["disposition"] = "qualified-fixed-profile"
        reclassified["component"]["branch_matrix"][7]["missing_conditions"] = []
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


if __name__ == "__main__":
    unittest.main()
