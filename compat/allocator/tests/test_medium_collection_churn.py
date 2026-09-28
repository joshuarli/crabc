from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/allocator/medium_collection_churn.py"
SPEC = importlib.util.spec_from_file_location("medium_collection_churn", MODULE)
assert SPEC is not None and SPEC.loader is not None
churn = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(churn)
CONTRACT = json.loads(churn.CONTRACT.read_text())


def line(*, medium_used: int = 128, medium_abandoned: int = 128) -> str:
    values = {name: 0 for name in churn.REQUIRED}
    values.update({
        "epoch": 1, "rss_kib": 9500, "hwm_kib": 9500,
        "rollup_rss_kib": 9500, "anonymous_kib": 9400,
        "referenced_kib": 9500, "page_map_entries": 130,
        "page_map_submaps": 2, "medium_used": medium_used,
        "medium_abandoned": medium_abandoned,
    })
    return "snapshot phase=allocated " + " ".join(f"{key}={value}" for key, value in values.items())


def product(*, immediate: bool = False, nonabandoning: bool = False) -> dict[str, object]:
    samples = [{
        "fields": {"epoch": 0, "phase": "baseline", "medium_used": 0,
                   "page_map_entries": 2, **{key: 0 for key in churn.MEDIUM_FIELDS}},
        "arena": {"rss_kib": 200},
    }]
    for epoch in range(1, 5):
        for phase in CONTRACT["phase_order"][1:]:
            allocated = phase in ("allocated", "remote_joined") or (
                nonabandoning and phase == "owner_cleared"
            )
            fields = {key: 0 for key in churn.MEDIUM_FIELDS}
            fields.update({
                "epoch": epoch, "phase": phase,
                "medium_used": 128 if allocated else 0,
                "medium_abandoned": 128 if allocated and not nonabandoning else 0,
                "medium_attached": 128 if allocated and nonabandoning else 0,
                "medium_remote_pending": 128 if nonabandoning and phase in
                    ("remote_joined", "owner_cleared") else 0,
                "page_map_entries": 130 if allocated else 2,
            })
            samples.append({
                "fields": fields,
                "arena": {"rss_kib": 8200 if allocated or not immediate else 200},
            })
    return {"samples": samples}


def pressure_product(*, arenas: int = 2, drained_entries: int = 3) -> dict[str, object]:
    samples = [{
        "fields": {"epoch": 0, "phase": "baseline", "page_map_entries": 1,
                   "arena_registry_count": 1, "rss_kib": 200, "anonymous_kib": 100,
                   "anon_huge_kib": 0, **{key: 0 for key in churn.MEDIUM_FIELDS}},
        "arena": {"count": 1, "rss_kib": 100},
    }]
    for epoch in (1, 2):
        for phase in CONTRACT["phase_order"][1:]:
            active = phase in ("allocated", "remote_joined")
            fields = {key: 0 for key in churn.MEDIUM_FIELDS}
            fields.update({
                "epoch": epoch, "phase": phase,
                "page_map_entries": 20483 if active else drained_entries,
                "arena_registry_count": arenas, "rss_kib": 500000,
                "anonymous_kib": 490000, "anon_huge_kib": 0,
                "medium_used": 20480 if active else 0,
                "medium_abandoned": 20480 if active else 0,
            })
            samples.append({"fields": fields, "arena": {"count": arenas, "rss_kib": 490000}})
    return {"samples": samples}


class MediumCollectionChurnReaderTest(unittest.TestCase):
    def test_snapshot_requires_a_partitioned_medium_image(self) -> None:
        parsed = churn.parse_snapshot(line())
        self.assertEqual((parsed["epoch"], parsed["phase"], parsed["medium_used"]),
                         (1, "allocated", 128))
        with self.assertRaises(churn.DiagnosticError):
            churn.parse_snapshot(line(medium_abandoned=127))
        with self.assertRaises(churn.DiagnosticError):
            churn.parse_snapshot(line().replace(" page_map_entries=130", ""))

    def test_mapping_reads_current_arena_instead_of_process_high_water(self) -> None:
        smaps = (
            "1000-2000 rw-p 00000000 00:00 0\n"
            "Size: 4 kB\nRss: 4 kB\n"
            "3000-4000 rw-p 00000000 00:00 0\n"
            "Size: 1048576 kB\nRss: 8192 kB\nAnonymous: 8192 kB\n"
            "AnonHugePages: 2048 kB\nReferenced: 8192 kB\nVmFlags: rd wr hg\n"
        )
        arena = churn.arena_mapping(smaps)
        self.assertEqual(arena["count"], 1)
        self.assertEqual(arena["rss_kib"], 8192)
        self.assertEqual(arena["mappings"][0]["vm_flags"], ["rd", "wr", "hg"])

    def test_mapping_sums_multiple_regular_arenas(self) -> None:
        one = (
            "1000-2000 rw-p 00000000 00:00 0\n"
            "Size: 1048576 kB\nRss: 8192 kB\nAnonymous: 8192 kB\n"
            "AnonHugePages: 2048 kB\nReferenced: 4096 kB\nVmFlags: rd wr hg\n"
        )
        two = one.replace("1000-2000", "3000-4000").replace(
            "Rss: 8192", "Rss: 4096").replace("VmFlags: rd wr hg", "VmFlags: rd wr nh")
        arena = churn.arena_mapping(one + two)
        self.assertEqual(arena["count"], 2)
        self.assertEqual(arena["rss_kib"], 12288)
        self.assertEqual(arena["anon_huge_kib"], 4096)
        self.assertEqual([a["vm_flags"][-1] for a in arena["mappings"]], ["hg", "nh"])

    def test_pressure_profile_has_its_own_bounded_workload(self) -> None:
        workload = churn.profile_workload(CONTRACT, "pressure-default")
        self.assertGreater(workload["blocks_per_epoch"] * workload["request_bytes"], 1 << 30)
        self.assertEqual(len(churn.expected_phases(CONTRACT, "pressure-default")),
                         1 + workload["epochs"] * 5)

    def test_paired_source_release_timing_matches_in_both_profiles(self) -> None:
        default = churn.compare(product(), product(), CONTRACT, "source-default")
        immediate = churn.compare(product(immediate=True), product(immediate=True),
                                  CONTRACT, "immediate-purge")
        self.assertEqual(default["status"], "match")
        self.assertEqual(immediate["status"], "match")
        self.assertEqual(default["arena_release_phases"][0]["c"], "retained_after_20ms")
        self.assertEqual(immediate["arena_release_phases"][0]["c"], "owner_cleared")
        pending = churn.compare(product(nonabandoning=True), product(nonabandoning=True),
                                CONTRACT, "nonabandoning-default")
        pending_immediate = churn.compare(
            product(nonabandoning=True, immediate=True),
            product(nonabandoning=True, immediate=True), CONTRACT,
            "nonabandoning-immediate",
        )
        self.assertEqual(pending["status"], "match")
        self.assertEqual(pending_immediate["arena_release_phases"][0]["c"], "owner_joined")

    def test_paired_reader_rejects_class_or_release_divergence(self) -> None:
        c = product()
        native = product(immediate=True)
        self.assertEqual(churn.compare(c, native, CONTRACT, "source-default")["status"], "diverge")
        native = product()
        native["samples"][2]["fields"]["medium_used"] = 120
        result = churn.compare(c, native, CONTRACT, "source-default")
        self.assertEqual(result["status"], "diverge")
        self.assertTrue(any("medium_used" in mismatch for mismatch in result["mismatches"]))

    def test_pressure_reader_requires_multiple_arenas_and_medium_retirement(self) -> None:
        paired = churn.compare(pressure_product(), pressure_product(),
                               CONTRACT, "pressure-default")
        self.assertEqual(paired["status"], "match")
        missing_arena = churn.compare(pressure_product(), pressure_product(arenas=1),
                                      CONTRACT, "pressure-default")
        self.assertIn("1:native:multi-arena pressure absent", missing_arena["mismatches"])
        retained = churn.compare(pressure_product(), pressure_product(drained_entries=20483),
                                 CONTRACT, "pressure-default")
        self.assertIn("1:native:registered medium image retained after drain",
                      retained["mismatches"])


if __name__ == "__main__":
    unittest.main()
