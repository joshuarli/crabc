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
