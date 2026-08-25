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
                "native-tls-codegen",
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
        self.assertIn("cpufeatures", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("no selected libc package", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("lockfile-verified", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("LLVM bitcode", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("not a staticlib/cdylib", gates["native-normal-engine-build-boundary"]["claim"])
        self.assertIn("private prefixed", gates["native-private-test-adapter"]["claim"])
        self.assertIn("no mi_* symbols", gates["native-private-test-adapter"]["claim"])

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

        boundary = self.contract["ledger_boundary"]
        self.assertEqual(boundary["status"], "intentionally-not-mirrored")
        for relative_path in boundary["aarch64_contracts_not_mirrored"]:
            self.assertTrue((ROOT / relative_path).is_file(), relative_path)
        self.assertIn("falsely claim parity", boundary["reason"])


if __name__ == "__main__":
    unittest.main()
