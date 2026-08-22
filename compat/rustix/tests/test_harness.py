#!/usr/bin/env python3
"""Focused standard-library tests for the Rustix compatibility harness."""

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/rustix/run.py"
SPEC = importlib.util.spec_from_file_location("rustix_harness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
harness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = harness
SPEC.loader.exec_module(harness)


class MetadataTests(unittest.TestCase):
    def test_checked_in_metadata_is_valid_and_has_no_production_dependency(self) -> None:
        report = harness.validate_metadata()
        self.assertEqual(report["target"], "aarch64-unknown-linux-musl")
        self.assertEqual(report["upstream"]["version"], "1.1.4")
        self.assertEqual(
            report["upstream"]["revision"],
            "cf67411d572468d5fc39e8ac8b4e649ae3e5e9ec",
        )
        self.assertEqual(report["coverage"]["reference_count"], 1647)
        self.assertEqual(report["coverage"]["candidate_count"], 1669)
        self.assertEqual(report["coverage"]["candidate_only_count"], 22)
        self.assertEqual(report["production_dependencies"], [])
        self.assertFalse(report["direct_c_abi_errno_roundtrip"])

    def test_absolute_rustix_checkout_paths_are_rejected(self) -> None:
        with self.assertRaises(harness.HarnessError):
            harness.check_no_local_absolute_path({"source_checkout_path": "/tmp/rustix"})

    def test_metadata_validation_is_deterministic(self) -> None:
        self.assertEqual(harness.validate_metadata(), harness.validate_metadata())


class CoverageLedgerTests(unittest.TestCase):
    """M9 mutations prove the coverage ledger cannot silently become inventory again."""

    def ledger(self) -> dict[str, object]:
        return copy.deepcopy(harness.load_toml(harness.COVERAGE_PATH))

    @staticmethod
    def capability(ledger: dict[str, object], identifier: str) -> dict[str, object]:
        capabilities = ledger["capability"]
        assert isinstance(capabilities, list)
        for capability in capabilities:
            assert isinstance(capability, dict)
            if capability["id"] == identifier:
                return capability
        raise AssertionError(f"missing capability fixture: {identifier}")

    def test_m9_report_has_exact_zero_unclassified_accounting(self) -> None:
        coverage = harness.validate_coverage(self.ledger())
        self.assertTrue(coverage["m9_green"])
        self.assertEqual(coverage["symbol_count"], 1669)
        self.assertEqual(coverage["classified_symbol_count"], 1669)
        self.assertEqual(coverage["unclassified_symbol_count"], 0)
        self.assertEqual(coverage["unclassified_capability_count"], 0)

    def test_coverage_rejects_a_missing_symbol(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "pattern.fnmatch")["symbols"] = ["fnmatc"]
        with self.assertRaisesRegex(harness.HarnessError, "matches no candidate export"):
            harness.validate_coverage(ledger)

    def test_coverage_rejects_a_duplicate_symbol_owner(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "pattern.glob")["symbols"].append("fnmatch")
        with self.assertRaisesRegex(harness.HarnessError, "belongs to both"):
            harness.validate_coverage(ledger)

    def test_coverage_rejects_an_extra_symbol(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "pattern.fnmatch")["symbols"] = ["not_a_crabc_export"]
        with self.assertRaisesRegex(harness.HarnessError, "matches no candidate export"):
            harness.validate_coverage(ledger)

    def test_coverage_rejects_an_unowned_candidate_only_export(self) -> None:
        ledger = self.ledger()
        records = ledger["candidate_only"]
        assert isinstance(records, list)
        records[0]["capability"] = "missing.owner"
        with self.assertRaisesRegex(harness.HarnessError, "unknown capability owner"):
            harness.validate_coverage(ledger)

    def test_coverage_rejects_an_unclassified_capability(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "pattern.fnmatch")["classification"] = "unclassified"
        with self.assertRaisesRegex(harness.HarnessError, "unknown capability classification"):
            harness.validate_coverage(ledger)

    def test_coverage_rejects_native_c_abi_or_errno_paths(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "math.fenv")["uses_public_c_abi"] = True
        with self.assertRaisesRegex(harness.HarnessError, "uses public C ABI"):
            harness.validate_coverage(ledger)

        ledger = self.ledger()
        self.capability(ledger, "math.fenv")["uses_errno_tls"] = True
        with self.assertRaisesRegex(harness.HarnessError, "uses TLS errno"):
            harness.validate_coverage(ledger)

    def test_coverage_rejects_abi_only_without_review_rationale(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "stdio.fopen64-alias")["why_no_native_operation"] = ""
        with self.assertRaisesRegex(harness.HarnessError, "lacks why_no_native_operation"):
            harness.validate_coverage(ledger)

    def test_coverage_rejects_anchor_only_rust_subsumption_evidence(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "error.termination.abort")["evidence"][0] = "crabc-rs.md#33"
        with self.assertRaisesRegex(harness.HarnessError, "anchor"):
            harness.validate_coverage(ledger)

    def test_coverage_rejects_missing_rust_subsumption_evidence_file(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "memory.bytes-basic")["behavior_evidence"] = [
            "crabc-rs/tests/m10_subsumed_missing.rs"
        ]
        with self.assertRaisesRegex(harness.HarnessError, "does not exist"):
            harness.validate_coverage(ledger)

    def test_coverage_rejects_duplicate_rust_subsumption_evidence(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "search.hash-table")["evidence"] = [
            "crabc-rs/m10_subsumed_evidence.md",
            "crabc-rs/m10_subsumed_evidence.md",
        ]
        with self.assertRaisesRegex(harness.HarnessError, "duplicate paths"):
            harness.validate_coverage(ledger)

    def test_coverage_requires_both_source_and_behavior_rust_subsumption_evidence(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "numeric.scalar-basic")["source_evidence"] = ["crabc-rs.md"]
        self.capability(ledger, "numeric.scalar-basic")["behavior_evidence"] = [
            "crabc-rs/m10_subsumed_evidence.md"
        ]
        self.capability(ledger, "numeric.scalar-basic")["evidence"] = [
            "crabc-rs.md",
            "crabc-rs/m10_subsumed_evidence.md",
        ]
        with self.assertRaisesRegex(harness.HarnessError, "behavior_evidence must identify"):
            harness.validate_coverage(ledger)

    def test_m10_keeps_long_double_math_and_bounded_formatting_deferred(self) -> None:
        ledger = self.ledger()
        elementary = self.capability(ledger, "math.elementary")
        long_double = self.capability(ledger, "math.elementary-long-double")
        self.assertNotIn("expl", elementary["symbols"])
        self.assertIn("expl", long_double["symbols"])
        output = self.capability(ledger, "stdio.format-output")
        bounded = self.capability(ledger, "stdio.format-bounded")
        self.assertNotIn("snprintf", output["symbols"])
        self.assertEqual(bounded["symbols"], ["snprintf", "vsnprintf"])

        elementary["symbols"].append("expl")
        with self.assertRaisesRegex(harness.HarnessError, "belongs to both"):
            harness.validate_coverage(ledger)

    def test_m10_preserves_the_whole_malloc_family_policy_exclusion(self) -> None:
        ledger = self.ledger()
        basic = self.capability(ledger, "memory.allocator-basic")
        observability = self.capability(ledger, "memory.allocator-observability")
        allocator_symbols = set(basic["symbols"])
        allocator_symbols.update(observability["symbols"])
        self.assertEqual(
            allocator_symbols,
            {
                "aligned_alloc",
                "calloc",
                "free",
                "malloc",
                "malloc_usable_size",
                "memalign",
                "posix_memalign",
                "realloc",
                "reallocarray",
                "valloc",
            },
        )
        self.assertEqual(basic["classification"], "scope-exception")
        self.assertEqual(observability["classification"], "scope-exception")
        self.assertEqual(basic["status"], "documented")
        self.assertEqual(observability["status"], "documented")
        self.assertEqual(basic["scope_exception_id"], harness.ALLOCATOR_SCOPE_EXCEPTION_ID)
        self.assertEqual(basic["scope_exception_version"], harness.ALLOCATOR_SCOPE_EXCEPTION_VERSION)
        self.assertEqual(basic["scope_exception_policy"], harness.ALLOCATOR_SCOPE_EXCEPTION_POLICY)
        self.assertEqual(basic["evidence"], list(harness.ALLOCATOR_SCOPE_EXCEPTION_EVIDENCE))
        self.assertNotIn("rust_equivalent", basic)
        self.assertNotIn("rust_equivalent", observability)

    def test_scope_exception_rejects_non_allocator_use_and_allocator_reclassification(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "memory.bytes-basic")["classification"] = "scope-exception"
        with self.assertRaisesRegex(harness.HarnessError, "reserved for the allocator whitelist"):
            harness.validate_coverage(ledger)

        ledger = self.ledger()
        self.capability(ledger, "memory.allocator-basic")["classification"] = "rust-subsumed"
        with self.assertRaisesRegex(harness.HarnessError, "must remain scope-exception"):
            harness.validate_coverage(ledger)

    def test_scope_exception_rejects_allocator_id_or_symbol_drift(self) -> None:
        ledger = self.ledger()
        self.capability(ledger, "memory.allocator-basic")["id"] = "memory.allocator-renamed"
        with self.assertRaisesRegex(harness.HarnessError, "reserved for the allocator whitelist"):
            harness.validate_coverage(ledger)

        ledger = self.ledger()
        symbols = self.capability(ledger, "memory.allocator-basic")["symbols"]
        symbols[0], symbols[1] = symbols[1], symbols[0]
        with self.assertRaisesRegex(harness.HarnessError, "symbols changed"):
            harness.validate_coverage(ledger)

    def test_scope_exception_rejects_allocator_metadata_drift(self) -> None:
        mutations = (
            ("scope_exception_id", "different-exception", "exception id changed"),
            ("scope_exception_version", 2, "exception version changed"),
            ("scope_exception_policy", "rust-subsumed", "exception policy changed"),
            ("evidence", ["crabc-rs.md"], "exception evidence changed"),
            ("status", "verified", "scope-exception must be documented"),
            ("rust_equivalent", "Box/Vec", "neither Rust-subsumed nor ABI-only"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                ledger = self.ledger()
                capability = self.capability(ledger, "memory.allocator-basic")
                capability[field] = value
                with self.assertRaisesRegex(harness.HarnessError, message):
                    harness.validate_coverage(ledger)


class DualBackendTests(unittest.TestCase):
    def test_stub_backends_compare_in_isolated_workspaces(self) -> None:
        fixture = ROOT / "compat/rustix/api.toml"
        command = [
            sys.executable,
            "-c",
            "import pathlib; p = pathlib.Path(__import__('os').environ['CRABC_RUSTIX_FIXTURE']); print(p.name)",
        ]
        report = harness.compare_backends(fixture, command, command, timeout=2.0)
        self.assertTrue(report["passed"])
        self.assertTrue(report["isolated_working_directories"])
        self.assertEqual(report["comparisons"], {
            "returncode_match": True,
            "stdout_match": True,
            "stderr_match": True,
        })

    def test_compare_requires_a_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.rs"
            with self.assertRaises(harness.HarnessError):
                harness.compare_backends(missing, ["true"], ["true"], timeout=1.0)


class SourceFixtureTests(unittest.TestCase):
    def test_source_compare_accepts_an_ordered_fixture_suite(self) -> None:
        args = harness.parse_args(
            [
                "source-compare",
                "--fixture",
                "compat/rustix/source/m2_statat.rs",
                "--fixture",
                "compat/rustix/source/m2_xattr.rs",
            ]
        )
        self.assertEqual(
            args.fixture,
            [
                Path("compat/rustix/source/m2_statat.rs"),
                Path("compat/rustix/source/m2_xattr.rs"),
            ],
        )

    def test_m6_process_fixture_is_available_to_source_compare(self) -> None:
        args = harness.parse_args(
            ["source-compare", "--fixture", "compat/rustix/source/m6_process.rs"]
        )
        self.assertEqual(args.fixture, [Path("compat/rustix/source/m6_process.rs")])
        self.assertTrue((ROOT / args.fixture[0]).is_file())

    def test_source_dependency_uses_a_fixed_api_alias(self) -> None:
        candidate = harness.source_dependency("crabc-rs", None)
        self.assertIn('api = { package = "crabc-rs"', candidate)
        self.assertIn(str(ROOT / "crabc-rs"), candidate)

        rustix = harness.source_dependency("rustix", Path("/opt/rustix"))
        self.assertIn('api = { package = "rustix"', rustix)
        self.assertIn(
            'features = ["event", "fs", "mm", "mount", "net", "param", "pipe", "process", "pty", "rand", "shm", "stdio", "system", "termios", "thread", "time"]',
            rustix,
        )

    def test_source_fixture_rejects_a_non_target_build(self) -> None:
        fixture = ROOT / "compat/rustix/source/m1_foundation.rs"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(harness.HarnessError):
                harness.compile_source_fixture(
                    fixture,
                    "crabc-rs",
                    None,
                    "x86_64-unknown-linux-musl",
                    Path(directory) / "project",
                    timeout=1.0,
                )

    def test_source_compare_rejects_an_unpinned_checkout(self) -> None:
        fixture = ROOT / "compat/rustix/source/m1_foundation.rs"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(harness.HarnessError):
                harness.compare_source_fixture(fixture, Path(directory), timeout=1.0)


if __name__ == "__main__":
    unittest.main()
