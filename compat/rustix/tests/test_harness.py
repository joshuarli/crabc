#!/usr/bin/env python3
"""Focused standard-library tests for the Rustix compatibility harness."""

from __future__ import annotations

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
