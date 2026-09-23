#!/usr/bin/env python3
"""Focused rejection tests for the resolver-network physical receipt reader."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/resolver_network_component_receipt.py"


def load_reader():
    spec = importlib.util.spec_from_file_location("resolver_network_component_receipt_test", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


class ResolverNetworkComponentReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reader = load_reader()

    def test_legacy_summary_only_report_cannot_establish_a_physical_receipt(self) -> None:
        with self.assertRaisesRegex(self.reader.ReceiptError, "physical receipt"):
            self.reader.validate_report_document({"schema_version": 1})

    def test_receipt_names_every_existing_candidate_mode_in_both_product_arms(self) -> None:
        labels = self.reader.expected_candidate_labels()
        self.assertEqual(len(labels), 12)
        self.assertEqual(set(labels), {
            "installed-static-et-exec", "installed-static-pie",
            "installed-dynamic-pie-ordinary", "installed-dynamic-pie-direct-entry",
            "installed-dynamic-non-pie-ordinary", "installed-dynamic-non-pie-direct-entry",
            "extracted-static-et-exec", "extracted-static-pie",
            "extracted-dynamic-pie-ordinary", "extracted-dynamic-pie-direct-entry",
            "extracted-dynamic-non-pie-ordinary", "extracted-dynamic-non-pie-direct-entry",
        })

    def test_current_image_manifest_tracks_the_repository_toolchain_and_exact_roster(self) -> None:
        manifest = self.reader.trusted_image_manifest(ROOT)
        self.assertEqual(manifest['image'], self.reader.PINNED_IMAGE.removeprefix('crabc-core-evidence@'))
        self.assertEqual(set(manifest['files']), {
            '/usr/local/bin/crabc-x86_64-musl-gcc', '/usr/bin/python3', '/usr/bin/readelf', '/usr/sbin/chroot',
            *(str(path) for path in self.reader.COMPILER_ORACLE_INPUTS.values()),
            str(self.reader.RUSTC), str(self.reader.LLD),
        })
        self.assertIn(f"{self.reader.pinned_toolchain(ROOT)}-x86_64-", str(self.reader.RUSTC))

    def test_raw_dns_events_without_required_transitions_remain_rejected(self) -> None:
        contract = self.reader.recompute_event_contract([], executions=13)
        self.assertFalse(contract["passed"])
        self.assertEqual(contract["required_names_missing"], sorted(self.reader.REQUIRED_SERVER_NAMES))

    def test_physical_reader_refuses_a_symlinked_artifact_path(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="resolver-network-reader.", dir=scratch) as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"physical\n")
            alias = root / "alias"
            alias.symlink_to(source.name)
            with self.assertRaisesRegex(self.reader.ReceiptError, "physical regular file"):
                self.reader.physical_file(alias, "symlinked receipt artifact")

    def test_product_validation_failure_is_a_receipt_rejection(self) -> None:
        class BrokenRunner:
            @staticmethod
            def static_manifest(_path: Path) -> object:
                raise RuntimeError("wrong product")

        with self.assertRaisesRegex(self.reader.ReceiptError, "product validation failed"):
            self.reader.validated_product_manifest(BrokenRunner(), "static", Path("/physical/product"), "fixture")

    def test_mutated_raw_stream_cannot_match_its_retained_identity(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="resolver-network-reader.", dir=scratch) as directory:
            root = Path(directory)
            stream = root / "receipt/executions/installed-static-et-exec.stdout"
            stream.parent.mkdir(parents=True)
            stream.write_bytes(b"original raw stream\n")
            record = self.reader.receipt_file_identity(root, stream)
            stream.write_bytes(b"mutated raw stream\n")
            with self.assertRaisesRegex(self.reader.ReceiptError, "identity differs"):
                self.reader.assert_receipt_file_identity(root, record, "candidate raw stdout", expected=stream)

    def test_missing_execution_stdout_sidecar_is_not_inferred_from_the_summary(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="resolver-network-reader.", dir=scratch) as directory:
            root = Path(directory)
            state = root / "state"
            sidecars = state / "receipt/executions"
            sidecars.mkdir(parents=True)
            argv = sidecars / "reference.argv.json"
            status = sidecars / "reference.status.json"
            stderr = sidecars / "reference.stderr"
            argv.write_bytes(json.dumps(["/workload"]).encode("utf-8"))
            status.write_bytes(b"0\n")
            stderr.write_bytes(b"")
            receipt = {
                "executions": {
                    "reference": {
                        "argv": self.reader.receipt_file_identity(root, argv),
                        "status": self.reader.receipt_file_identity(root, status),
                        "stdout": {
                            "path": "/workspace/state/receipt/executions/reference.stdout",
                            "sha256": "0" * 64,
                            "byte_length": 0,
                            "mode": 0o644,
                        },
                        "stderr": self.reader.receipt_file_identity(root, stderr),
                        "root": {},
                    },
                },
            }
            with self.assertRaisesRegex(self.reader.ReceiptError, "execution stdout is not a physical regular file"):
                self.reader.execution_record(root, state, receipt, "reference", ["/workload"], state)

    def test_mode_only_dynamic_product_copy_drift_is_rejected(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="resolver-network-reader.", dir=scratch) as directory:
            root = Path(directory)
            product = root / "product"
            library = product / "usr/lib"
            library.mkdir(parents=True)
            source = library / "libc.so"
            source.write_bytes(b"same bytes\n")
            source.chmod(0o644)
            copied = root / "execution"
            shutil.copytree(product, copied)
            self.reader.compare_product_copy(product, copied, "fixture")
            (copied / "usr/lib/libc.so").chmod(0o755)
            with self.assertRaisesRegex(self.reader.ReceiptError, "mode differ"):
                self.reader.compare_product_copy(product, copied, "fixture")

    def test_product_paths_reject_reusing_one_physical_root_for_both_arms(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="resolver-network-reader.", dir=scratch) as directory:
            root = Path(directory)
            for name in ("installed-static", "installed-dynamic", "extracted-dynamic"):
                (root / name).mkdir()
            products = {
                "installed": {
                    "static": {"source": "caller-prepared-installed", "path": "/workspace/installed-static", "manifest": {}},
                    "dynamic": {"source": "caller-prepared-installed", "path": "/workspace/installed-dynamic", "manifest": {}},
                },
                "extracted": {
                    "static": {"source": "caller-prepared-extracted", "path": "/workspace/installed-static", "manifest": {}},
                    "dynamic": {"source": "caller-prepared-extracted", "path": "/workspace/extracted-dynamic", "manifest": {}},
                },
            }
            with self.assertRaisesRegex(self.reader.ReceiptError, "reuse a physical product root"):
                self.reader.product_paths(root, {"products": products})

    def test_header_closure_requires_each_physical_header_under_the_bound_roots(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="resolver-network-reader.", dir=scratch) as directory:
            root = Path(directory)
            musl_include = root / "musl/include"
            resource = root / "compiler/include"
            musl_include.mkdir(parents=True)
            resource.mkdir(parents=True)
            netdb = musl_include / "netdb.h"
            netdb.write_bytes(b"netdb closure\n")
            trace = root / "headers.trace"
            trace.write_text(f". {netdb}\n", encoding="utf-8")
            with mock.patch.object(self.reader, "MUSL_INCLUDE", musl_include):
                closure = self.reader.header_closure(root, trace, resource)
                self.assertEqual(closure["headers"], [self.reader.receipt_file_identity(root, netdb)])
                outside = root / "outside.h"
                outside.write_bytes(b"outside\n")
                trace.write_text(f". {outside}\n", encoding="utf-8")
                with self.assertRaisesRegex(self.reader.ReceiptError, "escaped"):
                    self.reader.header_closure(root, trace, resource)


class ResolverNetworkRealReceiptTests(unittest.TestCase):
    """Replay only a real fresh v2 report; never synthesize a passing receipt."""

    @classmethod
    def setUpClass(cls) -> None:
        value = os.environ.get("CRABC_RESOLVER_NETWORK_TEST_REPORT")
        if not value:
            raise unittest.SkipTest(
                "set CRABC_RESOLVER_NETWORK_TEST_REPORT to a fresh native resolver receipt"
            )
        cls.reader = load_reader()
        cls.root = Path(os.environ.get("CRABC_RESOLVER_NETWORK_TEST_ROOT", "/workspace"))
        cls.report = Path(value)

    def test_fresh_physical_report_replays_without_a_synthetic_success_fixture(self) -> None:
        report = self.reader.validate_report(self.root, self.report)
        self.assertEqual(report["schema_version"], 2)
        self.assertTrue(report["passed"])
        self.assertEqual(report["receipt"]["scope"], ["libc.resolver"])


if __name__ == "__main__":
    unittest.main()
