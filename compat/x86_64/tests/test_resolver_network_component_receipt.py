#!/usr/bin/env python3
"""Focused rejection tests for the resolver-network physical receipt reader."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import struct
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


def tc_failover_events() -> list[dict[str, object]]:
    name = "tc-failover.example.test."
    question = (b"\x0btc-failover\x07example\x04test\0\0\1\0\1")
    request = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    truncated = struct.pack("!HHHHHH", 0x1234, 0x8380, 1, 0, 0, 0) + question
    complete = (struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question +
                b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((198, 51, 100, 55)))
    routes = (("valid", "udp", "drop", None), ("drop", "udp", "drop", None),
              ("fallback", "udp", "tc-sequence", truncated),
              ("fallback", "tcp", "answer", complete))
    return [dict(name=name, role=role, transport=transport, action=action,
                 qtype=1, qclass=1, identifier=0x1234 if transport == "udp" else None,
                 request_hex=request.hex(), response_hex=response.hex() if response else None)
            for role, transport, action, response in routes]


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

    def test_image_input_authentication_rejects_content_mode_alias_and_search_path_drift(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            work = Path(directory)
            original = work / "original"
            replacement = work / "replacement"
            alias = work / "command"
            original.write_bytes(b"immutable input")
            replacement.write_bytes(original.read_bytes())
            original.chmod(0o644)
            replacement.chmod(0o644)
            alias.symlink_to(original)
            identity = self.reader.receipt_file_identity(ROOT, original)
            manifest = {"path": os.environ["PATH"], "files": {str(alias): {
                "path": str(original), "sha256": identity["sha256"],
                "size": identity["byte_length"], "mode": identity["mode"],
            }}}
            with mock.patch.object(self.reader, "trusted_image_manifest", return_value=manifest):
                self.assertIs(self.reader.authenticate_image_inputs(ROOT), manifest)
                original.write_bytes(b"changed content")
                with self.assertRaisesRegex(self.reader.ReceiptError, "identity differs"):
                    self.reader.authenticate_image_inputs(ROOT)
                original.write_bytes(b"immutable input")
                original.chmod(0o600)
                with self.assertRaisesRegex(self.reader.ReceiptError, "identity differs"):
                    self.reader.authenticate_image_inputs(ROOT)
                original.chmod(0o644)
                alias.unlink()
                alias.symlink_to(replacement)
                with self.assertRaisesRegex(self.reader.ReceiptError, "input path differs"):
                    self.reader.authenticate_image_inputs(ROOT)
                with mock.patch.dict(os.environ, {"PATH": "/unexpected/bin"}):
                    with self.assertRaisesRegex(self.reader.ReceiptError, "search path differs"):
                        self.reader.authenticate_image_inputs(ROOT)

    def test_historical_image_receipt_is_rejected_without_changing_its_identity(self) -> None:
        historical = {"image": {
            "id": "crabc-core-evidence@sha256:307d75f06680c631437f9faa5f7c726613fcea6f1875dda8cf368ad4b6da1b3d",
            "manifest": {},
        }}
        before = json.dumps(historical, sort_keys=True)
        with self.assertRaisesRegex(self.reader.ReceiptError, "image identity differs"):
            self.reader.image_manifest(ROOT, historical)
        self.assertEqual(json.dumps(historical, sort_keys=True), before)

    def test_raw_dns_events_without_required_transitions_remain_rejected(self) -> None:
        contract = self.reader.recompute_event_contract([], executions=13)
        self.assertFalse(contract["passed"])
        self.assertEqual(contract["required_names_missing"], sorted(self.reader.REQUIRED_SERVER_NAMES))

    def test_tcp_failover_wire_bytes_and_route_are_checked_independently(self) -> None:
        events = tc_failover_events()
        self.assertTrue(self.reader.tc_failover_provenance(events))
        ad_bit = [{**event, "request_hex": event["request_hex"][:4] + "0120" + event["request_hex"][8:]}
                  for event in events]
        self.assertTrue(self.reader.tc_failover_provenance(ad_bit))
        changed = [dict(event) for event in events]
        changed[2]["response_hex"] = changed[2]["response_hex"].replace("8380", "8180", 1)
        self.assertFalse(self.reader.tc_failover_provenance(changed))
        self.assertFalse(self.reader.tc_failover_provenance(events[1:]))
        self.assertFalse(self.reader.tc_failover_provenance(events[:2] + events[3:] + events[2:3]))

    def test_fallback_query_without_an_answer_from_fallback_endpoint_is_rejected(self) -> None:
        events = [
            {"name": name, "role": "valid", "transport": "udp", "action": "answer"}
            for name in self.reader.REQUIRED_SERVER_NAMES
        ]
        events.extend([
            {"name": "malformed.example.test.", "role": "valid", "transport": "udp", "action": "malformed-sequence"},
            {"name": "fallback.example.test.", "role": "valid", "transport": "udp", "action": "drop"},
            {"name": "fallback.example.test.", "role": "drop", "transport": "udp", "action": "drop"},
            {"name": "fallback.example.test.", "role": "fallback", "transport": "udp", "action": "drop"},
            {"name": "alias.example.test.", "role": "valid", "transport": "udp", "action": "cname"},
            {"name": "chain.example.test.", "role": "valid", "transport": "udp", "action": "cname-chain"},
            {"name": "tc.example.test.", "role": "valid", "transport": "udp", "action": "tc-sequence"},
            {"name": "tc.example.test.", "role": "valid", "transport": "tcp", "action": "answer"},
        ])
        contract = self.reader.recompute_event_contract(events, executions=1)
        self.assertFalse(contract["passed"])

    def test_aggregate_events_cannot_substitute_for_a_missing_mode_stream(self) -> None:
        events = [{"name": name, "role": "valid", "transport": "udp", "action": "answer"}
                  for name in self.reader.REQUIRED_SERVER_NAMES
                  if name not in {"source-spoof.example.test.", "tc-failover.example.test."}]
        events.extend([
            {"name": "malformed.example.test.", "action": "malformed-sequence"},
            {"name": "fallback.example.test.", "role": "valid", "action": "drop"},
            {"role": "drop", "action": "drop"},
            {"name": "fallback.example.test.", "role": "fallback", "transport": "udp", "action": "answer"},
            {"name": "alias.example.test.", "action": "cname"},
            {"name": "chain.example.test.", "role": "valid", "transport": "udp", "action": "cname-chain"},
            {"name": "tc.example.test.", "transport": "udp", "action": "tc-sequence"},
            {"name": "tc.example.test.", "transport": "tcp", "action": "answer"},
            {"name": "source-spoof.example.test.", "role": "valid", "transport": "udp",
             "action": "source-spoof-sequence", "forged_source": "127.0.0.4",
             "valid_source": "127.0.0.1"},
        ])
        events.extend(tc_failover_events())
        aggregate = events * 2
        self.assertTrue(self.reader.recompute_event_contract(aggregate, executions=2)["passed"])
        wrong_chain = [
            {**event, "role": "fallback"} if event.get("name") == "chain.example.test." else event
            for event in aggregate
        ]
        self.assertFalse(self.reader.recompute_event_contract(wrong_chain, executions=2)["passed"])
        swapped = {"reference": aggregate, "installed-static-et-exec": []}
        self.assertFalse(self.reader.recompute_event_contract(
            aggregate, executions=2, by_execution=swapped,
        )["passed"])

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
    """Replay only a real fresh v3 report; never synthesize a passing receipt."""

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
        self.assertEqual(report["schema_version"], 3)
        self.assertTrue(report["passed"])
        self.assertEqual(report["receipt"]["scope"], ["libc.resolver"])

    def test_real_tcp_retry_event_cannot_be_moved_between_executions(self) -> None:
        report = self.reader.validate_report(self.root, self.report)
        records = report["receipt"]["dns"]["by_execution"]
        labels = ("reference", *self.reader.expected_candidate_labels())
        streams = {
            label: json.loads(Path(records[label]["events"]["path"]).read_text(encoding="utf-8"))["events"]
            for label in labels
        }
        reference = streams["reference"]
        moved = [event for event in reference if event.get("name") == "tc.example.test." and
                 event.get("transport") == "tcp" and event.get("action") == "answer"]
        self.assertTrue(moved)
        reference[:] = [event for event in reference if event not in moved]
        streams["installed-static-et-exec"].extend(moved)
        aggregate = [event for stream in streams.values() for event in stream]
        self.assertTrue(self.reader.recompute_event_contract(aggregate, executions=13)["passed"])
        self.assertFalse(self.reader.recompute_event_contract(
            aggregate, executions=13, by_execution=streams,
        )["passed"])


if __name__ == "__main__":
    unittest.main()
