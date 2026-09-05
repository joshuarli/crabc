#!/usr/bin/env python3
"""Qualification receipts reject incomplete, stale or cross-product evidence."""
from __future__ import annotations

import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_dynamic_qualification as qualification
import crabc_cc_owned_dynamic as driver

REAL_PRODUCT_IDENTITY = qualification.product_identity


class OwnedDynamicQualificationTests(unittest.TestCase):
    def setUp(self):
        temporary_root = ROOT / ".work/x86_64/tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / ".work/product"
        self.work.mkdir(parents=True)
        pins = self.root / "compat/upstreams.toml"
        pins.parent.mkdir(parents=True)
        pins.write_text("pinned musl fixture\n")
        self.source = "a" * 64
        self.manifest = "b" * 64
        for patch in (
            mock.patch.object(qualification, "ROOT", self.root),
            mock.patch.object(qualification, "PUBLICATION", self.root / ".work/publication.json"),
            mock.patch.object(qualification, "source_digest", return_value=self.source),
            mock.patch.object(qualification, "contract_digests", return_value={"contracts": "c" * 64}),
            mock.patch.object(qualification, "product_identity", return_value=self.manifest),
            mock.patch.object(qualification, "require_clean_source", return_value="clean-revision"),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        expected = b"installed dynamic: allocation errno stdio threads\nordinary exit\n"
        self.put("expected.stdout", expected)
        self.put("oracle.stdout", expected)
        for product in qualification.PRODUCTS:
            (self.work / product).mkdir()
            self.put(f"{product}/payload", b"runtime")
            installed_manifest = {"files": {"payload": qualification.digest(self.work / product / "payload")}, "symlinks": {}}
            self.put(f"{product}/share/crabc/manifest.json", installed_manifest)
            for name, output in ((f"{product}-consumer", expected), (f"non-pie-{product}", expected), (f"spawn-{product}", b"")):
                self.put(name, b"owned ELF fixture")
                self.put(name + ".stdout", output)
                self.put(name + ".crabc-link.json", {
                    "output_sha256": qualification.digest(self.work / name),
                    "manifest_sha256": self.manifest,
                    "mode": "exec" if name.startswith("non-pie-") else "pie",
                    "campaign_complete": False, "binding": "now",
                    "link_trace": ["declared input"], "owned_runtime_inputs": ["usr/lib/libc.so"],
                })
            for case, (script, mode) in qualification.CASES.items():
                artifact = self.put(f"leaf-artifacts/{product}-{case}/consumer", b"actual leaf artifact")
                log = self.put(f"qualification-cases/{product}/{case}.log", f"ordinary differential passed; evidence: {artifact.parent}\n".encode())
                self.put(f"qualification-cases/{product}/{case}.json", {
                    "schema": qualification.SCHEMA, "product": product, "case": case, "script": script,
                    "entry_mode": mode, "source_sha256": self.source, "manifest_sha256": self.manifest,
                    "log": qualification.relative(log), "log_sha256": qualification.digest(log), "exit_status": 0,
                    "source_mount": str(self.root), "artifacts": qualification.artifact_snapshot(log, str(self.root)),
                })
        prepare_log = self.put("qualification-prepare.log", b"source judges and musl pin validated\n")
        self.put("qualification-prepare.json", {
            "schema": qualification.SCHEMA, "source_sha256": self.source,
            "log": qualification.relative(prepare_log), "log_sha256": qualification.digest(prepare_log),
            "oracle": {"version": "musl-1.2.6", "runtime_sha256": "d" * 64,
                       "compiler_wrapper_sha256": "e" * 64, "pins_sha256": qualification.digest(pins)},
            "checks": ["installed-driver", "owned-crt", "owned-loader-source", "pinned-musl-oracle"], "exit_status": 0,
        })
        for name in ("runtime.tar", "second-runtime.tar"):
            with tarfile.open(self.work / name, "w") as archive:
                for relative in ("payload", "share/crabc/manifest.json"):
                    data = (self.work / "installed" / relative).read_bytes()
                    member = tarfile.TarInfo(relative)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))

    def put(self, name, value):
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json.dumps(value, sort_keys=True).encode() if isinstance(value, dict) else value)
        return path

    def test_materialization_binds_payload_source_and_contracts_without_publication(self):
        product = self.work / "installed"
        payloads = {"payload": qualification.digest(product / "payload")}
        state = {
            "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
            "status": "materialized-unqualified", "source_sha256": self.source,
            "contracts": {"contracts": "c" * 64}, "payload_files": payloads,
            "runtime_v1_published": False, "campaign_complete": False, "public_support": False,
            "modes": ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
            "runtime_profile": qualification.MATERIALIZATION_PROFILE,
            "qualification": qualification.MATERIALIZATION_QUALIFICATION,
        }
        path = self.put("installed/share/crabc/dynamic-product-state.json", state)
        manifest = {"files": {**payloads, "share/crabc/dynamic-product-state.json": qualification.digest(path)}}
        with mock.patch.object(driver, "validate", return_value=manifest):
            self.assertEqual(REAL_PRODUCT_IDENTITY(product), qualification.digest(product / "share/crabc/manifest.json"))
            for key, value in (("status", "verified"), ("source_sha256", "0" * 64),
                               ("contracts", {}), ("payload_files", {}),
                               ("runtime_v1_published", True), ("campaign_complete", True)):
                with self.subTest(field=key):
                    path.write_text(json.dumps({**state, key: value}))
                    with self.assertRaises(qualification.QualificationError):
                        REAL_PRODUCT_IDENTITY(product)

    def test_complete_receipt_requires_explicit_clean_reviewed_publication(self):
        receipt = qualification.collect(self.work)
        self.assertEqual(receipt["status"], "qualified-pending-review")
        self.assertFalse(receipt["runtime_v1_published"])
        self.assertFalse(receipt["family_completion"])
        self.assertFalse(receipt["promotion_ready"])
        self.assertFalse(receipt["public_support"])
        self.assertIsNone(qualification.load_publication())
        path = self.put("qualification.json", receipt)
        self.assertEqual(qualification.validate_receipt(path), receipt)
        qualification.write_new(qualification.PUBLICATION, {
            "schema": qualification.SCHEMA, "receipt": qualification.relative(path),
            "receipt_sha256": qualification.digest(path), "source_revision": "clean-revision",
        })
        self.assertEqual(qualification.load_publication(), receipt)
        with mock.patch.object(qualification, "require_clean_source", return_value="later-revision"):
            with self.assertRaisesRegex(qualification.QualificationError, "source revision is stale"):
                qualification.load_publication()

    def test_missing_second_product_cancellation_cannot_be_inferred_from_other_products(self):
        (self.work / "qualification-cases/second/io-cancellation.json").unlink()
        with self.assertRaisesRegex(qualification.QualificationError, "coverage cases"):
            qualification.collect(self.work)

    def test_coverage_rejects_stale_source_wrong_product_and_missing_mode(self):
        path = self.work / "qualification-cases/installed/dlopen-non-pie.json"
        original = qualification.read(path)
        for key, value in (("source_sha256", "0" * 64), ("product", "extracted"), ("entry_mode", "--dynamic-pie"), ("exit_status", 1)):
            with self.subTest(field=key):
                changed = {**original, key: value}
                path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(qualification.QualificationError, "mismatched coverage"):
                    qualification.collect(self.work)
        path.write_text(json.dumps(original))

    def test_changed_case_log_and_base_executable_are_rejected(self):
        log = self.work / "qualification-cases/installed/cli.log"
        original_log = log.read_bytes()
        log.write_bytes(b"later unrelated success")
        with self.assertRaisesRegex(qualification.QualificationError, "log hash mismatch"):
            qualification.collect(self.work)
        log.write_bytes(original_log)
        (self.work / "installed-consumer").write_bytes(b"other ELF")
        with self.assertRaisesRegex(qualification.QualificationError, "executable receipt hash"):
            qualification.collect(self.work)

    def test_actual_leaf_elf_and_driver_evidence_cannot_change_after_case(self):
        (self.work / "leaf-artifacts/extracted-elf-scope-alias/consumer").write_bytes(b"replacement fixture")
        with self.assertRaisesRegex(qualification.QualificationError, "leaf artifact evidence changed"):
            qualification.collect(self.work)

    def test_missing_oracle_identity_and_stale_pins_are_rejected(self):
        path = self.work / "qualification-prepare.json"
        original = qualification.read(path)
        for mutate in (lambda value: value.pop("oracle"), lambda value: value["oracle"].__setitem__("pins_sha256", "0" * 64)):
            changed = copy.deepcopy(original)
            mutate(changed)
            path.write_text(json.dumps(changed))
            with self.assertRaises(qualification.QualificationError):
                qualification.collect(self.work)

    def test_equal_archives_from_another_product_are_rejected(self):
        for name in ("runtime.tar", "second-runtime.tar"):
            with tarfile.open(self.work / name, "w") as archive:
                member = tarfile.TarInfo("unrelated")
                archive.addfile(member, io.BytesIO())
        with self.assertRaisesRegex(qualification.QualificationError, "package member count"):
            qualification.collect(self.work)

    def test_stale_contract_or_edited_receipt_cannot_validate(self):
        receipt = qualification.collect(self.work)
        path = self.put("qualification.json", receipt)
        with mock.patch.object(qualification, "contract_digests", return_value={"contracts": "0" * 64}):
            with self.assertRaisesRegex(qualification.QualificationError, "receipt is stale"):
                qualification.validate_receipt(path)
        receipt["runtime_v1_published"] = True
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(qualification.QualificationError, "receipt is stale"):
            qualification.validate_receipt(path)


if __name__ == "__main__":
    unittest.main()
