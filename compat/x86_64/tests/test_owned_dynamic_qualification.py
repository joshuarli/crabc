#!/usr/bin/env python3
"""Qualification receipts reject incomplete, stale or cross-product evidence."""
from __future__ import annotations

import copy
import contextlib
import importlib.util
import io
import json
import os
import shutil
import stat
from pathlib import Path
import sys
import subprocess
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
        pins.write_text('[musl]\nversion = "1.2.6"\nsha256 = "' + "d" * 64
                        + '"\nfallback_revision = "' + "e" * 40 + '"\n')
        wrapper = self.root / "docker/x86_64-musl-oracle-gcc"
        wrapper.parent.mkdir()
        wrapper.write_bytes(b"tracked oracle wrapper\n")
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
                    "schema": 1, "format": driver.FORMAT, "runtime_imports": [],
                    "output_path": str(self.work / name),
                    "output_sha256": qualification.digest(self.work / name),
                    "manifest_sha256": self.manifest,
                    "mode": "exec" if name.startswith("non-pie-") else "pie",
                    "campaign_complete": False, "binding": "now",
                    "link_trace": ["declared input"],
                    "owned_runtime_inputs": sorted("usr/lib/" + entry for entry in
                        (("crt1.o" if name.startswith("non-pie-") else "Scrt1.o"),
                         "crabc-dynamic-attach.o", "crti.o", "libc.so", "libcrabc-builtins.a", "crtn.o")),
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
        oracle_payloads = {
            "runtime": b"observed oracle runtime", "compiler_wrapper": wrapper.read_bytes(),
            "specs": b"pinned specs", "source_manifest":
                ("format=crabc-pinned-musl-oracle-v1\nversion=1.2.6\nsource_sha256=" + "d" * 64
                 + "\nfallback_revision=" + "e" * 40 + "\narchitecture=x86_64\n").encode(),
        }
        for name, payload in oracle_payloads.items():
            self.put("qualification-oracle/" + name, payload)
        self.put("qualification-oracle/specs_manifest",
                 (qualification.digest(self.work / "qualification-oracle/specs")
                  + "  /opt/musl-1.2.6/lib/musl-gcc.specs\n").encode())
        oracle_files = {name: qualification.digest(self.work / "qualification-oracle" / name)
                        for name in qualification.ORACLE_FILES}
        prepare_log = self.put("qualification-prepare.log", b"source judges and musl pin validated\n")
        self.put("qualification-prepare.json", {
            "schema": qualification.SCHEMA, "source_sha256": self.source,
            "log": qualification.relative(prepare_log), "log_sha256": qualification.digest(prepare_log),
            "oracle": {"version": "musl-1.2.6", "runtime_sha256": oracle_files["runtime"],
                       "compiler_wrapper_sha256": oracle_files["compiler_wrapper"],
                       "pins_sha256": qualification.digest(pins), "files": oracle_files},
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
            self.assertIsNone(qualification.load_publication())

    def publish(self, path):
        with mock.patch.object(sys, "argv", ["owned_dynamic_qualification.py", "publish", "--receipt", str(path)]), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return qualification.main()

    def test_reviewed_pointer_republishes_atomically_after_source_changes(self):
        first = self.put("qualification.json", qualification.collect(self.work))
        self.assertEqual(self.publish(first), 0)
        old_receipt_bytes = first.read_bytes()
        old_case = self.work / "qualification-cases/installed/cycle.json"
        old_case_bytes = old_case.read_bytes()
        second_work = self.root / ".work/fresh-product"
        shutil.copytree(self.work, second_work)
        (second_work / "qualification.json").unlink()
        new_source = "f" * 64
        for path in second_work.rglob("*.log"):
            path.write_text(path.read_text().replace(str(self.work), str(second_work)))
        for path in second_work.glob("qualification-cases/*/*.json"):
            record = json.loads(path.read_text().replace(str(self.work.relative_to(self.root)), str(second_work.relative_to(self.root))))
            record["source_sha256"] = new_source
            log = self.root / record["log"]
            record["log_sha256"] = qualification.digest(log)
            record["artifacts"] = qualification.artifact_snapshot(log, str(self.root))
            path.write_text(json.dumps(record))
        prepare = second_work / "qualification-prepare.json"
        record = qualification.read(prepare)
        record["source_sha256"] = new_source
        record["log"] = qualification.relative(second_work / "qualification-prepare.log")
        prepare.write_text(json.dumps(record))
        for path in second_work.glob("*.crabc-link.json"):
            path.write_text(path.read_text().replace(str(self.work), str(second_work)))
        with mock.patch.object(qualification, "source_digest", return_value=new_source), \
             mock.patch.object(qualification, "require_clean_source", return_value="next-clean-revision"):
            second = second_work / "qualification.json"
            qualification.write_new(second, qualification.collect(second_work))
            self.assertEqual(self.publish(second), 0)
            self.assertEqual(qualification.load_publication()["work"], qualification.relative(second_work))
            self.assertEqual(stat.S_IMODE(qualification.PUBLICATION.stat().st_mode), 0o644)
        self.assertEqual(first.read_bytes(), old_receipt_bytes)
        self.assertEqual(old_case.read_bytes(), old_case_bytes)
        self.assertFalse(list(qualification.PUBLICATION.parent.glob(".publication-*.json")))

    def test_source_change_during_republication_preserves_old_pointer_and_receipts(self):
        path = self.put("qualification.json", qualification.collect(self.work))
        self.assertEqual(self.publish(path), 0)
        pointer_bytes = qualification.PUBLICATION.read_bytes()
        receipt_bytes = path.read_bytes()
        with mock.patch.object(qualification, "require_clean_source", side_effect=["clean-revision", "later-revision"]):
            self.assertEqual(self.publish(path), 1)
        self.assertEqual(qualification.PUBLICATION.read_bytes(), pointer_bytes)
        self.assertEqual(path.read_bytes(), receipt_bytes)
        self.assertFalse(list(qualification.PUBLICATION.parent.glob(".publication-*.json")))

    def test_dirty_source_makes_existing_publication_unqualified(self):
        path = self.put("qualification.json", qualification.collect(self.work))
        self.assertEqual(self.publish(path), 0)
        with mock.patch.object(qualification, "require_clean_source", side_effect=qualification.QualificationError("dirty source")):
            self.assertIsNone(qualification.load_publication())

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

    def test_base_receipt_cannot_claim_another_output_or_an_ambient_runtime_roster(self):
        path = self.work / "installed-consumer.crabc-link.json"
        original = qualification.read(path)
        for key, value in (("output_path", str(self.work / "other-consumer")),
                           ("owned_runtime_inputs", ["/ambient/libc.so"]),
                           ("runtime_imports", ["undeclared_import"])):
            path.write_text(json.dumps({**original, key: value}))
            with self.assertRaisesRegex(qualification.QualificationError, "base driver"):
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

    def test_oracle_identity_cannot_be_an_arbitrary_well_formed_digest(self):
        path = self.work / "qualification-prepare.json"
        record = qualification.read(path)
        record["oracle"]["runtime_sha256"] = "0" * 64
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(qualification.QualificationError, "oracle"):
            qualification.collect(self.work)

    def test_live_oracle_change_and_wrapper_source_mismatch_are_rejected(self):
        oracle = qualification.read(self.work / "qualification-prepare.json")["oracle"]
        live = self.root / ".work/live-oracle"
        shutil.copytree(self.work / "qualification-oracle", live)
        with mock.patch.object(qualification, "ORACLE_FILES", {name: live / name for name in oracle["files"]}):
            qualification.require_live_oracle(self.work, oracle)
            (live / "runtime").write_bytes(b"different live runtime")
            with self.assertRaisesRegex(qualification.QualificationError, "live oracle files differ"):
                qualification.require_live_oracle(self.work, oracle)
        (self.root / "docker/x86_64-musl-oracle-gcc").write_bytes(b"changed tracked wrapper")
        with self.assertRaisesRegex(qualification.QualificationError, "wrapper differs from pinned source"):
            qualification.validate_oracle(self.work, oracle)

    def test_oracle_runner_rejects_scratch_outside_checkout_before_tool_execution(self):
        environment = dict(os.environ, TMPDIR="/tmp")
        completed = subprocess.run(["bash", str(ROOT / "compat/x86_64/run_musl_oracle.sh")],
                                   env=environment, capture_output=True, text=True)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("oracle TMPDIR must be a physical checkout .work directory", completed.stderr)

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
