#!/usr/bin/env python3
"""Focused admission and retained-observation tests for public data evidence."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "public_data_ordinary_link_evidence_test",
    ROOT / "compat/x86_64/public_data_ordinary_link_evidence.py",
)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


class PublicDataOrdinaryLinkEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/public-data-ordinary-link-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.root = Path(self.temporary.name)
        (self.root / ".work/input/static/products/primary/share/crabc").mkdir(parents=True)
        (self.root / ".work/input/dynamic/share/crabc").mkdir(parents=True)
        self.preparation = self.root / ".work/input/static/preparation.json"
        self.static = self.root / ".work/input/static/products/primary"
        self.dynamic = self.root / ".work/input/dynamic"
        self.static_manifest = self.static / "share/crabc/manifest.json"
        self.dynamic_manifest = self.dynamic / "share/crabc/manifest.json"
        self.dynamic_state = self.dynamic / "share/crabc/dynamic-product-state.json"
        for path in (self.preparation, self.static_manifest, self.dynamic_manifest, self.dynamic_state):
            path.write_text("{}\n", encoding="utf-8")
        self.source = {"revision": "a" * 40, "content_sha256": "b" * 64}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def preparation_record(self, product: Path | None = None) -> dict:
        product = self.static if product is None else product
        manifest = evidence.work_file_identity(self.root, product / "share/crabc/manifest.json", "static manifest")
        return {
            "source": dict(self.source),
            "products": {"primary": {"path": product.relative_to(self.root).as_posix(), "manifest": manifest}},
        }

    def admit(self, *, preparation: dict | None = None, state_source: str | None = None,
              product: Path | None = None) -> dict:
        preparation = self.preparation_record(product) if preparation is None else preparation
        state_source = self.source["content_sha256"] if state_source is None else state_source
        with (
            mock.patch.object(evidence.static_products, "validate_receipt", return_value=preparation),
            mock.patch.object(evidence.static_products, "source_identity", return_value=dict(self.source)),
            mock.patch.object(
                evidence.qualification,
                "product_identity",
                return_value=hashlib.sha256(self.dynamic_manifest.read_bytes()).hexdigest(),
            ),
            mock.patch.object(evidence.qualification, "read", return_value={"source_sha256": state_source}),
        ):
            return evidence.admit_inputs(self.root, self.preparation, self.static, self.dynamic)

    def test_policy_selects_exact_32_objects_and_ten_declared_aliases(self) -> None:
        objects, aliases = evidence.selected_objects()
        self.assertEqual(len(objects), 32)
        self.assertEqual(len(aliases), 10)
        self.assertEqual({item["name"] for item in objects if item["declaration_kind"] == "abi-only"},
                         evidence.ABI_ONLY_NAMES)
        self.assertNotIn("_dl_debug_addr", {item["name"] for item in objects})

    def test_omitted_object_or_alias_is_rejected_before_probe_observation(self) -> None:
        contract = copy.deepcopy(evidence.selection.load_contract())
        contract["object_contracts"] = [
            item for item in contract["object_contracts"] if item["name"] != "stdout"
        ]
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "32"):
            evidence.selected_objects(contract)
        contract = copy.deepcopy(evidence.selection.load_contract())
        next(item for item in contract["object_contracts"] if item["name"] == "tzname")["alias_target"] = ""
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "aliases"):
            evidence.selected_objects(contract)

    def test_admission_rejects_wrong_prepared_primary_and_source_mismatch(self) -> None:
        wrong = self.root / ".work/input/static/products/other"
        (wrong / "share/crabc").mkdir(parents=True)
        (wrong / "share/crabc/manifest.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "not preparation primary"):
            self.admit(preparation=self.preparation_record(wrong))
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "source digests differ"):
            self.admit(state_source="c" * 64)

    def test_admission_returns_both_sealed_product_identities(self) -> None:
        admitted = self.admit()
        self.assertEqual(admitted["source"], self.source)
        self.assertEqual(admitted["static_preparation"]["primary"]["path"],
                         self.static.relative_to(self.root).as_posix())
        self.assertEqual(admitted["dynamic_product"]["path"], self.dynamic.relative_to(self.root).as_posix())

    def test_candidate_link_rejects_a_wrong_driver_receipt_path(self) -> None:
        inputs = self.admit()
        work = self.root / ".work/receipt"
        work.mkdir()
        for name in ("probe.o", "static", "static-pie", "dynamic-pie", "dynamic-non-pie",
                     "static.crabc-link.json", "static-pie.crabc-link.json",
                     "dynamic-pie.crabc-link.json", "dynamic-non-pie.crabc-link.json"):
            (work / name).write_bytes(b"retained\n")
        links = {}
        for mode, linkage, kind in (
            ("static", "static", "static"), ("static-pie", "static-pie", "static"),
            ("dynamic-pie", "pie", "dynamic"), ("dynamic-non-pie", "non-pie", "dynamic"),
        ):
            receipt = work / (mode + ".crabc-link.json")
            links[mode] = {
                "linkage": linkage, "product": kind,
                "receipt": evidence.work_file_identity(self.root, receipt, "receipt"),
                "executable": evidence.work_file_identity(self.root, work / mode, "executable"),
                "linker": {"path": "/opt/ld.lld", "sha256": "d" * 64},
                "product_manifest": (inputs["static_preparation"]["primary"]["manifest"]
                                     if kind == "static" else inputs["dynamic_product"]["manifest"]),
            }
        with mock.patch.object(evidence.products, "validate_retained_link", return_value={"receipt_sha256": "x"}) as reader:
            evidence.validate_links(self.root, work, inputs, links)
            self.assertEqual(reader.call_count, 4)
        links["static"]["receipt"]["path"] = links["static-pie"]["receipt"]["path"]
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "artifact path"):
            evidence.validate_links(self.root, work, inputs, links)

    def test_observation_rejects_static_alignment_and_declared_alias_drift(self) -> None:
        objects, aliases = evidence.selected_objects()
        policy = {"names": [item["name"] for item in objects], "aliases": aliases}
        contracts = {item["name"]: item for item in objects}

        def row(name: str, *, value: str = "0000000000001000") -> dict:
            contract = contracts[name]
            return {
                "name": name, "type": contract["type"], "binding": contract["binding"],
                "visibility": contract["visibility"], "version": None, "version_default": False,
                "section_index": "9", "value": value, "size_bytes": contract["size_bytes"],
            }

        imports = [
            {
                "name": name, "type": "NOTYPE", "binding": "GLOBAL", "visibility": "DEFAULT",
                "version": None, "version_default": False, "section_index": "UND",
                "value": "0000000000000000", "size_bytes": 0,
            }
            for name in [*policy["names"], "write"]
        ]

        def static_rows() -> list[dict]:
            rows = {name: row(name, value=f"{0x1000 + index * 0x100:x}") for index, name in enumerate(policy["names"])}
            for alias in aliases:
                target = rows[alias["target"]]
                rows[alias["name"]] = row(alias["name"], value=target["value"])
            return list(rows.values())

        current = static_rows()
        with mock.patch.object(evidence, "rows_for", side_effect=lambda _work, label:
                               imports if label == "object-symbols" else current):
            observations = evidence.observe(self.root, self.root / ".work", policy)
            self.assertEqual(len(observations["imports"]), 33)

        misaligned = static_rows()
        next(item for item in misaligned if item["name"] == "__environ")["value"] = "3"
        with mock.patch.object(evidence, "rows_for", side_effect=lambda _work, label:
                               imports if label == "object-symbols" else misaligned):
            with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "alignment"):
                evidence.observe(self.root, self.root / ".work", policy)

        alias_drift = static_rows()
        next(item for item in alias_drift if item["name"] == "timezone")["value"] = "0000000000007ff8"
        with mock.patch.object(evidence, "rows_for", side_effect=lambda _work, label:
                               imports if label == "object-symbols" else alias_drift):
            with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "alias"):
                evidence.observe(self.root, self.root / ".work", policy)

    def oracle_identity(self, work: Path) -> dict:
        oracle_dir = work / "qualification-oracle"
        oracle_dir.mkdir()
        files = {}
        for name in evidence.qualification.ORACLE_FILES:
            path = oracle_dir / name
            if name == "compiler_wrapper":
                path.write_bytes((ROOT / "docker/x86_64-musl-oracle-gcc").read_bytes())
            elif name == "source_manifest":
                pins = tomllib.loads((ROOT / "compat/upstreams.toml").read_text())["musl"]
                path.write_text(
                    "format=crabc-pinned-musl-oracle-v1\n"
                    + f"version={pins['version']}\nsource_sha256={pins['sha256']}\n"
                    + f"fallback_revision={pins['fallback_revision']}\narchitecture=x86_64\n",
                    encoding="utf-8",
                )
            elif name == "specs_manifest":
                path.write_text("placeholder\n", encoding="utf-8")
            else:
                path.write_bytes((name + "-retained").encode())
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        (oracle_dir / "specs_manifest").write_text(
            files["specs"] + "  /opt/musl-1.2.6/lib/musl-gcc.specs\n", encoding="utf-8"
        )
        files["specs_manifest"] = hashlib.sha256((oracle_dir / "specs_manifest").read_bytes()).hexdigest()
        return {
            "version": "musl-1.2.6", "runtime_sha256": files["runtime"],
            "compiler_wrapper_sha256": files["compiler_wrapper"],
            "pins_sha256": hashlib.sha256((ROOT / "compat/upstreams.toml").read_bytes()).hexdigest(),
            "files": files,
        }

    def test_host_oracle_replay_uses_retained_bytes_and_rejects_tamper(self) -> None:
        work_parent = ROOT / ".work/x86_64/public-data-ordinary-link-tests"
        with tempfile.TemporaryDirectory(dir=work_parent) as directory:
            work = Path(directory)
            oracle = self.oracle_identity(work)
            with mock.patch.object(evidence.qualification, "require_live_oracle",
                                   side_effect=AssertionError("host replay must not probe /opt")):
                evidence.validate_oracle_identity(work, oracle)
            (work / "qualification-oracle/runtime").write_bytes(b"changed")
            with self.assertRaises(evidence.qualification.QualificationError):
                evidence.validate_oracle_identity(work, oracle)


if __name__ == "__main__":
    unittest.main()
