#!/usr/bin/env python3
"""Regression guards for text-family semantic evidence attachment.

The selector may record the current immutable text component coordinator, but
that receipt is not permission to promote the planned family.  These tests use
the reader's public result shape so the attachment cannot quietly treat a
component receipt as a family-completion receipt.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_abi_selection as selection
import owned_text_math_locale_stdio_family as text_family


class TextFamilySemanticAttachmentTests(unittest.TestCase):
    """Bind a replayed component receipt without changing family admission."""

    def setUp(self) -> None:
        common_checkout = mock.patch.object(selection, "_common_checkout", return_value=ROOT)
        common_checkout.start()
        self.addCleanup(common_checkout.stop)
        parent = ROOT / ".work/x86_64/native-abi-text-family-attachment-tests"
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.static_preparation = self.work / "static/preparation.json"
        self.dynamic_qualification = self.work / "dynamic/qualification.json"
        self.static_product = self.work / "static/products/primary"
        self.dynamic_product = self.work / "dynamic/products/primary"
        self.alternate_static_product = self.work / "alternate/static"
        self.alternate_dynamic_product = self.work / "alternate/dynamic"
        for product, manifest in (
                (self.static_product, "static-primary"),
                (self.dynamic_product, "dynamic-primary"),
                (self.alternate_static_product, "static-alternate"),
                (self.alternate_dynamic_product, "dynamic-alternate")):
            path = product / "share/crabc/manifest.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(manifest + "\n", encoding="utf-8")
        self.static_preparation.parent.mkdir(parents=True, exist_ok=True)
        self.dynamic_qualification.parent.mkdir(parents=True, exist_ok=True)
        self.static_preparation.write_text('{"static":"preparation"}\n', encoding="utf-8")
        self.dynamic_qualification.write_text('{"dynamic":"qualification"}\n', encoding="utf-8")
        self.request = self.work / "posix/request.json"
        self.request.parent.mkdir(parents=True, exist_ok=True)
        self.request.write_text('{"request":"matrix"}\n', encoding="utf-8")
        self.matrix = self.work / "posix/execution.json"
        self.receipt = self.work / "receipt.json"
        self.source = {"revision": "a" * 40, "content_sha256": "b" * 64, "clean": True}
        self.paths = {
            "static_preparation": self.static_preparation,
            "static_product": self.static_product,
            "dynamic_product": self.dynamic_product,
        }
        self.matrix.write_text(json.dumps({
            "inputs": self._family_inputs(), "request": self._family_identity(self.request),
        }, sort_keys=True) + "\n", encoding="utf-8")
        self.receipt.write_text(json.dumps(self._record(), sort_keys=True) + "\n", encoding="utf-8")

    def _family_identity(self, path: Path) -> dict[str, object]:
        return {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }

    def _family_inputs(self) -> dict[str, object]:
        return {
            "static_preparation": self._family_identity(self.static_preparation),
            "dynamic_qualification": self._family_identity(self.dynamic_qualification),
            "source": {key: self.source[key] for key in ("revision", "content_sha256")},
        }

    def _record(self) -> dict[str, object]:
        coordinator_source = {key: self.source[key] for key in ("revision", "content_sha256")}
        components = {}
        for name, specification in text_family.COMPONENTS.items():
            components[name] = {
                "scope": list(specification.scope),
                "credits": list(specification.credits),
                "pairs": {
                    pair: {"modes": list(text_family.PAIR_MODES), "rows": {row: {} for row in specification.rows}}
                    for pair in text_family.PAIRS
                },
            }
        return {
            "schema": text_family.SCHEMA,
            "status": "immutable-component-coordination-verified",
            "family": text_family.FAMILY,
            "capabilities": list(text_family.CAPABILITIES),
            "inputs": {
                "request": {"path": ".work/request.json"},
                "family_execution": self._family_identity(self.matrix),
                "pthread_family": {"path": ".work/pthread/receipt.json"},
                "source_before": coordinator_source,
                "source_after": coordinator_source,
                "roster": selection.selecting_source_file_identity(text_family.ROSTER_PATH),
            },
            "components": components,
            "component_complete": False,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }

    def _reader(self, *, mutate_output: bool = False, product_pairs: dict[str, dict[str, Path]] | None = None):
        receipt = self.receipt
        pairs = product_pairs or {
            "primary": {"static": self.static_product, "dynamic": self.dynamic_product},
        }

        def validate_receipt(root: Path, supplied: Path) -> dict[str, object]:
            self.assertEqual(root, ROOT)
            self.assertEqual(supplied, receipt.relative_to(ROOT))
            observed = json.loads(receipt.read_text(encoding="utf-8"))
            if mutate_output:
                receipt.write_text('{"changed":true}\n', encoding="utf-8")
            return observed

        def validate_matrix(root: Path, supplied: Path) -> dict[str, object]:
            self.assertEqual(root, ROOT)
            self.assertEqual(supplied, self.matrix)
            return {"inputs": self._family_inputs(), "request": self._family_identity(self.request)}

        def read_matrix_request(supplied: Path) -> dict[str, object]:
            self.assertEqual(supplied, self.request)
            return json.loads(self.request.read_text(encoding="utf-8"))

        def input_products(root: Path, request: dict[str, object]):
            self.assertEqual(root, ROOT)
            self.assertEqual(request, json.loads(self.request.read_text(encoding="utf-8")))
            return self._family_inputs(), pairs

        family = SimpleNamespace(
            validate_receipt=validate_matrix,
            file_identity=lambda root, path: self._family_identity(path),
            read=read_matrix_request,
            input_products=input_products,
        )
        return SimpleNamespace(
            SCHEMA=text_family.SCHEMA,
            FAMILY=text_family.FAMILY,
            CAPABILITIES=text_family.CAPABILITIES,
            COMPONENTS=text_family.COMPONENTS,
            PAIRS=text_family.PAIRS,
            PAIR_MODES=text_family.PAIR_MODES,
            ROSTER_PATH=text_family.ROSTER_PATH,
            validate_receipt=validate_receipt,
            family=family,
        )

    def _adapter(self, *, mutate_output: bool = False) -> dict[str, object]:
        with mock.patch.object(selection, "_text_family_reader", return_value=self._reader(mutate_output=mutate_output)):
            companion = selection.text_family_semantic_adapter(self.receipt, paths=self.paths, source=self.source)
        self.assertIsNotNone(companion)
        assert companion is not None
        return companion

    def test_replayed_component_receipt_attaches_only_semantic_availability(self) -> None:
        companion = self._adapter()
        self.assertEqual(companion["status"], "text-family-component-semantics-attached")
        self.assertEqual(companion["result"]["capabilities"], list(text_family.CAPABILITIES))
        self.assertFalse(companion["result"]["component_complete"])
        self.assertFalse(companion["result"]["family_completion"])
        self.assertFalse(companion["result"]["promotion_ready"])
        self.assertFalse(companion["result"]["public_support"])
        self.assertEqual(companion["product_cohort"]["static_preparation"],
                         self._family_identity(self.static_preparation))
        self.assertEqual(companion["product_cohort"]["primary"]["static"]["path"],
                         self.static_product.relative_to(ROOT).as_posix())
        self.assertEqual(companion["product_cohort"]["primary"]["dynamic"]["path"],
                         self.dynamic_product.relative_to(ROOT).as_posix())

        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        blockers, evidence = selection.family_semantic_evidence(
            inputs["families"], headers_layouts_companion=None, text_family_companion=companion,
            paths=self.paths,
        )
        self.assertNotIn(text_family.FAMILY, {row["family"] for row in blockers})
        self.assertEqual(evidence, [{
            "family": text_family.FAMILY,
            "status": "text-family-component-semantics-attached",
            "capabilities": list(text_family.CAPABILITIES),
            "requirements_discharged": ["family-semantic-evidence-unavailable"],
            "family_completion": False,
        }])
        family = next(row for row in inputs["families"] if row["id"] == text_family.FAMILY)
        self.assertEqual(family["status"], "planned")

    def test_receipt_rejects_completion_or_roster_substitution(self) -> None:
        cases = (
            ("completion", lambda record: record.__setitem__("family_completion", True), "completion"),
            ("capability", lambda record: record.__setitem__("capabilities", []), "differs"),
            ("pair", lambda record: record["components"]["math"]["pairs"].pop("primary"), "differs"),
        )
        for name, mutate, message in cases:
            with self.subTest(case=name):
                record = self._record()
                mutate(record)
                self.receipt.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
                with mock.patch.object(selection, "_text_family_reader", return_value=self._reader()), \
                        self.assertRaisesRegex(selection.SelectionError, message):
                    selection.text_family_semantic_adapter(self.receipt, paths=self.paths, source=self.source)

    def test_adapter_rejects_a_receipt_changed_during_reader_replay(self) -> None:
        with mock.patch.object(selection, "_text_family_reader", return_value=self._reader(mutate_output=True)), \
                self.assertRaisesRegex(selection.SelectionError, "changed during validation"):
            selection.text_family_semantic_adapter(self.receipt, paths=self.paths, source=self.source)

    def test_same_source_receipt_with_another_primary_product_cohort_is_rejected(self) -> None:
        alternate_pairs = {
            "primary": {"static": self.alternate_static_product, "dynamic": self.alternate_dynamic_product},
        }
        with mock.patch.object(selection, "_text_family_reader", return_value=self._reader(product_pairs=alternate_pairs)), \
                self.assertRaisesRegex(selection.SelectionError, "primary static product differs"):
            selection.text_family_semantic_adapter(self.receipt, paths=self.paths, source=self.source)

    def test_final_recheck_rejects_a_changed_component_receipt(self) -> None:
        companion = self._adapter()
        changed = self._record()
        changed["inputs"]["request"] = {"path": ".work/changed-request.json"}
        self.receipt.write_text(json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8")
        with mock.patch.object(selection, "_text_family_reader", return_value=self._reader()), \
                self.assertRaisesRegex(selection.SelectionError, "changed during final recheck"):
            selection._recheck_text_family_semantics(companion, paths=self.paths, source=self.source)


if __name__ == "__main__":
    unittest.main()
