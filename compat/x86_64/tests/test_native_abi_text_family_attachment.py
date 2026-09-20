#!/usr/bin/env python3
"""Regression guards for text-family semantic evidence attachment.

The selector may record the current immutable text component coordinator, but
that receipt is not permission to promote the planned family.  These tests use
the reader's public result shape so the attachment cannot quietly treat a
component receipt as a family-completion receipt.
"""
from __future__ import annotations

import json
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
        self.receipt = self.work / "receipt.json"
        self.source = {"revision": "a" * 40, "content_sha256": "b" * 64, "clean": True}
        self.receipt.write_text(json.dumps(self._record(), sort_keys=True) + "\n", encoding="utf-8")

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
                "family_execution": {"path": ".work/posix/receipt.json"},
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

    def _reader(self, *, mutate_output: bool = False):
        receipt = self.receipt

        def validate_receipt(root: Path, supplied: Path) -> dict[str, object]:
            self.assertEqual(root, ROOT)
            self.assertEqual(supplied, receipt.relative_to(ROOT))
            observed = json.loads(receipt.read_text(encoding="utf-8"))
            if mutate_output:
                receipt.write_text('{"changed":true}\n', encoding="utf-8")
            return observed

        return SimpleNamespace(
            SCHEMA=text_family.SCHEMA,
            FAMILY=text_family.FAMILY,
            CAPABILITIES=text_family.CAPABILITIES,
            COMPONENTS=text_family.COMPONENTS,
            PAIRS=text_family.PAIRS,
            PAIR_MODES=text_family.PAIR_MODES,
            ROSTER_PATH=text_family.ROSTER_PATH,
            validate_receipt=validate_receipt,
        )

    def _adapter(self, *, mutate_output: bool = False) -> dict[str, object]:
        with mock.patch.object(selection, "_text_family_reader", return_value=self._reader(mutate_output=mutate_output)):
            companion = selection.text_family_semantic_adapter(self.receipt, source=self.source)
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

        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        blockers, evidence = selection.family_semantic_evidence(
            inputs["families"], headers_layouts_companion=None, text_family_companion=companion,
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
                    selection.text_family_semantic_adapter(self.receipt, source=self.source)

    def test_adapter_rejects_a_receipt_changed_during_reader_replay(self) -> None:
        with mock.patch.object(selection, "_text_family_reader", return_value=self._reader(mutate_output=True)), \
                self.assertRaisesRegex(selection.SelectionError, "changed during validation"):
            selection.text_family_semantic_adapter(self.receipt, source=self.source)

    def test_final_recheck_rejects_a_changed_component_receipt(self) -> None:
        companion = self._adapter()
        changed = self._record()
        changed["inputs"]["request"] = {"path": ".work/changed-request.json"}
        self.receipt.write_text(json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8")
        with mock.patch.object(selection, "_text_family_reader", return_value=self._reader()), \
                self.assertRaisesRegex(selection.SelectionError, "changed during final recheck"):
            selection._recheck_text_family_semantics(companion, source=self.source)


if __name__ == "__main__":
    unittest.main()
