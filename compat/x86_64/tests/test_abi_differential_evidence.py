"""Evidence-set binding for the compat.abi-differential gate.

These cases cover the set's own contract: it binds exactly one current source
revision, its products and report bytes, and the gate reads each leaf result
separately. Leaf replays themselves belong to the leaf readers' tests.
"""

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import abi_differential_evidence as evidence  # noqa: E402
import qualification_gates  # noqa: E402

SOURCE = {"revision": "1" * 40, "content_sha256": "2" * 64}


class AbiDifferentialEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        parent = evidence.ROOT / ".work" / "x86_64" / "tmp"
        parent.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(dir=parent))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.work))
        for name in ("static", "dynamic"):
            (self.work / name).mkdir()
        (self.work / "preparation.json").write_text(json.dumps({"source": SOURCE}))
        relative = self.work.relative_to(evidence.ROOT).as_posix()
        self.reports = {}
        for name in evidence.REPORTS:
            path = self.work / f"{name}.json"
            path.write_text(name)
            self.reports[name] = path
        self.record = {
            "schema": evidence.SCHEMA,
            "source": SOURCE,
            "inputs": {
                "static_product": f"{relative}/static",
                "static_preparation": f"{relative}/preparation.json",
                "dynamic_product": f"{relative}/dynamic",
            },
            "reports": {
                name: {"path": f"{relative}/{name}.json", "sha256": evidence._sha256(path)}
                for name, path in self.reports.items()
            },
        }
        self.receipt = self.work / evidence.RECEIPT_NAME
        patcher = mock.patch.object(evidence, "current_source", return_value=dict(SOURCE))
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self) -> Path:
        self.receipt.write_text(json.dumps(self.record))
        return self.receipt

    def test_current_set_loads_with_resolved_products_and_reports(self) -> None:
        loaded = evidence.load(self.write())
        self.assertEqual(loaded.inputs["dynamic_product"], self.work / "dynamic")
        self.assertEqual(set(loaded.reports), set(evidence.REPORTS))
        self.assertEqual(len(evidence.LEAF_READERS), 5)

    def test_set_from_another_product_source_is_stale(self) -> None:
        self.record["source"] = {"revision": "1" * 40, "content_sha256": "3" * 64}
        with self.assertRaisesRegex(evidence.EvidenceError, "assembled from product source"):
            evidence.load(self.write())

    def test_set_sealed_at_another_revision_with_the_same_products_loads(self) -> None:
        self.record["source"] = {"revision": "3" * 40, "content_sha256": "2" * 64}
        (self.work / "preparation.json").write_text(
            json.dumps({"source": {"revision": "4" * 40, "content_sha256": "2" * 64}}))
        self.assertEqual(evidence.load(self.write()).inputs["dynamic_product"], self.work / "dynamic")

    def test_products_from_another_revision_are_stale(self) -> None:
        (self.work / "preparation.json").write_text(json.dumps({"source": {"revision": "4" * 40}}))
        with self.assertRaisesRegex(evidence.EvidenceError, "static preparation"):
            evidence.load(self.write())

    def test_changed_report_bytes_are_rejected(self) -> None:
        self.write()
        self.reports["native_abi_ratchet"].write_text("replaced")
        with self.assertRaisesRegex(evidence.EvidenceError, "changed after assembly"):
            evidence.load(self.receipt)

    def test_leaf_rejection_is_that_row_only(self) -> None:
        self.write()

        def reject(_set: object) -> str:
            raise evidence.EvidenceError("floor regressed")

        readers = {name: (lambda _set: "ok") for name in evidence.LEAF_READERS}
        readers["native_abi_ratchet"] = reject
        with mock.patch.object(evidence, "LEAF_READERS", readers):
            results = evidence.validate_receipt(evidence.ROOT, self.receipt)["results"]
        self.assertFalse(results["native_abi_ratchet"]["met"])
        self.assertIn("floor regressed", results["native_abi_ratchet"]["detail"])
        self.assertTrue(all(result["met"] for name, result in results.items() if name != "native_abi_ratchet"))

    def test_assembly_binds_the_five_retained_leaves(self) -> None:
        import native_abi_ratchet

        output = evidence.OUTPUT_PARENT / f"assemble-test-{self.work.name}"
        self.addCleanup(lambda: __import__("shutil").rmtree(output, ignore_errors=True))
        arguments = argparse.Namespace(
            static_product=self.work / "static",
            static_preparation=self.work / "preparation.json",
            dynamic_product=self.work / "dynamic",
            native_abi_inventory=self.reports["native_abi_inventory"],
            native_abi_elf_facts=self.reports["native_abi_elf_facts"],
            header_declaration_inventory=self.reports["header_declaration_inventory"],
            public_data_ordinary_link=self.reports["public_data_ordinary_link"],
            output=output,
        )
        with mock.patch.object(native_abi_ratchet, "check",
                               return_value=self.reports["native_abi_ratchet"]):
            receipt = evidence.assemble(arguments)
        record = json.loads(receipt.read_text())
        self.assertEqual(record["schema"], "crabc.x86_64-abi-differential-evidence/v2")
        self.assertEqual(set(record), {"schema", "source", "inputs", "reports"})
        self.assertEqual(set(record["reports"]), set(evidence.REPORTS))
        self.assertEqual(evidence.load(receipt).reports["native_abi_ratchet"],
                         self.reports["native_abi_ratchet"])

    def test_every_gate_evidence_row_has_a_reader(self) -> None:
        families = qualification_gates.load_families()
        commands = [entry["command"] for entry in families["compat.abi-differential"]["native_evidence"]]
        for command in commands:
            self.assertIn(("compat.abi-differential", command), qualification_gates.READERS)
        self.assertEqual(
            set(qualification_gates.ABI_EVIDENCE_ROWS.values()), set(evidence.LEAF_READERS),
        )


if __name__ == "__main__":
    unittest.main()
