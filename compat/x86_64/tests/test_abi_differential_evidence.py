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
            "selection_companions": {},
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
        self.assertNotIn("ordinary_link_report", loaded.selection_arguments())

    def test_set_from_another_revision_is_stale(self) -> None:
        self.record["source"] = {"revision": "3" * 40, "content_sha256": "2" * 64}
        with self.assertRaisesRegex(evidence.EvidenceError, "assembled at"):
            evidence.load(self.write())

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

    def cohort(self) -> "evidence.Cohort":
        return evidence.Cohort(
            static_product=self.work / "static", dynamic_product=self.work / "dynamic",
            static_preparation=self.work / "preparation.json",
            **{name: self.reports[name] for name in evidence.COLLECTED_REPORTS},
        )

    def test_ordinary_declaration_producer_uses_the_selected_static_and_dynamic_products(self) -> None:
        producer = next(row for row in evidence.PRODUCERS if row.keyword == "ordinary_declaration_abi_report")
        argv, environment = producer.command(self.cohort(), {}, self.work / "declarations")
        self.assertEqual(argv[argv.index("--static-product") + 1], str(self.work / "static"))
        self.assertEqual(argv[argv.index("--dynamic-product") + 1], str(self.work / "dynamic"))
        self.assertNotIn("--static-preparation", argv)
        self.assertEqual(environment, {})

    def producer(self, keyword: str, *, fails: bool = False, requires: tuple[str, ...] = ()) -> "evidence.CompanionProducer":
        def command(_cohort, reports, output):
            for name in requires:
                assert reports[name].is_file()
            script = "import sys, pathlib; o = pathlib.Path(sys.argv[1]); o.mkdir(); (o / 'report.json').write_text('r')"
            return ([sys.executable, "-c", script + ("; sys.exit(3)" if fails else ""), str(output)], {})
        return evidence.CompanionProducer(keyword, command, evidence._in, requires=requires)

    def collect(self, producers) -> dict:
        output = evidence.OUTPUT_PARENT / f"companions-test-{self.work.name}"
        self.addCleanup(lambda: __import__("shutil").rmtree(output, ignore_errors=True))
        with mock.patch.object(evidence, "PRODUCERS", producers):
            manifest = evidence.collect_companions(self.cohort(), output)
        return manifest, json.loads(manifest.read_text())

    def test_collection_binds_produced_companions_for_its_cohort(self) -> None:
        manifest, record = self.collect((
            self.producer("loader_debug_report"),
            self.producer("pthread_alias_contract_report", requires=("loader_debug_report",)),
        ))
        self.assertEqual(record["outcomes"]["pthread_alias_contract_report"]["status"], "produced")
        self.assertEqual(record["outcomes"]["text_family_semantic_report"]["status"], "family-flow")
        companions = evidence.load_companions(manifest, self.cohort())
        self.assertEqual(set(companions), {"loader_debug_report", "pthread_alias_contract_report",
                                           *evidence.SOURCE_COMPANIONS})
        self.assertEqual(companions["headers_layouts_aggregate_report"],
                         evidence.ROOT / evidence.SOURCE_COMPANIONS["headers_layouts_aggregate_report"])

    def test_failed_producer_and_its_dependents_are_never_bound(self) -> None:
        manifest, record = self.collect((
            self.producer("loader_debug_report", fails=True),
            self.producer("pthread_alias_contract_report", requires=("loader_debug_report",)),
            self.producer("crt_startup_report"),
        ))
        self.assertEqual(record["outcomes"]["loader_debug_report"]["status"], "failed")
        self.assertEqual(record["outcomes"]["pthread_alias_contract_report"],
                         {"status": "blocked", "requires": ["loader_debug_report"]})
        self.assertEqual(set(evidence.load_companions(manifest, self.cohort())),
                         {"crt_startup_report", *evidence.SOURCE_COMPANIONS})

    def test_manifest_for_another_cohort_or_changed_bytes_is_rejected(self) -> None:
        manifest, record = self.collect((self.producer("crt_startup_report"),))
        other = self.cohort().__class__(**{**self.cohort().__dict__, "dynamic_product": self.work / "static"})
        with self.assertRaisesRegex(evidence.EvidenceError, "another cohort"):
            evidence.load_companions(manifest, other)
        (evidence.ROOT / record["companions"]["crt_startup_report"]["path"]).write_text("replaced")
        with self.assertRaisesRegex(evidence.EvidenceError, "changed after collection"):
            evidence.load_companions(manifest, self.cohort())

    def test_fchdir_work_directory_is_collected_and_forwarded(self) -> None:
        def command(_cohort, _reports, output):
            script = ("import pathlib, sys; o = pathlib.Path(sys.argv[1]); o.mkdir(); "
                      "(o / 'report.json').write_text('receipt'); (o / 'workload.o').write_bytes(b'object')")
            return [sys.executable, "-c", script, str(output)], {}

        producer = evidence.CompanionProducer("fchdir_ordinary_import_work", command, lambda output: output)
        with mock.patch.object(evidence, "_validate_fchdir_work") as validate, mock.patch.object(evidence, "PRODUCERS", (producer,)):
            manifest, record = self.collect((producer,))
            self.assertEqual(record["outcomes"]["fchdir_ordinary_import_work"]["status"], "produced")
            work = evidence.load_companions(manifest, self.cohort())["fchdir_ordinary_import_work"]
            self.assertTrue(work.is_dir())
            (work / "workload.o").write_bytes(b"changed")
            with self.assertRaisesRegex(evidence.EvidenceError, "changed after collection"):
                evidence.load_companions(manifest, self.cohort())
            (work / "workload.o").write_bytes(b"object")
            self.record["selection_companions"] = {
                "fchdir_ordinary_import_work": record["companions"]["fchdir_ordinary_import_work"]}
            self.assertEqual(evidence.load(self.write()).selection_arguments()["fchdir_ordinary_import_work"], work)
        validate.assert_called_with(work, static_product=self.work / "static", dynamic_product=self.work / "dynamic")

    def test_fchdir_work_seal_rejects_changed_content_and_symlinks(self) -> None:
        work = self.work / "fchdir"
        work.mkdir()
        (work / "report.json").write_text("receipt")
        (work / "workload.o").write_bytes(b"object")
        self.record["selection_companions"]["fchdir_ordinary_import_work"] = {
            "path": work.relative_to(evidence.ROOT).as_posix(),
            "sha256": evidence._companion_sha256("fchdir_ordinary_import_work", work),
        }
        with mock.patch.object(evidence, "_validate_fchdir_work"):
            self.assertIn("fchdir_ordinary_import_work", evidence.load(self.write()).companions)
            (work / "workload.o").write_bytes(b"changed")
            with self.assertRaisesRegex(evidence.EvidenceError, "changed after assembly"):
                evidence.load(self.write())
            (work / "workload.o").write_bytes(b"object")
            (work / "escaped").symlink_to(self.reports["native_abi_ratchet"])
            with self.assertRaisesRegex(evidence.EvidenceError, "non-physical entry"):
                evidence.load(self.write())

    def test_fchdir_work_replays_receipt_against_selected_products(self) -> None:
        work = self.work / "fchdir"
        work.mkdir()
        (work / "report.json").write_text("receipt")
        self.record["selection_companions"]["fchdir_ordinary_import_work"] = {
            "path": work.relative_to(evidence.ROOT).as_posix(),
            "sha256": evidence._companion_sha256("fchdir_ordinary_import_work", work),
        }
        with mock.patch.object(evidence.fchdir_import_receipt, "validate_report", side_effect=ValueError("foreign products")) as reader:
            with self.assertRaisesRegex(evidence.EvidenceError, "foreign products"):
                evidence.load(self.write())
        reader.assert_called_once_with(work / "report.json", static_product=self.work / "static",
                                       dynamic_product=self.work / "dynamic")

    def test_assembly_forwards_fchdir_work_and_seals_it(self) -> None:
        import native_abi_ratchet
        import native_abi_selection

        work = self.work / "fchdir"
        work.mkdir()
        (work / "report.json").write_text("receipt")
        output = evidence.OUTPUT_PARENT / f"assemble-test-{self.work.name}"
        self.addCleanup(lambda: __import__("shutil").rmtree(output, ignore_errors=True))
        cohort = self.cohort()
        arguments = argparse.Namespace(**cohort.__dict__, output=output, companions=None,
                                       selection_companion=[f"fchdir_ordinary_import_work={work}"])

        def build_report(*, output, **kwargs):
            self.assertEqual(kwargs["fchdir_ordinary_import_work"], work)
            output.mkdir()
            (output / "report.json").write_text("selection")

        with mock.patch.object(evidence, "_validate_fchdir_work") as validate, \
             mock.patch.object(native_abi_ratchet, "check", return_value=self.reports["native_abi_ratchet"]), \
             mock.patch.object(native_abi_selection, "build_report", side_effect=build_report):
            receipt = evidence.assemble(arguments)
        entry = json.loads(receipt.read_text())["selection_companions"]["fchdir_ordinary_import_work"]
        self.assertEqual(entry["path"], work.relative_to(evidence.ROOT).as_posix())
        self.assertEqual(entry["sha256"], evidence._companion_sha256("fchdir_ordinary_import_work", work))
        validate.assert_called_with(work, static_product=self.work / "static", dynamic_product=self.work / "dynamic")

    def test_provider_links_directory_is_forwarded_and_sealed_as_one_cohort(self) -> None:
        work = self.work / "provider-links"
        work.mkdir()
        (work / "report.json").write_text("receipt")
        (work / "providers.o").write_bytes(b"object")
        self.record["selection_companions"]["provider_link_work"] = {
            "path": work.relative_to(evidence.ROOT).as_posix(),
            "sha256": evidence._companion_sha256("provider_link_work", work),
        }
        self.assertEqual(evidence.load(self.write()).selection_arguments()["provider_link_work"], work)
        (work / "providers.o").write_bytes(b"changed")
        with self.assertRaisesRegex(evidence.EvidenceError, "changed after assembly"):
            evidence.load(self.write())

    def test_source_companion_must_be_its_fixed_source_report(self) -> None:
        name = "headers_layouts_aggregate_report"
        self.record["selection_companions"][name] = {
            "path": evidence.SOURCE_COMPANIONS[name],
            "sha256": evidence._sha256(evidence.ROOT / evidence.SOURCE_COMPANIONS[name]),
        }
        self.assertIn(name, evidence.load(self.write()).companions)
        self.record["selection_companions"][name]["path"] = self.reports["native_abi_ratchet"].relative_to(
            evidence.ROOT).as_posix()
        with self.assertRaisesRegex(evidence.EvidenceError, "must be its source report"):
            evidence.load(self.write())

    def test_every_companion_keyword_has_one_producer_or_named_owner(self) -> None:
        producers = [producer.keyword for producer in evidence.PRODUCERS]
        self.assertEqual(len(producers), len(set(producers)))
        owned = [*producers, *evidence.SOURCE_COMPANIONS, *evidence.FAMILY_FLOW_COMPANIONS]
        self.assertEqual(sorted(owned), sorted(evidence.SELECTION_COMPANIONS))
        order = {name: index for index, name in enumerate(producers)}
        for producer in evidence.PRODUCERS:
            self.assertTrue(all(order[name] < order[producer.keyword] for name in producer.requires))

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
