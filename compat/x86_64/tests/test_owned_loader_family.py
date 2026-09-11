"""Contract tests for installed native loader-family evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))

import owned_loader_family as family


SOURCE = "a" * 64
ORACLE = {
    "version": "musl-1.2.6",
    "runtime_sha256": "b" * 64,
    "compiler_wrapper_sha256": "c" * 64,
    "pins_sha256": "d" * 64,
    "files": {"runtime": "b" * 64},
}
READELF = {"path": "/opt/native-tools/readelf", "sha256": "e" * 64, "mode": 0o755}


class LoaderFamilyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/test-owned-loader-family"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.qualification_work = self.work / "qualification"
        self.qualification_work.mkdir()
        self.manifests = {product: (str(index + 1) * 64) for index, product in enumerate(family.PRODUCTS)}
        self.paths: dict[str, dict[str, Path]] = {}
        self.inventory_child_hashes: dict[str, str] = {}
        for product in family.PRODUCTS:
            (self.qualification_work / product).mkdir()
            directory = self.qualification_work / "qualification-cases" / product
            directory.mkdir(parents=True)
            for case in family.qualification.CASES:
                (directory / (case + ".json")).write_text("{}\n", encoding="utf-8")
            inputs = {}
            for field in ("receipt", "oracle_capture", "readelf_capture"):
                path = self.work / "inventories" / product / (field + ".json")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")
                inputs[field] = path
            raw_child = inputs["receipt"].parent / (inputs["receipt"].name + ".raw/candidate-loader.header.txt")
            raw_child.parent.mkdir(parents=True)
            raw_child.write_text(product + " raw readelf stream\n", encoding="utf-8")
            self.inventory_child_hashes[product] = family._digest(raw_child, "fixture inventory raw stream")
            self.paths[product] = inputs
        preparation = self.qualification_work / "qualification-prepare.json"
        preparation.write_text(json.dumps({
            "schema": family.qualification.SCHEMA,
            "source_sha256": SOURCE,
            "log": ".work/ignored.log",
            "log_sha256": "f" * 64,
            "oracle": ORACLE,
            "checks": [],
            "exit_status": 0,
        }), encoding="utf-8")
        cases = {}
        for product in family.PRODUCTS:
            for case in family.qualification.CASES:
                path = self.qualification_work / "qualification-cases" / product / (case + ".json")
                identity = family._identity(ROOT, path, "fixture qualification case")
                cases[identity["path"]] = identity["sha256"]
        preparation_identity = family._identity(ROOT, preparation, "fixture preparation")
        self.qualification = {
            "schema": family.qualification.SCHEMA,
            "status": "qualified-pending-review",
            "work": self.qualification_work.relative_to(ROOT).as_posix(),
            "source_sha256": SOURCE,
            "contracts": {},
            "products": self.manifests,
            "preparation": {preparation_identity["path"]: preparation_identity["sha256"]},
            "cases": cases,
            "base_evidence": {},
            "archives": {},
            "runtime_v1_published": False,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }
        self.qualification_path = self.qualification_work / "qualification.json"
        self.qualification_path.write_text("{}\n", encoding="utf-8")
        self.request_path = self.work / "request.json"
        self._write_request()
        self.product_override: str | None = None
        self.source_override: str | None = None
        self.oracle_override: object | None = None
        self.readelf_override: dict[str, object] | None = None
        self.mutate_input_during_inventory = False
        self.mutate_inventory_child_after_initial_validation = False
        self.qualification_validations = 0
        self.inventory_validations = {product: 0 for product in family.PRODUCTS}
        self.patchers = [
            patch.object(family.qualification, "source_digest", return_value=SOURCE),
            patch.object(family.qualification, "validate_receipt", side_effect=self._validate_qualification),
            patch.object(family.qualification, "validate_oracle", return_value={}),
            patch.object(family.inventory, "validate_receipt", side_effect=self._validate_inventory),
            patch.object(family.inventory, "supplied_oracle_capture", side_effect=self._oracle_capture),
            patch.object(family.inventory, "supplied_readelf_capture", side_effect=self._readelf_capture),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _write_request(self) -> None:
        self.request_path.write_text(json.dumps({
            "schema": family.SCHEMA,
            "qualification": self.qualification_path.relative_to(ROOT).as_posix(),
            "inventories": {
                product: {field: path.relative_to(ROOT).as_posix() for field, path in values.items()}
                for product, values in self.paths.items()
            },
        }), encoding="utf-8")

    def _oracle_capture(self, path: Path) -> dict[str, object]:
        identity = family._identity(ROOT, path, "fixture oracle capture")
        oracle = ORACLE if self.oracle_override is None else self.oracle_override
        return {**identity, "identity": {"oracle": oracle, "loader_alias": {}}}

    def _readelf_capture(self, path: Path) -> dict[str, object]:
        identity = family._identity(ROOT, path, "fixture readelf capture")
        readelf = READELF
        if self.readelf_override is not None and "second" in path.parts:
            readelf = self.readelf_override
        return {**identity, "identity": {"readelf": readelf}}

    def _validate_qualification(self, path: Path) -> dict[str, object]:
        self.qualification_validations += 1
        if path != self.qualification_path:
            raise family.qualification.QualificationError("fixture qualification path differs")
        for relative, expected in self.qualification["cases"].items():
            if family._identity(ROOT, ROOT / relative, "fixture qualification case")["sha256"] != expected:
                raise family.qualification.QualificationError("fixture qualification child differs")
        return self.qualification

    def _validate_inventory(self, receipt: Path, product_root: Path, oracle: Path, readelf: Path) -> dict[str, object]:
        product = product_root.name
        self.inventory_validations[product] += 1
        raw_child = receipt.parent / (receipt.name + ".raw/candidate-loader.header.txt")
        if family._digest(raw_child, "fixture inventory raw stream") != self.inventory_child_hashes[product]:
            raise family.inventory.InventoryError("fixture inventory raw stream differs")
        selected_product = self.product_override or product
        selected_root = self.qualification_work / selected_product
        oracle_capture = self._oracle_capture(oracle)
        readelf_capture = self._readelf_capture(readelf)
        result = {
            "schema": family.inventory.SCHEMA,
            "component": "native-x86-loader-inventory",
            "inventory_complete": True,
            "runtime_test_executed": False,
            "runtime_verified": False,
            "capture": {
                "before": {
                    "product": {
                        "root": selected_root.relative_to(ROOT).as_posix(),
                        "manifest_sha256": self.manifests[selected_product],
                    },
                    "source": {"source_sha256": self.source_override or SOURCE},
                    "oracle": oracle_capture,
                    "readelf": readelf_capture,
                },
                "after": {
                    "product": {
                        "root": selected_root.relative_to(ROOT).as_posix(),
                        "manifest_sha256": self.manifests[selected_product],
                    },
                    "source": {"source_sha256": self.source_override or SOURCE},
                    "oracle": oracle_capture,
                    "readelf": readelf_capture,
                },
            },
        }
        if self.mutate_input_during_inventory:
            self.mutate_input_during_inventory = False
            receipt.write_text('{"changed-during-collection":true}\n', encoding="utf-8")
        if (self.mutate_inventory_child_after_initial_validation and product == "extracted"
                and self.inventory_validations[product] == 1):
            self.mutate_inventory_child_after_initial_validation = False
            installed = self.paths["installed"]["receipt"]
            (installed.parent / (installed.name + ".raw/candidate-loader.header.txt")).write_text(
                "changed raw readelf stream\n", encoding="utf-8",
            )
        return result

    def test_component_declares_the_four_loader_capabilities(self) -> None:
        self.assertEqual(
            family.CAPABILITIES,
            (
                "runtime.loader",
                "runtime.private-facades",
                "loader.dlfcn-basic",
                "loader.dlfcn-introspection",
            ),
        )

    def test_roster_keeps_all_four_capabilities_and_current_frozen_catalogs(self) -> None:
        roster = family.load_roster()
        self.assertEqual([entry["id"] for entry in roster["required"]], [row[0] for row in family.EXPECTED_ROWS])
        synthetic = next(row for row in roster["required"] if row["id"] == "synthetic-loader-catalog")
        corpus = next(row for row in roster["required"] if row["id"] == "frozen-package-corpus")
        self.assertEqual(tuple(synthetic["synthetic_cases"]), tuple(family.corpus_evidence.LOADER_CASES))
        self.assertEqual(tuple(corpus["package_cases"]), tuple(case.id for case in family.corpus_evidence._corpus_cases()))

    def test_roster_rejects_reordered_or_omitted_frozen_catalog(self) -> None:
        text = family.ROSTER_PATH.read_text(encoding="utf-8")
        reordered = self.work / "reordered.toml"
        reordered.write_text(text.replace('"nested-needed", "nested-dlopen"', '"nested-dlopen", "nested-needed"', 1), encoding="utf-8")
        with self.assertRaisesRegex(family.LoaderFamilyError, "synthetic catalog"):
            family.load_roster(reordered)
        omitted = self.work / "omitted.toml"
        omitted.write_text(text.replace(', "weak-strong",\n]', ',\n]', 1), encoding="utf-8")
        with self.assertRaisesRegex(family.LoaderFamilyError, "synthetic catalog"):
            family.load_roster(omitted)

    def test_request_rejects_missing_product_unknown_field_and_duplicate_json_key(self) -> None:
        request = json.loads(self.request_path.read_text(encoding="utf-8"))
        missing = copy.deepcopy(request)
        del missing["inventories"]["extracted"]
        with self.assertRaisesRegex(family.LoaderFamilyError, "product roster"):
            family.validate_request(ROOT, missing)
        extra = copy.deepcopy(request)
        extra["inventories"]["installed"]["product"] = "wrong"
        with self.assertRaisesRegex(family.LoaderFamilyError, "request fields"):
            family.validate_request(ROOT, extra)
        duplicate = self.work / "duplicate.json"
        duplicate.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
        with self.assertRaisesRegex(family.LoaderFamilyError, "repeats"):
            family._read(ROOT, duplicate, "duplicate request")
        duplicate_inventory = self.work / "duplicate-inventory.json"
        duplicate_inventory.write_text(
            '{"schema":"' + family.SCHEMA + '","qualification":"' + self.qualification_path.relative_to(ROOT).as_posix()
            + '","inventories":{"installed":{},"installed":{}}}', encoding="utf-8",
        )
        with self.assertRaisesRegex(family.LoaderFamilyError, "repeats"):
            family._read(ROOT, duplicate_inventory, "duplicate inventory request")

    def test_roster_rejects_a_valid_case_redirected_away_from_the_non_pie_mode(self) -> None:
        text = family.ROSTER_PATH.read_text(encoding="utf-8")
        redirected = self.work / "redirected.toml"
        redirected.write_text(
            text.replace(
                'qualification_cases = ["elf-scope-alias", "lazy-pie", "lazy-non-pie", "loader-synthetic"]',
                'qualification_cases = ["elf-scope-alias", "lazy-pie", "loader-synthetic"]',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(family.LoaderFamilyError, "qualification behavior map"):
            family.load_roster(redirected)

    def test_roster_rejects_a_duplicate_required_mode_or_catalog_case(self) -> None:
        text = family.ROSTER_PATH.read_text(encoding="utf-8")
        duplicate_mode = self.work / "duplicate-mode.toml"
        duplicate_mode.write_text(
            text.replace(
                'qualification_cases = ["elf-scope-alias", "lazy-pie", "lazy-non-pie", "loader-synthetic"]',
                'qualification_cases = ["elf-scope-alias", "lazy-pie", "lazy-pie", "lazy-non-pie", "loader-synthetic"]',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(family.LoaderFamilyError, "repeats a case"):
            family.load_roster(duplicate_mode)
        duplicate_case = self.work / "duplicate-case.toml"
        duplicate_case.write_text(
            text.replace('"nested-needed", "nested-dlopen"', '"nested-needed", "nested-needed", "nested-dlopen"', 1),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(family.LoaderFamilyError, "repeats a case"):
            family.load_roster(duplicate_case)

    def test_collect_binds_all_three_products_and_reconstructs_immutable_receipt(self) -> None:
        report = family.collect(ROOT, self.work)
        self.assertEqual(self.qualification_validations, 2)
        self.assertEqual(self.inventory_validations, {product: 2 for product in family.PRODUCTS})
        self.assertEqual(report["tools"]["before"], READELF)
        self.assertEqual(report["oracle"], ORACLE)
        self.assertEqual(set(report["coverage"]), {row[0] for row in family.EXPECTED_ROWS})
        self.assertEqual(report["coverage"]["frozen-package-corpus"]["package_cases"], list(family._corpus_cases()))
        path = family.execute(ROOT, self.work)
        self.assertEqual(path.name, "receipt.json")
        self.assertFalse(path.stat().st_mode & 0o222)
        self.assertEqual(family.validate_receipt(ROOT, path), report)

    def test_collect_rejects_a_missing_current_qualification_case(self) -> None:
        key = next(iter(self.qualification["cases"]))
        del self.qualification["cases"][key]
        with self.assertRaisesRegex(family.LoaderFamilyError, "complete current case roster"):
            family.collect(ROOT, self.work)

    def test_collect_rejects_inventory_for_another_product_or_source(self) -> None:
        self.product_override = "second"
        with self.assertRaisesRegex(family.LoaderFamilyError, "another qualification product"):
            family.collect(ROOT, self.work)
        self.product_override = None
        self.source_override = "f" * 64
        with self.assertRaisesRegex(family.LoaderFamilyError, "source differs"):
            family.collect(ROOT, self.work)

    def test_collect_rejects_oracle_and_cross_product_readelf_tampering(self) -> None:
        self.oracle_override = {**ORACLE, "runtime_sha256": "0" * 64}
        with self.assertRaisesRegex(family.LoaderFamilyError, "oracle differs"):
            family.collect(ROOT, self.work)
        self.oracle_override = None
        self.readelf_override = {**READELF, "sha256": "0" * 64}
        with self.assertRaisesRegex(family.LoaderFamilyError, "different readelf"):
            family.collect(ROOT, self.work)

    def test_collect_rejects_changed_sealed_qualification_case_input(self) -> None:
        path = self.qualification_work / "qualification-cases/installed/cycle.json"
        path.write_text('{"changed":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(family.LoaderFamilyError, "dynamic qualification differs"):
            family.collect(ROOT, self.work)

    def test_collect_revalidates_a_transitive_qualification_child_at_the_end(self) -> None:
        child = self.qualification_work / "qualification-cases/installed/account-files.json"
        initial_receipt = self.qualification_path.read_bytes()
        expected_calls = len(family.PRODUCTS) * sum(len(cases) for _, _, cases in family.EXPECTED_ROWS)
        calls = 0
        original = family._qualification_case_identity

        def mutate_after_initial_coverage(*args: object) -> dict[str, object]:
            nonlocal calls
            result = original(*args)
            calls += 1
            if calls == expected_calls:
                child.write_text('{"changed-after-initial-validation":true}\n', encoding="utf-8")
            return result

        with patch.object(family, "_qualification_case_identity", side_effect=mutate_after_initial_coverage):
            with self.assertRaisesRegex(family.LoaderFamilyError, "dynamic qualification differs"):
                family.collect(ROOT, self.work)
        self.assertEqual(calls, expected_calls)
        self.assertEqual(self.qualification_path.read_bytes(), initial_receipt)
        self.assertGreaterEqual(self.qualification_validations, 2)

    def test_collect_revalidates_a_transitive_inventory_child_at_the_end(self) -> None:
        initial_receipt = self.paths["installed"]["receipt"].read_bytes()
        self.mutate_inventory_child_after_initial_validation = True
        with self.assertRaisesRegex(family.LoaderFamilyError, "installed inventory differs"):
            family.collect(ROOT, self.work)
        self.assertEqual(self.paths["installed"]["receipt"].read_bytes(), initial_receipt)
        self.assertEqual(self.inventory_validations["installed"], 2)
        self.assertEqual(self.inventory_validations["second"], 1)
        self.assertEqual(self.inventory_validations["extracted"], 1)

    def test_collect_rejects_an_inventory_input_changed_after_its_preimage(self) -> None:
        self.mutate_input_during_inventory = True
        with self.assertRaisesRegex(family.LoaderFamilyError, "input changed during loader family collection"):
            family.collect(ROOT, self.work)

    def test_collect_rejects_a_promoting_prerequisite_or_promoted_report(self) -> None:
        self.qualification["family_completion"] = True
        with self.assertRaisesRegex(family.LoaderFamilyError, "promotion boundary"):
            family.collect(ROOT, self.work)
        self.qualification["family_completion"] = False
        path = family.execute(ROOT, self.work)
        path.chmod(0o644)
        report = json.loads(path.read_text(encoding="utf-8"))
        report["public_support"] = True
        path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(family.LoaderFamilyError, "receipt changed"):
            family.validate_receipt(ROOT, path)

    def test_validate_receipt_rejects_json_scalar_aliases(self) -> None:
        path = family.execute(ROOT, self.work)
        path.chmod(0o644)
        original = json.loads(path.read_text(encoding="utf-8"))
        for name, replacement in {
            "component_complete": 1,
            "family_completion": 0,
            "promotion_ready": 0,
            "public_support": 0,
        }.items():
            forged = copy.deepcopy(original)
            forged[name] = replacement
            path.write_text(json.dumps(forged, allow_nan=False), encoding="utf-8")
            with self.assertRaisesRegex(family.LoaderFamilyError, "receipt changed"):
                family.validate_receipt(ROOT, path)
        forged = copy.deepcopy(original)
        forged["request"]["before"]["size"] = float(forged["request"]["before"]["size"])
        path.write_text(json.dumps(forged, allow_nan=False), encoding="utf-8")
        with self.assertRaisesRegex(family.LoaderFamilyError, "receipt changed"):
            family.validate_receipt(ROOT, path)

    def test_read_rejects_nonfinite_json_constants(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            path = self.work / (constant.replace("-", "negative-") + ".json")
            path.write_text('{"number":' + constant + '}', encoding="utf-8")
            with self.assertRaisesRegex(family.LoaderFamilyError, "non-finite JSON constant"):
                family._read(ROOT, path, "nonfinite fixture")


if __name__ == "__main__":
    unittest.main()
