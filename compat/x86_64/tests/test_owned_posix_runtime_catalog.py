"""The POSIX family catalog cannot omit frozen scope or manufacture evidence."""

from copy import deepcopy
from pathlib import Path
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_posix_runtime_catalog as catalog


class OwnedPosixRuntimeCatalogTests(unittest.TestCase):
    def setUp(self):
        self.document = tomllib.loads(catalog.CATALOG_PATH.read_text())
        self.expected = catalog.frozen_family_symbols()

    def validate(self):
        return catalog.validate_catalog(self.document, self.expected)

    def test_checked_catalog_accounts_for_all_selected_capabilities_without_qualification(self):
        result = self.validate()
        self.assertEqual(set(result.capabilities), set(self.expected))
        self.assertEqual(sum(len(row.symbols) for row in result.capabilities.values()), 149)
        self.assertEqual(len(result.static_cells), 6)
        self.assertEqual(len(result.dynamic_cells), 12)
        self.assertEqual(result.status, "proposal")

    def test_capability_or_spelling_omission_cannot_be_hidden_by_adjusting_counts(self):
        original = deepcopy(self.document)
        self.document["capability"].pop()
        self.document["capability_count"] -= 1
        with self.assertRaisesRegex(catalog.CatalogError, "capability roster"):
            self.validate()
        self.document = original
        self.document["capability"][0]["symbols"] = []
        self.document["symbol_count"] -= 1
        with self.assertRaisesRegex(catalog.CatalogError, "spelling roster"):
            self.validate()

    def test_duplicate_capability_or_spelling_is_rejected(self):
        original = deepcopy(self.document)
        self.document["capability"].append(deepcopy(self.document["capability"][0]))
        with self.assertRaisesRegex(catalog.CatalogError, "duplicate capability"):
            self.validate()
        self.document = original
        self.document["capability"][0]["symbols"] *= 2
        with self.assertRaisesRegex(catalog.CatalogError, "spelling roster"):
            self.validate()

    def test_each_product_mode_and_interpreter_entry_is_required(self):
        matrix = self.document["required_product_matrix"]
        for kind in ("static", "dynamic"):
            original = list(matrix[kind])
            for cell in original:
                with self.subTest(kind=kind, cell=cell):
                    matrix[kind] = [value for value in original if value != cell]
                    with self.assertRaisesRegex(catalog.CatalogError, "product matrix"):
                        self.validate()
            matrix[kind] = original

    def test_unregistered_or_duplicate_product_cannot_replace_extraction(self):
        for replacement in ("ambient:pie:kernel", "installed:pie:kernel"):
            with self.subTest(replacement=replacement):
                self.document["required_product_matrix"]["dynamic"][-1] = replacement
                with self.assertRaisesRegex(catalog.CatalogError, "product matrix"):
                    self.validate()

    def test_workload_omission_and_unknown_binding_are_rejected(self):
        original = deepcopy(self.document)
        self.document["required_workload"].pop()
        with self.assertRaisesRegex(catalog.CatalogError, "workload roster"):
            self.validate()
        self.document = original
        self.document["capability"][0]["closure_workloads"] = ["imagined-pass"]
        with self.assertRaisesRegex(catalog.CatalogError, "workload binding"):
            self.validate()

    def test_proposal_cannot_claim_runtime_completion(self):
        self.document["status"] = "verified"
        with self.assertRaisesRegex(catalog.CatalogError, "proposal"):
            self.validate()
        self.document["status"] = "proposal"
        self.document["family_completion"] = True
        with self.assertRaisesRegex(catalog.CatalogError, "catalog fields"):
            self.validate()

    def test_source_binding_cannot_escape_checkout_or_point_to_missing_source(self):
        for source in ("../STATUS.md", "libc/src/imagined-provider.rs"):
            with self.subTest(source=source):
                self.document["capability"][0]["source_bindings"] = [source]
                with self.assertRaisesRegex(catalog.CatalogError, "source binding"):
                    self.validate()


if __name__ == "__main__":
    unittest.main()
