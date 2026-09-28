"""Contract tests for the resolver family's six-root cohort join."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_resolver_family_cohort as cohort  # noqa: E402


class ResolverFamilyCohortTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="resolver-family-cohort-test.", dir=ROOT / ".work"))
        self.products = {
            label: {
                kind: self._product(label, kind)
                for kind in ("static", "dynamic")
            }
            for label in cohort.PAIRS
        }
        self.canonical = {
            label: {
                kind: {
                    "path": path.relative_to(ROOT).as_posix(),
                    "manifest": cohort._file_identity(ROOT, path / "share/crabc/manifest.json", f"{label} {kind}"),
                }
                for kind, path in values.items()
            }
            for label, values in self.products.items()
        }

    def tearDown(self) -> None:
        shutil.rmtree(self.work)

    def _product(self, label: str, kind: str) -> Path:
        product = self.work / label / kind
        manifest = product / "share/crabc/manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(f"{label}-{kind}\n", encoding="utf-8")
        return product

    def _relative(self, path: Path) -> str:
        return path.relative_to(ROOT).as_posix()

    def _component_products(self) -> dict[str, object]:
        pair = lambda label: {kind: self._relative(path) for kind, path in self.products[label].items()}
        return {
            "resolver-network-physical": {"primary": pair("primary"), "extracted": pair("extracted")},
            "classic-netdb": {"selected": pair("primary")},
            "resolver-alias-private-bodies": {"selected": pair("primary")},
            "resolver-cancellation": {"selected": pair("primary")},
            "protocol-database-product": {
                "primary": pair("primary"), "reproduction": pair("reproduction"), "extracted": pair("extracted"),
            },
        }

    def test_every_component_root_and_manifest_binds_to_one_canonical_pair(self) -> None:
        source = {"revision": "a" * 40, "content_sha256": "b" * 64,
                  "static_preparation": {"path": "receipt", "sha256": "c" * 64, "byte_length": 1, "mode": 0o444},
                  "dynamic_qualification": {"path": "receipt", "sha256": "d" * 64, "byte_length": 1, "mode": 0o444}}
        with mock.patch.object(cohort, "_canonical_products", return_value=(source, self.canonical)):
            report = cohort.validate(
                ROOT,
                static_preparation=self.work / "unused-static.json",
                dynamic_qualification=self.work / "unused-dynamic.json",
                component_products=self._component_products(),
            )

        self.assertEqual(report["schema"], cohort.SCHEMA)
        self.assertEqual(report["component_bindings"]["resolver-network-physical"]["primary"]["pair"], "primary")
        self.assertEqual(report["component_bindings"]["classic-netdb"]["selected"]["pair"], "primary")
        self.assertEqual(report["component_bindings"]["protocol-database-product"]["reproduction"]["pair"], "reproduction")
        self.assertFalse(report["family_completion"])

    def test_mixed_static_and_dynamic_roots_are_rejected(self) -> None:
        components = self._component_products()
        cancellation = components["resolver-cancellation"]
        assert isinstance(cancellation, dict)
        selected = cancellation["selected"]
        assert isinstance(selected, dict)
        selected["static"] = self._relative(self.products["extracted"]["static"])
        source = {"revision": "a" * 40, "content_sha256": "b" * 64,
                  "static_preparation": {"path": "receipt", "sha256": "c" * 64, "byte_length": 1, "mode": 0o444},
                  "dynamic_qualification": {"path": "receipt", "sha256": "d" * 64, "byte_length": 1, "mode": 0o444}}
        with mock.patch.object(cohort, "_canonical_products", return_value=(source, self.canonical)):
            with self.assertRaisesRegex(cohort.ResolverFamilyCohortError, "do not form one canonical"):
                cohort.validate(
                    ROOT,
                    static_preparation=self.work / "unused-static.json",
                    dynamic_qualification=self.work / "unused-dynamic.json",
                    component_products=components,
                )

    def test_single_pair_components_cannot_switch_to_another_cohort_arm(self) -> None:
        source = {"revision": "a" * 40, "content_sha256": "b" * 64,
                  "static_preparation": {"path": "receipt", "sha256": "c" * 64, "byte_length": 1, "mode": 0o444},
                  "dynamic_qualification": {"path": "receipt", "sha256": "d" * 64, "byte_length": 1, "mode": 0o444}}
        for identifier in ("classic-netdb", "resolver-alias-private-bodies", "resolver-cancellation"):
            with self.subTest(component=identifier):
                components = self._component_products()
                selected = components[identifier]
                assert isinstance(selected, dict)
                selected["selected"] = {
                    kind: self._relative(path)
                    for kind, path in self.products["extracted"].items()
                }
                with mock.patch.object(cohort, "_canonical_products", return_value=(source, self.canonical)):
                    with self.assertRaisesRegex(cohort.ResolverFamilyCohortError, "selected binds another canonical pair"):
                        cohort.validate(
                            ROOT,
                            static_preparation=self.work / "unused-static.json",
                            dynamic_qualification=self.work / "unused-dynamic.json",
                            component_products=components,
                        )

    def test_copied_dynamic_qualification_receipt_is_rejected(self) -> None:
        source = {"revision": "a" * 40, "content_sha256": "b" * 64}
        static_receipt = self.work / "static/preparation.json"
        static_receipt.parent.mkdir()
        static_receipt.write_text("{}\n", encoding="utf-8")
        prepared = {"source": source, "products": {}}
        for label, pair in self.products.items():
            manifest = cohort._file_identity(ROOT, pair["static"] / "share/crabc/manifest.json", label)
            prepared["products"][label] = {
                "path": self._relative(pair["static"]),
                "manifest": {"path": manifest["path"], "sha256": manifest["sha256"],
                             "size": manifest["byte_length"]},
            }

        dynamic_work = self.work / "dynamic-work"
        qualified = {"work": self._relative(dynamic_work), "source_sha256": source["content_sha256"],
                     "family_completion": False, "public_support": False, "products": {}}
        for label, dynamic_label in cohort.PAIRS.items():
            manifest = dynamic_work / dynamic_label / "share/crabc/manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(f"{label}-dynamic\n", encoding="utf-8")
            qualified["products"][dynamic_label] = cohort._file_identity(ROOT, manifest, label)["sha256"]
        receipt = dynamic_work / "qualification.json"
        receipt.write_text(json.dumps(qualified), encoding="utf-8")
        copied = self.work / "copied-qualification.json"
        shutil.copyfile(receipt, copied)

        with (mock.patch.object(cohort.static, "validate_receipt", return_value=prepared),
              mock.patch.object(cohort.static, "source_identity", return_value=source),
              mock.patch.object(cohort.static, "product_paths",
                                return_value={label: pair["static"] for label, pair in self.products.items()}),
              mock.patch.object(cohort.dynamic, "collect", return_value=qualified)):
            valid_source, valid_products = cohort.canonical_products(ROOT, static_receipt, receipt)
            self.assertEqual(valid_source["content_sha256"], source["content_sha256"])
            self.assertEqual(set(valid_products), set(cohort.PAIRS))
            with self.assertRaisesRegex(cohort.ResolverFamilyCohortError,
                                        "dynamic qualification receipt is outside its work directory"):
                cohort.canonical_products(ROOT, static_receipt, copied)


if __name__ == "__main__":
    unittest.main()
