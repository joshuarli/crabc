"""Contract tests for the bounded non-promoting resolver-family coordinator."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_resolver_family as family  # noqa: E402


class OwnedResolverFamilyTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="resolver-family-test.", dir=ROOT / ".work"))

    def tearDown(self) -> None:
        shutil.rmtree(self.work)

    def _file(self, name: str, value: str = "evidence\n") -> Path:
        path = self.work / name
        path.write_text(value, encoding="utf-8")
        return path

    def _directory(self, name: str) -> Path:
        path = self.work / name
        path.mkdir()
        (path / "manifest").write_text("product\n", encoding="utf-8")
        return path

    def _relative(self, path: Path) -> str:
        return path.relative_to(ROOT).as_posix()

    def _request(self, components: dict[str, object]) -> Path:
        path = self.work / "request.json"
        path.write_text(json.dumps({"schema": family.REQUEST_SCHEMA, "components": components}), encoding="utf-8")
        return path

    def _all_reader_request(self) -> dict[str, object]:
        report = self._relative(self._file("report.json"))
        product = self._relative(self._directory("product"))
        cancellation_work = self._relative(self._directory("cancellation-work"))
        cancellation_static = self._relative(self._directory("cancellation-static"))
        cancellation_dynamic = self._relative(self._directory("cancellation-dynamic"))
        cohort = self._relative(self._file("cohort.json"))
        return {
            "resolver-network-physical": {"report": report},
            "classic-netdb": {"report": report},
            "resolver-alias-private-bodies": {
                "report": report,
                "static_product": product,
                "dynamic_product": product,
                "product_report": cohort,
                "static_preparation": cohort,
                "elf_facts": cohort,
                "base_inventory": cohort,
            },
            "resolver-cancellation": {
                "work": cancellation_work,
                "static_product": cancellation_static,
                "dynamic_product": cancellation_dynamic,
            },
        }

    def test_roster_maps_each_frozen_capability_to_behavior_proofs(self) -> None:
        components, proofs = family._roster(ROOT)
        frozen = family._frozen_capability_projection(ROOT)

        self.assertEqual(tuple(frozen), family.FROZEN_CAPABILITIES)
        self.assertEqual(
            set(components),
            {
                "resolver-network-physical", "classic-netdb", "resolver-alias-private-bodies",
                "resolver-cancellation", "protocol-database-product", "resolver-family-cohort",
            },
        )
        for identifier in ("resolver-network-physical", "classic-netdb", "resolver-cancellation",
                           "protocol-database-product", "resolver-family-cohort"):
            self.assertEqual(components[identifier].modes, family.SIX_MODES)
        for capability in family.FROZEN_CAPABILITIES:
            self.assertTrue(any(capability in proof.capabilities for proof in proofs), capability)

    def test_missing_component_reports_and_missing_readers_are_explicit_gaps(self) -> None:
        report = family.collect(ROOT, self._request({}))

        self.assertFalse(report["family_complete"])
        self.assertFalse(report["promotion_ready"])
        self.assertFalse(report["public_support"])
        self.assertEqual(
            {gap["component"] for gap in report["gaps"]},
            {
                "resolver-network-physical", "classic-netdb", "resolver-alias-private-bodies",
                "resolver-cancellation", "protocol-database-product", "resolver-family-cohort",
            },
        )
        self.assertEqual(
            report["components"]["resolver-cancellation"]["gap"]["reason"],
            "missing-component-report",
        )
        self.assertFalse(report["capabilities"]["network.resolver"]["admitted"])

    def test_existing_readers_cannot_hide_the_unreadable_required_components(self) -> None:
        calls: list[str] = []

        def valid_reader(_root: Path, paths: dict[str, Path]) -> dict[str, object]:
            calls.append(next(iter(paths)))
            return {"replayed": True}

        request = self._request(self._all_reader_request())
        report = family.collect(
            ROOT,
            request,
            readers={
                "resolver-network-physical": valid_reader,
                "classic-netdb": valid_reader,
                "resolver-alias-private-bodies": valid_reader,
                "resolver-cancellation": valid_reader,
            },
        )

        self.assertEqual(len(calls), 4)
        self.assertTrue(report["components"]["resolver-network-physical"]["admitted"])
        self.assertTrue(report["components"]["classic-netdb"]["admitted"])
        self.assertTrue(report["components"]["resolver-alias-private-bodies"]["admitted"])
        self.assertTrue(report["components"]["resolver-cancellation"]["admitted"])
        self.assertTrue(report["proofs"]["resolver-cancellation-and-retirement"]["admitted"])
        self.assertFalse(report["proofs"]["protocol-database-installed-behavior"]["admitted"])
        self.assertFalse(report["proofs"]["common-current-product-cohort"]["admitted"])
        self.assertFalse(report["family_complete"])

    def test_unknown_or_incomplete_component_input_fails_before_reader_replay(self) -> None:
        unknown = self._request({"not-resolver": {}})
        with self.assertRaisesRegex(family.ResolverFamilyError, "unknown component"):
            family.collect(ROOT, unknown)

        incomplete = self._request({"resolver-network-physical": {}})
        report = family.collect(ROOT, incomplete)
        self.assertEqual(
            report["components"]["resolver-network-physical"]["gap"]["reason"],
            "component-reader-rejected",
        )

    def test_reader_cannot_change_a_declared_product_during_replay(self) -> None:
        def valid_reader(_root: Path, _paths: dict[str, Path]) -> dict[str, object]:
            return {"replayed": True}

        def mutating_alias_reader(_root: Path, paths: dict[str, Path]) -> dict[str, object]:
            (paths["static_product"] / "manifest").write_text("changed\n", encoding="utf-8")
            return {"replayed": True}

        report = family.collect(
            ROOT,
            self._request(self._all_reader_request()),
            readers={
                "resolver-network-physical": valid_reader,
                "classic-netdb": valid_reader,
                "resolver-alias-private-bodies": mutating_alias_reader,
            },
        )

        alias = report["components"]["resolver-alias-private-bodies"]
        self.assertFalse(alias["admitted"])
        self.assertEqual(alias["gap"]["reason"], "component-reader-rejected")
        self.assertIn("input changed during reader replay", alias["gap"]["detail"])

    def test_written_assessment_reconstructs_and_rejects_changed_request(self) -> None:
        request = self._request({})
        output = self.work / "assessment.json"
        written = family.write_assessment(ROOT, request.relative_to(ROOT), output.relative_to(ROOT))
        reconstructed = family.validate_assessment(ROOT, written.relative_to(ROOT))
        self.assertFalse(reconstructed["family_complete"])

        request.write_text(json.dumps({"schema": family.REQUEST_SCHEMA, "components": {"unknown": {}}}), encoding="utf-8")
        with self.assertRaisesRegex(family.ResolverFamilyError, "request changed"):
            family.validate_assessment(ROOT, written.relative_to(ROOT))


if __name__ == "__main__":
    unittest.main()
