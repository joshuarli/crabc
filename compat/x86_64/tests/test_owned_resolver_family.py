"""Contract tests for the bounded non-promoting resolver-family coordinator."""

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
        protocol = self._relative(self._file("protocol-database.json"))
        cohort = self._relative(self._file("cohort.json"))
        static_preparation = self._relative(self._file("static-preparation.json"))
        dynamic_qualification = self._relative(self._file("dynamic-qualification.json"))
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
            "protocol-database-product": {"report": protocol},
            "resolver-family-cohort": {
                "static_preparation": static_preparation,
                "dynamic_qualification": dynamic_qualification,
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
        self.assertEqual(
            components["resolver-family-cohort"].request_fields,
            ("static_preparation", "dynamic_qualification"),
        )
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

    def test_existing_readers_and_cohort_reader_require_one_complete_request(self) -> None:
        calls: list[str] = []

        def valid_reader(_root: Path, paths: dict[str, Path]) -> dict[str, object]:
            calls.append(next(iter(paths)))
            return {"replayed": True}

        def valid_cohort_reader(_root: Path, paths: dict[str, Path],
                                replays: dict[str, tuple[dict[str, Path], dict[str, object]]]) -> dict[str, object]:
            self.assertEqual(set(paths), {"static_preparation", "dynamic_qualification"})
            self.assertEqual(
                set(replays),
                {
                    "resolver-network-physical", "classic-netdb", "resolver-alias-private-bodies",
                    "resolver-cancellation", "protocol-database-product",
                },
            )
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
                "protocol-database-product": valid_reader,
            },
            cohort_reader=valid_cohort_reader,
        )

        self.assertEqual(len(calls), 5)
        self.assertTrue(report["components"]["resolver-network-physical"]["admitted"])
        self.assertTrue(report["components"]["classic-netdb"]["admitted"])
        self.assertTrue(report["components"]["resolver-alias-private-bodies"]["admitted"])
        self.assertTrue(report["components"]["resolver-cancellation"]["admitted"])
        self.assertTrue(report["components"]["protocol-database-product"]["admitted"])
        self.assertTrue(report["components"]["resolver-family-cohort"]["admitted"])
        self.assertTrue(report["proofs"]["resolver-cancellation-and-retirement"]["admitted"])
        self.assertTrue(report["proofs"]["protocol-database-installed-behavior"]["admitted"])
        self.assertTrue(report["proofs"]["common-current-product-cohort"]["admitted"])
        self.assertTrue(report["family_complete"])
        self.assertFalse(report["promotion_ready"])
        self.assertFalse(report["public_support"])

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

    def _cohort(self) -> tuple[dict[str, object], dict[str, dict[str, dict[str, object]]]]:
        source = {"revision": "r" * 40, "content_sha256": "c" * 64}
        products = {
            label: {kind: {"path": f".work/x86_64/cohort/{label}-{kind}", "manifest": {}}
                    for kind in ("static", "dynamic")}
            for label in ("primary", "reproduction", "extracted")
        }
        return source, products

    def test_plan_fixes_a_fresh_layout_and_request_for_the_supplied_cohort(self) -> None:
        import owned_resolver_family_cohort as cohort

        (ROOT / ".work/x86_64/tmp").mkdir(parents=True, exist_ok=True)
        parent = Path(tempfile.mkdtemp(prefix="resolver-family-plan.", dir=ROOT / ".work/x86_64/tmp"))
        self.addCleanup(shutil.rmtree, parent)
        preparation = self._file("preparation.json")
        qualification = self._file("qualification.json")
        output = parent / "run"
        output.mkdir()
        layout = family.execution_layout(output.relative_to(ROOT))
        network_report = ROOT / layout["network_report"]
        self.addCleanup(lambda: network_report.unlink(missing_ok=True))
        with mock.patch.object(cohort, "canonical_products", return_value=self._cohort()) as canonical:
            plan_path = family.plan_execution(ROOT, preparation, qualification, output)
            canonical.assert_called_once_with(ROOT, preparation, qualification)
            with self.assertRaisesRegex(family.ResolverFamilyError, "must be fresh"):
                family.plan_execution(ROOT, preparation, qualification, output)
            with self.assertRaisesRegex(family.ResolverFamilyError, "cannot read resolver family output"):
                family.plan_execution(ROOT, preparation, qualification, parent / "absent")
            elsewhere = self.work / "elsewhere"
            elsewhere.mkdir()
            with self.assertRaisesRegex(family.ResolverFamilyError, r"below checkout \.work/x86_64"):
                family.plan_execution(ROOT, preparation, qualification, elsewhere)
            self.assertEqual(canonical.call_count, 1, "invalid outputs must fail before cohort replay")

        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        self.assertEqual(plan["schema"], family.PLAN_SCHEMA)
        self.assertEqual(plan["layout"], layout)
        self.assertEqual(plan["products"]["extracted"]["dynamic"], ".work/x86_64/cohort/extracted-dynamic")
        request = json.loads((ROOT / layout["request"]).read_text(encoding="utf-8"))
        self.assertEqual(request["schema"], family.REQUEST_SCHEMA)
        components, _proofs = family._roster(ROOT)
        self.assertEqual(set(request["components"]), set(components))
        for identifier, component in components.items():
            self.assertEqual(set(request["components"][identifier]), set(component.request_fields), identifier)
        alias = request["components"]["resolver-alias-private-bodies"]
        self.assertEqual((alias["static_product"], alias["dynamic_product"]),
                         (".work/x86_64/cohort/primary-static", ".work/x86_64/cohort/primary-dynamic"))
        self.assertEqual(request["components"]["resolver-cancellation"]["static_product"],
                         alias["static_product"])
        self.assertEqual(request["components"]["resolver-family-cohort"], {
            "static_preparation": self._relative(preparation),
            "dynamic_qualification": self._relative(qualification),
        })
        self.assertTrue(layout["network_report"].startswith("compat/reports/resolver-network/x86_64/"))
        self.assertTrue(network_report.parent.is_dir() and not network_report.exists())
        for name in ("classic_work", "cancellation_work"):
            self.assertTrue((ROOT / layout[name]).is_dir(), name)
        for name in ("network_work_root", "protocol_work", "loader_debug", "inventory", "elf_facts", "alias"):
            self.assertFalse((ROOT / layout[name]).exists(), name)

    def _complete_assessment(self) -> tuple[Path, dict[str, object]]:
        preparation = self._file("preparation.json")
        qualification = self._file("qualification.json")
        request = self._request({})
        source = {"revision": "r" * 40, "content_sha256": "c" * 64}
        assessment = {
            "schema": family.SCHEMA,
            "family": "libc.resolver",
            "contract": family._identity(ROOT, ROOT / "compat/x86_64/resolver-family.toml"),
            "request": family._identity(ROOT, request),
            "capabilities": {name: {"admitted": True} for name in family.FROZEN_CAPABILITIES},
            "components": {name: {"admitted": True} for name in family.EXPECTED_COMPONENTS},
            "proofs": {},
            "gaps": [],
            "family_complete": True,
            "promotion_ready": False,
            "public_support": False,
        }
        assessment["components"]["resolver-family-cohort"]["result"] = {"source": {
            **source,
            "static_preparation": family._identity(ROOT, preparation),
            "dynamic_qualification": family._identity(ROOT, qualification),
        }}
        path = self._file("assessment.json", json.dumps(assessment))
        return path, source

    def test_admission_facts_bind_a_complete_assessment_to_current_bytes(self) -> None:
        import owned_posix_static_products as static

        path, source = self._complete_assessment()
        with mock.patch.object(static, "source_identity", return_value=source):
            facts = family.admission_facts(ROOT, path.relative_to(ROOT))
        self.assertEqual(facts["source"], source)
        self.assertEqual(facts["static_preparation"]["path"], self._relative(self.work / "preparation.json"))
        self.assertEqual(facts["assessment"], family._identity(ROOT, path))

        with mock.patch.object(static, "source_identity", return_value={**source, "revision": "o" * 40}):
            with self.assertRaisesRegex(family.ResolverFamilyError, "not bound to current source"):
                family.admission_facts(ROOT, path.relative_to(ROOT))
        with mock.patch.object(static, "source_identity", return_value=source):
            (self.work / "qualification.json").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(family.ResolverFamilyError, "dynamic_qualification receipt changed"):
                family.admission_facts(ROOT, path.relative_to(ROOT))

    def test_admission_facts_reject_incomplete_or_changed_assessments(self) -> None:
        import owned_posix_static_products as static

        path, source = self._complete_assessment()
        original = json.loads(path.read_text(encoding="utf-8"))
        mutations = {
            "completion boundary": lambda value: value.update(family_complete=False),
            "completion boundary ": lambda value: value.update(promotion_ready=True),
            "component admission": lambda value: value["components"]["classic-netdb"].update(admitted=False),
            "capability admission": lambda value: value["capabilities"].pop("network.netdb"),
            "contract changed": lambda value: value["contract"].update(sha256="0" * 64),
        }
        with mock.patch.object(static, "source_identity", return_value=source):
            for message, mutate in mutations.items():
                changed = json.loads(json.dumps(original))
                mutate(changed)
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.subTest(message=message):
                    with self.assertRaisesRegex(family.ResolverFamilyError, message.strip()):
                        family.admission_facts(ROOT, path.relative_to(ROOT))
            path.write_text(json.dumps(original), encoding="utf-8")
            (self.work / "request.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(family.ResolverFamilyError, "request changed"):
                family.admission_facts(ROOT, path.relative_to(ROOT))


if __name__ == "__main__":
    unittest.main()
