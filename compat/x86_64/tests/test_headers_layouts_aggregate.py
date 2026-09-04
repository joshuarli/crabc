#!/usr/bin/env python3
"""Focused contracts for the x86 header-completion assessment boundary."""

from __future__ import annotations

import copy
import dataclasses
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "headers_layouts_aggregate.py"
RUNNER = ROOT / "compat" / "x86_64" / "run_headers_layouts_aggregate.sh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


AGGREGATE = load_module("headers_layouts_aggregate_test", SCRIPT)


class HeadersLayoutsAggregateTests(unittest.TestCase):
    def current_report(self) -> dict[str, object]:
        """Build fresh facts without rewriting the checked aggregate artifact."""

        return AGGREGATE.build_report()

    def assessment_contract(self):
        return AGGREGATE.header_completion_assessment_contract(
            AGGREGATE.load_toml(AGGREGATE.FOUNDATION_PATH)
        )

    def green_facts(self):
        contract = self.assessment_contract()
        return AGGREGATE.HeaderFoundationCompletionFacts(
            installed_surface_requirements=tuple(
                (key, True) for key in contract.installed_surface_completion_keys
            ),
            declaration_identity_mismatch_rows=0,
            declaration_source_form_differences=0,
            callable_visibility_mismatch_rows=0,
            prototype_or_named_declaration_mismatch_rows=0,
            record_byte_layout_mismatch_rows=0,
            candidate_external_callable_names=("current", "deferred_a", "deferred_b"),
            current_provider_callable_names=("current",),
            # A nonzero deferred set is intentionally green when it has exact
            # C-ABI closure routing. It is not a header-completion blocker.
            expected_deferred_callable_names=("deferred_a", "deferred_b"),
            deferred_owner_groups=(
                AGGREGATE.DeferredOwnerRouting(
                    identifier="deferred-cabi-owner",
                    linkage_owner_family="libc.c-abi-compat",
                    linkage_owner_obligation="final-callable-provider-archive-closure",
                    members=("deferred_a", "deferred_b"),
                ),
            ),
            missing_reference_declaration_name_count=0,
            missing_reference_declaration_record_count=0,
            undispositioned_candidate_callable_count=0,
            undispositioned_missing_reference_name_count=0,
        )

    def assess(self, facts):
        return AGGREGATE.assess_header_foundation_completion(
            facts, self.assessment_contract()
        )

    def reports_with_green_header_dimensions(self):
        """Keep real routing facts while making only generic header rows green."""

        reports = copy.deepcopy(AGGREGATE.load_context()[-1])
        by_id = {
            entry["id"]: entry
            for entry in reports
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        }
        declaration = by_id["declaration-macro-visibility"]["summary"]
        callable_visibility = by_id["callable-visibility"]["summary"]
        prototype = by_id["prototype-layout"]["summary"]
        record_layout = by_id["record-byte-layout"]["summary"]
        assert isinstance(declaration, dict)
        assert isinstance(callable_visibility, dict)
        assert isinstance(prototype, dict)
        assert isinstance(record_layout, dict)
        declaration["mismatch_row_count"] = 0
        declaration["source_form_difference_count"] = 0
        callable_visibility["mismatch_row_count"] = 0
        prototype["mismatch_row_count"] = 0
        comparisons = record_layout["comparison_counts"]
        assert isinstance(comparisons, dict)
        comparisons["mismatch"] = 0
        return reports

    def test_current_assessment_is_finite_planned_header_evidence(self) -> None:
        report = self.current_report()
        AGGREGATE.validate_report(report)

        self.assertEqual(report["schema"], AGGREGATE.REPORT_SCHEMA)
        self.assertEqual(report["family"], "libc.headers-layouts")
        self.assertTrue(report["accounting_complete"])
        self.assertFalse(report["family_completion"])
        self.assertFalse(report["promotion_ready"])
        self.assertFalse(report["public_support"])
        self.assertEqual(report["direct_probe_count"], 55)
        self.assertEqual(report["profile_obligation_count"], 21)
        self.assertEqual(report["language_profile_count"], 7)
        self.assertEqual(report["abi_facet_count"], 25)
        self.assertEqual(report["linkage_owner_count"], 3)
        self.assertEqual(
            report["blockers"],
            [
                "declaration-identity",
                "declaration-source-forms",
                "callable-visibility",
                "prototype-or-named-declarations",
            ],
        )
        self.assertNotIn("callable-provider-closure", report["blockers"])
        self.assertNotIn("runtime-semantics", report["blockers"])
        self.assertNotIn("family-promotion", report["blockers"])
        blocker_counts = report["blocker_counts"]
        assert isinstance(blocker_counts, dict)
        self.assertEqual(blocker_counts["record_byte_layout_mismatch_rows"], 0)
        self.assertEqual(blocker_counts["callable_ownership_routing_invalid"], 0)
        header_completion = report["header_completion"]
        assert isinstance(header_completion, dict)
        self.assertFalse(header_completion["complete"])
        self.assertEqual(header_completion["algorithm"], "header-foundation-v1")
        self.assertEqual(
            header_completion["explicit_nonrequirements"],
            [
                "archive-extraction",
                "final-provider-archive-closure",
                "promotion-public-support",
                "runtime-semantics",
                "selected-provider-linkage-audit",
                "static-export-complement",
                "unprovided-callable-count",
            ],
        )
        downstream = report["downstream_provider_archive_obligations"]
        assert isinstance(downstream, dict)
        self.assertEqual(downstream["linkage_owner_family"], "libc.c-abi-compat")
        self.assertEqual(
            downstream["linkage_owner_obligation"],
            "final-callable-provider-archive-closure",
        )
        self.assertEqual(downstream["deferred_callable_count"], 328)
        self.assertTrue(downstream["routing_exact"])
        self.assertEqual(downstream["provider_archive_evidence_state"], "incomplete")
        self.assertTrue(downstream["final_provider_archive_closure_available"])
        self.assertFalse(downstream["final_provider_archive_closure_complete"])
        self.assertTrue(downstream["selected_provider_linkage_audit_available"])
        self.assertFalse(downstream["selected_provider_linkage_audit_complete"])
        generic_reports = report["generic_reports"]
        assert isinstance(generic_reports, list)
        self.assertIn(
            "record-byte-layout",
            {entry["id"] for entry in generic_reports if isinstance(entry, dict)},
        )

    def test_control_rejects_manual_completion_or_omitted_coverage(self) -> None:
        report = self.current_report()
        changed = copy.deepcopy(report)
        changed["family_completion"] = True
        with self.assertRaisesRegex(AGGREGATE.AggregateError, "family completion"):
            AGGREGATE.validate_report(changed)

        changed = copy.deepcopy(report)
        header_completion = changed["header_completion"]
        assert isinstance(header_completion, dict)
        header_completion["complete"] = True
        changed["family_completion"] = True
        with self.assertRaisesRegex(
            AGGREGATE.AggregateError, "header completion assessment"
        ):
            AGGREGATE.validate_report(changed)

        changed = copy.deepcopy(report)
        accounting_coverage = changed["accounting_coverage"]
        assert isinstance(accounting_coverage, list)
        accounting_coverage.pop()
        with self.assertRaisesRegex(AGGREGATE.AggregateError, "accounting coverage"):
            AGGREGATE.validate_report(changed)

    def test_control_rejects_stale_input_digests_and_unexpected_report_members(self) -> None:
        report = self.current_report()
        changed = copy.deepcopy(report)
        inputs = changed["inputs"]
        assert isinstance(inputs, list) and isinstance(inputs[0], dict)
        inputs[0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(AGGREGATE.AggregateError, "input digest"):
            AGGREGATE.validate_report(changed)

        changed = copy.deepcopy(report)
        generic_reports = changed["generic_reports"]
        assert isinstance(generic_reports, list)
        generic_reports.append({"id": "unexpected", "summary": {}})
        with self.assertRaisesRegex(AGGREGATE.AggregateError, "generic report"):
            AGGREGATE.validate_report(changed)

    def test_fresh_assessment_hashes_its_execution_sources(self) -> None:
        report = self.current_report()
        inputs = report["inputs"]
        assert isinstance(inputs, list)
        paths = {entry["path"] for entry in inputs if isinstance(entry, dict)}

        self.assertIn("compat/x86_64/headers_layouts_aggregate.py", paths)
        self.assertIn("compat/x86_64/run_headers_layouts_aggregate.sh", paths)
        self.assertIn("compat/x86_64/header_callable_disposition.py", paths)
        self.assertIn("compat/x86_64/header_callable_linkage_audit.py", paths)
        self.assertIn("compat/x86_64/header_record_layout_matrix.toml", paths)
        self.assertIn("compat/x86_64/header_record_layout_matrix.py", paths)
        self.assertIn(
            "compat/x86_64/generated/header_record_layout_matrix/report.json", paths
        )
        self.assertTrue(set(AGGREGATE.runner_paths()).issubset(paths))

    def test_all_header_dimensions_independently_block_completion(self) -> None:
        contract = self.assessment_contract()
        first_key, _value = self.green_facts().installed_surface_requirements[0]
        green = self.green_facts()
        cases = (
            (
                "installed-surface",
                dataclasses.replace(
                    green,
                    installed_surface_requirements=(
                        (first_key, False),
                        *green.installed_surface_requirements[1:],
                    ),
                ),
            ),
            (
                "declaration-identity",
                dataclasses.replace(green, declaration_identity_mismatch_rows=1),
            ),
            (
                "declaration-source-forms",
                dataclasses.replace(green, declaration_source_form_differences=1),
            ),
            (
                "callable-visibility",
                dataclasses.replace(green, callable_visibility_mismatch_rows=1),
            ),
            (
                "prototype-or-named-declarations",
                dataclasses.replace(
                    green, prototype_or_named_declaration_mismatch_rows=1
                ),
            ),
            (
                "record-byte-layouts",
                dataclasses.replace(green, record_byte_layout_mismatch_rows=1),
            ),
            (
                "callable-ownership-routing",
                dataclasses.replace(
                    green,
                    deferred_owner_groups=(
                        dataclasses.replace(
                            green.deferred_owner_groups[0],
                            linkage_owner_family="libc.posix-runtime",
                        ),
                    ),
                ),
            ),
        )
        self.assertEqual(
            tuple(identifier for identifier, _facts in cases),
            contract.required_dimensions,
        )
        for expected_blocker, facts in cases:
            with self.subTest(blocker=expected_blocker):
                assessment = self.assess(facts)
                self.assertFalse(assessment["complete"])
                self.assertIn(expected_blocker, assessment["blockers"])

    def test_provider_gaps_do_not_block_green_header_assessment(self) -> None:
        facts = self.green_facts()
        assessment = self.assess(facts)
        current_report = self.current_report()
        downstream = current_report["downstream_provider_archive_obligations"]
        assert isinstance(downstream, dict)

        self.assertTrue(assessment["complete"])
        self.assertEqual(assessment["blockers"], [])
        self.assertEqual(len(facts.expected_deferred_callable_names), 2)
        self.assertEqual(downstream["deferred_callable_count"], 328)
        self.assertFalse(downstream["final_provider_archive_closure_complete"])
        self.assertFalse(downstream["selected_provider_linkage_audit_complete"])
        self.assertNotIn(
            "unprovided_callable_count",
            AGGREGATE.HeaderFoundationCompletionFacts.__dataclass_fields__,
        )
        self.assertNotIn(
            "selected_provider_linkage_audit_complete",
            AGGREGATE.HeaderFoundationCompletionFacts.__dataclass_fields__,
        )
        self.assertNotIn(
            "archive_extraction_complete",
            AGGREGATE.HeaderFoundationCompletionFacts.__dataclass_fields__,
        )

    def test_unavailable_provider_metadata_cannot_block_a_built_header_assessment(self) -> None:
        """The assessment builder admits only header facts, not C-ABI metadata."""

        reports = self.reports_with_green_header_dimensions()

        def unavailable(foundation):
            provider_audit = foundation.pop("selected_callable_provider_linkage_audit")
            assert isinstance(provider_audit, dict)
            disposition = foundation["callable_disposition"]
            assert isinstance(disposition, dict)
            disposition.pop("final_provider_archive_closure_complete")
            # This is downstream provider metadata, not a routing fact.
            disposition["unprovided_callable_count"] = "unavailable"

        def complete(foundation):
            provider_audit = foundation["selected_callable_provider_linkage_audit"]
            disposition = foundation["callable_disposition"]
            assert isinstance(provider_audit, dict)
            assert isinstance(disposition, dict)
            provider_audit["full_callable_closure"] = True
            disposition["final_provider_archive_closure_complete"] = True

        variants = (
            ("unavailable", unavailable, "unavailable", False),
            ("incomplete", lambda _foundation: None, "incomplete", True),
            ("complete", complete, "complete", True),
        )
        expected_assessment = None
        for name, mutate, expected_state, expected_available in variants:
            with self.subTest(provider_evidence=name):
                foundation = AGGREGATE.load_toml(AGGREGATE.FOUNDATION_PATH)
                mutate(foundation)
                facts, assessment = AGGREGATE.build_header_completion_assessment(
                    foundation, reports
                )
                self.assertTrue(assessment["complete"])
                if expected_assessment is None:
                    expected_assessment = assessment
                else:
                    self.assertEqual(assessment, expected_assessment)

                downstream = AGGREGATE.downstream_provider_archive_obligations(
                    foundation, facts, self.assessment_contract()
                )
                self.assertEqual(
                    downstream["provider_archive_evidence_state"], expected_state
                )
                self.assertEqual(
                    downstream["selected_provider_linkage_audit_available"],
                    expected_available,
                )
                self.assertEqual(
                    downstream["final_provider_archive_closure_available"],
                    expected_available,
                )
                if not expected_available:
                    self.assertFalse(
                        downstream["selected_provider_linkage_audit_complete"]
                    )
                    self.assertFalse(
                        downstream["final_provider_archive_closure_complete"])
                else:
                    expected_complete = expected_state == "complete"
                    self.assertEqual(
                        downstream["selected_provider_linkage_audit_complete"],
                        expected_complete,
                    )
                    self.assertEqual(
                        downstream["final_provider_archive_closure_complete"],
                        expected_complete,
                    )

        broken_routing = AGGREGATE.load_toml(AGGREGATE.FOUNDATION_PATH)
        disposition = broken_routing["callable_disposition"]
        assert isinstance(disposition, dict)
        disposition["report"] = "compat/x86_64/generated/missing-disposition.json"
        with self.assertRaisesRegex(AGGREGATE.AggregateError, "callable disposition"):
            AGGREGATE.build_header_completion_assessment(broken_routing, reports)

    def test_provider_success_cannot_compensate_for_a_header_mismatch(self) -> None:
        # The predicate has no provider/archive input. Even a hypothetical
        # complete provider closure cannot erase an identity mismatch.
        facts = dataclasses.replace(
            self.green_facts(), declaration_identity_mismatch_rows=1
        )
        assessment = self.assess(facts)
        self.assertFalse(assessment["complete"])
        self.assertIn("declaration-identity", assessment["blockers"])
        with self.assertRaises(TypeError):
            AGGREGATE.assess_header_foundation_completion(
                facts,
                self.assessment_contract(),
                {
                    "final_provider_archive_closure_complete": True,
                    "selected_provider_linkage_audit_complete": True,
                    "unprovided_callable_count": 0,
                },
            )

    def test_deferred_routing_rejects_missing_overlapping_and_wrong_owner_coverage(self) -> None:
        green = self.green_facts()
        group = green.deferred_owner_groups[0]
        cases = {
            "missing": dataclasses.replace(
                green,
                deferred_owner_groups=(
                    dataclasses.replace(group, members=("deferred_a",)),
                ),
            ),
            "overlapping": dataclasses.replace(
                green,
                deferred_owner_groups=(
                    group,
                    AGGREGATE.DeferredOwnerRouting(
                        identifier="overlap",
                        linkage_owner_family="libc.c-abi-compat",
                        linkage_owner_obligation="final-callable-provider-archive-closure",
                        members=("deferred_b",),
                    ),
                ),
            ),
            "wrong-owner": dataclasses.replace(
                green,
                deferred_owner_groups=(
                    dataclasses.replace(
                        group, linkage_owner_family="libc.text-math-locale-stdio"
                    ),
                ),
            ),
            "wrong-obligation": dataclasses.replace(
                green,
                deferred_owner_groups=(
                    dataclasses.replace(
                        group, linkage_owner_obligation="runtime-behavior"
                    ),
                ),
            ),
            "undispositioned": dataclasses.replace(
                green, undispositioned_candidate_callable_count=1
            ),
            "missing-reference": dataclasses.replace(
                green, missing_reference_declaration_name_count=1
            ),
            "missing-reference-record": dataclasses.replace(
                green, missing_reference_declaration_record_count=1
            ),
        }
        for name, facts in cases.items():
            with self.subTest(case=name):
                assessment = self.assess(facts)
                self.assertFalse(assessment["complete"])
                self.assertIn("callable-ownership-routing", assessment["blockers"])

    def test_accounted_incomplete_linkage_audit_is_explicit(self) -> None:
        report = {
            "schema": "crabc.x86_64-header-callable-linkage-audit/v2",
            "inventory_schema": "crabc.x86_64-header-callable-inventory-report/v2",
            "scope": {
                "family_promotion": False,
                "feature_archive_profiles_extracted_here": False,
                "feature_archive_provider_accounting": True,
                "public_support": False,
                "uses_whole_archive": False,
            },
            "external_callable_count": 1525,
            "ratcheted_external_callable_count": 1119,
            "summary": {
                "callable_provider_counts": {
                    "declared_unverified_feature_archives": 0,
                    "default_static": 1119,
                    "unprovided": 328,
                    "verified_feature_archives": 78,
                },
                "complete": False,
                "extraction_status_counts": {"extracted": 1119},
                "incomplete_reasons": [
                    "static export complement is nonempty",
                    "one or more candidate external callables have no declared archive provider",
                ],
                "static_export_complement_count": 406,
            },
        }
        AGGREGATE.validate_accounted_incomplete_linkage_audit_report(report)

        changed = copy.deepcopy(report)
        summary = changed["summary"]
        assert isinstance(summary, dict)
        summary["complete"] = True
        with self.assertRaisesRegex(AGGREGATE.AggregateError, "must remain incomplete"):
            AGGREGATE.validate_accounted_incomplete_linkage_audit_report(changed)

    def test_runner_list_is_safe_complete_and_has_no_dispatcher_recursion(self) -> None:
        runners = AGGREGATE.runner_paths()

        self.assertEqual(len(runners), len(set(runners)))
        self.assertGreaterEqual(len(runners), 55)
        self.assertTrue(all(path.endswith(".sh") for path in runners))
        self.assertTrue(all(not path.startswith("/") and ".." not in Path(path).parts for path in runners))
        self.assertIn("compat/x86_64/run_header_abi_matrix.sh", runners)
        self.assertIn("compat/x86_64/run_header_record_layout_matrix.sh", runners)
        self.assertIn("compat/x86_64/run_time_header_abi.sh", runners)

    def test_checked_output_rejects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            report_path.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(AGGREGATE.AggregateError, "output drifted"):
                AGGREGATE.check_output(AGGREGATE.build_report(), report_path)

    def test_runner_is_a_checked_native_boundary(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("--runner-contract-list", source)
        self.assertIn("--check", source)
        self.assertIn("--check-accounted-incomplete-linkage-audit", source)
        self.assertIn("ACCOUNTED-INCOMPLETE", source)
        self.assertNotIn("dev-x86_64.sh", source)
        self.assertIn("family promotion", source)


if __name__ == "__main__":
    unittest.main()
