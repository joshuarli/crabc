#!/usr/bin/env python3
"""Focused contracts for the non-promoting x86 header accounting aggregate."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "headers_layouts_aggregate.py"
REPORT = ROOT / "compat" / "x86_64" / "generated" / "headers_layouts_aggregate" / "report.json"
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
    def checked_report(self) -> dict[str, object]:
        return json.loads(REPORT.read_text(encoding="utf-8"))

    def test_checked_report_is_a_finite_non_promoting_accounting_boundary(self) -> None:
        report = self.checked_report()
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
        self.assertIn("declaration-macro-identity", report["blockers"])
        self.assertIn("callable-provider-closure", report["blockers"])
        blocker_counts = report["blocker_counts"]
        assert isinstance(blocker_counts, dict)
        self.assertEqual(blocker_counts["record_byte_layout_mismatch_rows"], 191)
        generic_reports = report["generic_reports"]
        assert isinstance(generic_reports, list)
        self.assertIn(
            "record-byte-layout",
            {entry["id"] for entry in generic_reports if isinstance(entry, dict)},
        )

    def test_control_rejects_false_completion_or_omitted_coverage(self) -> None:
        report = self.checked_report()
        changed = copy.deepcopy(report)
        changed["family_completion"] = True
        with self.assertRaisesRegex(AGGREGATE.AggregateError, "family completion"):
            AGGREGATE.validate_report(changed)

        changed = copy.deepcopy(report)
        completion_coverage = changed["completion_coverage"]
        assert isinstance(completion_coverage, list)
        completion_coverage.pop()
        with self.assertRaisesRegex(AGGREGATE.AggregateError, "completion coverage"):
            AGGREGATE.validate_report(changed)

    def test_control_rejects_stale_input_digests_and_unexpected_report_members(self) -> None:
        report = self.checked_report()
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

    def test_checked_report_hashes_the_aggregate_execution_sources(self) -> None:
        report = self.checked_report()
        inputs = report["inputs"]
        assert isinstance(inputs, list)
        paths = {entry["path"] for entry in inputs if isinstance(entry, dict)}

        self.assertIn("compat/x86_64/headers_layouts_aggregate.py", paths)
        self.assertIn("compat/x86_64/run_headers_layouts_aggregate.sh", paths)
        self.assertIn("compat/x86_64/header_record_layout_matrix.toml", paths)
        self.assertIn("compat/x86_64/header_record_layout_matrix.py", paths)
        self.assertIn(
            "compat/x86_64/generated/header_record_layout_matrix/report.json", paths
        )
        self.assertTrue(set(AGGREGATE.runner_paths()).issubset(paths))

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
                    "unprovided": 346,
                    "verified_feature_archives": 60,
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
