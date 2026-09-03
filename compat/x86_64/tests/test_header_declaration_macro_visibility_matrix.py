#!/usr/bin/env python3
"""Focused contracts for generic x86 declaration/macro visibility evidence."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = ROOT / "compat" / "x86_64" / "header_declaration_macro_visibility_matrix.py"
CHECKED_REPORT = (
    ROOT
    / "compat"
    / "x86_64"
    / "generated"
    / "header_declaration_macro_visibility_matrix"
    / "report.json"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MATRIX = load_module("header_declaration_macro_visibility_matrix_test", MATRIX_PATH)


class HeaderDeclarationMacroVisibilityMatrixTests(unittest.TestCase):
    def test_same_named_source_form_difference_remains_visibility_matched(self) -> None:
        source_difference = {
            "candidate_only": [],
            "candidate_only_count": 0,
            "incompatible": [
                {
                    "candidate_signature": "int (int)",
                    "kind": "function",
                    "name": "shared",
                    "reference_signature": "long (long)",
                }
            ],
            "incompatible_count": 1,
            "matched_count": 2,
            "reference_only": [],
            "reference_only_count": 0,
        }

        comparison = MATRIX.derive_visibility_difference(source_difference)

        self.assertEqual(comparison["candidate_only"], [])
        self.assertEqual(comparison["reference_only"], [])
        self.assertEqual(comparison["matched_count"], 3)
        self.assertEqual(
            comparison["separately_accounted_source_form_difference_count"],
            1,
        )

    def test_identity_only_difference_strips_signatures_but_remains_a_mismatch(self) -> None:
        source_difference = {
            "candidate_only": [
                {"kind": "macro", "name": "PROJECT_ONLY", "signature": "object-like: 1"}
            ],
            "candidate_only_count": 1,
            "incompatible": [],
            "incompatible_count": 0,
            "matched_count": 0,
            "reference_only": [
                {"kind": "typedef", "name": "reference_size", "signature": "unsigned long"}
            ],
            "reference_only_count": 1,
        }

        comparison = MATRIX.derive_visibility_difference(source_difference)

        self.assertEqual(
            comparison["candidate_only"],
            [{"kind": "macro", "name": "PROJECT_ONLY"}],
        )
        self.assertEqual(
            comparison["reference_only"],
            [{"kind": "typedef", "name": "reference_size"}],
        )
        self.assertEqual(comparison["matched_count"], 0)
        self.assertEqual(
            comparison["separately_accounted_source_form_difference_count"],
            0,
        )

    def test_checked_report_ratchets_identity_without_leaking_source_signatures(self) -> None:
        contract = MATRIX.load_contract()
        report = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))

        MATRIX.validate_checked_report(report, contract)

        self.assertEqual(
            report["summary"]["comparison_counts"],
            {
                "candidate-only-pending-c-abi-policy": 56,
                "matched": 367,
                "mismatch": 913,
                "oracle-not-applicable": 1,
            },
        )
        self.assertEqual(report["summary"]["source_form_difference_count"], 22143)
        self.assertEqual(report["summary"]["source_form_only_difference_row_count"], 51)
        mismatches = [row for row in report["rows"] if row["comparison"] == "mismatch"]
        self.assertTrue(mismatches)
        for row in mismatches:
            for entry in [*row["candidate_only"], *row["reference_only"]]:
                self.assertEqual(set(entry), {"kind", "name"})
        self.assertTrue(
            any(
                row["comparison"] == "matched"
                and row.get("source_form_comparison") == "mismatch"
                and row["separately_accounted_source_form_difference_count"] > 0
                for row in report["rows"]
            )
        )

    def test_noncomparable_rows_retain_checked_summaries_not_identity_deltas(self) -> None:
        report = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        project_only = next(
            row
            for row in report["rows"]
            if row["comparison"] == "candidate-only-pending-c-abi-policy"
        )
        oracle_not_applicable = next(
            row
            for row in report["rows"]
            if row["comparison"] == "oracle-not-applicable"
        )

        self.assertEqual(
            set(project_only),
            {
                "candidate",
                "candidate_status",
                "comparison",
                "disposition",
                "header",
                "profile",
                "reference",
                "reference_status",
            },
        )
        self.assertEqual(
            set(oracle_not_applicable),
            {
                "candidate",
                "candidate_status",
                "comparison",
                "header",
                "oracle_not_applicable_reason",
                "profile",
                "reference",
                "reference_status",
            },
        )
        for row in (project_only, oracle_not_applicable):
            self.assertEqual(set(row["candidate"]), {"count", "kind_counts", "sha256"})
            self.assertNotIn("candidate_only", row)
            self.assertNotIn("reference_only", row)

    def test_work_package_owns_the_checked_generated_report(self) -> None:
        contract = MATRIX.load_contract()

        self.assertIn(
            "compat/x86_64/generated/header_declaration_macro_visibility_matrix/report.json",
            contract.work_package["source_owners"],
        )

    def test_statx_gnu_identities_are_no_longer_reference_only(self) -> None:
        report = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in report["rows"]
        }
        names = {
            "statx",
            "statx_timestamp",
            "STATX_TYPE",
            "STATX_BASIC_STATS",
            "STATX_WRITE_ATOMIC",
            "STATX_ATTR_WRITE_ATOMIC",
        }
        for header in ("sys/stat.h", "ftw.h"):
            for profile in ("c11-gnu", "cxx17-gnu", "cxx17-strict"):
                row = rows[(header, profile)]
                for field in ("candidate_only", "reference_only"):
                    self.assertFalse(
                        names & {fact["name"] for fact in row[field]},
                        f"{header}:{profile} {field} statx identities",
                    )


if __name__ == "__main__":
    unittest.main()
