#!/usr/bin/env python3
"""Focused contracts for the compiler-derived x86 record-layout matrix."""

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
MATRIX_PATH = ROOT / "compat" / "x86_64" / "header_record_layout_matrix.py"
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "header_record_layout_matrix.toml"
REPORT_PATH = ROOT / "compat" / "x86_64" / "generated" / "header_record_layout_matrix" / "report.json"
RUNNER = ROOT / "compat" / "x86_64" / "run_header_record_layout_matrix.sh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MATRIX = load_module("header_record_layout_matrix_test", MATRIX_PATH)


class HeaderRecordLayoutMatrixTests(unittest.TestCase):
    def test_contract_uses_fixed_profiles_and_explicit_layout_categories(self) -> None:
        contract = MATRIX.load_contract()
        self.assertEqual(contract.schema, "crabc.x86_64-header-record-layout-matrix/v1")
        self.assertEqual([profile.identifier for profile in contract.profiles], [
            "c11-gnu", "cxx17-gnu", "c11-strict", "c11-posix-2008",
            "c11-xopen-700", "c11-bsd", "cxx17-strict",
        ])
        self.assertEqual(
            contract.not_applicable_categories,
            ("incomplete", "anonymous-only", "bit-field", "flexible-tail", "non-addressable-field"),
        )
        self.assertFalse(contract.policy["archive_linkage"])
        self.assertFalse(contract.policy["runtime"])
        self.assertFalse(contract.policy["family_promotion"])

    def test_field_disposition_marks_layout_exceptions_without_dropping_size(self) -> None:
        fields = MATRIX.field_dispositions(
            [
                {"kind": "FieldDecl", "name": "normal", "type": {"qualType": "int"}},
                {"kind": "FieldDecl", "name": "bits", "isBitfield": True, "type": {"qualType": "unsigned"}},
                {"kind": "FieldDecl", "name": "tail", "type": {"qualType": "char[]"}},
                {"kind": "FieldDecl", "type": {"qualType": "struct inner"}},
            ],
            [0, 32, 64, 96],
        )
        self.assertEqual(fields[0]["name"], "normal")
        self.assertEqual(fields[0]["offset"], 0)
        self.assertEqual(fields[0]["offset_bits"], 0)
        self.assertEqual(fields[0]["applicability"], "applicable")
        self.assertEqual(fields[1]["reason"], "bit-field")
        self.assertIsNone(fields[1]["offset"])
        self.assertEqual(fields[2]["reason"], "flexible-tail")
        self.assertEqual(fields[3]["reason"], "non-addressable-field")

    def test_record_dump_parser_accepts_c_and_cxx_layout_forms(self) -> None:
        output = """
*** Dumping AST Record Layout
Type: struct c_record

Layout: <ASTRecordLayout
  Size:64
  DataSize:64
  Alignment:32
  FieldOffsets: [0, 32]>
*** Dumping AST Record Layout
Type: struct CxxRecord

Layout: <ASTRecordLayout
  Size:64
  DataSize:64
  Alignment:32
  BaseOffsets: []>
  VBaseOffsets: []>
  FieldOffsets: [0, 32]>
"""
        parsed = MATRIX.parse_layouts(output)
        self.assertEqual(parsed["struct c_record"], {"size": 8, "alignment": 4, "offsets": [0, 32]})
        self.assertEqual(parsed["struct CxxRecord"]["size"], 8)

    def test_checked_report_is_finite_non_promoting_and_hash_bound(self) -> None:
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        MATRIX.validate_checked_report(report, MATRIX.load_contract())
        self.assertEqual(report["summary"]["row_count"], 1337)
        self.assertEqual(report["summary"]["profile_count"], 7)
        self.assertFalse(report["summary"]["complete"])
        self.assertIn("mismatch", report["summary"]["comparison_counts"])
        self.assertTrue(any("record-byte-layouts" in reason for reason in report["summary"]["incomplete_reasons"]))
        self.assertFalse(report["scope"]["family_promotion"])
        self.assertFalse(report["scope"]["public_support"])

    def test_report_validation_rejects_row_drift(self) -> None:
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        changed = copy.deepcopy(report)
        changed["rows"].pop()
        with self.assertRaisesRegex(MATRIX.RecordLayoutMatrixError, "row count"):
            MATRIX.validate_checked_report(changed, MATRIX.load_contract())

    def test_runner_is_a_checked_native_boundary(self) -> None:
        result = subprocess.run(["bash", "-n", str(RUNNER)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("--check", source)
        self.assertIn("header_record_layout_matrix.py", source)
        self.assertIn("-fdump-record-layouts-simple", MATRIX_PATH.read_text(encoding="utf-8"))
        self.assertIn("family remains planned", source)


if __name__ == "__main__":
    unittest.main()
