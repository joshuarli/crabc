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

    def test_transitive_record_keeps_its_physical_header_origin(self) -> None:
        """Do not attribute a compact fcntl AST record to an including wrapper."""
        header_root = ROOT / "include"
        fcntl_path = str(header_root / "fcntl.h")
        semaphore_path = str(header_root / "semaphore.h")
        flock = {
            "kind": "RecordDecl",
            "name": "flock",
            "loc": {
                "offset": 20,
                "line": 2,
                "col": 1,
                "includedFrom": {"file": semaphore_path},
            },
        }
        ast = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "TypedefDecl",
                    "name": "fcntl_prelude",
                    "loc": {"file": fcntl_path, "line": 1, "col": 1},
                },
                flock,
            ],
        }

        def flock_header(primary_header: str) -> str | None:
            nodes = MATRIX.declaration_nodes(ast, header_root, primary_header)
            return next(
                visible
                for node, visible, _context, _field_path in nodes
                if node.get("name") == "flock"
            )

        self.assertIsNone(flock_header("semaphore.h"))
        self.assertEqual(flock_header("fcntl.h"), "fcntl.h")

    def test_compact_direct_record_uses_only_a_direct_include_context(self) -> None:
        """Compact records may use the primary include, never an intermediate header."""
        header_root = ROOT / "include"
        primary_path = str(header_root / "fenv.h")

        def record_header(included_from: str, prior_physical_header: str | None = None) -> str | None:
            inner = []
            if prior_physical_header is not None:
                inner.append(
                    {
                        "kind": "TypedefDecl",
                        "name": "physical_prelude",
                        "loc": {"file": prior_physical_header, "line": 1, "col": 1},
                    }
                )
            inner.append(
                {
                    "kind": "RecordDecl",
                    "name": "compact_fenv",
                    "loc": {
                        "offset": 20,
                        "line": 2,
                        "col": 1,
                        "includedFrom": {"file": included_from},
                    },
                }
            )
            ast = {
                "kind": "TranslationUnitDecl",
                "inner": inner,
            }
            nodes = MATRIX.declaration_nodes(ast, header_root, "fenv.h")
            return next(
                visible
                for node, visible, _context, _field_path in nodes
                if node.get("name") == "compact_fenv"
            )

        self.assertEqual(record_header(primary_path), "fenv.h")
        self.assertEqual(record_header("/tmp/record-layout-matrix/ast.c"), "fenv.h")
        self.assertIsNone(record_header(str(header_root / "fcntl.h")))
        self.assertIsNone(record_header(primary_path, str(header_root / "bits" / "fenv.h")))

    def test_physical_spelling_location_beats_include_context(self) -> None:
        """A spelling location remains source ownership even through a wrapper."""
        header_root = ROOT / "include"
        record = {
            "loc": {
                "spellingLoc": {"file": str(header_root / "fcntl.h")},
                "includedFrom": {"file": str(header_root / "semaphore.h")},
            }
        }
        self.assertEqual(MATRIX.source_header(record, header_root), "fcntl.h")

    def test_declared_uapi_root_is_limited_to_the_three_record_wrappers(self) -> None:
        """Physical Linux UAPI records are visible only through their mapped wrapper."""
        with tempfile.TemporaryDirectory(prefix="crabc-record-uapi-") as temporary:
            root = Path(temporary)
            project = root / "project"
            uapi = root / "uapi"
            (project / "sys").mkdir(parents=True)
            (uapi / "linux").mkdir(parents=True)
            for wrapper, dependency in MATRIX.UAPI_RECORD_WRAPPERS.items():
                (project / wrapper).touch()
                (uapi / dependency).touch()

            def records(wrapper: str, dependency: str):
                ast = {
                    "kind": "TranslationUnitDecl",
                    "inner": [
                        {
                            "kind": "RecordDecl",
                            "id": f"{wrapper}-allowed",
                            "name": "allowed_record",
                            "tagUsed": "struct",
                            "completeDefinition": True,
                            "loc": {"file": str(uapi / dependency), "line": 1, "col": 1},
                        },
                        {
                            "kind": "RecordDecl",
                            "id": f"{wrapper}-unrelated",
                            "name": "unrelated_record",
                            "tagUsed": "struct",
                            "completeDefinition": True,
                            "loc": {"file": str(uapi / "linux" / "unrelated.h"), "line": 2, "col": 1},
                        },
                    ],
                }
                return MATRIX.direct_records(ast, project, wrapper, uapi)

            for wrapper, dependency in MATRIX.UAPI_RECORD_WRAPPERS.items():
                self.assertEqual([record.key for record in records(wrapper, dependency)], ["struct:allowed_record"])

            unrelated_wrapper = "net/if.h"
            (project / "net").mkdir()
            (project / unrelated_wrapper).touch()
            self.assertEqual(records(unrelated_wrapper, "linux/if.h"), [])

    def test_bits_records_require_the_same_direct_wrapper_context_in_both_trees(self) -> None:
        """A direct bits indirection compares symmetrically; transitive bits do not leak."""
        with tempfile.TemporaryDirectory(prefix="crabc-record-bits-") as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            reference = root / "reference"
            for tree in (candidate, reference):
                (tree / "bits").mkdir(parents=True)
                (tree / "fenv.h").touch()
                (tree / "stdio.h").touch()
                (tree / "bits" / "fenv.h").touch()

            def ast(tree: Path, included_from: str):
                return {
                    "kind": "TranslationUnitDecl",
                    "inner": [
                        {
                            "kind": "RecordDecl",
                            "id": str(tree),
                            "name": "fenv_record",
                            "tagUsed": "struct",
                            "completeDefinition": True,
                            "loc": {
                                "file": str(tree / "bits" / "fenv.h"),
                                "includedFrom": {"file": included_from},
                                "line": 1,
                                "col": 1,
                            },
                        }
                    ],
                }

            candidate_records = MATRIX.direct_records(ast(candidate, str(candidate / "fenv.h")), candidate, "fenv.h")
            reference_records = MATRIX.direct_records(ast(reference, str(reference / "fenv.h")), reference, "fenv.h")
            self.assertEqual([record.key for record in candidate_records], ["struct:fenv_record"])
            self.assertEqual([record.key for record in reference_records], ["struct:fenv_record"])
            self.assertEqual(
                MATRIX.compare_records(
                    [{"key": record.key, "tag": record.tag, "name": record.name, "alias": record.alias, "applicability": "applicable", "size": 1, "alignment": 1, "fields": []} for record in candidate_records],
                    [{"key": record.key, "tag": record.tag, "name": record.name, "alias": record.alias, "applicability": "applicable", "size": 1, "alignment": 1, "fields": []} for record in reference_records],
                )["incompatible_count"],
                0,
            )
            transitive = MATRIX.direct_records(ast(candidate, str(candidate / "stdio.h")), candidate, "fenv.h")
            self.assertEqual(transitive, [])

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

    def test_report_validation_rejects_reference_record_schema_drift(self) -> None:
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        changed = copy.deepcopy(report)
        row = next(row for row in changed["rows"] if row["reference_records"])
        record = next(record for record in row["reference_records"] if record["applicability"] == "applicable")
        record["size"] = None
        with self.assertRaisesRegex(MATRIX.RecordLayoutMatrixError, "reference record.*size"):
            MATRIX.validate_checked_report(changed, MATRIX.load_contract())

    def test_report_validation_recomputes_differences_and_summary_counts(self) -> None:
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        changed = copy.deepcopy(report)
        row = next(row for row in changed["rows"] if row["comparison"] in {"matched", "mismatch"})
        row["difference"]["matched_count"] += 1
        with self.assertRaisesRegex(MATRIX.RecordLayoutMatrixError, "difference counts"):
            MATRIX.validate_checked_report(changed, MATRIX.load_contract())

        changed = copy.deepcopy(report)
        changed["summary"]["reference_record_count"] += 1
        with self.assertRaisesRegex(MATRIX.RecordLayoutMatrixError, "summary counts"):
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
