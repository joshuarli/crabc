#!/usr/bin/env python3
"""Focused drift and schema tests for the routine x86 C ABI evidence matrix."""

from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "generate_c_abi_evidence_matrix.py"
SPEC = importlib.util.spec_from_file_location("x86_c_abi_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
matrix = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = matrix
SPEC.loader.exec_module(matrix)


class X86RoutineCAbiEvidenceMatrixTests(unittest.TestCase):
    def document(self) -> dict[str, object]:
        return copy.deepcopy(matrix.load_toml(matrix.MATRIX_PATH))

    @staticmethod
    def row(document: dict[str, object], identifier: str) -> dict[str, object]:
        rows = document["row"]
        assert isinstance(rows, list)
        for row in rows:
            assert isinstance(row, dict)
            if row["id"] == identifier:
                return row
        raise AssertionError(f"missing row {identifier}")

    def test_checked_in_matrix_and_generated_outputs_are_drift_free(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("2 rows", completed.stdout)

    def test_routine_template_drives_all_repeated_evidence_edges(self) -> None:
        outputs = matrix.build_outputs(self.document())
        base = matrix.GENERATED_DIRECTORY / "getpagesize-noarg-scalar"
        c_probe = outputs[base / "header_probe.c"]
        cxx_probe = outputs[base / "header_probe.cpp"]
        start = outputs[base / "start.S"]
        runner = outputs[base / "run.sh"]
        report = outputs[matrix.GENERATED_DIRECTORY / "report.json"]

        self.assertIn("__builtin_types_compatible_p", c_probe)
        self.assertIn("typedef int (*crabc_getpagesize_noarg_scalar_signature)(void);", c_probe)
        self.assertIn("getpagesize C declaration", c_probe)
        self.assertIn("__is_same", cxx_probe)
        self.assertIn("getpagesize C++ declaration", cxx_probe)
        self.assertIn("call getpagesize", start)
        self.assertIn("../../../../..", runner)
        self.assertIn("run_getpagesize_header_abi.sh", runner)
        self.assertIn("run_libc_getpagesize.sh", runner)
        self.assertIn("oracle_candidate_build_run_and_export_check", report)
        self.assertIn("ledger_fields", report)
        self.assertIn("campaign-family libc.posix-runtime", report)

    def test_template_escape_requires_a_nonempty_bespoke_reason(self) -> None:
        document = self.document()
        row = self.row(document, "getpagesize-noarg-scalar")
        del row["template"]
        with self.assertRaisesRegex(matrix.MatrixError, "bespoke_reason"):
            matrix.build_outputs(document)

        row["bespoke_reason"] = "A future variadic or lifetime-sensitive contract cannot use the no-argument scalar template."
        row["bespoke_class"] = "variadic-calling-convention"
        with self.assertRaisesRegex(matrix.MatrixError, "cannot bypass the routine template"):
            matrix.build_outputs(document)

    def test_exports_and_capability_ownership_are_validated_against_authority(self) -> None:
        document = self.document()
        row = self.row(document, "gethostid-noarg-scalar")
        row["expected_exports"] = ["gethostid_not_exported"]
        with self.assertRaisesRegex(matrix.MatrixError, "expected_exports"):
            matrix.build_outputs(document)

        document = self.document()
        row = self.row(document, "gethostid-noarg-scalar")
        row["owner_family"] = "libc.c-abi-compat"
        with self.assertRaisesRegex(matrix.MatrixError, "does not own"):
            matrix.build_outputs(document)

    def test_output_checker_rejects_a_changed_generated_probe(self) -> None:
        outputs = matrix.build_outputs(self.document())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix.write_outputs(outputs, root)
            changed = root / matrix.GENERATED_DIRECTORY / "gethostid-noarg-scalar" / "header_probe.c"
            changed.write_text("stale generated output\n", encoding="utf-8")
            with self.assertRaisesRegex(matrix.MatrixError, "output drifted"):
                matrix.check_outputs(outputs, root)


if __name__ == "__main__":
    unittest.main()
