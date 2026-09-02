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
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "generate_c_abi_evidence_matrix.py"
SPEC = importlib.util.spec_from_file_location("x86_c_abi_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
matrix = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = matrix
SPEC.loader.exec_module(matrix)


class X86RoutineCAbiEvidenceMatrixTests(unittest.TestCase):
    def document(self) -> dict[str, object]:
        document, _sources = matrix.load_matrix()
        return copy.deepcopy(document)

    @staticmethod
    def sources() -> object:
        _document, sources = matrix.load_matrix()
        return sources

    def build_outputs(self, document: dict[str, object]) -> dict[Path, str]:
        return matrix.build_outputs(document, self.sources())

    @staticmethod
    def fixture_matrix_root(root: Path) -> Path:
        matrix_path = root / "compat" / "x86_64" / "c_abi_evidence_matrix.toml"
        matrix_path.parent.mkdir(parents=True)
        matrix_path.write_text(
            "schema = \"crabc.x86_64-c-abi-evidence-matrix/v1\"\n"
            "target = \"x86_64-unknown-linux-musl\"\n"
            "platform = \"Linux/x86-64 little-endian\"\n"
            "oracle = \"Pinned musl 1.2.6\"\n"
            "\n"
            "[policy]\n"
            "native_execution_only = true\n"
            "public_support = false\n"
            "historical_retrofit_required = false\n"
            "\n"
            "[template.noarg-scalar-static-v1]\n"
            "c_probe = \"prototype-function-pointer\"\n"
            "cxx_probe = \"prototype-function-pointer-c-linkage\"\n"
            "static_entry = \"direct-call-exit\"\n"
            "oracle_candidate = \"existing-focused-runner\"\n"
            "export_check = \"static-c-abi-export-ratchet\"\n"
            "\n"
            "[fragments]\n"
            "directory = \"compat/x86_64/c_abi_evidence_matrix/families\"\n",
            encoding="utf-8",
        )
        return matrix_path

    @staticmethod
    def write_fixture_fragment(
        root: Path,
        filename: str,
        *,
        family_identifier: str = "libc.posix-runtime",
        row_identifier: str = "fixture-row",
        owner_family: str | None = None,
    ) -> Path:
        fragment = root / "compat" / "x86_64" / "c_abi_evidence_matrix" / "families" / filename
        fragment.parent.mkdir(parents=True, exist_ok=True)
        fragment.write_text(
            "schema = \"crabc.x86_64-c-abi-evidence-matrix-family/v1\"\n"
            "\n"
            "[family]\n"
            f"id = \"{family_identifier}\"\n"
            f"aggregate_command = \"./scripts/dev-x86_64.sh routine-c-abi-matrix {family_identifier}\"\n"
            "\n"
            "[[row]]\n"
            f"id = \"{row_identifier}\"\n"
            f"owner_family = \"{owner_family or family_identifier}\"\n",
            encoding="utf-8",
        )
        return fragment

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

    def test_checked_in_matrix_reports_its_fragment_sources(self) -> None:
        document, sources = matrix.load_matrix()
        self.assertEqual([family["id"] for family in document["family"]], ["libc.posix-runtime"])
        self.assertEqual(
            [fragment["path"] for fragment in sources.fragments],
            ["compat/x86_64/c_abi_evidence_matrix/families/libc.posix-runtime.toml"],
        )
        self.assertNotEqual(sources.sha256, sources.root["sha256"])

        report = matrix.generated_report(document, matrix.validate_matrix(document), sources)
        self.assertEqual(report["matrix_source"], sources.root)
        self.assertEqual(report["source_fragments"], list(sources.fragments))
        self.assertEqual(report["matrix_sha256"], sources.sha256)

    def test_fragment_loader_rejects_filename_and_owner_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix_path = self.fixture_matrix_root(root)
            self.write_fixture_fragment(root, "wrong-name.toml")
            with self.assertRaisesRegex(matrix.MatrixError, "filename"):
                matrix.load_matrix(matrix_path, repository_root=root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix_path = self.fixture_matrix_root(root)
            self.write_fixture_fragment(root, "libc.posix-runtime.toml", owner_family="libc.c-abi-compat")
            with self.assertRaisesRegex(matrix.MatrixError, "owner_family"):
                matrix.load_matrix(matrix_path, repository_root=root)

    def test_fragment_loader_rejects_duplicate_row_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix_path = self.fixture_matrix_root(root)
            self.write_fixture_fragment(root, "libc.posix-runtime.toml")
            self.write_fixture_fragment(
                root,
                "libc.c-abi-compat.toml",
                family_identifier="libc.c-abi-compat",
                row_identifier="fixture-row",
            )
            with self.assertRaisesRegex(matrix.MatrixError, "row fixture-row is duplicated"):
                matrix.load_matrix(matrix_path, repository_root=root)

    def test_fragment_loader_rejects_root_records_and_symlinked_fragments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix_path = self.fixture_matrix_root(root)
            matrix_path.write_text(
                matrix_path.read_text(encoding="utf-8")
                + "\n[[family]]\nid = \"libc.posix-runtime\"\n"
                + "aggregate_command = \"./scripts/dev-x86_64.sh routine-c-abi-matrix libc.posix-runtime\"\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(matrix.MatrixError, "shared policy"):
                matrix.load_matrix(matrix_path, repository_root=root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix_path = self.fixture_matrix_root(root)
            fragment = self.write_fixture_fragment(root, "libc.posix-runtime.toml")
            symlink = fragment.with_name("libc.c-abi-compat.toml")
            symlink.symlink_to(fragment.name)
            with self.assertRaisesRegex(matrix.MatrixError, "not a regular file"):
                matrix.load_matrix(matrix_path, repository_root=root)

    def test_fragment_source_digest_covers_fragment_bytes_and_lexical_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix_path = self.fixture_matrix_root(root)
            posix_fragment = self.write_fixture_fragment(root, "libc.posix-runtime.toml")
            self.write_fixture_fragment(
                root,
                "libc.c-abi-compat.toml",
                family_identifier="libc.c-abi-compat",
                row_identifier="compat-row",
            )
            document, first_sources = matrix.load_matrix(matrix_path, repository_root=root)
            self.assertEqual(
                [family["id"] for family in document["family"]],
                ["libc.c-abi-compat", "libc.posix-runtime"],
            )

            posix_fragment.write_text(
                posix_fragment.read_text(encoding="utf-8") + "# source digest regression\n",
                encoding="utf-8",
            )
            _document, second_sources = matrix.load_matrix(matrix_path, repository_root=root)
            self.assertNotEqual(first_sources.sha256, second_sources.sha256)

    def test_routine_template_drives_all_repeated_evidence_edges(self) -> None:
        outputs = self.build_outputs(self.document())
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
        self.assertIn("routine-c-abi-matrix libc.posix-runtime", report)

    def test_family_aggregate_executes_the_checked_generated_runner_registry(self) -> None:
        document = self.document()
        sources = self.sources()
        outputs = matrix.build_outputs(document, sources)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix.write_outputs(outputs, root)
            with mock.patch.object(
                matrix.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0),
            ) as run:
                result = matrix.run_family(document, sources, root, "libc.posix-runtime")

        self.assertEqual(result, 0)
        self.assertEqual(
            [Path(call.args[0][0]).relative_to(root).as_posix() for call in run.call_args_list],
            [
                "compat/x86_64/generated/c_abi_evidence_matrix/getpagesize-noarg-scalar/run.sh",
                "compat/x86_64/generated/c_abi_evidence_matrix/gethostid-noarg-scalar/run.sh",
            ],
        )
        self.assertTrue(all(call.kwargs["cwd"] == matrix.ROOT for call in run.call_args_list))
        self.assertTrue(all(call.kwargs["check"] is False for call in run.call_args_list))

    def test_family_aggregate_rejects_unknown_family_before_running_anything(self) -> None:
        document = self.document()
        sources = self.sources()
        outputs = matrix.build_outputs(document, sources)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix.write_outputs(outputs, root)
            with mock.patch.object(matrix.subprocess, "run") as run:
                with self.assertRaisesRegex(matrix.MatrixError, "unknown matrix family"):
                    matrix.run_family(document, sources, root, "libc.unknown")
        run.assert_not_called()

    def test_family_aggregate_stops_at_the_first_runner_failure(self) -> None:
        document = self.document()
        sources = self.sources()
        outputs = matrix.build_outputs(document, sources)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix.write_outputs(outputs, root)
            with mock.patch.object(
                matrix.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=23),
            ) as run:
                result = matrix.run_family(document, sources, root, "libc.posix-runtime")

        self.assertEqual(result, 23)
        self.assertEqual(run.call_count, 1)

    def test_template_escape_requires_a_nonempty_bespoke_reason(self) -> None:
        document = self.document()
        row = self.row(document, "getpagesize-noarg-scalar")
        del row["template"]
        with self.assertRaisesRegex(matrix.MatrixError, "bespoke_reason"):
            self.build_outputs(document)

        row["bespoke_reason"] = "A future variadic or lifetime-sensitive contract cannot use the no-argument scalar template."
        row["bespoke_class"] = "variadic-calling-convention"
        with self.assertRaisesRegex(matrix.MatrixError, "cannot bypass the routine template"):
            self.build_outputs(document)

    def test_exports_and_capability_ownership_are_validated_against_authority(self) -> None:
        document = self.document()
        row = self.row(document, "gethostid-noarg-scalar")
        row["expected_exports"] = ["gethostid_not_exported"]
        with self.assertRaisesRegex(matrix.MatrixError, "expected_exports"):
            self.build_outputs(document)

        document = self.document()
        row = self.row(document, "gethostid-noarg-scalar")
        row["owner_family"] = "libc.c-abi-compat"
        with self.assertRaisesRegex(matrix.MatrixError, "does not own"):
            self.build_outputs(document)

    def test_output_checker_rejects_a_changed_generated_probe(self) -> None:
        outputs = self.build_outputs(self.document())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix.write_outputs(outputs, root)
            changed = root / matrix.GENERATED_DIRECTORY / "gethostid-noarg-scalar" / "header_probe.c"
            changed.write_text("stale generated output\n", encoding="utf-8")
            with self.assertRaisesRegex(matrix.MatrixError, "output drifted"):
                matrix.check_outputs(outputs, root)


if __name__ == "__main__":
    unittest.main()
