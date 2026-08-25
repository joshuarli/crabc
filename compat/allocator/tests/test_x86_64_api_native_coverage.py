#!/usr/bin/env python3
"""Pure-Python tests for the selected-release x86 API symbol assessment."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_api_native_coverage.py"
SPEC = importlib.util.spec_from_file_location("x86_64_api_native_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COVERAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COVERAGE
SPEC.loader.exec_module(COVERAGE)


def sorted_digest(names: list[str]) -> str:
    return hashlib.sha256("\n".join(names).encode()).hexdigest()


class NativeApiCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release_schema = COVERAGE.release_evidence.load_schema()
        cls.source_inventory = COVERAGE.release_evidence.load_source_symbol_inventory(
            cls.release_schema
        )

    def release_fixture(self) -> tuple[dict[str, object], dict[str, object]]:
        """Return a valid small synthetic symbol report and matching schema.

        The fixture keeps the checked-in source ledgers real while replacing
        the 225-name object inventory with 190 source functions plus 35
        private names.  This exercises presence/absence logic without making
        this pure-Python test duplicate a native report's full symbol list.
        """

        schema = copy.deepcopy(self.release_schema)
        dynamic = list(self.source_inventory["expected_dynamic_names"])
        object_names = sorted(dynamic + [f"mi_private_fixture_{i:02d}" for i in range(35)])
        schema["object_global_mi_symbol_inventory"] = {
            "meaning": COVERAGE.release_evidence.OBJECT_INVENTORY_MEANING,
            "count": len(object_names),
            "sorted_names_sha256": sorted_digest(object_names),
        }
        source_report = {
            "base_header": {
                key: value
                for key, value in self.source_inventory["base_header"].items()
                if key != "names"
            },
            "statistics_header": {
                key: value
                for key, value in self.source_inventory["statistics_header"].items()
                if key != "names"
            },
            "normal_release_exceptions": self.source_inventory["normal_release_exceptions"],
            "source_union_count": self.source_inventory["source_union_count"],
            "expected_dynamic_count": self.source_inventory["expected_dynamic_count"],
            "expected_dynamic_names_sha256": self.source_inventory[
                "expected_dynamic_names_sha256"
            ],
        }
        report = {
            "format": 1,
            "schema": schema["schema"],
            "status": "passed",
            "provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
            "target": copy.deepcopy(COVERAGE.EXPECTED_TARGET),
            "upstream": {
                **COVERAGE.EXPECTED_UPSTREAM,
                "archive_sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
            },
            "profile": COVERAGE.EXPECTED_PROFILE,
            "release_selection": copy.deepcopy(COVERAGE._expected_release_selection(schema)),
            "build": {
                "shared_command": ["musl-gcc", "-shared"],
                "mode_probe_command": ["musl-gcc", "-c", "mode-probe.c"],
                "object_commands": [["musl-gcc", "-c", "alloc.c"]],
                "elf": {
                    "class": "ELF64",
                    "endianness": "little",
                    "machine": "Advanced Micro Devices X86-64",
                },
            },
            "symbols": {
                "object_global_mi_inventory": schema["object_global_mi_symbol_inventory"],
                "dynamic_default_visible_mi_inventory": schema[
                    "dynamic_default_visible_mi_symbol_inventory"
                ],
                "object_global_defined_mi": object_names,
                "dynamic_default_visible_mi": dynamic,
            },
            "source_declaration_inventory": source_report,
            "scope": copy.deepcopy(schema["scope"]),
        }
        return report, schema

    @staticmethod
    def use_release_schema(schema: dict[str, object]):
        """Keep synthetic symbol inventories behind the production loader seam."""

        return mock.patch.object(COVERAGE.release_evidence, "load_schema", return_value=schema)

    def test_schema_is_native_only_and_does_not_promote_api_or_runtime_support(self) -> None:
        schema = COVERAGE.load_schema()
        self.assertEqual(schema["target"], COVERAGE.EXPECTED_TARGET)
        self.assertEqual(schema["profile"], COVERAGE.EXPECTED_PROFILE)
        self.assertFalse(schema["scope"]["behavior_claimed"])
        self.assertFalse(schema["scope"]["rust_implementation_claimed"])
        self.assertFalse(schema["scope"]["public_runtime_or_api_compatibility"])
        self.assertFalse(schema["scope"]["public_crabc_support"])
        self.assertEqual(schema["classification"]["non_object_source_form"], "not-an-object-symbol")

    def test_schema_rejects_boolean_integer_and_scope_type_aliases(self) -> None:
        schema = COVERAGE.load_schema()
        schema["format"] = True
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as temporary:
            json.dump(schema, temporary)
            temporary.flush()
            with mock.patch.object(COVERAGE, "SCHEMA_PATH", Path(temporary.name)):
                with self.assertRaisesRegex(COVERAGE.CoverageError, "unsupported"):
                    COVERAGE.load_schema()

        schema = COVERAGE.load_schema()
        schema["scope"]["behavior_claimed"] = 0
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as temporary:
            json.dump(schema, temporary)
            temporary.flush()
            with mock.patch.object(COVERAGE, "SCHEMA_PATH", Path(temporary.name)):
                with self.assertRaisesRegex(COVERAGE.CoverageError, "scope boundary"):
                    COVERAGE.load_schema()

    def test_assessment_records_function_presence_and_non_object_source_forms(self) -> None:
        report, schema = self.release_fixture()
        with self.use_release_schema(schema):
            result = COVERAGE.assess(report)
        self.assertEqual(result["target"], COVERAGE.EXPECTED_TARGET)
        self.assertEqual(result["normal_release_selection"], report["release_selection"])
        self.assertEqual(result["summary"]["source_declared_function_count"], 194)
        self.assertEqual(result["summary"]["object_symbol_function_present"], 190)
        self.assertEqual(result["summary"]["dynamic_symbol_function_present"], 190)
        self.assertGreater(result["summary"]["not_an_object_symbol_item_count"], 0)

        functions = [item for item in result["items"] if item["kind"] == "source-declared-c-function"]
        self.assertEqual(len(functions), 194)
        self.assertEqual(
            next(item for item in functions if item["name"] == "mi_malloc_size")["dynamic_symbol"],
            "absent",
        )
        self.assertEqual(
            next(item for item in functions if item["name"] == "mi_malloc")["classification"],
            "object-symbol",
        )
        non_objects = [item for item in result["items"] if item["classification"] == "not-an-object-symbol"]
        self.assertTrue(non_objects)
        self.assertTrue(
            all(
                item["object_symbol"] == "not-an-object-symbol"
                and item["dynamic_symbol"] == "not-an-object-symbol"
                for item in non_objects
            )
        )

    def test_report_rejects_wrong_release_identity_and_selection(self) -> None:
        mutations = (
            (lambda report: report.update({"format": True}), "pinned release-evidence"),
            (lambda report: report.update({"status": "passed-with-warnings"}), "passed native release"),
            (lambda report: report["target"].update({"architecture": "aarch64"}), "target or profile"),
            (lambda report: report["upstream"].update({"revision": "forged"}), "upstream pin"),
            (lambda report: report["release_selection"]["target_mode_assertions"].append("__aarch64__"), "target/mode"),
            (lambda report: report["build"]["elf"].update({"machine": "AArch64"}), "ELF identity"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                report, schema = self.release_fixture()
                mutate(report)
                with self.use_release_schema(schema):
                    with self.assertRaisesRegex(COVERAGE.CoverageError, message):
                        COVERAGE.validate_release_report(report)

    def test_report_rejects_forged_symbol_list_and_pinned_source_inventory(self) -> None:
        report, schema = self.release_fixture()
        report["symbols"]["dynamic_default_visible_mi"] = report["symbols"][
            "dynamic_default_visible_mi"
        ][:-1]
        with self.use_release_schema(schema):
            with self.assertRaisesRegex(COVERAGE.CoverageError, "dynamic symbols"):
                COVERAGE.validate_release_report(report)

        report, schema = self.release_fixture()
        report["source_declaration_inventory"]["source_union_count"] += 1
        with self.use_release_schema(schema):
            with self.assertRaisesRegex(COVERAGE.CoverageError, "source declaration inventory"):
                COVERAGE.validate_release_report(report)

        api = json.loads(COVERAGE.release_evidence.SOURCE_API_PATH.read_text(encoding="utf-8"))
        api["declarations"][0]["name"] = "mi_forged_source_item"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as temporary:
            json.dump(api, temporary)
            temporary.flush()
            report, schema = self.release_fixture()
            with self.use_release_schema(schema):
                with mock.patch.object(
                    COVERAGE.release_evidence, "SOURCE_API_PATH", Path(temporary.name)
                ):
                    with self.assertRaisesRegex(COVERAGE.CoverageError, "declaration digest"):
                        COVERAGE.validate_release_report(report)

    def test_assessment_rejects_source_form_ledger_digest_drift(self) -> None:
        coverage = json.loads(
            COVERAGE.release_evidence.SOURCE_COVERAGE_PATH.read_text(encoding="utf-8")
        )
        coverage["header_surfaces"][0]["macro_definitions"][0]["name"] = "forged_macro"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as temporary:
            json.dump(coverage, temporary)
            temporary.flush()
            report, schema = self.release_fixture()
            with self.use_release_schema(schema):
                with mock.patch.object(
                    COVERAGE.release_evidence, "SOURCE_COVERAGE_PATH", Path(temporary.name)
                ):
                    with self.assertRaisesRegex(
                        COVERAGE.CoverageError, "source inventory file digest"
                    ):
                        COVERAGE.assess(report)

    def test_build_requires_native_provenance_before_writing_assessment(self) -> None:
        report, _schema = self.release_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            release_path = Path(temporary) / "release.json"
            output_path = Path(temporary) / "assessment.json"
            release_path.write_text(json.dumps(report), encoding="utf-8")
            with mock.patch.object(
                COVERAGE.release_evidence,
                "require_native_x86_64",
                side_effect=COVERAGE.release_evidence.EvidenceError("native provenance required"),
            ):
                with self.assertRaisesRegex(COVERAGE.CoverageError, "native provenance required"):
                    COVERAGE.build(release_report_path=release_path, report_path=output_path)
            self.assertFalse(output_path.exists())

    def test_build_rejects_release_provenance_from_another_launcher_run(self) -> None:
        report, schema = self.release_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            release_path = Path(temporary) / "release.json"
            output_path = Path(temporary) / "assessment.json"
            release_path.write_text(json.dumps(report), encoding="utf-8")
            with self.use_release_schema(schema):
                with mock.patch.object(
                    COVERAGE.release_evidence,
                    "require_native_x86_64",
                    return_value={"execution_mode": "native", "host_architecture": "amd64"},
                ):
                    with self.assertRaisesRegex(
                        COVERAGE.CoverageError, "does not match this native run"
                    ):
                        COVERAGE.build(release_report_path=release_path, report_path=output_path)
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
