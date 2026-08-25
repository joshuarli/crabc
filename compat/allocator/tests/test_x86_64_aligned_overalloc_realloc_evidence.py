#!/usr/bin/env python3
"""Pure contract tests for private native x86-64 aligned realloc evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_aligned_overalloc_realloc_evidence.py"
spec = importlib.util.spec_from_file_location("aligned_overalloc_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_private_native_scope_geometry_and_rust_selection(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(schema["target"], evidence.EXPECTED_TARGET)
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["scope"], evidence.EXPECTED_SCOPE)
        self.assertTrue(schema["scope"]["ordinary_arena_backed_offset_aligned_request_only"])
        self.assertFalse(schema["scope"]["public_x86_libc_or_ldso_support"])
        self.assertEqual(schema["rust_test"]["test_filter"], evidence.RUST_TEST_FILTER)
        self.assertEqual(schema["trace"]["expected_values"]["trace.aligned_overalloc.adjust"], 57)
        self.assertEqual(schema["trace"]["expected_values"]["trace.aligned_overalloc.growth_usable"], 103)
        self.assertEqual(schema["c_probe_sha256"], evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()))

    def test_schema_rejects_scope_trace_anchor_or_format_drift(self):
        mutations = (
            (lambda value: value["scope"].update({"public_x86_libc_or_ldso_support": True}), "checked-in schema drifted"),
            (lambda value: value["trace"]["expected_values"].update({"trace.aligned_overalloc.valid": 0}), "checked-in schema drifted"),
            (lambda value: value["source_anchors"][0].update({"sha256": "0" * 64}), "checked-in schema drifted"),
            (lambda value: value.update({"format": True}), "checked-in schema drifted"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as stream:
                    json.dump(value, stream)
                    stream.flush()
                    with self.assertRaisesRegex(evidence.EvidenceError, message):
                        evidence.load_schema(Path(stream.name))


class CommandAndTraceTests(unittest.TestCase):
    def test_c_command_retains_fixed_release_pthread_and_tls_selection(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/aligned-overalloc-realloc-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command("/usr/bin/musl-gcc", source, temporary / "aligned-overalloc-realloc.c", temporary / "aligned-overalloc-realloc-c", schema)
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(evidence.normalize_command(command, temporary, source), schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-pthread"], schema)

    def test_trace_parser_requires_the_exact_address_independent_record(self):
        trace = evidence.parse_trace("\n".join([evidence.TRACE_BEGIN, *(f"{key}={value}" for key, value in evidence.EXPECTED_TRACE_VALUES.items()), evidence.TRACE_END]), description="test trace")
        evidence.validate_trace(trace, description="test trace")
        self.assertEqual(evidence.compare_traces(trace, trace)["status"], "matched")
        with self.assertRaisesRegex(evidence.EvidenceError, "raw address"):
            evidence.parse_trace(f"{evidence.TRACE_BEGIN}\ntrace.aligned_overalloc.pointer=0x1\n{evidence.TRACE_END}", description="test trace")
        changed = dict(trace)
        changed["trace.aligned_overalloc.valid"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "value mismatches"):
            evidence.validate_trace(changed, description="test trace")


class ReportTests(unittest.TestCase):
    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/aligned-overalloc-realloc-evidence")
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": evidence.normalize_command(evidence.c_trace_command("/usr/bin/musl-gcc", temporary / "source/mimalloc-3.5.0", temporary / "aligned-overalloc-realloc.c", temporary / "aligned-overalloc-realloc-c", schema), temporary, temporary / "source/mimalloc-3.5.0"),
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": ["<temporary-evidence-root>/aligned-overalloc-realloc-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
                "trace": trace,
            },
            rust_probe={
                "cargo_command": evidence.normalize_command(evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"), temporary, None),
                "lockfile": {"path": evidence.relative(evidence.LOCKFILE), "sha256": evidence.sha256_file(evidence.LOCKFILE)},
                "passed_test_count": 1,
                "source": {"path": evidence.relative(evidence.RUST_TEST_SOURCE), "sha256": evidence.sha256_file(evidence.RUST_TEST_SOURCE)},
                "target_dir": {"isolated": True, "retained": False, "value": "<temporary-evidence-root>/rust-target"},
                "trace": trace,
            },
        )

    def test_report_is_private_and_binds_both_probe_identities(self):
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["comparison"], {"compared_value_count": 29, "status": "matched"})
        self.assertTrue(report["scope"]["terminal_arena_release_only"])
        self.assertFalse(report["scope"]["public_crabc_support"])
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])

    def test_report_rejects_weakened_elf_rust_or_scope_evidence(self):
        report = self.complete_report()
        mutations = (
            (lambda value: value["c_probe"].update({"elf": {}}), "C identity"),
            (lambda value: value["rust_probe"]["cargo_command"].remove("--locked"), "Rust command drifted"),
            (lambda value: value["scope"].update({"terminal_arena_release_only": False}), "private boundary"),
            (lambda value: value["rust_probe"].update({"passed_test_count": True}), "Rust test selection"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                weakened = copy.deepcopy(report)
                mutate(weakened)
                with self.assertRaisesRegex(evidence.EvidenceError, message):
                    evidence.validate_report(weakened)


if __name__ == "__main__":
    unittest.main()
