#!/usr/bin/env python3
"""Pure contracts for the native x86-64 medium full/retire differential."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_medium_full_retire_evidence.py"
spec = importlib.util.spec_from_file_location("medium_full_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_medium_geometry_and_scope(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(len(schema["trace"]["expected_values"]), 37)
        self.assertEqual(schema["trace"]["expected_values"]["trace.medium_full.capacity"], 42)
        self.assertEqual(
            schema["harness_dependency"],
            {
                "path": "compat/allocator/x86_64_regular_small_evidence.py",
                "sha256": evidence.sha256_file(evidence.BASE_PATH),
            },
        )
        self.assertTrue(schema["scope"]["abandonment_disabled_only"])
        self.assertFalse(schema["scope"]["general_lifecycle_claimed"])

    def test_schema_rejects_probe_scope_or_trace_drift(self):
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update({"abandonment_disabled_only": False}),
            lambda value: value["trace"]["expected_values"].update({"trace.medium_full.valid": 0}),
            lambda value: value["source_anchors"][0].update({"sha256": "0" * 64}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as stream:
                    json.dump(value, stream)
                    stream.flush()
                    with self.assertRaisesRegex(evidence.EvidenceError, "schema drifted"):
                        evidence.load_schema(Path(stream.name))


class TraceAndReportTests(unittest.TestCase):
    def complete_report(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/medium-full-retire-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.normalize_command(
            evidence.c_trace_command("/usr/bin/musl-gcc", source, temporary / "medium-full-retire.c", temporary / "medium-full-retire-c", schema),
            temporary, source,
        )
        rust_command = evidence.normalize_command(
            evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"), temporary, None
        )
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={"build_command": c_command, "elf": evidence.EXPECTED_C_ELF,
                     "run_command": ["<temporary-evidence-root>/medium-full-retire-c"],
                     "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()), "trace": trace},
            rust_probe={"cargo_command": rust_command,
                        "lockfile": {"path": evidence.relative(evidence.LOCKFILE), "sha256": evidence.sha256_file(evidence.LOCKFILE)},
                        "passed_test_count": 1,
                        "source": {"path": evidence.relative(evidence.RUST_TEST_SOURCE), "sha256": evidence.sha256_file(evidence.RUST_TEST_SOURCE)},
                        "target_dir": {"isolated": True, "retained": False, "value": "<temporary-evidence-root>/rust-target"},
                        "trace": trace},
        )

    def test_parser_requires_exact_pointer_free_trace(self):
        trace = evidence.parse_trace(
            "\n".join([evidence.TRACE_BEGIN, *(f"{key}={value}" for key, value in evidence.EXPECTED_TRACE_VALUES.items()), evidence.TRACE_END]),
            description="test trace",
        )
        evidence.validate_trace(trace, description="test trace")
        with self.assertRaisesRegex(evidence.EvidenceError, "raw address"):
            evidence.parse_trace(f"{evidence.TRACE_BEGIN}\ntrace.medium_full.pointer=0x1\n{evidence.TRACE_END}", description="test trace")

    def test_report_binds_both_native_probe_identities(self):
        report = self.complete_report()
        self.assertEqual(report["kind"], evidence.MEDIUM_KIND)
        self.assertEqual(report["comparison"], {"compared_value_count": 37, "status": "matched"})
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])
        weakened = copy.deepcopy(report)
        weakened["scope"]["abandonment_disabled_only"] = False
        with self.assertRaisesRegex(evidence.EvidenceError, "private boundary"):
            evidence.validate_report(weakened)


if __name__ == "__main__":
    unittest.main()
