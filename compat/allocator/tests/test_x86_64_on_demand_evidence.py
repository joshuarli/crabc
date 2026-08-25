#!/usr/bin/env python3
"""Pure contracts for private native x86-64 on-demand evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_on_demand_evidence.py"
spec = importlib.util.spec_from_file_location("on_demand_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_oracle_option_scope_and_ordinary_rust_test(self):
        schema = evidence.load_schema()
        self.assertEqual(
            evidence.SCHEMA_PATH,
            ROOT / "compat/allocator/x86_64-on-demand-evidence-v3.5.0.json",
        )
        self.assertEqual(schema["target"], evidence.EXPECTED_TARGET)
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["scope"], evidence.EXPECTED_SCOPE)
        self.assertTrue(schema["scope"]["oracle_option_setup_only"])
        self.assertFalse(schema["scope"]["production_page_on_demand_policy_claimed"])
        self.assertFalse(schema["scope"]["failed_commit_recovery_claimed"])
        self.assertEqual(schema["rust_test"]["test_filter"], evidence.RUST_TEST_FILTER)
        self.assertEqual(schema["c_probe_sha256"], evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()))

    def test_default_schema_load_fails_closed_when_the_checked_in_contract_is_missing(self):
        with mock.patch.object(evidence, "SCHEMA_PATH", ROOT / "missing-on-demand-schema.json"):
            with self.assertRaisesRegex(evidence.EvidenceError, "cannot read"):
                evidence.load_schema()

    def test_schema_rejects_option_scope_geometry_or_anchor_drift(self):
        mutations = (
            (lambda value: value["scope"].update({"oracle_option_setup_only": False}), "private boundary"),
            (lambda value: value["scope"].update({"production_page_on_demand_policy_claimed": True}), "private boundary"),
            (lambda value: value["trace"]["expected_values"].update({"trace.on_demand.post_slice_pcommitted": 7}), "fixed trace"),
            (lambda value: value["source_anchors"][2].update({"sha256": "0" * 64}), "source anchor contract"),
            (lambda value: value.update({"format": True}), "unsupported"),
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
        temporary = Path("/tmp/on-demand-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc", source, temporary / "on-demand.c", temporary / "on-demand-c", schema
        )
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(evidence.normalize_command(command, temporary, source), schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-pthread"], schema)

    def test_trace_parser_requires_exact_address_independent_record(self):
        trace = evidence.parse_trace(
            "\n".join(
                [
                    evidence.TRACE_BEGIN,
                    *(f"{key}={value}" for key, value in evidence.EXPECTED_TRACE_VALUES.items()),
                    evidence.TRACE_END,
                ]
            ),
            description="test trace",
        )
        evidence.validate_trace(trace, description="test trace")
        self.assertEqual(evidence.compare_traces(trace, trace)["status"], "matched")
        changed = dict(trace)
        changed["trace.on_demand.post_slice_pcommitted"] = 7
        with self.assertRaisesRegex(evidence.EvidenceError, "value mismatches"):
            evidence.validate_trace(changed, description="test trace")


class ReportTests(unittest.TestCase):
    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/on-demand-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": evidence.normalize_command(
                    evidence.c_trace_command(
                        "/usr/bin/musl-gcc",
                        source,
                        temporary / "on-demand.c",
                        temporary / "on-demand-c",
                        schema,
                    ),
                    temporary,
                    source,
                ),
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": ["<temporary-evidence-root>/on-demand-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
                "trace": trace,
            },
            rust_probe={
                "cargo_command": evidence.normalize_command(
                    evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"),
                    temporary,
                    None,
                ),
                "lockfile": {
                    "path": evidence.relative(evidence.LOCKFILE),
                    "sha256": evidence.sha256_file(evidence.LOCKFILE),
                },
                "passed_test_count": 1,
                "source": {
                    "path": evidence.relative(evidence.RUST_TEST_SOURCE),
                    "sha256": evidence.sha256_file(evidence.RUST_TEST_SOURCE),
                },
                "target_dir": {
                    "isolated": True,
                    "retained": False,
                    "value": "<temporary-evidence-root>/rust-target",
                },
                "trace": trace,
            },
        )

    def test_report_is_private_and_binds_exact_native_probe_identities(self):
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["comparison"], {"compared_value_count": 23, "status": "matched"})
        self.assertTrue(report["scope"]["oracle_option_setup_only"])
        self.assertFalse(report["scope"]["failed_commit_recovery_claimed"])
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])

    def test_report_rejects_weakened_rust_or_scope_evidence(self):
        report = self.complete_report()
        mutations = (
            (lambda value: value["c_probe"].update({"elf": {}}), "C ELF identity"),
            (lambda value: value["rust_probe"]["cargo_command"].remove("--locked"), "Rust command drifted"),
            (lambda value: value["scope"].update({"oracle_option_setup_only": False}), "source or private boundary"),
            (lambda value: value["rust_probe"].update({"passed_test_count": True}), "Rust selection"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                weakened = copy.deepcopy(report)
                mutate(weakened)
                with self.assertRaisesRegex(evidence.EvidenceError, message):
                    evidence.validate_report(weakened)


class NativeGateTests(unittest.TestCase):
    def test_native_gate_delegates_to_canonical_provenance(self):
        with mock.patch.object(
            evidence.run,
            "require_native_x86_64",
            side_effect=evidence.run.HarnessError("native provenance required"),
        ):
            with self.assertRaisesRegex(evidence.EvidenceError, "native provenance required"):
                evidence.require_native_x86_64()


if __name__ == "__main__":
    unittest.main()
