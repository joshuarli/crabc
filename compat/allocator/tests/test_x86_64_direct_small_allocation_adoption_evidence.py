#!/usr/bin/env python3
"""Pure contracts for native x86-64 direct-small adoption evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_direct_small_allocation_adoption_evidence.py"
spec = importlib.util.spec_from_file_location("direct_small_adoption_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_the_private_direct_cache_reclaim_contract(self) -> None:
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(
            schema["c_probe_sha256"],
            evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
        )
        self.assertEqual(schema["rust_test"]["test_filter"], evidence.RUST_TEST_FILTER)
        self.assertTrue(schema["scope"]["direct_small_only"])
        self.assertTrue(schema["scope"]["allocation_time_same_origin_adoption_only"])
        self.assertFalse(schema["scope"]["general_abandonment_or_adoption_claimed"])
        self.assertFalse(schema["scope"]["cross_thread_adoption_claimed"])
        self.assertEqual(
            {
                "trace.direct_small_adoption.direct_range_start": 113,
                "trace.direct_small_adoption.direct_range_end": 128,
                "trace.direct_small_adoption.direct_range_empty_before_allocation": 1,
                "trace.direct_small_adoption.direct_range_restored": 1,
            },
            {
                key: schema["trace"]["expected_values"][key]
                for key in (
                    "trace.direct_small_adoption.direct_range_start",
                    "trace.direct_small_adoption.direct_range_end",
                    "trace.direct_small_adoption.direct_range_empty_before_allocation",
                    "trace.direct_small_adoption.direct_range_restored",
                )
            },
        )

    def test_schema_rejects_scope_probe_and_trace_drift(self) -> None:
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["scope"].update({"direct_small_only": False}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.direct_small_adoption.valid": 0}
            ),
            lambda value: value["source_anchors"][0].update({"sha256": "0" * 64}),
            lambda value: value.update({"format": True}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", encoding="utf-8"
                ) as stream:
                    json.dump(value, stream)
                    stream.flush()
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.load_schema(Path(stream.name))


class CommandAndTraceTests(unittest.TestCase):
    def test_c_command_retains_fixed_release_pthread_and_tls_selection(self) -> None:
        schema = evidence.load_schema()
        temporary = Path("/tmp/direct-small-allocation-adoption-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / "direct-small-allocation-adoption.c",
            temporary / "direct-small-allocation-adoption-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(
            evidence.normalize_command(command, temporary, source), schema
        )
        weakened = [part for part in command if part != "-pthread"]
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command(weakened, schema)

    def test_trace_parser_requires_the_exact_address_free_record(self) -> None:
        trace = evidence.parse_trace(
            "\n".join(
                [
                    evidence.TRACE_BEGIN,
                    *(
                        f"{key}={value}"
                        for key, value in evidence.EXPECTED_TRACE_VALUES.items()
                    ),
                    evidence.TRACE_END,
                ]
            ),
            description="test trace",
        )
        evidence.validate_trace(trace, description="test trace")
        self.assertEqual(evidence.compare_traces(trace, trace)["status"], "matched")
        with self.assertRaisesRegex(evidence.EvidenceError, "raw address"):
            evidence.parse_trace(
                f"{evidence.TRACE_BEGIN}\n"
                "trace.direct_small_adoption.pointer=0x1\n"
                f"{evidence.TRACE_END}",
                description="test trace",
            )
        weakened = dict(trace)
        weakened["trace.direct_small_adoption.valid"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "value mismatches"):
            evidence.validate_trace(weakened, description="test trace")


class ReportTests(unittest.TestCase):
    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/direct-small-allocation-adoption-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.normalize_command(
            evidence.c_trace_command(
                "/usr/bin/musl-gcc",
                source,
                temporary / "direct-small-allocation-adoption.c",
                temporary / "direct-small-allocation-adoption-c",
                schema,
            ),
            temporary,
            source,
        )
        rust_command = evidence.normalize_command(
            evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"),
            temporary,
            None,
        )
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": c_command,
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": [
                    "<temporary-evidence-root>/direct-small-allocation-adoption-c"
                ],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
                "trace": trace,
            },
            rust_probe={
                "cargo_command": rust_command,
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

    def test_report_is_private_and_binds_both_native_probe_identities(self) -> None:
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(
            report["comparison"],
            {
                "compared_value_count": len(evidence.EXPECTED_TRACE_VALUES),
                "status": "matched",
            },
        )
        self.assertTrue(report["scope"]["direct_small_only"])
        self.assertFalse(report["scope"]["general_lifecycle_claimed"])
        self.assertEqual(report["c_probe"]["elf"], evidence.EXPECTED_C_ELF)
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])

    def test_report_rejects_weakened_elf_rust_or_scope_evidence(self) -> None:
        report = self.complete_report()
        mutations = (
            (lambda value: value["c_probe"].update({"elf": {}}), "C ELF identity"),
            (
                lambda value: value["c_probe"].update({"source_sha256": "0" * 64}),
                "C source hash",
            ),
            (
                lambda value: value["rust_probe"]["cargo_command"].remove("--locked"),
                "Rust command drifted",
            ),
            (
                lambda value: value["scope"].update({"direct_small_only": False}),
                "private boundary",
            ),
            (
                lambda value: value["rust_probe"].update({"passed_test_count": True}),
                "Rust selection",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                weakened = copy.deepcopy(report)
                mutate(weakened)
                with self.assertRaisesRegex(evidence.EvidenceError, message):
                    evidence.validate_report(weakened)


if __name__ == "__main__":
    unittest.main()
