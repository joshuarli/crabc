#!/usr/bin/env python3
"""Contract tests for native x86-64 small-direct remote evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "compat/allocator/x86_64_direct_remote_evidence.py"
SPEC = importlib.util.spec_from_file_location("crabc_x86_64_direct_remote_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class SchemaTests(unittest.TestCase):
    def test_schema_is_native_private_and_binds_the_complete_pin(self) -> None:
        schema = EVIDENCE.load_schema()
        self.assertEqual(schema["target"], EVIDENCE.EXPECTED_TARGET)
        self.assertEqual(schema["upstream"], EVIDENCE.EXPECTED_UPSTREAM)
        self.assertEqual(schema["scope"], EVIDENCE.EXPECTED_SCOPE)
        self.assertEqual(schema["source_anchors"], [
            {
                "member": member,
                "start_line": start_line,
                "end_line": end_line,
                "sha256": sha256,
            }
            for member, start_line, end_line, sha256 in EVIDENCE.EXPECTED_SOURCE_ANCHORS
        ])
        self.assertEqual(schema["trace"]["expected_values"], EVIDENCE.EXPECTED_TRACE_VALUES)
        self.assertEqual(
            schema["c_probe_sha256"],
            EVIDENCE.sha256_bytes(EVIDENCE.C_TRACE_PROBE.encode("utf-8")),
        )
        self.assertEqual(EVIDENCE.run.load_pin()["sha256"], EVIDENCE.EXPECTED_ARCHIVE_SHA256)

    def test_schema_rejects_private_contract_drift(self) -> None:
        mutations = (
            (lambda schema: schema["scope"].update({"small_direct_route_only": False}), "private boundary"),
            (lambda schema: schema["scope"].update({"public_mi_api_claimed": 0}), "private boundary"),
            (lambda schema: schema["upstream"].update({"revision": "0" * 40}), "upstream"),
            (lambda schema: schema["source_anchors"][2].update({"sha256": "0" * 64}), "source anchor contract"),
            (lambda schema: schema.update({"c_probe_sha256": "0" * 64}), "C probe source hash"),
            (lambda schema: schema.update({"format": True}), "unsupported"),
            (lambda schema: schema.update({"format": 1.0}), "unsupported"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                schema = EVIDENCE.load_schema()
                mutate(schema)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as stream:
                    json.dump(schema, stream)
                    stream.flush()
                    with self.assertRaisesRegex(EVIDENCE.EvidenceError, message):
                        EVIDENCE.load_schema(Path(stream.name))


class CommandAndTraceTests(unittest.TestCase):
    def test_c_command_retains_fixed_release_and_pthread_profile(self) -> None:
        schema = EVIDENCE.load_schema()
        temporary = Path("/tmp/small-direct-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        command = EVIDENCE.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / "small-direct-remote.c",
            temporary / "small-direct-remote-c",
            schema,
        )
        EVIDENCE.validate_c_command(command, schema)
        normalized = EVIDENCE.normalize_command(command, temporary, source)
        EVIDENCE.validate_normalized_c_command(normalized, schema)

        without_pthread = [part for part in command if part != "-pthread"]
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "pthread/TLS mode"):
            EVIDENCE.validate_c_command(without_pthread, schema)

        malformed = list(normalized)
        malformed.remove("-DMI_LIBC_MUSL=1")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "C command drifted"):
            EVIDENCE.validate_normalized_c_command(malformed, schema)

    def test_trace_parser_and_comparator_reject_nonlogical_or_drifting_records(self) -> None:
        trace_lines = [
            EVIDENCE.TRACE_BEGIN,
            *(f"{key}={value}" for key, value in EVIDENCE.EXPECTED_TRACE_VALUES.items()),
            EVIDENCE.TRACE_END,
        ]
        trace = EVIDENCE.parse_trace("\n".join(trace_lines), description="test trace")
        EVIDENCE.validate_trace(trace, description="test trace")
        self.assertEqual(EVIDENCE.compare_traces(trace, trace)["status"], "matched")

        raw_address = "\n".join(
            [EVIDENCE.TRACE_BEGIN, "trace.small_direct_remote.pointer=0x1000", EVIDENCE.TRACE_END]
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "raw address"):
            EVIDENCE.parse_trace(raw_address, description="test trace")

        missing = dict(trace)
        missing.pop("trace.small_direct_remote.valid")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "missing"):
            EVIDENCE.validate_trace(missing, description="test trace")

        different = dict(trace)
        different["trace.small_direct_remote.post_allocate_remote_count"] = 1
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "value mismatches"):
            EVIDENCE.compare_traces(trace, different)


class ReportTests(unittest.TestCase):
    def complete_report(self) -> dict[str, object]:
        schema = EVIDENCE.load_schema()
        temporary = Path("/tmp/small-direct-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = EVIDENCE.normalize_command(
            EVIDENCE.c_trace_command(
                "/usr/bin/musl-gcc",
                source,
                temporary / "small-direct-remote.c",
                temporary / "small-direct-remote-c",
                schema,
            ),
            temporary,
            source,
        )
        rust_command = EVIDENCE.normalize_command(
            EVIDENCE.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"),
            temporary,
            None,
        )
        trace = dict(EVIDENCE.EXPECTED_TRACE_VALUES)
        return EVIDENCE.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=EVIDENCE.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": c_command,
                "elf": EVIDENCE.EXPECTED_C_ELF,
                "run_command": ["<temporary-evidence-root>/small-direct-remote-c"],
                "source_sha256": EVIDENCE.sha256_bytes(EVIDENCE.C_TRACE_PROBE.encode("utf-8")),
                "trace": trace,
            },
            rust_probe={
                "cargo_command": rust_command,
                "lockfile": {
                    "path": EVIDENCE.relative(EVIDENCE.LOCKFILE),
                    "sha256": EVIDENCE.sha256_file(EVIDENCE.LOCKFILE),
                },
                "passed_test_count": 1,
                "source": {
                    "path": EVIDENCE.relative(EVIDENCE.RUST_TEST_SOURCE),
                    "sha256": EVIDENCE.sha256_file(EVIDENCE.RUST_TEST_SOURCE),
                },
                "target_dir": {
                    "isolated": True,
                    "retained": False,
                    "value": "<temporary-evidence-root>/rust-target",
                },
                "trace": trace,
            },
        )

    def test_report_is_private_and_binds_both_probe_identities(self) -> None:
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["comparison"], {"compared_value_count": 28, "status": "matched"})
        self.assertFalse(report["scope"]["public_mi_api_claimed"])
        self.assertTrue(report["scope"]["small_direct_route_only"])
        self.assertEqual(report["source"]["archive_sha256"], EVIDENCE.EXPECTED_ARCHIVE_SHA256)
        self.assertEqual(report["c_probe"]["elf"], EVIDENCE.EXPECTED_C_ELF)
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])

    def test_report_rejects_weakened_c_rust_or_scope_evidence(self) -> None:
        mutations = (
            (lambda report: report["c_probe"].update({"source_sha256": "0" * 64}), "C source hash"),
            (lambda report: report["c_probe"].update({"elf": {}}), "C ELF identity"),
            (lambda report: report["rust_probe"]["cargo_command"].remove("--locked"), "Rust command drifted"),
            (lambda report: report["source"].update({"archive_sha256": "0" * 64}), "archive identity"),
            (lambda report: report["scope"].update({"small_direct_route_only": False}), "source or private boundary"),
            (lambda report: report["scope"].update({"small_direct_route_only": 1}), "source or private boundary"),
            (lambda report: report.update({"format": True}), "format-1"),
            (lambda report: report.update({"format": 1.0}), "format-1"),
            (lambda report: report["rust_probe"].update({"passed_test_count": True}), "Rust selection"),
            (
                lambda report: report["c_probe"]["trace"].update(
                    {"trace.small_direct_remote.valid": True}
                ),
                "non-integer values",
            ),
            (
                lambda report: report["c_probe"]["trace"].update(
                    {"trace.small_direct_remote.valid": 1.0}
                ),
                "non-integer values",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                malformed = copy.deepcopy(self.complete_report())
                mutate(malformed)
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, message):
                    EVIDENCE.validate_report(malformed)


if __name__ == "__main__":
    unittest.main()
