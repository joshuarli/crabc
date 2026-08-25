#!/usr/bin/env python3
"""Pure contracts for the full non-direct-small post-exit x86-64 lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_full_non_direct_small_force_collect_post_exit_evidence.py"
spec = importlib.util.spec_from_file_location("full_non_direct_small_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_the_fixed_full_non_direct_small_protocol(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(len(schema["trace"]["expected_values"]), 25)
        values = schema["trace"]["expected_values"]
        self.assertEqual(values["trace.full_non_direct_small_exit.request_size"], 1032)
        self.assertEqual(values["trace.full_non_direct_small_exit.block_size"], 1280)
        self.assertEqual(values["trace.full_non_direct_small_exit.capacity"], 51)
        self.assertEqual(values["trace.full_non_direct_small_exit.slice_count"], 1)
        self.assertEqual(
            schema["rust_test"],
            {
                "path": "crabc-mimalloc/src/main_heap_page.rs",
                "target_arch": "x86_64",
                "test_filter": (
                    "main_heap_page::tests::"
                    "x86_64_full_non_direct_small_force_collect_post_exit_trace_matches_pinned_c"
                ),
            },
        )
        self.assertTrue(schema["scope"]["one_joined_remote_free_during_thread_exit_only"])
        self.assertTrue(schema["scope"]["sequential_joined_consumer_frees_only"])
        self.assertFalse(schema["scope"]["general_remote_free_routing_claimed"])

    def test_schema_rejects_probe_scope_source_or_rust_selection_drift(self):
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update(
                {"one_joined_remote_free_during_thread_exit_only": False}
            ),
            lambda value: value["source_anchors"][0].update({"sha256": "0" * 64}),
            lambda value: value["rust_test"].update({"path": "crabc-mimalloc/src/single_thread.rs"}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.full_non_direct_small_exit.capacity": 50}
            ),
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
        temporary = Path("/tmp/full-non-direct-small-force-collect-post-exit-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.normalize_command(
            evidence.c_trace_command(
                "/usr/bin/musl-gcc",
                source,
                temporary / "full-non-direct-small-force-collect-post-exit.c",
                temporary / "full-non-direct-small-force-collect-post-exit-c",
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
                    "<temporary-evidence-root>/full-non-direct-small-force-collect-post-exit-c"
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

    def test_c_command_retains_pthread_tls_and_native_oracle_selection(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/full-non-direct-small-command")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / "full-non-direct-small-force-collect-post-exit.c",
            temporary / "full-non-direct-small-force-collect-post-exit-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(
            evidence.normalize_command(command, temporary, source), schema
        )
        weakened = [part for part in command if part != "-pthread"]
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command(weakened, schema)

    def test_parser_requires_an_exact_pointer_free_trace(self):
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
        with self.assertRaisesRegex(evidence.EvidenceError, "raw address"):
            evidence.parse_trace(
                f"{evidence.TRACE_BEGIN}\n"
                "trace.full_non_direct_small_exit.pointer=0x1\n"
                f"{evidence.TRACE_END}",
                description="pointerful trace",
            )

    def test_report_binds_both_probes_and_post_exit_scope(self):
        report = self.complete_report()
        self.assertEqual(report["kind"], evidence.NON_DIRECT_EXIT_KIND)
        self.assertEqual(
            report["comparison"], {"compared_value_count": 25, "status": "matched"}
        )
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])
        weakened = copy.deepcopy(report)
        weakened["scope"]["mapped_process_route_only"] = False
        with self.assertRaisesRegex(evidence.EvidenceError, "private boundary"):
            evidence.validate_report(weakened)


if __name__ == "__main__":
    unittest.main()
