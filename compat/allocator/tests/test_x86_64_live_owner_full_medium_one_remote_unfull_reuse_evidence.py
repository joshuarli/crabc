#!/usr/bin/env python3
"""Static contracts for the live-owner one-remote unfull/reuse oracle lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_live_owner_full_medium_one_remote_unfull_reuse_evidence.py"
spec = importlib.util.spec_from_file_location("crabc_x86_64_live_owner_one_remote", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_freezes_the_compact_43_fact_boundary(self):
        schema = evidence.load_schema()
        self.assertTrue(evidence.exactly_matches(schema, evidence._schema_template()))
        self.assertEqual(
            schema["harness_dependency"],
            {
                "path": evidence.relative(evidence.BASE_PATH),
                "sha256": evidence.sha256_file(evidence.BASE_PATH),
            },
        )
        values = schema["trace"]["expected_values"]
        self.assertEqual(len(values), 43)
        self.assertEqual(values[evidence.PREFIX + "request"], 10248)
        self.assertEqual(values[evidence.PREFIX + "block_size"], 12288)
        self.assertEqual(values[evidence.PREFIX + "capacity"], 42)
        self.assertEqual(values[evidence.PREFIX + "reserved"], 42)
        self.assertEqual(values[evidence.PREFIX + "slice_count"], 8)
        self.assertEqual(values[evidence.PREFIX + "first_used_after_collect"], 41)
        self.assertEqual(values[evidence.PREFIX + "regular_queue_count_after_collect"], 2)
        self.assertEqual(values[evidence.PREFIX + "predecessor_exhausted_before_reuse"], 1)
        self.assertEqual(values[evidence.PREFIX + "reused_exact_remote_block"], 1)
        self.assertTrue(schema["scope"]["c_oracle_real_pthread_required"])
        self.assertTrue(schema["scope"]["c_oracle_no_thread_teardown"])
        self.assertFalse(schema["scope"]["emulation_accepted"])

    def test_schema_rejects_type_scope_pin_and_trace_drift(self):
        mutations = (
            lambda value: value.update({"format": True}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update({"emulation_accepted": 0}),
            lambda value: value["source_anchors"][0].update({"sha256": "0" * 64}),
            lambda value: value["trace"]["expected_values"].update(
                {evidence.PREFIX + "first_used_after_collect": 42}
            ),
            lambda value: value["trace"]["expected_values"].update(
                {evidence.PREFIX + "valid": True}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                schema = evidence.load_schema()
                mutate(schema)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as stream:
                    json.dump(schema, stream)
                    stream.flush()
                    with self.assertRaisesRegex(evidence.EvidenceError, "schema drifted"):
                        evidence.load_schema(Path(stream.name))


class ProbeTests(unittest.TestCase):
    def test_probe_preserves_remote_pointer_until_exact_reuse(self):
        probe = evidence.C_TRACE_PROBE
        worker = probe[probe.index("static void* remote_worker") : probe.index("\nint main(void)")]
        self.assertEqual(worker.count("mi_free(block);"), 1)
        self.assertNotIn("fixture->blocks[0] = NULL", worker)
        self.assertIn("remote_block = fixture.blocks[0];", probe)
        self.assertIn("fixture.blocks[0] = NULL;", probe)
        self.assertLess(
            probe.index("remote_block = fixture.blocks[0];"),
            probe.index("fixture.blocks[0] = NULL;"),
        )
        self.assertIn("first_page->local_free != NULL", probe)
        self.assertIn(
            "first_reusable_after_collect = (first_page->free != NULL || first_page->local_free != NULL);",
            probe,
        )
        self.assertIn(
            "first_free_exact_remote_internal = (first_page->free == remote_block);",
            probe,
        )
        self.assertIn(
            "first_local_free_empty_internal = (first_page->local_free == NULL);",
            probe,
        )
        self.assertIn("reused_exact_remote_block = (reused == remote_block);", probe)
        self.assertIn("while (successor_page->used < successor_page->reserved)", probe)
        self.assertIn("mi_heap_collect(heap, false);", probe)
        self.assertNotIn("mi_thread_done", probe)
        evidence.validate_c_probe_contract(probe)

    def test_probe_validator_rejects_teardown_or_missing_reuse_boundary(self):
        mutations = (
            evidence.C_TRACE_PROBE.replace("mi_heap_collect(heap, false);", "mi_heap_collect(heap, true);", 1),
            evidence.C_TRACE_PROBE.replace("mi_free(block);", "mi_thread_done();", 1),
            evidence.C_TRACE_PROBE.replace(
                "first_free_exact_remote_internal = (first_page->free == remote_block);",
                "first_free_exact_remote_internal = false;",
                1,
            ),
            evidence.C_TRACE_PROBE.replace("reused_exact_remote_block = (reused == remote_block);", "reused_exact_remote_block = false;", 1),
            evidence.C_TRACE_PROBE.replace("while (successor_page->used < successor_page->reserved)", "if (successor_page->used < successor_page->reserved)", 1),
        )
        for probe in mutations:
            with self.subTest(probe=probe):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_c_probe_contract(probe)


class CommandAndTraceTests(unittest.TestCase):
    def test_command_normalization_keeps_exact_native_release_profile(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/live-owner-full-medium-one-remote-unfull-reuse-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "musl-gcc", source, temporary / f"{evidence.STEM}.c", temporary / f"{evidence.STEM}-c", schema
        )
        evidence.validate_c_command(command, schema)
        normalized = evidence.normalize_command(command, temporary, source)
        evidence.validate_normalized_c_command(normalized, schema)
        self.assertEqual(normalized[-3:], ["-pthread", "-o", f"{evidence.NORMALIZED_EVIDENCE_ROOT}/{evidence.STEM}-c"])

    def test_trace_requires_exact_integer_facts(self):
        trace = copy.deepcopy(evidence.EXPECTED_TRACE_VALUES)
        evidence.validate_trace(trace, description="complete trace")
        self.assertEqual(evidence.compare_traces(trace, trace)["compared_value_count"], 43)
        trace[evidence.PREFIX + "reused_exact_remote_block"] = True
        with self.assertRaisesRegex(evidence.EvidenceError, "non-integer"):
            evidence.validate_trace(trace, description="boolean trace")


class ReportTests(unittest.TestCase):
    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/live-owner-full-medium-one-remote-unfull-reuse-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.normalize_command(
            evidence.c_trace_command(
                "musl-gcc",
                source,
                temporary / f"{evidence.STEM}.c",
                temporary / f"{evidence.STEM}-c",
                schema,
            ),
            temporary,
            source,
        )
        rust_command = evidence.normalize_command(
            evidence.rust_trace_command("cargo", temporary / "rust-target"),
            temporary,
            None,
        )
        trace = copy.deepcopy(evidence.EXPECTED_TRACE_VALUES)
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": c_command,
                "elf": copy.deepcopy(evidence.EXPECTED_C_ELF),
                "run_command": [f"{evidence.NORMALIZED_EVIDENCE_ROOT}/{evidence.STEM}-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode("utf-8")),
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
                    "value": f"{evidence.NORMALIZED_EVIDENCE_ROOT}/rust-target",
                },
                "trace": trace,
            },
        )

    def test_report_construction_binds_both_native_probe_records(self):
        report = self.complete_report()
        self.assertEqual(report["comparison"], {"compared_value_count": 43, "status": "matched"})
        evidence.validate_report(report)

    def test_report_rejects_provenance_source_and_trace_drift(self):
        mutations = (
            lambda report: report["provenance"].update({"host_architecture": "aarch64"}),
            lambda report: report["source"].update({"release_flags": []}),
            lambda report: report["c_probe"].update({"source_sha256": "0" * 64}),
            lambda report: report["rust_probe"]["trace"].update(
                {evidence.PREFIX + "reused_exact_remote_block": True}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                report = copy.deepcopy(self.complete_report())
                mutate(report)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_report(report)


if __name__ == "__main__":
    unittest.main()
