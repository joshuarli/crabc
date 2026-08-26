#!/usr/bin/env python3
"""Contract tests for the dynamic nonfull distinct-bin aggregate lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_dynamic_nonfull_regular_pages_distinct_bin_aggregate_evidence.py"
spec = importlib.util.spec_from_file_location("dynamic_nonfull_regular_pages_distinct_bin_aggregate", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_the_exact_two_page_dynamic_lifecycle(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        values = schema["trace"]["expected_values"]
        prefix = "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate."
        self.assertEqual(len(values), 43)
        self.assertEqual(values[f"{prefix}full_retain_two"], 1)
        self.assertEqual(values[f"{prefix}distinct_bins"], 1)
        self.assertEqual(values[f"{prefix}producer_joined_before_consumer_frees"], 1)
        self.assertEqual(values[f"{prefix}page0.dynamic_abandoned_count_one_after_thread_done"], 1)
        self.assertEqual(values[f"{prefix}page1.dynamic_abandoned_count_one_after_thread_done"], 1)
        self.assertEqual(values[f"{prefix}second_dynamic_abandoned_count_zero_after_second_free"], 1)
        self.assertEqual(values[f"{prefix}first_dynamic_abandoned_count_one_after_second_free"], 1)
        self.assertEqual(values[f"{prefix}first_dynamic_abandoned_count_zero_after_final_free"], 1)
        self.assertEqual(values[f"{prefix}first_page_map_all_slices_unregistered_after_final_free"], 1)
        self.assertTrue(schema["scope"]["c_oracle_dynamic_heap_new_in_arena_only"])
        self.assertTrue(schema["scope"]["c_oracle_full_retain_two_only"])
        self.assertTrue(schema["scope"]["c_oracle_real_thread_exit_and_join_required"])
        self.assertTrue(schema["scope"]["c_oracle_second_then_first_sequential_frees_only"])
        self.assertFalse(schema["scope"]["rust_real_thread_or_join_claimed"])
        self.assertEqual(
            schema["tls"],
            {
                "compiler_model": "initial-exec",
                "mimalloc_model": "MI_TLS_MODEL_LOCAL",
                "thread_pointer_path": "x86_64-fs-tls-slot-fallback",
            },
        )
        self.assertEqual(
            schema["rust_test"]["test_filter"],
            "dynamic_theap::tests::"
            "x86_64_dynamic_nonfull_regular_pages_distinct_bin_aggregate_trace_matches_pinned_c",
        )

    def test_schema_rejects_hash_scope_trace_and_target_drift(self):
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update({"c_oracle_full_retain_two_only": False}),
            lambda value: value["scope"].update({"rust_real_thread_or_join_claimed": True}),
            lambda value: value["tls"].update({"mimalloc_model": "MI_TLS_MODEL_PTHREADS"}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.valid": 0}
            ),
            lambda value: value["rust_test"].update({"target_arch": "aarch64"}),
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


class TraceAndCommandTests(unittest.TestCase):
    def test_trace_requires_the_exact_43_logical_values(self):
        trace = copy.deepcopy(evidence.EXPECTED_TRACE_VALUES)
        evidence.validate_trace(trace, description="complete dynamic aggregate trace")
        for mutate in (
            lambda value: value.pop(
                "trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.page1.used_one_after_thread_done"
            ),
            lambda value: value.update({"trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.extra": 1}),
            lambda value: value.update(
                {"trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.valid": True}
            ),
            lambda value: value.update(
                {"trace.dynamic_nonfull_regular_pages_distinct_bin_aggregate.route_empty_after_final_free": 0}
            ),
        ):
            value = copy.deepcopy(trace)
            mutate(value)
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_trace(value, description="mutated dynamic aggregate trace")

    def test_c_command_requires_native_pthread_tls_contract(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-nonfull-regular-pages-distinct-bin-aggregate-command")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / f"{evidence.STEM}.c",
            temporary / f"{evidence.STEM}-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-pthread"], schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-ftls-model=initial-exec"], schema)

    def test_probe_keeps_the_real_worker_lifecycle_and_safe_post_free_reads(self):
        probe = evidence.C_TRACE_PROBE
        self.assertIn("mi_heap_new_in_arena(fixture->arena_id)", probe)
        self.assertIn("mi_option_set(mi_option_page_full_retain, 2);", probe)
        self.assertIn("mi_thread_done();", probe)
        self.assertIn("pthread_join(producer, NULL)", probe)
        self.assertIn("mi_free(fixture.blocks[1]);", probe)
        self.assertIn("mi_free(fixture.blocks[0]);", probe)
        self.assertIn("page_map_span_has_members", probe)
        self.assertIn("page_map_span_is_clear", probe)
        self.assertIn("pages_abandoned", probe)
        self.assertIn("abandoned_count", probe)
        self.assertNotIn("mi_heap_collect(", probe)
        join = probe.index("if (pthread_join(producer, NULL) != 0) goto output;")
        second_free = probe.index("mi_free(fixture.blocks[1]);")
        first_free = probe.index("mi_free(fixture.blocks[0]);")
        self.assertLess(join, second_free)
        self.assertLess(second_free, first_free)
        after_second = probe[second_free:first_free]
        self.assertNotIn("fixture.pages[1]->", after_second)
        after_first = probe[first_free:]
        self.assertNotIn("fixture.pages[0]->", after_first)

    def test_report_construction_is_repeatable_and_schema_locked(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-nonfull-regular-pages-distinct-bin-aggregate-report")
        source = temporary / "source/mimalloc-3.5.0"
        build_command = evidence.normalize_command(
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
        trace = copy.deepcopy(schema["trace"]["expected_values"])
        c_probe = {
            "build_command": build_command,
            "elf": {
                "class": "ELF64",
                "endianness": "little",
                "machine": "Advanced Micro Devices X86-64",
            },
            "run_command": [f"{evidence.NORMALIZED_EVIDENCE_ROOT}/{evidence.STEM}-c"],
            "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode("utf-8")),
            "trace": trace,
        }
        rust_probe = {
            "cargo_command": [
                "cargo", "test", "--locked", "--target", evidence.TARGET,
                "--target-dir", f"{evidence.NORMALIZED_EVIDENCE_ROOT}/rust-target",
                "-p", "crabc-mimalloc", "--lib", "--no-default-features",
                evidence.RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1",
            ],
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
            "trace": copy.deepcopy(trace),
        }
        first = evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe=c_probe,
            rust_probe=rust_probe,
        )
        second = evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe=c_probe,
            rust_probe=rust_probe,
        )
        self.assertEqual(first, second)
        malformed = copy.deepcopy(first)
        malformed["c_probe"]["run_command"] = ["wrong"]
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(malformed)

    def test_native_gate_rejects_non_native_provenance(self):
        with mock.patch.object(
            evidence.RUNNER,
            "require_native_x86_64",
            side_effect=evidence.RUNNER.HarnessError("native x86-64 required"),
        ):
            with self.assertRaisesRegex(evidence.EvidenceError, "native x86-64 required"):
                evidence.require_native_x86_64()


if __name__ == "__main__":
    unittest.main()
