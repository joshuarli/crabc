#!/usr/bin/env python3
"""Contract tests for the private full-singleton C/Rust differential."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_dynamic_full_singleton_homogeneous_aggregate_evidence.py"
spec = importlib.util.spec_from_file_location("singleton_aggregate_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_two_full_singleton_pages_and_terminal_release(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        values = schema["trace"]["expected_values"]
        prefix = "trace.dynamic_full_singleton_homogeneous_aggregate."
        self.assertEqual(len(values), 51)
        self.assertEqual(values[f"{prefix}page_count"], 2)
        self.assertEqual(values[f"{prefix}full_queue_count_before_thread_done"], 2)
        self.assertEqual(values[f"{prefix}request_size"], 524289)
        self.assertEqual(values[f"{prefix}block_size"], 589824)
        self.assertEqual(values[f"{prefix}capacity"], 1)
        self.assertEqual(values[f"{prefix}reserved"], 1)
        self.assertEqual(values[f"{prefix}slice_count"], 9)
        self.assertEqual(values[f"{prefix}page0.used_after_thread_done"], 1)
        self.assertEqual(values[f"{prefix}page1.used_after_first_terminal"], 1)
        self.assertTrue(schema["scope"]["c_oracle_real_thread_exit_and_join_required"])
        self.assertTrue(schema["scope"]["c_oracle_two_full_singleton_pages_before_thread_done"])
        self.assertTrue(schema["scope"]["c_oracle_independent_singleton_terminal_release_only"])
        self.assertFalse(schema["scope"]["dynamic_abandoned_bitmap_or_count_claimed"])
        self.assertFalse(schema["scope"]["rust_real_thread_or_join_claimed"])
        self.assertEqual(schema["rust_test"]["test_filter"], evidence.RUST_TEST_FILTER)

    def test_schema_rejects_hash_scope_trace_and_lifecycle_drift(self):
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update({"c_oracle_two_full_singleton_pages_before_thread_done": False}),
            lambda value: value["scope"].update({"rust_real_thread_or_join_claimed": True}),
            lambda value: value["tls"].update({"mimalloc_model": "MI_TLS_MODEL_PTHREADS"}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.dynamic_full_singleton_homogeneous_aggregate.page1.used_after_first_terminal": 2}
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

    def test_rust_trace_measures_each_singleton_page_map_span(self):
        source = evidence.RUST_TEST_SOURCE.read_text(encoding="utf-8")
        start = source.index("fn run_dynamic_full_singleton_homogeneous_aggregate_trace")
        end = source.index(
            "\n    #[test]\n    fn dynamic_thread_exit_full_singleton_pages_route_releases_each_same_size_page",
            start,
        )
        helper = source[start:end]
        for fragment in (
            "let page0_map_span = route",
            ".test_page_map_span(first)",
            "let page1_map_span = route",
            ".test_page_map_span(second)",
            "page0_map_span.0 == slice_count",
            "page1_map_span.0 == slice_count",
            "route.test_page_map_range_is_clear(first_span_start, first_span_size)",
            "page1_map_span_after_first_terminal.0 == slice_count",
            "drain.test_page_map_range_is_clear(second_span_start, second_span_size)",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, helper)


class TraceAndCommandTests(unittest.TestCase):
    @staticmethod
    def _report_inputs():
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-full-singleton-homogeneous-aggregate-pure-report")
        source = temporary / "source/mimalloc-3.5.0"
        stem = "dynamic-full-singleton-homogeneous-aggregate"
        c_build = evidence.normalize_command(
            evidence.c_trace_command(
                "musl-gcc",
                source,
                temporary / f"{stem}.c",
                temporary / f"{stem}-c",
                schema,
            ),
            temporary,
            source,
        )
        trace = copy.deepcopy(schema["trace"]["expected_values"])
        c_probe = {
            "build_command": c_build,
            "elf": {
                "class": "ELF64",
                "endianness": "little",
                "machine": "Advanced Micro Devices X86-64",
            },
            "run_command": [f"{evidence.NORMALIZED_EVIDENCE_ROOT}/{stem}-c"],
            "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
            "trace": trace,
        }
        rust_probe = {
            "cargo_command": evidence.normalize_command(
                evidence.rust_trace_command("cargo", temporary / "rust-target"),
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
                "value": f"{evidence.NORMALIZED_EVIDENCE_ROOT}/rust-target",
            },
            "trace": copy.deepcopy(trace),
        }
        return schema, c_probe, rust_probe

    def test_report_construction_and_validation_compare_c_and_rust_without_base_mutation(self):
        schema, c_probe, rust_probe = self._report_inputs()
        base_state = {
            name: getattr(evidence._base, name)
            for name in ("validate_report", "load_schema", "_schema_template")
        }
        args = {
            "schema": schema,
            "provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
            "archive_sha256": evidence.EXPECTED_ARCHIVE_SHA256,
            "anchors": schema["source_anchors"],
            "c_probe": c_probe,
            "rust_probe": rust_probe,
        }
        first = evidence.report_from_results(**args)
        second = evidence.report_from_results(**args)
        self.assertEqual(first, second)
        self.assertEqual(
            first["comparison"],
            {"compared_value_count": len(evidence.EXPECTED_TRACE_VALUES), "status": "matched"},
        )
        for name, value in base_state.items():
            self.assertIs(getattr(evidence._base, name), value)

    def test_report_rejects_structurally_incomplete_or_mismatched_rust_trace(self):
        schema, c_probe, rust_probe = self._report_inputs()
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report({"kind": "incomplete"})
        mismatched = copy.deepcopy(rust_probe)
        mismatched["trace"]["trace.dynamic_full_singleton_homogeneous_aggregate.page1.used_after_first_terminal"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "differs from the fixed singleton trace"):
            evidence.report_from_results(
                schema=schema,
                provenance={"execution_mode": "native", "host_architecture": "x86_64"},
                archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
                anchors=schema["source_anchors"],
                c_probe=c_probe,
                rust_probe=mismatched,
            )

    def test_trace_requires_exact_two_page_shape(self):
        schema = evidence.load_schema()
        trace = copy.deepcopy(schema["trace"]["expected_values"])
        evidence.validate_trace(trace, description="complete singleton trace")
        trace.pop("trace.dynamic_full_singleton_homogeneous_aggregate.page1.used_after_thread_done")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_trace(trace, description="missing singleton field")
        trace = copy.deepcopy(schema["trace"]["expected_values"])
        trace["trace.dynamic_full_singleton_homogeneous_aggregate.page0.used_after_thread_done"] = 2
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_trace(trace, description="wrong singleton state")

    def test_c_command_requires_native_pthread_tls_contract(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-full-singleton-homogeneous-aggregate-command")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / "dynamic-full-singleton-homogeneous-aggregate.c",
            temporary / "dynamic-full-singleton-homogeneous-aggregate-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-pthread"], schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-ftls-model=initial-exec"], schema)

    def test_worker_validator_rejects_shortcuts_and_post_exit_theap_access(self):
        probe = evidence.C_TRACE_PROBE
        for replacement in (
            "mi_free(f->blocks[0]);",
            "mi_heap_collect(f->heap, true);",
            "pthread_exit(NULL);",
            "mi_thread_done(); (void)f->heap;",
            "",
        ):
            with self.subTest(replacement=replacement):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_worker_teardown_source(
                        probe.replace("mi_thread_done();", replacement, 1)
                    )
        source = probe.replace(
            "if (pthread_join(worker, NULL) != 0)",
            "mi_free(f.blocks[0]); if (pthread_join(worker, NULL) != 0)",
            1,
        )
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_worker_teardown_source(source)

    def test_probe_declares_two_page_worker_and_saved_metadata_before_terminal_release(self):
        probe = evidence.C_TRACE_PROBE
        self.assertIn("pthread_create", probe)
        self.assertIn("mi_thread_done()", probe)
        self.assertIn("pthread_join(worker", probe)
        self.assertIn("PAGE_COUNT 2", probe)
        self.assertIn("MI_TLS_MODEL_LOCAL", probe)
        self.assertIn("MI_HAS_TLS_SLOT", probe)
        self.assertIn("slice_indices", probe)
        self.assertNotIn("f->heap", probe)
        self.assertIn("f->arena_pages = arena_pages", probe)
        self.assertLess(
            probe.index("f->arena_pages = arena_pages"),
            probe.index("signal_ready(f, f->setup_valid)"),
        )
        post_thread_done = probe.split("mi_thread_done();", 1)[1]
        self.assertNotIn("_mi_heap_theap(", post_thread_done)
        after_first_terminal = probe.split("mi_free(f.blocks[0]);", 1)[1]
        self.assertNotIn("f.pages[0]->", after_first_terminal)
        self.assertNotIn("f.pages[1]->", after_first_terminal)


if __name__ == "__main__":
    unittest.main()
