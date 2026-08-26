#!/usr/bin/env python3
"""Contract tests for the private homogeneous full-large aggregate lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_dynamic_full_large_homogeneous_aggregate_evidence.py"
spec = importlib.util.spec_from_file_location("dynamic_full_large_homogeneous_aggregate_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_two_full_large_pages_and_active_tls_map(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        values = schema["trace"]["expected_values"]
        prefix = "trace.dynamic_full_large_homogeneous_aggregate."
        self.assertEqual(len(values), 67)
        self.assertEqual(values[f"{prefix}page_count"], 2)
        self.assertEqual(values[f"{prefix}full_queue_count_before_thread_done"], 2)
        self.assertEqual(values[f"{prefix}request_size"], 86706)
        self.assertEqual(values[f"{prefix}block_size"], 98304)
        self.assertEqual(values[f"{prefix}capacity"], 42)
        self.assertEqual(values[f"{prefix}slice_count"], 64)
        self.assertEqual(values[f"{prefix}page0.page_map_slice_count_after_thread_done"], 63)
        self.assertEqual(values[f"{prefix}page1.page_map_slice_count_after_thread_done"], 63)
        self.assertEqual(values[f"{prefix}page0.slice_count_after_thread_done"], 64)
        self.assertEqual(values[f"{prefix}page1.slice_count_after_thread_done"], 64)
        self.assertEqual(values[f"{prefix}page0.used_after_unmapped_prefix"], 37)
        self.assertEqual(values[f"{prefix}page1.used_after_unmapped_prefix"], 37)
        self.assertEqual(values[f"{prefix}page0.used_after_reabandon_boundary"], 36)
        self.assertEqual(values[f"{prefix}page1.used_after_reabandon_boundary"], 36)
        self.assertEqual(values[f"{prefix}page1.page_map_slice_count_after_first_terminal"], 63)
        self.assertEqual(values[f"{prefix}page1.used_after_first_terminal"], 42)
        self.assertTrue(schema["scope"]["c_oracle_two_pages_before_thread_done"])
        self.assertTrue(schema["scope"]["c_oracle_independent_page_release_only"])
        self.assertTrue(schema["scope"]["c_oracle_real_thread_exit_and_join_required"])
        self.assertFalse(schema["scope"]["rust_real_thread_or_join_claimed"])
        self.assertEqual(
            schema["tls"],
            {
                "compiler_model": "initial-exec",
                "mimalloc_model": "MI_TLS_MODEL_LOCAL",
                "thread_pointer_path": "x86_64-fs-tls-slot-fallback",
            },
        )
        self.assertIn(
            {
                "member": "src/page-map.c",
                "start_line": 460,
                "end_line": 465,
                "sha256": "16d731af7789d5a35e755fe6b652b09b97992bfd39a31336778965e9751ac427",
            },
            schema["source_anchors"],
        )
        self.assertNotIn(
            {"member": "src/page-map.c", "start_line": 139, "end_line": 145},
            [{k: v for k, v in anchor.items() if k != "sha256"} for anchor in schema["source_anchors"]],
        )

    def test_schema_rejects_hash_scope_trace_and_lifecycle_drift(self):
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update({"c_oracle_two_pages_before_thread_done": False}),
            lambda value: value["scope"].update({"rust_real_thread_or_join_claimed": True}),
            lambda value: value["tls"].update({"mimalloc_model": "MI_TLS_MODEL_PTHREADS"}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.dynamic_full_large_homogeneous_aggregate.page1.used_after_reabandon_boundary": 37}
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
    def test_report_construction_and_validation_are_repeatable_without_base_mutation(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-full-large-homogeneous-aggregate-pure-report")
        source = temporary / "source/mimalloc-3.5.0"
        stem = "dynamic-full-large-homogeneous-aggregate"
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
        base_state = {
            name: getattr(evidence._base, name)
            for name in ("validate_report", "load_schema", "_schema_template")
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
        for name, value in base_state.items():
            self.assertIs(getattr(evidence._base, name), value)

    def test_report_validation_rejects_structurally_incomplete_report(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-full-large-homogeneous-aggregate-report")
        source = temporary / "source/mimalloc-3.5.0"
        stem = "dynamic-full-large-homogeneous-aggregate"
        build = evidence.normalize_command(
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
        malformed = {
            "kind": "mimalloc-x86_64-dynamic-full-large-homogeneous-aggregate-differential-evidence",
            "c_probe": {
                "build_command": build,
                "run_command": ["<temporary-evidence-root>/dynamic-full-large-homogeneous-aggregate-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
            },
        }
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(malformed)

    def test_trace_requires_exact_two_page_shape(self):
        schema = evidence.load_schema()
        trace = copy.deepcopy(schema["trace"]["expected_values"])
        evidence.validate_trace(trace, description="complete aggregate trace")
        trace.pop("trace.dynamic_full_large_homogeneous_aggregate.page1.used_after_thread_done")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_trace(trace, description="missing aggregate field")
        trace = copy.deepcopy(schema["trace"]["expected_values"])
        trace["trace.dynamic_full_large_homogeneous_aggregate.page0.used_after_reabandon_boundary"] = 37
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_trace(trace, description="wrong aggregate boundary")

    def test_c_command_requires_native_pthread_tls_contract(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-full-large-homogeneous-aggregate-command")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / "dynamic-full-large-homogeneous-aggregate.c",
            temporary / "dynamic-full-large-homogeneous-aggregate-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-pthread"], schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-ftls-model=initial-exec"], schema)

    def test_probe_declares_two_page_worker_and_no_post_exit_theap_access(self):
        probe = evidence.C_TRACE_PROBE
        self.assertIn("pthread_create", probe)
        self.assertIn("mi_thread_done()", probe)
        self.assertIn("pthread_join(worker", probe)
        self.assertIn("PAGE_COUNT 2", probe)
        self.assertIn("f->page_blocks[1] < 42", probe)
        self.assertIn("_mi_safe_ptr_page", probe)
        self.assertIn("MI_TLS_MODEL_LOCAL", probe)
        self.assertIn("MI_HAS_TLS_SLOT", probe)
        self.assertNotIn("theap->pages[MI_BIN_FULL]", probe.split("mi_thread_done();", 1)[1])
        self.assertNotIn("theap->pages_free_direct", probe.split("mi_thread_done();", 1)[1])


if __name__ == "__main__":
    unittest.main()
