#!/usr/bin/env python3
"""Pure contracts for the dynamic OS-aligned singleton x86-64 lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_dynamic_os_aligned_singleton_evidence.py"
spec = importlib.util.spec_from_file_location("dynamic_os_aligned_singleton_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_the_fixed_os_aligned_singleton_owner_exit_protocol(self) -> None:
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(schema["profile"], evidence.EXPECTED_PROFILE)
        self.assertEqual(len(schema["trace"]["expected_values"]), 21)
        values = schema["trace"]["expected_values"]
        self.assertEqual(values["trace.dynamic_os_aligned_singleton.request_size"], 7)
        self.assertEqual(values["trace.dynamic_os_aligned_singleton.alignment"], 131072)
        self.assertEqual(values["trace.dynamic_os_aligned_singleton.reserved"], 1)
        self.assertEqual(values["trace.dynamic_os_aligned_singleton.used"], 1)
        self.assertEqual(
            schema["rust_test"],
            {
                "path": "crabc-mimalloc/src/dynamic_theap.rs",
                "target_arch": "x86_64",
                "test_filter": evidence.RUST_TEST_FILTER,
            },
        )
        self.assertTrue(schema["scope"]["one_dynamic_os_aligned_singleton_owner_exit_only"])
        self.assertTrue(schema["scope"]["joined_consumer_free_only"])
        self.assertTrue(schema["scope"]["real_pinned_c_mi_thread_done"])
        self.assertTrue(schema["scope"]["typed_rust_nonabandoning_fixture_only"])
        self.assertFalse(schema["scope"]["general_abandonment_or_adoption_claimed"])
        self.assertFalse(schema["scope"]["general_os_abandoned_list_claimed"])

    def test_schema_rejects_probe_scope_source_or_rust_selection_drift(self) -> None:
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update(
                {"one_dynamic_os_aligned_singleton_owner_exit_only": False}
            ),
            lambda value: value["source_anchors"][0].update({"sha256": "0" * 64}),
            lambda value: value["rust_test"].update(
                {"test_filter": "dynamic_theap::tests::unrelated"}
            ),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.dynamic_os_aligned_singleton.alignment": 65536}
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
    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-os-aligned-singleton-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.normalize_command(
            evidence.c_trace_command(
                "/usr/bin/musl-gcc",
                source,
                temporary / "dynamic-os-aligned-singleton.c",
                temporary / "dynamic-os-aligned-singleton-c",
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
                "run_command": ["<temporary-evidence-root>/dynamic-os-aligned-singleton-c"],
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

    def test_c_command_retains_pthread_tls_and_native_oracle_selection(self) -> None:
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-os-aligned-singleton-command")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / "dynamic-os-aligned-singleton.c",
            temporary / "dynamic-os-aligned-singleton-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(
            evidence.normalize_command(command, temporary, source), schema
        )
        weakened = [part for part in command if part != "-pthread"]
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command(weakened, schema)

    def test_c_probe_uses_real_owner_exit_and_address_independent_os_observations(self) -> None:
        source = evidence.C_TRACE_PROBE
        for observation in (
            "mi_heap_malloc_aligned(heap, 7, 128 * 1024)",
            "mi_page_is_huge(page) && !mi_page_is_in_full(page)",
            "page->block_size > MI_SMALL_MAX_OBJ_SIZE",
            "full->first == NULL && full->last == NULL",
            "mi_thread_done();",
            "_mi_safe_ptr_page(fixture.block)",
            "mi_lock(&heap->os_abandoned_pages_lock)",
            "heap->os_abandoned_pages == page",
            "mi_page_thread_id(page) == MI_THREADID_ABANDONED",
            "_mi_safe_ptr_page((const void*)saved_block_address) == NULL",
            "mi_free((void*)saved_block_address);",
        ):
            with self.subTest(observation=observation):
                self.assertIn(observation, source)
        self.assertNotIn("%p", source)

    def test_rust_trace_observes_the_matching_typed_owner_exit_and_terminal_release(self) -> None:
        source = evidence.RUST_TEST_SOURCE.read_text(encoding="utf-8")
        for observation in (
            "drain.test_dynamic_regular_slot_is_clear()",
            "handoff.test_os_abandoned_page_head() == page.as_ptr()",
            "huge_queue_singleton_before_owner_exit",
            "full_queue_empty_before_owner_exit",
            "(*page.as_ptr()).abandoned_test_thread_id() == THREAD_ID_ABANDONED",
            "handoff.remote_free_after_failed_reclaim(block)",
            "page_map_clear_after_final_free",
        ):
            with self.subTest(observation=observation):
                self.assertIn(observation, source)

    def test_parser_requires_an_exact_pointer_free_trace(self) -> None:
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
        with self.assertRaisesRegex(evidence.EvidenceError, "raw address"):
            evidence.parse_trace(
                f"{evidence.TRACE_BEGIN}\n"
                "trace.dynamic_os_aligned_singleton.pointer=0x1\n"
                f"{evidence.TRACE_END}",
                description="pointerful trace",
            )

    def test_report_binds_both_probes_and_the_narrow_private_scope(self) -> None:
        report = self.complete_report()
        self.assertEqual(report["kind"], evidence.DYNAMIC_OS_ALIGNED_SINGLETON_KIND)
        self.assertEqual(
            report["comparison"], {"compared_value_count": 21, "status": "matched"}
        )
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])
        mutations = (
            (lambda value: value["c_probe"].update({"elf": {}}), "C ELF identity"),
            (lambda value: value["c_probe"].update({"source_sha256": "0" * 64}), "C source hash"),
            (lambda value: value["rust_probe"]["cargo_command"].remove("--locked"), "Rust command drifted"),
            (lambda value: value["scope"].update({"joined_consumer_free_only": False}), "private boundary"),
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
