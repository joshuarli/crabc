#!/usr/bin/env python3
"""Pure contracts for the dynamic full-large one-remote post-exit x86-64 lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_dynamic_full_large_one_remote_force_collect_to_mapped_evidence.py"
spec = importlib.util.spec_from_file_location("dynamic_full_large_one_remote_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_the_fixed_dynamic_full_large_one_remote_protocol(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(len(schema["trace"]["expected_values"]), 31)
        values = schema["trace"]["expected_values"]
        self.assertEqual(values["trace.dynamic_full_large_one_remote_exit.request_size"], 86706)
        self.assertEqual(values["trace.dynamic_full_large_one_remote_exit.block_size"], 98304)
        self.assertEqual(values["trace.dynamic_full_large_one_remote_exit.capacity"], 42)
        self.assertEqual(values["trace.dynamic_full_large_one_remote_exit.slice_count"], 64)
        self.assertEqual(
            values["trace.dynamic_full_large_one_remote_exit.page_map_slice_count_after_owner_exit"],
            63,
        )
        self.assertEqual(
            values["trace.dynamic_full_large_one_remote_exit.page_map_tail_unregistered_after_owner_exit"],
            1,
        )
        self.assertEqual(
            schema["rust_test"],
            {
                "path": "crabc-mimalloc/src/dynamic_theap.rs",
                "target_arch": "x86_64",
                "test_filter": (
                    "dynamic_theap::tests::"
                    "x86_64_dynamic_full_large_one_remote_force_collect_to_mapped_trace_matches_pinned_c"
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
                {"trace.dynamic_full_large_one_remote_exit.capacity": 41}
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
        temporary = Path("/tmp/dynamic-full-large-one-remote-force-collect-to-mapped-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.normalize_command(
            evidence.c_trace_command(
                "/usr/bin/musl-gcc",
                source,
                temporary / "dynamic-full-large-one-remote-force-collect-to-mapped.c",
                temporary / "dynamic-full-large-one-remote-force-collect-to-mapped-c",
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
                "<temporary-evidence-root>/dynamic-full-large-one-remote-force-collect-to-mapped-c"
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
        temporary = Path("/tmp/dynamic-full-large-one-remote-command")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / "dynamic-full-large-one-remote-force-collect-to-mapped.c",
            temporary / "dynamic-full-large-one-remote-force-collect-to-mapped-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(
            evidence.normalize_command(command, temporary, source), schema
        )
        weakened = [part for part in command if part != "-pthread"]
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command(weakened, schema)

    def test_c_probe_distinguishes_source_page_map_area_from_terminal_arena_span(self):
        self.assertIn(
            "page_map_slice_count_after_owner_exit = mi_slice_count_of_size(page_area_size)",
            evidence.C_TRACE_PROBE,
        )
        self.assertIn(
            "for (size_t index = 0; index < page_map_slice_count_after_owner_exit; index++)",
            evidence.C_TRACE_PROBE,
        )
        self.assertIn(
            "saved_slice_start + index * MI_ARENA_SLICE_SIZE",
            evidence.C_TRACE_PROBE,
        )
        self.assertIn(
            "page_map_registered_after_thread_done = true;",
            evidence.C_TRACE_PROBE,
        )
        self.assertIn(
            "page_map_tail_unregistered_after_owner_exit = true;",
            evidence.C_TRACE_PROBE,
        )
        self.assertIn(
            "page_map_unregistered_after_final_free = false;",
            evidence.C_TRACE_PROBE,
        )

    def test_rust_trace_observes_queue_owner_bitmap_and_nonfinal_count(self):
        source = evidence.RUST_TEST_SOURCE.read_text(encoding="utf-8")
        for observation in (
            "page_ref.is_queue_detached()",
            "page_ref.remote_free_test_head() & 1 == 0",
            "let owner_exit_transition_completed = drain.test_dynamic_regular_slot_is_clear();",
            "handoff.test_dynamic_arena_page_is_set()",
            "page.as_ref().used() } as usize + 2 == capacity",
        ):
            with self.subTest(observation=observation):
                self.assertIn(observation, source)

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
                "trace.dynamic_full_large_one_remote_exit.pointer=0x1\n"
                f"{evidence.TRACE_END}",
                description="pointerful trace",
            )

    def test_report_binds_both_probes_and_post_exit_scope(self):
        report = self.complete_report()
        self.assertEqual(report["kind"], evidence.DYNAMIC_FULL_LARGE_ONE_REMOTE_EXIT_KIND)
        self.assertEqual(
            report["comparison"], {"compared_value_count": 31, "status": "matched"}
        )
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])
        weakened = copy.deepcopy(report)
        weakened["scope"]["mapped_process_route_only"] = False
        with self.assertRaisesRegex(evidence.EvidenceError, "private boundary"):
            evidence.validate_report(weakened)


if __name__ == "__main__":
    unittest.main()
