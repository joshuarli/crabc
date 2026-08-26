#!/usr/bin/env python3
"""Pure contracts for the dynamic full direct-small unmapped x86-64 lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_dynamic_full_direct_small_unmapped_reabandon_evidence.py"
spec = importlib.util.spec_from_file_location(
    "dynamic_full_direct_small_unmapped_evidence", SCRIPT
)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_the_fixed_dynamic_full_direct_small_unmapped_protocol(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(len(schema["trace"]["expected_values"]), 38)
        values = schema["trace"]["expected_values"]
        prefix = "trace.dynamic_full_direct_small_unmapped_exit."
        self.assertEqual(values[f"{prefix}request_size"], 1024)
        self.assertEqual(values[f"{prefix}block_size"], 1024)
        self.assertEqual(values[f"{prefix}capacity"], 64)
        self.assertEqual(values[f"{prefix}reserved"], 64)
        self.assertEqual(values[f"{prefix}slice_count"], 1)
        self.assertEqual(values[f"{prefix}direct_cache_range_start"], 113)
        self.assertEqual(values[f"{prefix}direct_cache_range_end"], 128)
        self.assertEqual(values[f"{prefix}used_after_thread_done"], 64)
        self.assertEqual(values[f"{prefix}used_after_first_consumer_free"], 64)
        self.assertEqual(values[f"{prefix}unmapped_prefix_free_count"], 9)
        self.assertEqual(values[f"{prefix}used_after_unmapped_prefix"], 56)
        self.assertEqual(values[f"{prefix}used_after_reabandon_boundary"], 54)
        self.assertEqual(values[f"{prefix}dynamic_abandoned_count_after_thread_done"], 0)
        self.assertEqual(
            values[f"{prefix}dynamic_abandoned_count_after_reabandon_boundary"], 1
        )
        self.assertEqual(values[f"{prefix}dynamic_abandoned_count_after_final_free"], 0)
        self.assertEqual(
            schema["rust_test"],
            {
                "path": "crabc-mimalloc/src/dynamic_theap.rs",
                "target_arch": "x86_64",
                "test_filter": (
                    "dynamic_theap::tests::"
                    "x86_64_dynamic_full_direct_small_unmapped_reabandon_trace_matches_pinned_c"
                ),
            },
        )
        self.assertTrue(schema["scope"]["dynamic_full_direct_small_regular_bin_only"])
        self.assertTrue(schema["scope"]["dynamic_unmapped_then_mapped_route_only"])
        self.assertTrue(schema["scope"]["no_remote_free_before_thread_done_only"])
        self.assertFalse(schema["scope"]["general_remote_free_routing_claimed"])
        self.assertIn(
            {
                "member": "src/page-queue.c",
                "start_line": 204,
                "end_line": 244,
                "sha256": "4216ce3f998d0a8c3891e0c89e1feaa34aff407d10e14135e68334ce833d6e6b",
            },
            schema["source_anchors"],
        )
        self.assertIn(
            {
                "member": "src/free.c",
                "start_line": 479,
                "end_line": 515,
                "sha256": "538f3923096192771e3a516447f42778a74ea93f1084605b4ac24fd3b28eb501",
            },
            schema["source_anchors"],
        )
        self.assertIn(
            {
                "member": "src/arena.c",
                "start_line": 631,
                "end_line": 651,
                "sha256": "f413bc26c42c40483f59f3b79042a836113403fa1ed9501d9d7baf4a130b5ee0",
            },
            schema["source_anchors"],
        )
        self.assertIn(
            {
                "member": "src/page-map.c",
                "start_line": 484,
                "end_line": 514,
                "sha256": "c4453ebc7aa0e6c6dbb59189b789d0d5ddf970499e2926d952558f4a1ae229a5",
            },
            schema["source_anchors"],
        )
        self.assertIn(
            {
                "member": "include/mimalloc/prim-tls.h",
                "start_line": 412,
                "end_line": 423,
                "sha256": "1f82dc8f2ada933d948e8dd7ab86fec34b0d47a281b5e9333fee5f1f23088337",
            },
            schema["source_anchors"],
        )

    def test_schema_rejects_probe_scope_source_or_trace_drift(self):
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update(
                {"dynamic_full_direct_small_regular_bin_only": False}
            ),
            lambda value: value["source_anchors"][13].update({"sha256": "0" * 64}),
            lambda value: value["rust_test"].update({"target_arch": "aarch64"}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.dynamic_full_direct_small_unmapped_exit.capacity": 63}
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
        stem = "dynamic-full-direct-small-unmapped-reabandon"
        temporary = Path("/tmp/dynamic-full-direct-small-unmapped-reabandon-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.normalize_command(
            evidence.c_trace_command(
                "/usr/bin/musl-gcc",
                source,
                temporary / f"{stem}.c",
                temporary / f"{stem}-c",
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
                "run_command": [f"<temporary-evidence-root>/{stem}-c"],
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
        stem = "dynamic-full-direct-small-unmapped-reabandon"
        temporary = Path("/tmp/dynamic-full-direct-small-unmapped-reabandon-command")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / f"{stem}.c",
            temporary / f"{stem}-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(
            evidence.normalize_command(command, temporary, source), schema
        )
        weakened = [part for part in command if part != "-pthread"]
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command(weakened, schema)

    def test_c_probe_keeps_the_live_direct_cache_observation_pre_exit(self):
        source = evidence.C_TRACE_PROBE
        self.assertIn("mi_option_set(mi_option_page_reclaim_on_free, 0);", source)
        self.assertIn("mi_option_set(mi_option_page_full_retain, 2);", source)
        self.assertIn("mi_heap_malloc_small(heap, request)", source)
        self.assertIn("direct_cache_range(theap, queue, page", source)
        self.assertIn("range_start != 113 || range_end != 128", source)
        self.assertIn("unmapped_prefix_free_count = reserved / 8 + 1;", source)
        self.assertIn("used_after_first_consumer_free = page->used;", source)
        self.assertIn("used_after_unmapped_prefix + unmapped_prefix_free_count != capacity + 1", source)
        self.assertIn(
            "used_after_reabandon_boundary + unmapped_prefix_free_count + 2 != capacity + 1",
            source,
        )
        post_thread_done = source.split("mi_thread_done();", 1)[1]
        self.assertNotIn("theap->", post_thread_done)
        self.assertNotIn("pages_free_direct", post_thread_done)
        self.assertNotIn("direct_cache_range(", post_thread_done)
        pre_exit = source.split("fixture.allow_thread_done = true;", 1)[0]
        self.assertIn("&worker_heap->arena_pages[arena->arena_idx]", pre_exit)
        self.assertIn("&worker_heap->abandoned_count[bin]", pre_exit)
        joined_consumer = source.split("if (pthread_join(producer, NULL) != 0) goto output;", 1)[1]
        self.assertNotIn("worker_heap->", joined_consumer)

    def test_c_probe_checks_partial_head_unmapped_then_mapped_and_terminal_release(self):
        source = evidence.C_TRACE_PROBE
        for observation in (
            "page_map_registered_after_thread_done = _mi_safe_ptr_page((const void*)saved_address) == page;",
            "!mi_page_is_owned(page)",
            "mi_page_thread_free(page) != NULL",
            "mi_page_thread_free(page) == NULL",
            "mi_bitmap_is_setN(arena_pages->pages, slice_index, 1)",
            "arena_pages->pages_abandoned[bin] == NULL",
            "mi_bitmap_is_setN(arena_pages->pages_abandoned[bin], slice_index, 1)",
            "mi_atomic_load_relaxed(dynamic_abandoned_count)",
            "mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count)",
        ):
            with self.subTest(observation=observation):
                self.assertIn(observation, source)
        terminal_tail = source.split("mi_free(fixture.blocks[block_count - 1]);", 1)[1].split(
            "valid =", 1
        )[0]
        self.assertIn("_mi_safe_ptr_page((const void*)saved_address) == NULL", terminal_tail)
        self.assertNotIn("page->", terminal_tail)

    def test_parser_requires_an_exact_pointer_free_trace(self):
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
                "trace.dynamic_full_direct_small_unmapped_exit.pointer=0x1\n"
                f"{evidence.TRACE_END}",
                description="pointerful trace",
            )

    def test_report_binds_both_probes_and_post_exit_scope(self):
        report = self.complete_report()
        self.assertEqual(
            report["kind"], evidence.DYNAMIC_FULL_DIRECT_SMALL_UNMAPPED_EXIT_KIND
        )
        self.assertEqual(report["comparison"], {"compared_value_count": 38, "status": "matched"})
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])
        weakened = copy.deepcopy(report)
        weakened["scope"]["dynamic_unmapped_then_mapped_route_only"] = False
        with self.assertRaisesRegex(evidence.EvidenceError, "private boundary"):
            evidence.validate_report(weakened)


if __name__ == "__main__":
    unittest.main()
