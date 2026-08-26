#!/usr/bin/env python3
"""Pure contracts for the dynamic full-large unmapped x86-64 lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_dynamic_full_large_unmapped_reabandon_evidence.py"
spec = importlib.util.spec_from_file_location("dynamic_full_large_unmapped_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_the_fixed_dynamic_full_large_unmapped_protocol(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(len(schema["trace"]["expected_values"]), 34)
        values = schema["trace"]["expected_values"]
        prefix = "trace.dynamic_full_large_unmapped_exit."
        self.assertEqual(values[f"{prefix}request_size"], 86706)
        self.assertEqual(values[f"{prefix}block_size"], 98304)
        self.assertEqual(values[f"{prefix}capacity"], 42)
        self.assertEqual(values[f"{prefix}reserved"], 42)
        self.assertEqual(values[f"{prefix}slice_count"], 64)
        self.assertEqual(values[f"{prefix}used_after_thread_done"], 42)
        self.assertEqual(values[f"{prefix}page_map_slice_count_after_thread_done"], 63)
        self.assertEqual(values[f"{prefix}page_map_tail_unregistered_after_thread_done"], 1)
        self.assertEqual(values[f"{prefix}unmapped_prefix_free_count"], 5)
        self.assertEqual(values[f"{prefix}used_after_unmapped_prefix"], 37)
        self.assertEqual(values[f"{prefix}used_after_reabandon_boundary"], 36)
        self.assertEqual(values[f"{prefix}dynamic_abandoned_count_after_thread_done"], 0)
        self.assertEqual(
            values[f"{prefix}dynamic_abandoned_count_after_reabandon_boundary"], 1
        )
        self.assertEqual(values[f"{prefix}dynamic_abandoned_count_after_final_free"], 0)
        self.assertNotIn(f"{prefix}producer_thread_done_completed", values)
        self.assertNotIn(f"{prefix}producer_joined_before_consumer_frees", values)
        self.assertEqual(
            schema["rust_test"],
            {
                "path": "crabc-mimalloc/src/dynamic_theap.rs",
                "target_arch": "x86_64",
                "test_filter": (
                    "dynamic_theap::tests::"
                    "x86_64_dynamic_full_large_unmapped_reabandon_trace_matches_pinned_c"
                ),
            },
        )
        self.assertTrue(schema["scope"]["dynamic_full_large_full_bin_only"])
        self.assertTrue(schema["scope"]["dynamic_unmapped_then_mapped_route_only"])
        self.assertTrue(schema["scope"]["c_oracle_real_thread_exit_and_join_required"])
        self.assertTrue(schema["scope"]["c_oracle_no_remote_free_before_thread_done_only"])
        self.assertTrue(schema["scope"]["c_oracle_sequential_joined_consumer_frees_only"])
        self.assertTrue(schema["scope"]["rust_typed_owner_exit_then_sequential_client_frees_only"])
        self.assertFalse(schema["scope"]["rust_real_thread_or_join_claimed"])
        self.assertFalse(schema["scope"]["general_remote_free_routing_claimed"])
        self.assertEqual(
            schema["tls"],
            {
                "compiler_model": "initial-exec",
                "mimalloc_model": "MI_TLS_MODEL_LOCAL",
                "thread_pointer_path": "x86_64-fs-tls-slot-fallback",
            },
        )
        for anchor in (
            {
                "member": "include/mimalloc/internal.h",
                "start_line": 38,
                "end_line": 75,
                "sha256": "5fcb7fc4ded7caedd3fbc10cb257af1f6679cff979e075b94781556997f81505",
            },
            {
                "member": "include/mimalloc/prim-tls.h",
                "start_line": 41,
                "end_line": 50,
                "sha256": "acfbfaa3f692a04fa9fc1833a7c65238b5c9c4f7dc37047ee1e52c144ad6de8d",
            },
            {
                "member": "include/mimalloc/prim-tls.h",
                "start_line": 61,
                "end_line": 73,
                "sha256": "1eff24a0bb7271ad024368ee5f46d52b2e31d370f1941689ac842a643b4b802e",
            },
            {
                "member": "include/mimalloc/prim-tls.h",
                "start_line": 116,
                "end_line": 127,
                "sha256": "5fa059e7f8ed17d475334c06df04e3a802ff360ce57db59d8d706c02d114d479",
            },
            {
                "member": "src/prim/prim-tls.c",
                "start_line": 25,
                "end_line": 39,
                "sha256": "0d63cba91b60be481a3d36fb3b63aade81bc32719f651712a60692e73bc6b3d6",
            },
            {
                "member": "src/prim/prim-tls.c",
                "start_line": 209,
                "end_line": 251,
                "sha256": "dcc472f7b145faa5140f2944857c1b7ca7285fdef45bd5e6ba62d266455d4b4c",
            },
            {
                "member": "src/free.c",
                "start_line": 479,
                "end_line": 515,
                "sha256": "538f3923096192771e3a516447f42778a74ea93f1084605b4ac24fd3b28eb501",
            },
            {
                "member": "src/arena.c",
                "start_line": 631,
                "end_line": 651,
                "sha256": "f413bc26c42c40483f59f3b79042a836113403fa1ed9501d9d7baf4a130b5ee0",
            },
            {
                "member": "src/page-map.c",
                "start_line": 460,
                "end_line": 465,
                "sha256": "16d731af7789d5a35e755fe6b652b09b97992bfd39a31336778965e9751ac427",
            },
            {
                "member": "src/page-map.c",
                "start_line": 484,
                "end_line": 514,
                "sha256": "c4453ebc7aa0e6c6dbb59189b789d0d5ddf970499e2926d952558f4a1ae229a5",
            },
            {
                "member": "include/mimalloc/internal.h",
                "start_line": 918,
                "end_line": 929,
                "sha256": "82eaca070fdc3c9091c26d385304168b89d8ed57338f36de071d3a18b48badb5",
            },
        ):
            with self.subTest(anchor=anchor):
                self.assertIn(anchor, schema["source_anchors"])
        for flat_branch_anchor in (
            ("src/page-map.c", 139, 145),
            ("src/page-map.c", 199, 209),
        ):
            with self.subTest(flat_branch_anchor=flat_branch_anchor):
                self.assertFalse(
                    any(
                        anchor["member"] == flat_branch_anchor[0]
                        and anchor["start_line"] == flat_branch_anchor[1]
                        and anchor["end_line"] == flat_branch_anchor[2]
                        for anchor in schema["source_anchors"]
                    )
                )

    def test_schema_rejects_probe_scope_source_or_trace_drift(self):
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update({"dynamic_full_large_full_bin_only": False}),
            lambda value: value["tls"].update({"mimalloc_model": "MI_TLS_MODEL_PTHREADS"}),
            lambda value: value["source_anchors"][9].update({"sha256": "0" * 64}),
            lambda value: value["rust_test"].update({"target_arch": "aarch64"}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.dynamic_full_large_unmapped_exit.used_after_reabandon_boundary": 37}
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
        stem = "dynamic-full-large-unmapped-reabandon"
        temporary = Path("/tmp/dynamic-full-large-unmapped-reabandon-evidence")
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
        stem = "dynamic-full-large-unmapped-reabandon"
        temporary = Path("/tmp/dynamic-full-large-unmapped-reabandon-command")
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

    def test_c_probe_keeps_all_theap_observations_pre_exit(self):
        source = evidence.C_TRACE_PROBE
        self.assertIn("MI_TLS_MODEL_LOCAL", source)
        self.assertIn("MI_HAS_TLS_SLOT", source)
        self.assertIn("pinned x86_64 FS TLS-slot fallback", source)
        self.assertIn("mi_option_set(mi_option_page_reclaim_on_free, 0);", source)
        self.assertIn("mi_option_set(mi_option_page_full_retain, -1);", source)
        self.assertIn("mi_heap_malloc(heap, request)", source)
        self.assertIn("full = &theap->pages[MI_BIN_FULL];", source)
        self.assertIn("direct_cache_is_empty(theap)", source)
        self.assertIn("unmapped_prefix_free_count = reserved / 8;", source)
        self.assertIn("used_after_unmapped_prefix + unmapped_prefix_free_count != capacity", source)
        self.assertIn("page_map_slice_count_after_thread_done = mi_slice_count_of_size(page_area_size)", source)
        self.assertIn("page_map_slice_count_after_thread_done != 63", source)
        self.assertIn("page_map_tail_unregistered_after_thread_done", source)
        self.assertIn(
            "used_after_reabandon_boundary + unmapped_prefix_free_count + 1 != capacity", source
        )
        post_thread_done = source.split("mi_thread_done();", 1)[1]
        self.assertNotIn("theap->", post_thread_done)
        self.assertNotIn("full->", post_thread_done)
        self.assertNotIn("pages_free_direct", post_thread_done)
        pre_exit = source.split("fixture.allow_thread_done = true;", 1)[0]
        self.assertIn("&worker_heap->arena_pages[arena->arena_idx]", pre_exit)
        self.assertIn("&worker_heap->abandoned_count[bin]", pre_exit)
        joined_consumer = source.split("if (pthread_join(producer, NULL) != 0) goto output;", 1)[1]
        self.assertNotIn("worker_heap->", joined_consumer)
        self.assertNotIn('OUT_B("producer_thread_done_completed"', source)
        self.assertNotIn('OUT_B("producer_joined_before_consumer_frees"', source)

    def test_c_probe_checks_normal_collection_unmapped_then_mapped_and_terminal_release(self):
        source = evidence.C_TRACE_PROBE
        self.assertEqual(source.count("mi_page_thread_free(page) == NULL"), 3)
        for observation in (
            "!mi_page_is_owned(page)",
            "mi_bitmap_is_setN(arena_pages->pages, slice_index, 1)",
            "arena_pages->pages_abandoned[bin] == NULL",
            "mi_bitmap_is_setN(arena_pages->pages_abandoned[bin], slice_index, 1)",
            "mi_atomic_load_relaxed(dynamic_abandoned_count)",
            "saved_slice_start + index * MI_ARENA_SLICE_SIZE",
            "mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count)",
        ):
            with self.subTest(observation=observation):
                self.assertIn(observation, source)
        terminal_tail = source.split("mi_free(fixture.blocks[block_count - 1]);", 1)[1].split(
            "valid =", 1
        )[0]
        self.assertIn("_mi_safe_ptr_page((const void*)(saved_slice_start", terminal_tail)
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
                "trace.dynamic_full_large_unmapped_exit.pointer=0x1\n"
                f"{evidence.TRACE_END}",
                description="pointerful trace",
            )

    def test_report_binds_both_probes_and_post_exit_scope(self):
        report = self.complete_report()
        self.assertEqual(report["kind"], evidence.DYNAMIC_FULL_LARGE_UNMAPPED_EXIT_KIND)
        self.assertEqual(report["comparison"], {"compared_value_count": 34, "status": "matched"})
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])
        weakened = copy.deepcopy(report)
        weakened["scope"]["dynamic_unmapped_then_mapped_route_only"] = False
        with self.assertRaisesRegex(evidence.EvidenceError, "private boundary"):
            evidence.validate_report(weakened)


if __name__ == "__main__":
    unittest.main()
