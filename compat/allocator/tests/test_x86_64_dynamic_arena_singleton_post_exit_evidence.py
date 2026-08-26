#!/usr/bin/env python3
"""Static contract tests for the detached arena-singleton evidence runner."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_dynamic_arena_singleton_post_exit_evidence.py"
spec = importlib.util.spec_from_file_location("dynamic_arena_singleton_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_is_self_consistent_and_bounded(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(len(schema["trace"]["expected_values"]), 21)
        self.assertEqual(schema["trace"]["expected_values"][evidence.PREFIX + "request_size"], 524289)
        self.assertEqual(schema["trace"]["expected_values"][evidence.PREFIX + "block_size"], 589824)
        self.assertTrue(schema["scope"]["c_oracle_one_full_arena_singleton_only"])
        self.assertTrue(schema["scope"]["c_oracle_real_thread_done_join_and_terminal_consumer_free"])
        self.assertTrue(schema["scope"]["c_rust_common_facts_only"])
        self.assertTrue(schema["scope"]["rust_scoped_thread_and_join_observed"])
        self.assertFalse(schema["scope"]["emulation_accepted"])

    def test_schema_rejects_scope_hash_and_trace_mutation(self):
        mutations = (
            lambda value: value["scope"].update({"c_oracle_one_full_arena_singleton_only": False}),
            lambda value: value["scope"].update({"emulation_accepted": 0}),
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["trace"]["expected_values"].update({evidence.PREFIX + "valid": 0}),
            lambda value: value["trace"]["expected_values"].update({evidence.PREFIX + "valid": True}),
            lambda value: value["rust_test"].update({"target_arch": "aarch64"}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as stream:
                    json.dump(value, stream)
                    stream.flush()
                    with self.assertRaisesRegex(evidence._base.EvidenceError, "schema drifted"):
                        evidence.load_schema(Path(stream.name))


class ProbeTests(unittest.TestCase):
    def test_source_range_is_local_to_the_evidence_runner(self):
        self.assertEqual(
            evidence.source_range(b"one\ntwo\nthree\n", 2, 3),
            b"two\nthree\n",
        )
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.source_range(b"one\n", 0, 1)

    def test_probe_has_one_real_worker_done_join_and_terminal_free(self):
        probe = evidence.C_TRACE_PROBE
        self.assertEqual(probe.count("pthread_create"), 1)
        self.assertEqual(probe.count("mi_thread_done()"), 1)
        self.assertEqual(probe.count("pthread_join(worker"), 2)  # normal path plus failure cleanup
        self.assertEqual(probe.count("mi_free(f.block)"), 1)
        self.assertIn("map_span_is_page(page, start, 9)", probe)
        self.assertIn("!mi_page_is_in_full(p)", probe)
        self.assertIn("map_clear = map_span_is(start, 9, false);", probe)
        self.assertIn("const size_t request = MI_LARGE_MAX_OBJ_SIZE + 1", probe)
        self.assertIn("CRABC_MI_DYNAMIC_ARENA_SINGLETON_POST_EXIT_TRACE_BEGIN", probe)
        self.assertIn("trace.dynamic_arena_singleton_post_exit.", probe)
        self.assertNotIn("PAGE_COUNT", probe)
        evidence.validate_worker_teardown_source(probe)

    def test_worker_validator_rejects_shortcuts_and_wrong_free_order(self):
        for replacement in (
            "mi_free(f->block);",
            "mi_heap_collect(f->heap, true);",
            "pthread_exit(NULL);",
            "mi_thread_done(); (void)f->heap;",
        ):
            with self.subTest(replacement=replacement):
                with self.assertRaises(evidence._base.EvidenceError):
                    evidence.validate_worker_teardown_source(
                        evidence.C_TRACE_PROBE.replace("mi_thread_done();", replacement, 1)
                    )
        moved = evidence.C_TRACE_PROBE.replace(
            "mi_thread_done(); if (pthread_mutex_lock(&f->mutex) == 0)",
            "mi_free(f->block); mi_thread_done(); if (pthread_mutex_lock(&f->mutex) == 0)",
            1,
        )
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.validate_worker_teardown_source(moved)
        incomplete_page_map_clear = evidence.C_TRACE_PROBE.replace(
            "map_clear = map_span_is(start, 9, false);",
            "map_clear = !map_span_is(start, 9, true);",
            1,
        )
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.validate_worker_teardown_source(incomplete_page_map_clear)
        wrong_page_identity = evidence.C_TRACE_PROBE.replace(
            "map_registered = map_count == 9 && map_span_is_page(page, start, 9);",
            "map_registered = map_count == 9 && map_span_is(start, 9, true);",
            1,
        )
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.validate_worker_teardown_source(wrong_page_identity)
        queue_still_linked = evidence.C_TRACE_PROBE.replace(
            " && !mi_page_is_in_full(p)",
            "",
            1,
        )
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.validate_worker_teardown_source(queue_still_linked)

    def test_trace_requires_exact_common_fact_shape(self):
        trace = copy.deepcopy(evidence.EXPECTED_TRACE_VALUES)
        evidence.validate_trace(trace, description="complete detached-arena trace")
        trace.pop(evidence.PREFIX + "valid")
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.validate_trace(trace, description="missing detached-arena trace")
        trace = copy.deepcopy(evidence.EXPECTED_TRACE_VALUES)
        trace[evidence.PREFIX + "capacity"] = 2
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.validate_trace(trace, description="wrong detached-arena trace")

    def _valid_report(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/dynamic-arena-singleton-evidence")
        source = Path("/tmp/pinned-mimalloc")
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
            evidence.rust_test_command("cargo", temporary / "rust-target"),
            temporary,
            None,
        )
        return {
            "c_probe": {
                "build_command": c_command,
                "elf": dict(evidence.EXPECTED_C_ELF),
                "run_command": [
                    f"{evidence.NORMALIZED_EVIDENCE_ROOT}/{evidence.STEM}-c"
                ],
                "source_sha256": evidence._base.sha256_bytes(
                    evidence.C_TRACE_PROBE.encode()
                ),
                "trace": copy.deepcopy(evidence.EXPECTED_TRACE_VALUES),
            },
            "comparison": {
                "compared_value_count": len(evidence.EXPECTED_TRACE_VALUES),
                "status": "matched",
            },
            "format": 1,
            "kind": "mimalloc-x86_64-dynamic-arena-singleton-post-exit-evidence",
            "profile": evidence.EXPECTED_PROFILE,
            "provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
            "rust_probe": {
                "cargo_command": rust_command,
                "lockfile": {
                    "path": evidence._base.relative(evidence.LOCKFILE),
                    "sha256": evidence._base.sha256_file(evidence.LOCKFILE),
                },
                "passed_test_count": 1,
                "source": {
                    "path": evidence._base.relative(evidence.RUST_TEST_SOURCE),
                    "sha256": evidence._base.sha256_file(evidence.RUST_TEST_SOURCE),
                },
                "target_dir": {
                    "isolated": True,
                    "retained": False,
                    "value": f"{evidence.NORMALIZED_EVIDENCE_ROOT}/rust-target",
                },
                "trace": copy.deepcopy(evidence.EXPECTED_TRACE_VALUES),
            },
            "scope": copy.deepcopy(evidence.EXPECTED_SCOPE),
            "source": {
                "archive_sha256": evidence.EXPECTED_ARCHIVE_SHA256,
                "anchors": copy.deepcopy(schema["source_anchors"]),
                "release_flags": copy.deepcopy(schema["release_flags"]),
                "release_source_set": copy.deepcopy(schema["release_source_set"]),
            },
            "status": "passed",
            "target": copy.deepcopy(evidence.EXPECTED_TARGET),
            "trace": copy.deepcopy(schema["trace"]),
            "upstream": copy.deepcopy(evidence.EXPECTED_UPSTREAM),
        }

    def test_report_rejects_forged_comparison_and_source_configuration(self):
        report = self._valid_report()
        evidence.validate_report(report)
        forged_comparison = copy.deepcopy(report)
        forged_comparison["comparison"] = {
            "compared_value_count": 0,
            "status": "forged",
        }
        with self.assertRaisesRegex(evidence._base.EvidenceError, "comparison drifted"):
            evidence.validate_report(forged_comparison)
        for field in ("release_flags", "release_source_set"):
            with self.subTest(field=field):
                forged_source = copy.deepcopy(report)
                forged_source["source"][field] = []
                with self.assertRaisesRegex(
                    evidence._base.EvidenceError, "source/trace contract drifted"
                ):
                    evidence.validate_report(forged_source)


if __name__ == "__main__":
    unittest.main()
