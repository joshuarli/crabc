#!/usr/bin/env python3
"""Static contracts for the live-owner full-medium remote-release lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_live_owner_full_medium_remote_release_evidence.py"
spec = importlib.util.spec_from_file_location(
    "crabc_x86_64_live_owner_full_medium_remote_release_evidence", SCRIPT
)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_the_private_live_owner_full_medium_release_route(self):
        schema = evidence.load_schema()
        self.assertTrue(evidence.exactly_matches(schema, evidence._schema_template()))
        values = schema["trace"]["expected_values"]
        prefix = evidence.PREFIX
        self.assertEqual(len(values), 35)
        self.assertEqual(values[prefix + "request"], 10248)
        self.assertEqual(values[prefix + "block_size"], 12288)
        self.assertEqual(values[prefix + "capacity"], 42)
        self.assertEqual(values[prefix + "reserved"], 42)
        self.assertEqual(values[prefix + "slice_count"], 8)
        self.assertEqual(values[prefix + "full_queue_count_before_remote"], 1)
        self.assertEqual(values[prefix + "regular_queue_count_before_remote"], 1)
        self.assertEqual(values[prefix + "page_count_before_remote"], 2)
        self.assertEqual(values[prefix + "joined_remote_free_count"], 42)
        self.assertEqual(values[prefix + "published_remote_count"], 42)
        self.assertEqual(values[prefix + "regular_queue_count_after_collect"], 1)
        self.assertEqual(values[prefix + "page_count_after_collect"], 1)
        self.assertTrue(
            schema["scope"]["c_oracle_join_before_non_atomic_owner_observation_required"]
        )
        self.assertTrue(schema["scope"]["c_oracle_no_thread_teardown"])
        self.assertTrue(schema["scope"]["c_oracle_real_pthread_required"])
        self.assertFalse(schema["scope"]["emulation_accepted"])
        self.assertFalse(schema["scope"]["public_crabc_support"])
        queue_anchors = [
            anchor
            for anchor in schema["source_anchors"]
            if anchor["member"] == "src/page-queue.c"
        ]
        self.assertEqual(
            queue_anchors,
            [
                {
                    "member": "src/page-queue.c",
                    "start_line": 252,
                    "end_line": 274,
                    "sha256": (
                        "d72c1999eec27a2818fd657c62aa93ada275b1e639115691"
                        "54a16619ca2f202b"
                    ),
                },
                {
                    "member": "src/page-queue.c",
                    "start_line": 344,
                    "end_line": 418,
                    "sha256": (
                        "575fa161a6e18b56f57b1e09dcb713e90c32f650193a9c9d"
                        "bff03645c476c653"
                    ),
                },
            ],
        )
        self.assertEqual(
            schema["rust_test"]["test_filter"],
            (
                "single_thread::tests::"
                "x86_64_live_owner_full_medium_remote_release_trace_matches_pinned_c"
            ),
        )

    def test_schema_rejects_strict_type_pin_scope_anchor_and_trace_drift(self):
        mutations = (
            lambda value: value.update({"format": True}),
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["scope"].update({"emulation_accepted": 0}),
            lambda value: value["scope"].update(
                {"c_oracle_live_owner_only": False}
            ),
            lambda value: value["source_anchors"][6].update({"sha256": "0" * 64}),
            lambda value: next(
                anchor
                for anchor in value["source_anchors"]
                if anchor["member"] == "src/page-queue.c"
                and anchor["start_line"] == 252
            ).update({"sha256": "0" * 64}),
            lambda value: value["target"].update({"architecture": "aarch64"}),
            lambda value: value["rust_test"].update({"target_arch": "aarch64"}),
            lambda value: value["trace"]["expected_values"].update(
                {evidence.PREFIX + "published_remote_count": 41}
            ),
            lambda value: value["trace"]["expected_values"].update(
                {evidence.PREFIX + "valid": True}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                schema = evidence.load_schema()
                mutate(schema)
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", encoding="utf-8"
                ) as stream:
                    json.dump(schema, stream)
                    stream.flush()
                    with self.assertRaisesRegex(
                        evidence.EvidenceError, "schema drifted"
                    ):
                        evidence.load_schema(Path(stream.name))

    def test_recursive_equality_does_not_coerce_boolean_integers(self):
        self.assertFalse(evidence.exactly_matches({"value": 1}, {"value": True}))
        self.assertFalse(
            evidence.exactly_matches(
                {"nested": [{"value": True}]}, {"nested": [{"value": 1}]}
            )
        )


class ProbeTests(unittest.TestCase):
    def test_probe_requires_real_joined_remote_frees_and_complete_release(self):
        probe = evidence.C_TRACE_PROBE
        self.assertIn("mi_option_set(mi_option_page_full_retain, -1);", probe)
        self.assertIn("mi_heap_malloc(heap, request)", probe)
        self.assertIn("pthread_create(&worker, NULL, remote_worker, &fixture)", probe)
        self.assertIn("pthread_join(worker, &worker_result)", probe)
        self.assertIn("mi_free(block);", probe)
        self.assertIn("mi_heap_collect(heap, false);", probe)
        self.assertLess(
            probe.index("while (fixture.first_count < reserved) {"),
            probe.index("capacity = first_page->capacity;"),
        )
        self.assertIn("queue_has_only_member(full, first_page)", probe)
        self.assertIn("queue_has_only_member(regular, successor_page)", probe)
        self.assertIn("queue->count == 1", probe)
        self.assertIn("queue->first == member && queue->last == member", probe)
        self.assertIn("member->prev == NULL && member->next == NULL", probe)
        self.assertIn("full->count == 0 && full->first == NULL", probe)
        self.assertIn("full->last == NULL", probe)
        self.assertIn("map_span_is_page(", probe)
        self.assertIn("map_span_is_clear(", probe)
        self.assertIn("mi_bitmap_is_clearN(", probe)
        self.assertIn("mi_bbitmap_is_setN(", probe)
        self.assertNotIn("mi_thread_done", probe)
        evidence.validate_c_probe_contract(probe)

    def test_probe_validator_rejects_lifecycle_join_membership_and_map_weakening(self):
        mutations = (
            evidence.C_TRACE_PROBE.replace(
                "mi_option_set(mi_option_page_full_retain, -1);",
                "mi_option_set(mi_option_page_full_retain, 2);",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "if (pthread_join(worker, &worker_result) != 0) goto output;",
                "if (pthread_join_after_owner_collect(worker, &worker_result) != 0) goto output;",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "mi_heap_collect(heap, false);",
                "mi_heap_collect(heap, true);",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "queue_has_only_member(full, first_page)",
                "full->first == first_page",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "queue->count == 1",
                "queue->count != 0",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "&& queue->first == member && queue->last == member",
                "&& queue->first == member",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "&& member->prev == NULL && member->next == NULL",
                "&& member->prev == NULL",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "&& full->last == NULL",
                "&& full->last != NULL",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "map_span_is_clear(\n      first_span_start, first_slice_count)",
                "map_span_is_page(\n      successor_page, successor_span_start, successor_slice_count)",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "int main(void) {",
                "int main(void) { mi_thread_done();",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "  block_size = first_page->block_size;\n  reserved = first_page->reserved;",
                "  block_size = first_page->block_size;\n  capacity = first_page->capacity;\n  reserved = first_page->reserved;",
                1,
            ).replace(
                "  capacity = first_page->capacity;\n  successor = mi_heap_malloc(heap, request);",
                "  successor = mi_heap_malloc(heap, request);",
                1,
            ),
        )
        for probe in mutations:
            with self.subTest(probe=probe):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_c_probe_contract(probe)


class CommandAndTraceTests(unittest.TestCase):
    def test_c_command_keeps_exact_release_source_and_pthread_profile(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/live-owner-full-medium-remote-release-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "musl-gcc",
            source,
            temporary / f"{evidence.STEM}.c",
            temporary / f"{evidence.STEM}-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        normalized = evidence.normalize_command(command, temporary, source)
        evidence.validate_normalized_c_command(normalized, schema)

        without_pthread = [part for part in command if part != "-pthread"]
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command(without_pthread, schema)

        malformed = list(normalized)
        malformed.remove(f"{evidence.NORMALIZED_PINNED_SOURCE}/src/arena.c")
        with self.assertRaisesRegex(evidence.EvidenceError, "C command drifted"):
            evidence.validate_normalized_c_command(malformed, schema)

    def test_trace_and_comparison_require_all_exact_integer_facts(self):
        trace = copy.deepcopy(evidence.EXPECTED_TRACE_VALUES)
        evidence.validate_trace(trace, description="complete trace")
        self.assertEqual(
            evidence.compare_traces(trace, trace),
            {"compared_value_count": 35, "status": "matched"},
        )

        missing = copy.deepcopy(trace)
        missing.pop(evidence.PREFIX + "first_slices_free_after_collect")
        with self.assertRaisesRegex(evidence.EvidenceError, "missing"):
            evidence.validate_trace(missing, description="missing trace")

        boolean = copy.deepcopy(trace)
        boolean[evidence.PREFIX + "published_remote_count"] = True
        with self.assertRaisesRegex(evidence.EvidenceError, "non-integer"):
            evidence.validate_trace(boolean, description="boolean trace")

        different = copy.deepcopy(trace)
        different[evidence.PREFIX + "page_count_after_collect"] = 2
        with self.assertRaisesRegex(evidence.EvidenceError, "differs"):
            evidence.compare_traces(trace, different)


class ReportTests(unittest.TestCase):
    def valid_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/live-owner-full-medium-remote-release-evidence")
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
        return {
            "c_probe": {
                "build_command": c_command,
                "elf": copy.deepcopy(evidence.EXPECTED_C_ELF),
                "run_command": [
                    f"{evidence.NORMALIZED_EVIDENCE_ROOT}/{evidence.STEM}-c"
                ],
                "source_sha256": evidence.sha256_bytes(
                    evidence.C_TRACE_PROBE.encode("utf-8")
                ),
                "trace": copy.deepcopy(evidence.EXPECTED_TRACE_VALUES),
            },
            "comparison": {
                "compared_value_count": len(evidence.EXPECTED_TRACE_VALUES),
                "status": "matched",
            },
            "format": 1,
            "kind": (
                "mimalloc-x86_64-live-owner-full-medium-remote-release-"
                "differential-evidence"
            ),
            "profile": evidence.EXPECTED_PROFILE,
            "provenance": {
                "execution_mode": "native",
                "host_architecture": "x86_64",
            },
            "rust_probe": {
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

    def test_report_binds_native_comparison_source_flags_and_source_set(self):
        report = self.valid_report()
        evidence.validate_report(report)
        self.assertEqual(
            report["comparison"],
            {"compared_value_count": 35, "status": "matched"},
        )

    def test_report_rejects_weakened_comparison_release_source_or_trace(self):
        mutations = (
            lambda report: report["comparison"].update(
                {"compared_value_count": True}
            ),
            lambda report: report["source"].update({"release_flags": []}),
            lambda report: report["source"].update({"release_source_set": []}),
            lambda report: report["source"].update(
                {"archive_sha256": "0" * 64}
            ),
            lambda report: report["scope"].update({"public_mi_api_claimed": 0}),
            lambda report: report["c_probe"]["trace"].update(
                {evidence.PREFIX + "valid": True}
            ),
            lambda report: report["rust_probe"]["trace"].update(
                {evidence.PREFIX + "page_count_after_collect": 2}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                report = copy.deepcopy(self.valid_report())
                mutate(report)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_report(report)


if __name__ == "__main__":
    unittest.main()
