#!/usr/bin/env python3
"""Static contracts for the later-main direct-small aggregate evidence lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_later_thread_exit_full_direct_small_pages_evidence.py"
spec = importlib.util.spec_from_file_location(
    "later_thread_exit_full_direct_small_pages_evidence", SCRIPT
)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_the_two_member_direct_small_partial_collector_route(self):
        schema = evidence.load_schema()
        self.assertTrue(evidence.exactly_matches(schema, evidence._schema_template()))
        values = schema["trace"]["expected_values"]
        prefix = evidence.PREFIX
        self.assertEqual(len(values), 67)
        self.assertEqual(values[prefix + "page_count"], 2)
        self.assertEqual(values[prefix + "request_size"], 1024)
        self.assertEqual(values[prefix + "block_size"], 1024)
        self.assertEqual(values[prefix + "capacity"], 64)
        self.assertEqual(values[prefix + "reserved"], 64)
        self.assertEqual(values[prefix + "slice_count"], 1)
        self.assertEqual(values[prefix + "direct_cache_range_start"], 113)
        self.assertEqual(values[prefix + "direct_cache_range_end"], 128)
        self.assertEqual(values[prefix + "page0.unmapped_prefix_free_count"], 9)
        self.assertEqual(values[prefix + "page1.unmapped_prefix_free_count"], 9)
        self.assertEqual(values[prefix + "page0.used_after_unmapped_prefix"], 56)
        self.assertEqual(values[prefix + "page1.used_after_unmapped_prefix"], 56)
        self.assertEqual(values[prefix + "page0.used_after_reabandon_boundary"], 54)
        self.assertEqual(values[prefix + "page1.used_after_reabandon_boundary"], 54)
        self.assertEqual(values[prefix + "abandoned_count_after_thread_done"], 0)
        self.assertEqual(values[prefix + "abandoned_count_after_first_terminal"], 0)
        self.assertEqual(values[prefix + "abandoned_count_after_second_boundary"], 1)
        self.assertEqual(values[prefix + "abandoned_count_after_final_terminal"], 0)
        self.assertTrue(
            schema["scope"]["c_oracle_real_pthread_thread_done_and_join_required"]
        )
        self.assertTrue(schema["scope"]["c_oracle_direct_small_regular_bin_only"])
        self.assertTrue(schema["scope"]["rust_scoped_test_worker_and_join_observed"])
        self.assertTrue(schema["scope"]["rust_later_main_typed_route_only"])
        self.assertFalse(
            schema["scope"]["rust_crabc_pthread_or_tls_callback_parity_claimed"]
        )
        self.assertEqual(
            schema["rust_test"]["test_filter"],
            (
                "main_heap_page::tests::"
                "x86_64_later_thread_exit_full_direct_small_pages_trace_matches_pinned_c"
            ),
        )

    def test_schema_rejects_hash_scope_type_and_trace_drift(self):
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["harness_dependency"].update({"sha256": "0" * 64}),
            lambda value: value["scope"].update(
                {"c_oracle_two_full_direct_small_pages_before_thread_done": False}
            ),
            lambda value: value["scope"].update({"emulation_accepted": 0}),
            lambda value: value["rust_test"].update({"target_arch": "aarch64"}),
            lambda value: value["trace"]["expected_values"].update(
                {evidence.PREFIX + "page1.used_after_reabandon_boundary": 53}
            ),
            lambda value: value["trace"]["expected_values"].update(
                {evidence.PREFIX + "valid": True}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", encoding="utf-8"
                ) as stream:
                    json.dump(value, stream)
                    stream.flush()
                    with self.assertRaisesRegex(
                        evidence._base.EvidenceError, "schema drifted"
                    ):
                        evidence.load_schema(Path(stream.name))


class ProbeTests(unittest.TestCase):
    def test_probe_requires_real_pthread_pre_exit_direct_cache_and_complete_maps(self):
        probe = evidence.C_TRACE_PROBE
        self.assertIn("mi_heap_malloc_small(heap, request)", probe)
        self.assertIn("PAGE_COUNT 2", probe)
        self.assertIn("BLOCKS_PER_PAGE 64", probe)
        self.assertIn("mi_thread_done()", probe)
        self.assertIn("pthread_join(producer, NULL)", probe)
        self.assertIn("fixture->direct_cache_range_matches = direct_cache_range(", probe)
        self.assertIn("map_span_is_page(page, *start_out, *count_out)", probe)
        self.assertIn("map_clear[page_index] = map_span_is(", probe)
        self.assertIn("!mi_page_is_owned(page)", probe)
        self.assertIn("mi_bbitmap_is_setN(", probe)
        self.assertIn(
            "CRABC_MI_LATER_THREAD_EXIT_FULL_DIRECT_SMALL_PAGES_TRACE_BEGIN", probe
        )
        evidence.validate_c_probe_contract(probe)

    def test_probe_validator_rejects_post_exit_theap_shortcuts_and_incomplete_release(self):
        mutations = (
            evidence.C_TRACE_PROBE.replace(
                "mi_thread_done();",
                "mi_thread_done(); theap->pages_free_direct[0] = NULL;",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "if (pthread_join(producer, NULL) != 0) goto output;",
                "if (pthread_join_after_client_frees(producer, NULL) != 0) goto output;",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "return map_span_is_page(page, *start_out, *count_out);",
                "return map_span_is(*start_out, *count_out, true);",
                1,
            ),
            evidence.C_TRACE_PROBE.replace(
                "starts[page_index], page_slice_count[page_index], false);",
                "starts[page_index], page_slice_count[page_index], true);",
                1,
            ),
            evidence.C_TRACE_PROBE.replace("&& !mi_page_is_owned(page);", "", 1),
        )
        for probe in mutations:
            with self.subTest(probe=probe):
                with self.assertRaises(evidence._base.EvidenceError):
                    evidence.validate_c_probe_contract(probe)

    def test_trace_requires_the_exact_common_two_member_shape(self):
        trace = copy.deepcopy(evidence.EXPECTED_TRACE_VALUES)
        evidence.validate_trace(trace, description="complete direct-small aggregate trace")
        trace.pop(evidence.PREFIX + "page1.arena_slice_released_after_terminal_free")
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.validate_trace(trace, description="missing direct-small aggregate fact")
        trace = copy.deepcopy(evidence.EXPECTED_TRACE_VALUES)
        trace[evidence.PREFIX + "page0.unmapped_prefix_free_count"] = True
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.validate_trace(trace, description="bool direct-small aggregate fact")
        trace = copy.deepcopy(evidence.EXPECTED_TRACE_VALUES)
        trace[evidence.PREFIX + "page1.used_after_reabandon_boundary"] = 55
        with self.assertRaises(evidence._base.EvidenceError):
            evidence.validate_trace(trace, description="wrong direct-small aggregate boundary")


class ReportTests(unittest.TestCase):
    def valid_report(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/later-thread-exit-full-direct-small-pages-evidence")
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
            "kind": (
                "mimalloc-x86_64-later-thread-exit-full-direct-small-pages-"
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

    def test_report_binds_exact_comparison_and_source_configuration(self):
        report = self.valid_report()
        evidence.validate_report(report)
        self.assertEqual(
            report["comparison"],
            {"compared_value_count": 67, "status": "matched"},
        )
        for value in (
            {"compared_value_count": 0, "status": "forged"},
            {"compared_value_count": True, "status": "matched"},
        ):
            with self.subTest(value=value):
                forged = copy.deepcopy(report)
                forged["comparison"] = value
                with self.assertRaisesRegex(
                    evidence._base.EvidenceError, "comparison drifted"
                ):
                    evidence.validate_report(forged)
        for field in ("release_flags", "release_source_set"):
            with self.subTest(field=field):
                forged = copy.deepcopy(report)
                forged["source"][field] = []
                with self.assertRaisesRegex(
                    evidence._base.EvidenceError, "source/trace contract drifted"
                ):
                    evidence.validate_report(forged)

    def test_report_rejects_c_rust_trace_disagreement(self):
        report = self.valid_report()
        report["rust_probe"]["trace"][
            evidence.PREFIX + "page1.used_after_reabandon_boundary"
        ] = 53
        with self.assertRaisesRegex(evidence._base.EvidenceError, "differs"):
            evidence.validate_report(report)


if __name__ == "__main__":
    unittest.main()
