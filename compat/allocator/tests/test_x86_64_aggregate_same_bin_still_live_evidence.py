#!/usr/bin/env python3
"""Pure contracts for native x86-64 same-bin aggregate StillLive evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_aggregate_same_bin_still_live_evidence.py"
spec = importlib.util.spec_from_file_location("aggregate_same_bin_still_live_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class AggregateSameBinStillLiveEvidenceTests(unittest.TestCase):
    def validate_report(self, report):
        actual_sha256_file = evidence.sha256_file

        def digest(path):
            if path == evidence.LOCKFILE:
                return actual_sha256_file(path)
            return "0" * 64

        with mock.patch.object(evidence, "sha256_file", side_effect=digest):
            evidence.validate_report(report)

    def mutated_schema(self, mutate):
        value = evidence.load_schema()
        mutate(value)
        stream = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False,
        )
        with stream:
            json.dump(value, stream)
        path = Path(stream.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return mock.patch.object(evidence, "SCHEMA_PATH", path)

    def complete_report(self):
        schema = evidence.load_schema()
        c_command = evidence.normalize_command(
            evidence.c_command(
                "/usr/bin/musl-gcc",
                Path("/tmp/source/mimalloc-3.5.0"),
                Path("/tmp/evidence/aggregate-same-bin-still-live.c"),
                Path("/tmp/evidence/aggregate-same-bin-still-live-c"),
                schema,
            ),
            Path("/tmp/evidence"),
            Path("/tmp/source/mimalloc-3.5.0"),
        )
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        c_probe = {
            "build_command": c_command,
            "elf": evidence.EXPECTED_C_ELF,
            "run_command": ["<temporary-evidence-root>/aggregate-same-bin-still-live-c"],
            "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode("utf-8")),
            "trace": trace,
        }
        rust_command = evidence.normalize_command(
            evidence.rust_command("/usr/bin/cargo", Path("/tmp/evidence/rust-target")),
            Path("/tmp/evidence"),
            None,
        )
        rust_probe = {
            "cargo_command": rust_command,
            "lockfile": {
                "path": "Cargo.lock",
                "sha256": evidence.sha256_file(evidence.LOCKFILE),
            },
            "passed_test_count": 1,
            "source": {
                "path": "crabc-mimalloc/src/main_heap_page.rs",
                "sha256": "0" * 64,
            },
            "target_dir": {
                "isolated": True,
                "retained": False,
                "value": "<temporary-evidence-root>/rust-target",
            },
            "trace": trace,
        }
        return {
            "c_probe": c_probe,
            "comparison": {"compared_value_count": 53, "status": "matched"},
            "format": 1,
            "kind": "mimalloc-x86_64-aggregate-same-bin-still-live-differential-evidence",
            "profile": schema["profile"],
            "provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
            "rust_probe": rust_probe,
            "scope": schema["scope"],
            "source": {
                "archive_sha256": evidence.run.load_pin()["sha256"],
                "anchors": schema["source_anchors"],
                "release_flags": schema["release_flags"],
                "release_source_set": schema["release_source_set"],
            },
            "status": "passed",
            "target": schema["target"],
            "trace": schema["trace"],
            "upstream": schema["upstream"],
        }

    def test_schema_is_pinned_native_only_and_binds_same_bin_traversal(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(
            schema["source_anchors"][6],
            {
                "member": "src/page-queue.c",
                "start_line": 147,
                "end_line": 172,
                "sha256": "67dd6914e2d62e8a2efb13d49cc92692b7d8e245363597f16a3ff1c076e9cf5d",
            },
        )
        self.assertEqual(
            schema["source_anchors"][8],
            {
                "member": "src/theap.c",
                "start_line": 21,
                "end_line": 51,
                "sha256": "801bb68f34d171e9060ae96dc57c136c17999fb7e0fec5bf7dbe5462badb3d53",
            },
        )
        self.assertEqual(len(schema["trace"]["expected_values"]), 53)
        self.assertIn(
            "trace.aggregate_same_bin_still_live.same_bin_queue_successor_visits_both_before_exit",
            schema["trace"]["expected_values"],
        )
        self.assertFalse(schema["scope"]["emulation_accepted"])
        self.assertFalse(schema["scope"]["general_routing_claimed"])
        self.assertTrue(
            schema["scope"]
            ["same_bin_queue_count_and_successor_traversal_only"]
        )

    def test_schema_rejects_drift_and_emulation(self):
        mutations = (
            lambda value: value.update({"unexpected": 1}),
            lambda value: value.update({"format": True}),
            lambda value: value["scope"].update({"emulation_accepted": True}),
            lambda value: value["trace"]["expected_values"].pop(
                "trace.aggregate_same_bin_still_live.valid",
            ),
            lambda value: value["source_anchors"].__setitem__(
                8,
                {
                    "member": "src/theap.c",
                    "start_line": 1,
                    "end_line": 2,
                    "sha256": "0" * 64,
                },
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.mutated_schema(mutate):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.load_schema()

    def test_trace_rejects_missing_unexpected_noninteger_and_wrong_values(self):
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        for mutate in (
            lambda value: value.pop("trace.aggregate_same_bin_still_live.valid"),
            lambda value: value.update({"trace.aggregate_same_bin_still_live.extra": 1}),
            lambda value: value.update({"trace.aggregate_same_bin_still_live.valid": True}),
            lambda value: value.update({"trace.aggregate_same_bin_still_live.valid": 0}),
        ):
            value = dict(trace)
            mutate(value)
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_trace(value, description="test trace")

    def test_c_probe_uses_real_same_bin_teardown_and_gated_three_free_route(self):
        probe = evidence.C_TRACE_PROBE
        create = probe.index("if (pthread_create(&worker, NULL, producer_main, &f) != 0) goto done;")
        join = probe.index("if (pthread_join(worker, NULL) != 0) goto done;")
        first_free = probe.index("mi_free(f.first_client);")
        second_free = probe.index("mi_free(f.second_client);")
        final_free = probe.index("mi_free(f.first_survivor);")
        self.assertIn("mi_thread_done();", probe)
        self.assertNotIn("mi_heap_collect(", probe)
        self.assertIn("#if MI_PAGE_MAP_FLAT != 0", probe)
        self.assertIn("mi_option_set(mi_option_page_reclaim_on_free, 0);", probe)
        self.assertIn(
            "mi_option_set(mi_option_page_reclaim_on_free, old_reclaim);",
            probe,
        )
        self.assertIn("first_client = mi_heap_malloc(heap, CRABC_SAME_BIN_REQUEST);", probe)
        self.assertIn("first_survivor = mi_heap_malloc(heap, CRABC_SAME_BIN_REQUEST);", probe)
        self.assertIn("for (size_t index = 0; index < first_page->reserved - 2; index++)", probe)
        self.assertIn("second_client = mi_heap_malloc(heap, CRABC_SAME_BIN_REQUEST);", probe)
        self.assertIn("_mi_bin(first_page->block_size) != _mi_bin(second_page->block_size)", probe)
        self.assertIn("queue_has_exact_bidirectional_two_page_links", probe)
        self.assertIn("queue_visits_exactly_both", probe)
        self.assertLess(create, join)
        self.assertLess(join, first_free)
        self.assertLess(first_free, second_free)
        self.assertLess(second_free, final_free)
        self.assertIn(
            "_mi_safe_ptr_page(\n      (const void*)(uintptr_t)f.first_survivor_address)",
            probe,
        )
        self.assertIn(
            "_mi_safe_ptr_page((const void*)(uintptr_t)f.second_client_address) == NULL",
            probe,
        )
        self.assertIn(
            "_mi_safe_ptr_page((const void*)(uintptr_t)f.first_survivor_address) == NULL",
            probe,
        )
        self.assertIn("f.first_client = NULL;", probe)
        self.assertIn("f.second_client = NULL;", probe)
        self.assertIn("f.first_survivor = NULL;", probe)
        self.assertNotIn("first_after_second_free->", probe[final_free:])
        printed_fields = re.findall(
            r'printf\("trace\.aggregate_same_bin_still_live\.([^=]+)=%d\\n"',
            probe,
        )
        self.assertEqual(tuple(printed_fields), evidence.TRACE_FIELDS)

    def test_rust_fixture_directly_observes_the_same_bin_predecessor_link(self):
        source = evidence.RUST_TEST_SOURCE.read_text(encoding="utf-8")
        self.assertIn(
            "let first_prev = unsafe { first_page.as_ref().test_queue_prev() };",
            source,
        )
        self.assertIn(
            "let second_prev = unsafe { second_page.as_ref().test_queue_prev() };",
            source,
        )
        self.assertIn("first_prev.is_null()", source)
        self.assertIn("second_prev == first_page.as_ptr()", source)
        self.assertIn("second_prev.is_null()", source)
        self.assertIn("first_prev == second_page.as_ptr()", source)

    def test_report_rejects_provenance_and_probe_drift(self):
        report = self.complete_report()
        self.validate_report(report)
        with mock.patch.object(evidence, "RUST_TEST_SOURCE", Path("/tmp/missing-main-heap.rs")):
            with self.assertRaises(evidence.EvidenceError):
                self.validate_report(report)
        weakened = copy.deepcopy(self.complete_report())
        weakened["provenance"] = {"execution_mode": "qemu", "host_architecture": "x86_64"}
        with self.assertRaises(evidence.EvidenceError):
            self.validate_report(weakened)
        weakened = copy.deepcopy(self.complete_report())
        weakened["c_probe"]["trace"]["trace.aggregate_same_bin_still_live.valid"] = 0
        with self.assertRaises(evidence.EvidenceError):
            self.validate_report(weakened)

    def test_report_rejects_command_drift(self):
        report = self.complete_report()
        report["c_probe"]["build_command"][1] = "-std=c99"
        with self.assertRaises(evidence.EvidenceError):
            self.validate_report(report)

    def test_native_gate_rejects_non_native_provenance(self):
        with mock.patch.object(
            evidence.run,
            "require_native_x86_64",
            side_effect=evidence.run.HarnessError("native x86-64 required"),
        ):
            with self.assertRaisesRegex(evidence.EvidenceError, "native x86-64 required"):
                evidence.require_native_x86_64()


if __name__ == "__main__":
    unittest.main()
