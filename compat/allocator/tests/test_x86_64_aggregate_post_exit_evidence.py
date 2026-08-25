#!/usr/bin/env python3
"""Pure contracts for native x86-64 aggregate post-exit evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_aggregate_post_exit_evidence.py"
spec = importlib.util.spec_from_file_location("aggregate_post_exit_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class AggregatePostExitEvidenceTests(unittest.TestCase):
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
                Path("/tmp/evidence/aggregate-post-exit.c"),
                Path("/tmp/evidence/aggregate-post-exit-c"),
                schema,
            ),
            Path("/tmp/evidence"),
            Path("/tmp/source/mimalloc-3.5.0"),
        )
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        c_probe = {
            "build_command": c_command,
            "elf": evidence.EXPECTED_C_ELF,
            "run_command": ["<temporary-evidence-root>/aggregate-post-exit-c"],
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
            "comparison": {"compared_value_count": 25, "status": "matched"},
            "format": 1,
            "kind": "mimalloc-x86_64-aggregate-post-exit-differential-evidence",
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

    def test_schema_is_pinned_and_native_only(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["source_anchors"][9]["member"], "src/page-map.c")
        self.assertEqual(
            [anchor["member"] for anchor in schema["source_anchors"][-3:]],
            ["src/heap.c", "src/free.c", "src/alloc.c"],
        )
        self.assertEqual(len(schema["trace"]["expected_values"]), 25)
        self.assertFalse(schema["scope"]["emulation_accepted"])
        self.assertFalse(schema["scope"]["general_routing_claimed"])
        self.assertTrue(schema["scope"]["two_live_nonfull_medium_pages_in_distinct_bins_only"])

    def test_schema_rejects_drift_and_emulation(self):
        mutations = (
            lambda value: value.update({"unexpected": 1}),
            lambda value: value.update({"format": True}),
            lambda value: value["scope"].update({"emulation_accepted": True}),
            lambda value: value["trace"]["expected_values"].pop(
                "trace.aggregate_post_exit.valid",
            ),
            lambda value: value["source_anchors"].__setitem__(
                9,
                {
                    "member": "src/page-map.c",
                    "start_line": 199,
                    "end_line": 209,
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
            lambda value: value.pop("trace.aggregate_post_exit.valid"),
            lambda value: value.update({"trace.aggregate_post_exit.extra": 1}),
            lambda value: value.update({"trace.aggregate_post_exit.valid": True}),
            lambda value: value.update({"trace.aggregate_post_exit.valid": 0}),
        ):
            value = dict(trace)
            mutate(value)
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_trace(value, description="test trace")

    def test_c_probe_uses_real_teardown_and_saved_addresses_after_each_release(self):
        probe = evidence.C_TRACE_PROBE
        create = probe.index("if (pthread_create(&worker, NULL, producer_main, &f) != 0) goto done;")
        join = probe.index("if (pthread_join(worker, NULL) != 0) goto done;")
        self.assertIn("mi_thread_done();", probe)
        self.assertNotIn("mi_heap_collect(", probe)
        self.assertIn("#if MI_PAGE_MAP_FLAT != 0", probe)
        self.assertIn("first = mi_heap_malloc(heap, MI_SMALL_MAX_OBJ_SIZE + 1);", probe)
        self.assertIn("second = mi_heap_malloc(heap, MI_MEDIUM_MAX_OBJ_SIZE / 2);", probe)
        self.assertIn("mi_free(f.second);", probe)
        self.assertIn("mi_free(f.first);", probe)
        second_free = probe.index("mi_free(f.second);")
        final_free = probe.index("mi_free(f.first);")
        self.assertLess(create, join)
        self.assertLess(join, second_free)
        self.assertLess(second_free, final_free)
        self.assertIn(
            "_mi_safe_ptr_page((const void*)(uintptr_t)f.second_address) == NULL",
            probe,
        )
        self.assertIn(
            "_mi_safe_ptr_page((const void*)(uintptr_t)f.first_address) == NULL",
            probe,
        )
        self.assertIn("f.second = NULL;", probe)
        self.assertIn("f.first = NULL;", probe)
        self.assertNotIn("f.second_page->", probe[second_free:])
        self.assertNotIn("f.first_page->", probe[final_free:])

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
        weakened["c_probe"]["trace"]["trace.aggregate_post_exit.valid"] = 0
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
