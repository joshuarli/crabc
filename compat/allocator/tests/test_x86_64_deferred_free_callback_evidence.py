#!/usr/bin/env python3
"""Pure contracts for native x86-64 deferred-free callback evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_deferred_free_callback_evidence.py"
spec = importlib.util.spec_from_file_location("deferred_free_callback_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class DeferredFreeCallbackEvidenceTests(unittest.TestCase):
    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/deferred-free-callback-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        return evidence.report_from_results(
            schema,
            {"execution_mode": "native", "host_architecture": "x86_64"},
            evidence.EXPECTED_ARCHIVE_SHA256,
            schema["source_anchors"],
            {
                "build_command": evidence.normalize_command(
                    evidence.c_trace_command(
                        "/usr/bin/musl-gcc",
                        source,
                        temporary / "deferred-free-callback.c",
                        temporary / "deferred-free-callback-c",
                        schema,
                    ),
                    temporary,
                    source,
                ),
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": ["<temporary-evidence-root>/deferred-free-callback-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
                "trace": trace,
            },
            {
                "cargo_command": evidence.normalize_command(
                    evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"),
                    temporary,
                    None,
                ),
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

    def test_schema_pins_source_callback_and_private_boundary(self) -> None:
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence.schema_template())
        self.assertEqual(len(schema["source_anchors"]), 6)
        self.assertEqual(schema["source_anchors"][0]["member"], "src/alloc.c")
        self.assertEqual(schema["source_anchors"][0]["end_line"], 258)
        self.assertEqual(len(schema["trace"]["expected_values"]), 15)
        self.assertFalse(schema["scope"]["registration_remains_crate_private"])
        self.assertTrue(schema["scope"]["runtime_registration_adapter_exposed"])
        self.assertFalse(schema["scope"]["emulation_accepted"])

    def test_schema_rejects_source_scope_and_trace_drift(self) -> None:
        mutations = (
            lambda value: value.update({"format": True}),
            lambda value: value["scope"].update({"public_mi_api_claimed": True}),
            lambda value: value["source_anchors"][0].update({"end_line": 257}),
            lambda value: value["trace"]["expected_values"].pop("trace.deferred_free.force_heartbeat_advanced"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as stream:
                    json.dump(value, stream)
                    stream.flush()
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.load_schema(Path(stream.name))

    def test_probe_uses_pinned_generic_and_actual_oom_retry(self) -> None:
        probe = evidence.C_TRACE_PROBE
        self.assertIn("mi_register_deferred_free(&deferred_callback, &trace);", probe)
        self.assertIn("_mi_malloc_generic(trace.theap, 2048, 0, NULL)", probe)
        self.assertIn("mi_reserve_os_memory_ex(32 * 1024 * 1024", probe)
        self.assertIn("mi_arena_try_alloc_at", probe)
        self.assertIn("mi_heap_malloc(heap, 64)", probe)
        self.assertIn("_mi_deferred_free(trace->theap, false);", probe)
        self.assertNotIn("mi_heap_collect(", probe)

    def test_trace_and_report_reject_drift(self) -> None:
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        evidence.validate_trace(trace, description="test trace")
        self.assertEqual(evidence.compare_traces(trace, trace)["status"], "matched")
        trace["trace.deferred_free.force_heartbeat_advanced"] = 0
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_trace(trace, description="test trace")

        report = self.complete_report()
        evidence.validate_report(report)
        weakened = copy.deepcopy(report)
        weakened["scope"]["runtime_registration_adapter_exposed"] = False
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(weakened)

    def test_commands_keep_release_tls_pthread_and_exact_rust_fixture(self) -> None:
        schema = evidence.load_schema()
        temporary = Path("/tmp/deferred-free-callback-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / "deferred-free-callback.c",
            temporary / "deferred-free-callback-c",
            schema,
        )
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(
            evidence.normalize_command(command, temporary, source), schema
        )
        evidence.validate_normalized_rust_command(
            evidence.normalize_command(
                evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"),
                temporary,
                None,
            )
        )


if __name__ == "__main__":
    unittest.main()
