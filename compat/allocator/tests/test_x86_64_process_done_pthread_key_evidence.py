#!/usr/bin/env python3
"""Pure contracts for the native C process-done pthread-key oracle lane."""

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
SCRIPT = ROOT / "compat/allocator/x86_64_process_done_pthread_key_evidence.py"
spec = importlib.util.spec_from_file_location("process_done_pthread_key_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class ProcessDonePthreadKeyEvidenceTests(unittest.TestCase):
    def mutated_schema(self, mutate):
        value = evidence.load_schema()
        mutate(value)
        stream = tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8", delete=False)
        with stream:
            json.dump(value, stream)
        path = Path(stream.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return mock.patch.object(evidence, "SCHEMA_PATH", path)

    def complete_report(self):
        schema = evidence.load_schema()
        command = evidence.normalize_command(
            evidence.c_trace_command(
                "/usr/bin/musl-gcc",
                Path("/tmp/source/mimalloc-3.5.0"),
                Path("/tmp/evidence/process-done-pthread-key.c"),
                Path("/tmp/evidence/process-done-pthread-key-c"),
                schema,
            ),
            Path("/tmp/evidence"),
            Path("/tmp/source/mimalloc-3.5.0"),
        )
        c_probe = {
            "build_command": command,
            "elf": evidence.EXPECTED_C_ELF,
            "run_command": ["<temporary-evidence-root>/process-done-pthread-key-c"],
            "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode("utf-8")),
            "trace": dict(evidence.EXPECTED_TRACE_VALUES),
        }
        return {
            "c_probe": c_probe,
            "format": 1,
            "kind": "mimalloc-x86_64-process-done-pthread-key-c-oracle-evidence",
            "profile": schema["profile"],
            "provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
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

    def test_schema_is_pinned_native_c_only_and_has_the_complete_trace(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["source_anchors"][0]["member"], "include/mimalloc/atomic.h")
        self.assertEqual(len(schema["trace"]["expected_values"]), 31)
        self.assertTrue(schema["scope"]["real_pinned_c_process_done_pthread_key"])
        self.assertTrue(schema["scope"]["after_process_done_worker_create_join_only"])
        self.assertTrue(schema["scope"]["automatic_destructor_absence_observed"])
        self.assertTrue(schema["scope"]["mi_tls_model_local_required"])
        self.assertTrue(schema["scope"]["no_explicit_thread_done_in_worker"])
        self.assertFalse(schema["scope"]["rust_process_done_pthread_key_claimed"])
        self.assertFalse(schema["scope"]["emulation_accepted"])

    def test_probe_requires_process_done_key_deletion_and_forbids_explicit_worker_teardown(self):
        source = evidence.C_TRACE_PROBE
        self.assertIn("extern pthread_key_t _mi_heap_default_key;", source)
        self.assertIn("mi_process_done();", source)
        self.assertIn("_mi_heap_default_key == MI_PTHREAD_KEY_INVALID", source)
        self.assertIn("#if !MI_TLS_MODEL_LOCAL", source)
        self.assertIn("mi_page_thread_free(page) != NULL", source)
        self.assertIn("context->worker_returned_naturally = true;", source)
        self.assertIn("pthread_join(worker, NULL)", source)
        evidence.validate_probe_source(source)

        for explicit_call in ("mi_thread_done();", "_mi_thread_done(NULL);", "pthread_exit(NULL);"):
            with self.subTest(explicit_call=explicit_call):
                injected = source.replace(
                    "context->worker_returned_naturally = true;",
                    f"{explicit_call}\n  context->worker_returned_naturally = true;",
                )
                with self.assertRaisesRegex(evidence.EvidenceError, "explicit teardown"):
                    evidence.validate_probe_source(injected)

    def test_probe_rejects_stale_owner_or_page_observation_order(self):
        source = evidence.C_TRACE_PROBE
        without_join_guard = source.replace(
            "if (block_size != 12288 || capacity != 2 || reserved != 42 || !same_page",
            "if (false || !same_page",
            1,
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "joined-page guard"):
            evidence.validate_probe_source(without_join_guard)

        without_final_reacquire = source.replace(
            "page = (page_start == NULL ? NULL : _mi_safe_ptr_page(page_start));",
            "page = page;",
            1,
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "reacquiring it"):
            evidence.validate_probe_source(without_final_reacquire)

    def test_schema_rejects_scope_trace_and_anchor_drift(self):
        mutations = (
            lambda value: value.update({"unexpected": 1}),
            lambda value: value.update({"format": True}),
            lambda value: value["scope"].update({"rust_process_done_pthread_key_claimed": True}),
            lambda value: value["scope"].update({"automatic_destructor_absence_observed": False}),
            lambda value: value["trace"]["expected_values"].pop("trace.process_done_pthread_key.valid"),
            lambda value: value["source_anchors"].__setitem__(
                0,
                {"member": "include/mimalloc/atomic.h", "start_line": 1, "end_line": 2, "sha256": "0" * 64},
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.mutated_schema(mutate):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.load_schema()

    def test_trace_rejects_missing_unexpected_noninteger_and_wrong_values(self):
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        for mutate in (
            lambda value: value.pop("trace.process_done_pthread_key.valid"),
            lambda value: value.update({"trace.process_done_pthread_key.extra": 1}),
            lambda value: value.update({"trace.process_done_pthread_key.valid": True}),
            lambda value: value.update({"trace.process_done_pthread_key.page_owner_matches_worker_after_join": 0}),
        ):
            value = dict(trace)
            mutate(value)
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_trace(value, description="test trace")

    def test_report_rejects_non_native_and_probe_command_drift(self):
        report = self.complete_report()
        evidence.validate_report(report)

        non_native = copy.deepcopy(report)
        non_native["provenance"] = {"execution_mode": "emulated", "host_architecture": "x86_64"}
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(non_native)

        command_drift = copy.deepcopy(report)
        command_drift["c_probe"]["build_command"][1] = "-std=c99"
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(command_drift)

        trace_drift = copy.deepcopy(report)
        trace_drift["c_probe"]["trace"]["trace.process_done_pthread_key.valid"] = 0
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(trace_drift)

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
