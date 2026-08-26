#!/usr/bin/env python3
"""Pure contracts for the native C cancellation pthread-destructor oracle lane."""

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
SCRIPT = ROOT / "compat/allocator/x86_64_cancellation_pthread_destructor_evidence.py"
spec = importlib.util.spec_from_file_location("cancellation_pthread_destructor_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class CancellationPthreadDestructorEvidenceTests(unittest.TestCase):
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
                Path("/tmp/evidence/cancellation-pthread-destructor.c"),
                Path("/tmp/evidence/cancellation-pthread-destructor-c"),
                schema,
            ),
            Path("/tmp/evidence"),
            Path("/tmp/source/mimalloc-3.5.0"),
        )
        c_probe = {
            "build_command": command,
            "elf": evidence.EXPECTED_C_ELF,
            "run_command": ["<temporary-evidence-root>/cancellation-pthread-destructor-c"],
            "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode("utf-8")),
            "trace": dict(evidence.EXPECTED_TRACE_VALUES),
        }
        return {
            "c_probe": c_probe,
            "format": 1,
            "kind": "mimalloc-x86_64-cancellation-pthread-destructor-c-oracle-evidence",
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
        self.assertEqual(schema["source_anchors"][0]["member"], "src/prim/unix/prim.c")
        self.assertEqual(len(schema["trace"]["expected_values"]), 46)
        self.assertTrue(schema["scope"]["explicit_cancel_then_testcancel_only"])
        self.assertTrue(schema["scope"]["deferred_cancellation_only"])
        self.assertTrue(schema["scope"]["no_explicit_thread_done_in_worker"])
        self.assertFalse(schema["scope"]["crabc_pthread_cancel_parity_claimed"])
        self.assertFalse(schema["scope"]["worker_async_cancellation_accepted"])
        self.assertFalse(schema["scope"]["emulation_accepted"])

    def test_probe_requires_deferred_testcancel_and_rejects_explicit_worker_teardown(self):
        source = evidence.C_TRACE_PROBE
        for fragment in (
            "pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state)",
            "pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old_cancel_type)",
            "pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)",
            "atomic_store_explicit(&context->ready, 1, memory_order_release);",
            "pthread_cancel(worker)",
            "context->entered_testcancel = true;",
            "pthread_testcancel();",
            "join_result == PTHREAD_CANCELED",
        ):
            self.assertIn(fragment, source)
        evidence.validate_probe_source(source)

        for explicit_call in ("mi_thread_done();", "_mi_thread_done(NULL);", "pthread_exit(NULL);"):
            with self.subTest(explicit_call=explicit_call):
                injected = source.replace(
                    "context->entered_testcancel = true;",
                    f"{explicit_call}\n  context->entered_testcancel = true;",
                )
                with self.assertRaisesRegex(evidence.EvidenceError, "explicit teardown"):
                    evidence.validate_probe_source(injected)

    def test_probe_rejects_extra_or_reordered_cancellation_control_flow(self):
        source = evidence.C_TRACE_PROBE
        mutations = (
            (
                source.replace(
                    "pthread_testcancel();",
                    "pthread_testcancel();\n  pthread_testcancel();",
                    1,
                ),
                "exactly one cancellation delivery",
            ),
            (
                source.replace(
                    "context->failure_stage = 2;",
                    "pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old_cancel_type);\n    "
                    "context->failure_stage = 2;",
                    1,
                ),
                "deferred cancellation exactly once",
            ),
            (
                source.replace(
                    "context->entered_testcancel = true;",
                    "(void)pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);\n  "
                    "context->entered_testcancel = true;",
                    1,
                ),
                "must not accept asynchronous cancellation",
            ),
            (
                source.replace(
                    "if (pthread_cancel(worker) != 0) goto output;",
                    "if (pthread_cancel(worker) != 0) goto output;\n  (void)pthread_cancel(worker);",
                    1,
                ),
                "exactly one parent cancellation request",
            ),
            (
                source.replace(
                    "context->entered_testcancel = true;\n  pthread_testcancel();",
                    "pthread_testcancel();\n  context->entered_testcancel = true;",
                    1,
                ),
                "worker cancellation ordering drifted",
            ),
            (
                source.replace(
                    "if (pthread_cancel(worker) != 0) goto output;\n  cancel_request_succeeded = 1;\n  "
                    "atomic_store_explicit(&context.cancel_gate, 1, memory_order_release);",
                    "atomic_store_explicit(&context.cancel_gate, 1, memory_order_release);\n  "
                    "if (pthread_cancel(worker) != 0) goto output;\n  cancel_request_succeeded = 1;",
                    1,
                ),
                "parent cancellation ordering drifted",
            ),
        )
        for mutated_source, message in mutations:
            with self.subTest(message=message):
                with self.assertRaisesRegex(evidence.EvidenceError, message):
                    evidence.validate_probe_source(mutated_source)

    def test_schema_rejects_scope_trace_and_anchor_drift(self):
        mutations = (
            lambda value: value.update({"unexpected": 1}),
            lambda value: value.update({"format": True}),
            lambda value: value["scope"].update({"crabc_pthread_cancel_parity_claimed": True}),
            lambda value: value["trace"]["expected_values"].pop(
                "trace.cancellation_pthread_destructor.valid"
            ),
            lambda value: value["source_anchors"].__setitem__(
                0,
                {"member": "src/prim/unix/prim.c", "start_line": 1, "end_line": 2, "sha256": "0" * 64},
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.mutated_schema(mutate):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.load_schema()

    def test_trace_rejects_missing_unexpected_noninteger_and_wrong_values(self):
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        for mutate in (
            lambda value: value.pop("trace.cancellation_pthread_destructor.valid"),
            lambda value: value.update({"trace.cancellation_pthread_destructor.extra": 1}),
            lambda value: value.update({"trace.cancellation_pthread_destructor.valid": True}),
            lambda value: value.update(
                {"trace.cancellation_pthread_destructor.join_result_is_pthread_canceled": 0}
            ),
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
        trace_drift["c_probe"]["trace"][
            "trace.cancellation_pthread_destructor.join_result_is_pthread_canceled"
        ] = 0
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
