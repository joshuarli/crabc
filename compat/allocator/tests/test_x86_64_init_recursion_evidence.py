#!/usr/bin/env python3
"""Pure contract checks for the native init/recursion evidence lane."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_init_recursion_evidence.py"
spec = importlib.util.spec_from_file_location("init_recursion_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class InitRecursionEvidenceTests(unittest.TestCase):
    def mutated_schema(self, mutate):
        value = evidence.load_schema()
        mutate(value)
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        stream = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False, dir=scratch,
        )
        with stream:
            json.dump(value, stream)
        path = Path(stream.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = ROOT / ".work/tmp/init-recursion-evidence"
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.c_trace_command(
            "/usr/bin/musl-gcc", source, temporary / "init-recursion.c",
            temporary / "init-recursion-c", schema,
        )
        trace_command = evidence.rust_test_command(
            "/usr/bin/cargo", temporary / "rust-target", evidence.TRACE_FILTER,
        )
        lifecycle_checks = []
        for check in evidence.EXPECTED_LIFECYCLE_CHECKS:
            command = evidence.rust_test_command(
                "/usr/bin/cargo", temporary / "rust-target", check["filter"],
            )
            lifecycle_checks.append({
                "cargo_command": evidence.normalize_command(command, temporary, None),
                "filter": check["filter"],
                "passed_test_count": 1,
                "source": {
                    "path": check["source"],
                    "sha256": evidence.sha256_file(ROOT / check["source"]),
                },
                "target_dir": {
                    "isolated": True,
                    "retained": False,
                    "value": f"{evidence.NORMALIZED_EVIDENCE_ROOT}/rust-target",
                },
            })
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": evidence.normalize_command(c_command, temporary, source),
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": [f"{evidence.NORMALIZED_EVIDENCE_ROOT}/init-recursion-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode("utf-8")),
                "trace": evidence.EXPECTED_TRACE_VALUES,
            },
            rust_probe={
                "cargo_command": evidence.normalize_command(trace_command, temporary, None),
                "lockfile": {
                    "path": evidence.relative(evidence.LOCKFILE),
                    "sha256": evidence.sha256_file(evidence.LOCKFILE),
                },
                "passed_test_count": 1,
                "source": {
                    "path": evidence.relative(evidence.RUST_TRACE_SOURCE),
                    "sha256": evidence.sha256_file(evidence.RUST_TRACE_SOURCE),
                },
                "target_dir": {
                    "isolated": True,
                    "retained": False,
                    "value": f"{evidence.NORMALIZED_EVIDENCE_ROOT}/rust-target",
                },
                "trace": evidence.EXPECTED_TRACE_VALUES,
            },
            lifecycle_checks=lifecycle_checks,
        )

    def test_schema_fixes_the_explicit_private_source_route(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["target"], evidence.EXPECTED_TARGET)
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["profile"], evidence.EXPECTED_PROFILE)
        self.assertTrue(schema["scope"]["explicit_process_and_worker_thread_route_only"])
        self.assertTrue(schema["scope"]["rust_direct_second_mutable_owner_refused"])
        self.assertFalse(schema["scope"]["automatic_pthread_destructor_claimed"])
        self.assertFalse(schema["scope"]["metadata_completion_claimed"])
        self.assertNotIn("mi_process_done();", evidence.C_TRACE_PROBE)
        self.assertEqual(schema["trace"]["expected_values"], evidence.EXPECTED_TRACE_VALUES)

    def test_schema_rejects_scope_source_and_trace_drift(self):
        mutations = (
            lambda value: value["scope"].update({"metadata_completion_claimed": True}),
            lambda value: value["scope"].update({"runtime_lifecycle_callback_parity_claimed": True}),
            lambda value: value["source_anchors"][0].update({"start_line": 306}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.init_recursion.recovery_default_initialized": 0}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                path = self.mutated_schema(mutate)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.load_schema(path)

    def test_trace_requires_equal_normalized_one_owner_transitions(self):
        evidence.compare_traces(
            evidence.EXPECTED_TRACE_VALUES, evidence.EXPECTED_TRACE_VALUES,
        )
        changed = dict(evidence.EXPECTED_TRACE_VALUES)
        changed["trace.init_recursion.reentrant_entry_preserves_one_owner"] = 0
        with self.assertRaises(evidence.EvidenceError):
            evidence.compare_traces(evidence.EXPECTED_TRACE_VALUES, changed)

    def test_report_requires_native_provenance_and_the_complete_lifecycle_batch(self):
        report = self.complete_report()
        evidence.validate_report(report)
        self.assertEqual(report["comparison"], {
            "compared_value_count": len(evidence.EXPECTED_TRACE_VALUES),
            "status": "matched",
        })
        self.assertEqual(len(report["lifecycle_checks"]), 3)

        report = self.complete_report()
        report["provenance"] = {"execution_mode": "emulated", "host_architecture": "x86_64"}
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(report)

        report = self.complete_report()
        report["lifecycle_checks"][1]["filter"] = "process_init::tests::other"
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(report)


if __name__ == "__main__":
    unittest.main()
