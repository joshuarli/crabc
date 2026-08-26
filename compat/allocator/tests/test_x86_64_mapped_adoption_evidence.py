#!/usr/bin/env python3
"""Pure contracts for native x86-64 allocation-time mapped-page adoption."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_mapped_adoption_evidence.py"
spec = importlib.util.spec_from_file_location("mapped_adoption_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class MappedAdoptionEvidenceTests(unittest.TestCase):
    def mutated_schema(self, mutate):
        value = evidence.load_schema()
        mutate(value)
        stream = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False
        )
        with stream:
            json.dump(value, stream)
        path = Path(stream.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/mapped-adoption-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.c_trace_command(
            "/usr/bin/musl-gcc",
            source,
            temporary / "mapped-adoption.c",
            temporary / "mapped-adoption-c",
            schema,
        )
        rust_command = evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target")
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": evidence.normalize_command(c_command, temporary, source),
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": [f"{evidence.NORMALIZED_EVIDENCE_ROOT}/mapped-adoption-c"],
                "source_sha256": evidence.sha256_bytes(
                    evidence.C_TRACE_PROBE.encode("utf-8")
                ),
                "trace": evidence.EXPECTED_TRACE_VALUES,
            },
            rust_probe={
                "cargo_command": evidence.normalize_command(rust_command, temporary, None),
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
                "trace": evidence.EXPECTED_TRACE_VALUES,
            },
        )

    def test_schema_is_the_fixed_native_same_origin_allocation_adoption_profile(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["target"], evidence.EXPECTED_TARGET)
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["profile"], evidence.EXPECTED_PROFILE)
        self.assertTrue(schema["scope"]["allocation_time_same_origin_adoption_only"])
        self.assertTrue(schema["scope"]["arena_backed_only"])
        self.assertFalse(schema["scope"]["general_abandonment_or_adoption_claimed"])
        self.assertFalse(schema["scope"]["cross_thread_adoption_claimed"])
        self.assertFalse(schema["scope"]["public_mi_api_claimed"])
        self.assertTrue(
            schema["scope"]["rust_test_adapter_adopt_before_third_allocation_only"]
        )
        self.assertEqual(schema["trace"]["expected_values"], evidence.EXPECTED_TRACE_VALUES)

    def test_schema_rejects_private_boundary_and_source_drift(self):
        mutations = (
            lambda value: value["scope"].update({"cross_thread_adoption_claimed": True}),
            lambda value: value["scope"].update({"general_abandonment_or_adoption_claimed": True}),
            lambda value: value["source_anchors"][0].update({"start_line": 656}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.mapped_adoption.used_after_allocation": 2}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                path = self.mutated_schema(mutate)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.load_schema(path)

    def test_trace_rejects_pointer_or_protocol_drift(self):
        evidence.validate_trace(
            evidence.EXPECTED_TRACE_VALUES,
            description="fixture",
        )
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_trace(
                {"trace.mapped_adoption.pointer": 1},
                description="fixture",
            )
        changed = dict(evidence.EXPECTED_TRACE_VALUES)
        changed["trace.mapped_adoption.queue_tail_reassociated"] = 0
        with self.assertRaises(evidence.EvidenceError):
            evidence.compare_traces(evidence.EXPECTED_TRACE_VALUES, changed)

    def test_report_is_strictly_native_and_rejects_scope_or_trace_drift(self):
        report = self.complete_report()
        evidence.validate_report(report)
        self.assertEqual(report["comparison"], {
            "compared_value_count": len(evidence.EXPECTED_TRACE_VALUES),
            "status": "matched",
        })

        report = self.complete_report()
        report["provenance"] = {
            "execution_mode": "emulated",
            "host_architecture": "x86_64",
        }
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(report)

        report = self.complete_report()
        report["c_probe"]["trace"] = dict(evidence.EXPECTED_TRACE_VALUES)
        report["c_probe"]["trace"]["trace.mapped_adoption.allocation_is_same_page"] = 0
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(report)


if __name__ == "__main__":
    unittest.main()
