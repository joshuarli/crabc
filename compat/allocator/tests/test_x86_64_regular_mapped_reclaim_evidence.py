#!/usr/bin/env python3
"""Closed contracts for native x86-64 regular mapped-reclaim evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_regular_mapped_reclaim_evidence.py"
SCRATCH = ROOT / ".work/allocator-x86_64/regular-mapped-reclaim-static-tests"
spec = importlib.util.spec_from_file_location("regular_mapped_reclaim_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_pinned_aligned_predicate_and_complete_trace(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["target"], evidence.EXPECTED_TARGET)
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["scope"], evidence.EXPECTED_SCOPE)
        self.assertEqual(schema["c_probe_sha256"], evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()))
        self.assertEqual(
            schema["source_anchors"],
            [
                {"member": member, "start_line": start, "end_line": end, "sha256": digest}
                for member, start, end, digest in evidence.EXPECTED_SOURCE_ANCHORS
            ],
        )
        self.assertEqual(
            set(schema["trace"]["expected_values"]),
            set(evidence.EXPECTED_TRACE_VALUES),
        )
        self.assertEqual(
            {
                (anchor["member"], anchor["start_line"], anchor["end_line"])
                for anchor in schema["source_anchors"]
            }
            & {
                ("src/alloc-aligned.c", 18, 28),
                ("src/alloc-aligned.c", 160, 187),
            },
            {
                ("src/alloc-aligned.c", 18, 28),
                ("src/alloc-aligned.c", 160, 187),
            },
        )

    def test_schema_rejects_aligned_source_or_live_client_trace_drift(self):
        mutations = (
            (lambda value: value["source_anchors"][1].update({"sha256": "0" * 64}), "source anchor hash"),
            (
                lambda value: value["trace"]["expected_values"].pop(
                    "trace.regular_mapped_reclaim.initial.natural_alignment.request1.all_live"
                ),
                "trace contract",
            ),
            (lambda value: value.update({"c_probe_sha256": "0" * 64}), "C probe source hash"),
        )
        SCRATCH.mkdir(parents=True, exist_ok=True)
        for mutate, message in mutations:
            with self.subTest(message=message):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", encoding="utf-8", dir=SCRATCH, delete=False
                ) as stream:
                    json.dump(value, stream)
                    path = Path(stream.name)
                try:
                    with self.assertRaisesRegex(evidence.EvidenceError, message):
                        evidence.load_schema(path)
                finally:
                    path.unlink(missing_ok=True)


class CommandAndReportTests(unittest.TestCase):
    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/workspace/.work/allocator-x86_64/regular-mapped-reclaim-static")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.normalize_command(
            evidence.c_trace_command(
                "/usr/bin/musl-gcc",
                source,
                temporary / "regular-mapped-reclaim.c",
                temporary / "regular-mapped-reclaim-c",
                schema,
            ),
            temporary,
            source,
        )
        rust_command = evidence.normalize_command(
            evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"),
            temporary,
            None,
        )
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": c_command,
                "cleanup_trace": dict(evidence.EXPECTED_CLEANUP_TRACE),
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": ["<temporary-evidence-root>/regular-mapped-reclaim-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
                "trace": trace,
            },
            rust_probe={
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
                    "value": "<temporary-evidence-root>/rust-target",
                },
                "trace": trace,
            },
        )

    def test_report_reconstructs_all_regular_and_alignment_results(self):
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["comparison"], {"compared_value_count": 12, "status": "matched"})
        self.assertEqual(report["c_probe"]["trace"], evidence.EXPECTED_TRACE_VALUES)
        self.assertEqual(report["rust_probe"]["trace"], evidence.EXPECTED_TRACE_VALUES)

    def test_report_rejects_missing_live_alignment_or_weakened_source_binding(self):
        mutations = (
            (
                lambda value: value["rust_probe"]["trace"].pop(
                    "trace.regular_mapped_reclaim.later.natural_alignment.request8.all_live"
                ),
                "fixed trace",
            ),
            (
                lambda value: value["source"]["anchors"][2].update({"sha256": "0" * 64}),
                "archive or anchors drifted",
            ),
            (
                lambda value: value["c_probe"].update({"source_sha256": "0" * 64}),
                "C source hash",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                weakened = copy.deepcopy(self.complete_report())
                mutate(weakened)
                with self.assertRaisesRegex(evidence.EvidenceError, message):
                    evidence.validate_report(weakened)


if __name__ == "__main__":
    unittest.main()
