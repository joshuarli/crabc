#!/usr/bin/env python3
"""Pure contract tests for private native x86-64 aligned realloc evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_aligned_overalloc_realloc_evidence.py"
spec = importlib.util.spec_from_file_location("aligned_overalloc_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_private_native_scope_geometry_and_rust_selection(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(schema["target"], evidence.EXPECTED_TARGET)
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["scope"], evidence.EXPECTED_SCOPE)
        self.assertTrue(schema["scope"]["ordinary_arena_backed_offset_aligned_request_only"])
        self.assertFalse(schema["scope"]["public_x86_libc_or_ldso_support"])
        self.assertEqual(schema["rust_test"]["test_filter"], evidence.RUST_TEST_FILTER)
        self.assertEqual(schema["trace"]["expected_values"]["trace.aligned_overalloc.adjust"], 57)
        self.assertEqual(schema["trace"]["expected_values"]["trace.aligned_overalloc.growth_usable"], 103)
        self.assertEqual(schema["c_probe_sha256"], evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()))

    def test_schema_rejects_scope_trace_anchor_or_format_drift(self):
        mutations = (
            (lambda value: value["scope"].update({"public_x86_libc_or_ldso_support": True}), "checked-in schema drifted"),
            (lambda value: value["trace"]["expected_values"].update({"trace.aligned_overalloc.valid": 0}), "checked-in schema drifted"),
            (lambda value: value["source_anchors"][0].update({"sha256": "0" * 64}), "checked-in schema drifted"),
            (lambda value: value.update({"format": True}), "checked-in schema drifted"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as stream:
                    json.dump(value, stream)
                    stream.flush()
                    with self.assertRaisesRegex(evidence.EvidenceError, message):
                        evidence.load_schema(Path(stream.name))


class CommandAndTraceTests(unittest.TestCase):
    def test_c_command_retains_fixed_release_pthread_and_tls_selection(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/aligned-overalloc-realloc-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command("/usr/bin/musl-gcc", source, temporary / "aligned-overalloc-realloc.c", temporary / "aligned-overalloc-realloc-c", schema)
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(evidence.normalize_command(command, temporary, source), schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-pthread"], schema)

    def test_trace_parser_requires_the_exact_address_independent_record(self):
        trace = evidence.parse_trace("\n".join([evidence.TRACE_BEGIN, *(f"{key}={value}" for key, value in evidence.EXPECTED_TRACE_VALUES.items()), evidence.TRACE_END]), description="test trace")
        evidence.validate_trace(trace, description="test trace")
        self.assertEqual(evidence.compare_traces(trace, trace)["status"], "matched")
        with self.assertRaisesRegex(evidence.EvidenceError, "raw address"):
            evidence.parse_trace(f"{evidence.TRACE_BEGIN}\ntrace.aligned_overalloc.pointer=0x1\n{evidence.TRACE_END}", description="test trace")
        changed = dict(trace)
        changed["trace.aligned_overalloc.valid"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "value mismatches"):
            evidence.validate_trace(changed, description="test trace")


class ReportTests(unittest.TestCase):
    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/aligned-overalloc-realloc-evidence")
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": evidence.normalize_command(evidence.c_trace_command("/usr/bin/musl-gcc", temporary / "source/mimalloc-3.5.0", temporary / "aligned-overalloc-realloc.c", temporary / "aligned-overalloc-realloc-c", schema), temporary, temporary / "source/mimalloc-3.5.0"),
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": ["<temporary-evidence-root>/aligned-overalloc-realloc-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
                "trace": trace,
            },
            rust_probe={
                "cargo_command": evidence.normalize_command(evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"), temporary, None),
                "lockfile": {"path": evidence.relative(evidence.LOCKFILE), "sha256": evidence.sha256_file(evidence.LOCKFILE)},
                "passed_test_count": 1,
                "source": {"path": evidence.relative(evidence.RUST_TEST_SOURCE), "sha256": evidence.sha256_file(evidence.RUST_TEST_SOURCE)},
                "target_dir": {"isolated": True, "retained": False, "value": "<temporary-evidence-root>/rust-target"},
                "trace": trace,
            },
        )

    def test_report_is_private_and_binds_both_probe_identities(self):
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["comparison"], {"compared_value_count": 29, "status": "matched"})
        self.assertTrue(report["scope"]["terminal_arena_release_only"])
        self.assertFalse(report["scope"]["public_crabc_support"])
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])

    def test_report_rejects_weakened_elf_rust_or_scope_evidence(self):
        report = self.complete_report()
        mutations = (
            (lambda value: value["c_probe"].update({"elf": {}}), "C identity"),
            (lambda value: value["rust_probe"]["cargo_command"].remove("--locked"), "Rust command drifted"),
            (lambda value: value["scope"].update({"terminal_arena_release_only": False}), "private boundary"),
            (lambda value: value["rust_probe"].update({"passed_test_count": True}), "Rust test selection"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                weakened = copy.deepcopy(report)
                mutate(weakened)
                with self.assertRaisesRegex(evidence.EvidenceError, message):
                    evidence.validate_report(weakened)


class SourceApiControlTests(unittest.TestCase):
    def observation(self, refused=False):
        values = {"request": 81, "alignment": 128, "offset": 11,
                  "allocated": 1, "zero": 1, "aligned": 1,
                  "usable": 0 if refused else 107,
                  "usable_errno": 22 if refused else 0,
                  "reallocated": 1, "realloc_aligned": 1,
                  "copied": 0 if refused else 1,
                  "realloc_errno": 22 if refused else 0,
                  "free_returned": 1, "free_errno": 22 if refused else 0}
        return "".join(f"{key}={value}\n" for key, value in values.items()).encode()

    def diagnostic(self):
        return b"".join(f"mimalloc: error: thread 0x123: {api}: invalid (unaligned) pointer: 0x456\n".encode()
                        for api in ("mi_usable_size", "mi_usable_size", "mi_free", "mi_free"))

    def test_valid_client_all_profiles_and_exact_c_debug_refusal(self):
        for profile in ("release", "debug-1", "stat-1", "stat-2"):
            for backend in ("c", "native"):
                refused = profile == "debug-1" and backend == "c"
                evidence.validate_source_api_observation(profile, backend, "process", int(refused),
                    self.observation(refused), self.diagnostic() if refused else b"")

    def test_refusal_is_not_matched_nonzero_or_a_native_waiver(self):
        for profile, backend, kind, status, stdout, stderr in (
            ("release", "c", "process", 1, self.observation(True), self.diagnostic()),
            ("debug-1", "native", "process", 1, self.observation(True), self.diagnostic()),
            ("debug-1", "c", "process", 0, self.observation(), b""),
            ("debug-1", "c", "timeout", 1, self.observation(True), self.diagnostic()),
            ("debug-1", "c", "process", 1, self.observation(True), b"unrelated error\n"),
            ("stat-2", "native", "process", 0, self.observation().replace(b"copied=1", b"copied=0"), b""),
        ):
            with self.subTest(profile=profile, backend=backend, kind=kind):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_source_api_observation(profile, backend, kind, status, stdout, stderr)

    def test_failed_real_compiler_process_keeps_raw_failure_without_receipt(self):
        m4, record, stress, receipts = evidence.source_api_helpers()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            directory = Path(temporary)
            source = directory / "pinned-source"
            (source / "include").mkdir(parents=True)
            (source / "include/mimalloc.h").write_text("header")
            (source / "LICENSE").write_text("license")
            with mock.patch.object(evidence.run, "ARTIFACT_ROOT", directory / "products"), \
                 mock.patch.object(evidence.run, "require_native_x86_64", return_value={}), \
                 mock.patch.object(evidence.run, "load_pin", return_value={"archive_root": "mimalloc-3.5.0"}), \
                 mock.patch.object(evidence.run, "fetch_archive", return_value=directory / "archive"), \
                 mock.patch.object(evidence.run, "safe_extract", return_value=source), \
                 mock.patch.object(evidence.run, "require_tool", return_value="/bin/false"), \
                 mock.patch.object(receipts, "source_seal", return_value={"revision": "a" * 40}), \
                 mock.patch.object(receipts, "write_receipt") as publish, \
                 mock.patch.object(evidence, "source_api_helpers", return_value=(m4, record, stress, receipts)):
                with self.assertRaisesRegex(evidence.EvidenceError, "oracle-build failed"):
                    evidence.run_source_api_control()
                publish.assert_not_called()
            logs = list(directory.rglob("release-oracle-build.json"))
            self.assertEqual(len(logs), 1)
            raw = json.loads(logs[0].read_text())
            self.assertEqual((raw["kind"], raw["status"]), ("process", 1))
            self.assertEqual(logs[0].with_suffix(".stderr").read_bytes(), b"")

    def test_changed_geometry_duplicate_or_missing_field_fails(self):
        original = self.observation()
        for changed in (original.replace(b"offset=11", b"offset=7"), original + b"copied=1\n",
                        original.replace(b"free_returned=1\n", b"")):
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_source_api_observation("release", "native", "process", 0, changed, b"")


if __name__ == "__main__":
    unittest.main()
