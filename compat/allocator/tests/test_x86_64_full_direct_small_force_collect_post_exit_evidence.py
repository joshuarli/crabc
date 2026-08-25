#!/usr/bin/env python3
"""Pure contracts for the private full-direct-small post-exit x86 lane."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_full_direct_small_force_collect_post_exit_evidence.py"
spec = importlib.util.spec_from_file_location("full_direct_small_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_direct_small_geometry_and_private_scope(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        values = schema["trace"]["expected_values"]
        self.assertEqual(len(values), 28)
        self.assertEqual(values["trace.full_direct_small_exit.request_size"], 1024)
        self.assertEqual(values["trace.full_direct_small_exit.block_size"], 1024)
        self.assertEqual(values["trace.full_direct_small_exit.capacity"], 64)
        self.assertEqual(values["trace.full_direct_small_exit.direct_cache_range_start"], 113)
        self.assertEqual(values["trace.full_direct_small_exit.direct_cache_range_end"], 128)
        self.assertEqual(
            values["trace.full_direct_small_exit.arena_abandoned_bin_bitmap_clear_after_final_free"],
            1,
        )
        self.assertTrue(schema["scope"]["full_direct_small_regular_bin_only"])
        self.assertTrue(schema["scope"]["mapped_process_route_only"])
        self.assertFalse(schema["scope"]["general_remote_free_routing_claimed"])

    def test_schema_rejects_probe_scope_anchor_or_trace_drift(self):
        mutations = (
            lambda value: value.update({"c_probe_sha256": "0" * 64}),
            lambda value: value["scope"].update({"mapped_process_route_only": False}),
            lambda value: value["source_anchors"][2].update({"sha256": "0" * 64}),
            lambda value: value["rust_test"].update({"target_arch": "aarch64"}),
            lambda value: value["trace"]["expected_values"].update(
                {"trace.full_direct_small_exit.capacity": 63}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as stream:
                    json.dump(value, stream)
                    stream.flush()
                    with self.assertRaisesRegex(evidence.EvidenceError, "schema drifted"):
                        evidence.load_schema(Path(stream.name))


class TraceAndCommandTests(unittest.TestCase):
    def test_parser_requires_exact_pointer_free_trace(self):
        trace = evidence.parse_trace(
            "\n".join(
                [
                    evidence.TRACE_BEGIN,
                    *(f"{key}={value}" for key, value in evidence.EXPECTED_TRACE_VALUES.items()),
                    evidence.TRACE_END,
                ]
            ),
            description="direct-small trace",
        )
        evidence.validate_trace(trace, description="direct-small trace")
        with self.assertRaisesRegex(evidence.EvidenceError, "raw address"):
            evidence.parse_trace(
                f"{evidence.TRACE_BEGIN}\ntrace.full_direct_small_exit.pointer=0x1\n{evidence.TRACE_END}",
                description="pointerful trace",
            )

    def test_c_command_retains_native_pthread_tls_profile(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/full-direct-small-command")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command(
            "/usr/bin/musl-gcc", source,
            temporary / "full-direct-small-force-collect-post-exit.c",
            temporary / "full-direct-small-force-collect-post-exit-c", schema,
        )
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(evidence.normalize_command(command, temporary, source), schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-pthread"], schema)

    def test_report_identity_keeps_direct_small_private_boundary(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/full-direct-small-report")
        source = temporary / "source/mimalloc-3.5.0"
        c_command = evidence.normalize_command(
            evidence.c_trace_command(
                "/usr/bin/musl-gcc", source,
                temporary / "full-direct-small-force-collect-post-exit.c",
                temporary / "full-direct-small-force-collect-post-exit-c", schema,
            ), temporary, source,
        )
        rust_command = evidence.normalize_command(
            evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"), temporary, None
        )
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        report = evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": c_command,
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": ["<temporary-evidence-root>/full-direct-small-force-collect-post-exit-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
                "trace": trace,
            },
            rust_probe={
                "cargo_command": rust_command,
                "lockfile": {"path": evidence.relative(evidence.LOCKFILE), "sha256": evidence.sha256_file(evidence.LOCKFILE)},
                "passed_test_count": 1,
                "source": {"path": evidence.relative(evidence.RUST_TEST_SOURCE), "sha256": evidence.sha256_file(evidence.RUST_TEST_SOURCE)},
                "target_dir": {"isolated": True, "retained": False, "value": "<temporary-evidence-root>/rust-target"},
                "trace": trace,
            },
        )
        self.assertEqual(report["kind"], evidence.DIRECT_EXIT_KIND)
        self.assertEqual(report["comparison"], {"compared_value_count": 28, "status": "matched"})
        weakened = copy.deepcopy(report)
        weakened["scope"]["full_direct_small_regular_bin_only"] = False
        with self.assertRaisesRegex(evidence.EvidenceError, "private boundary"):
            evidence.validate_report(weakened)


if __name__ == "__main__":
    unittest.main()
