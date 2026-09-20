#!/usr/bin/env python3
"""Contract checks for the automatic regular-arena reservation receipt."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_automatic_arena_reservation_evidence.py"
SCHEMA = ROOT / "compat/allocator/x86_64-automatic-arena-reservation-evidence-v3.5.0.json"

spec = importlib.util.spec_from_file_location("automatic_arena_reservation_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AutomaticArenaReservationEvidenceContractTests(unittest.TestCase):
    def test_checked_schema_binds_the_exact_standalone_producer(self) -> None:
        self.assertTrue(SCRIPT.is_file(), "automatic arena reservation native driver is missing")
        self.assertTrue(SCHEMA.is_file(), "automatic arena reservation checked schema is missing")
        self.assertEqual(json.loads(SCHEMA.read_text(encoding="utf-8")), module.schema_template())
        self.assertEqual(module.REPORT_DEFAULT, ROOT / "compat/reports/allocator/x86_64/automatic-arena-reservation.json")
        self.assertIn('run.temporary_directory(\"crabc-mimalloc-x86_64-automatic-arena-\")', SCRIPT.read_text(encoding="utf-8"))
        self.assertTrue(module.EXPECTED_SCOPE["concurrent_fresh_regular_arena_reservation_claimed"])
        self.assertFalse(module.EXPECTED_SCOPE["automatic_reserve_lock_coalescing_claimed"])
        self.assertFalse(module.EXPECTED_SCOPE["simultaneous_reserve_lock_miss_or_coalescing_claimed"])
        self.assertIn("_mi_thread_init()", module.C_TRACE_PROBE)
        self.assertIn("root_is_current(theap)", module.C_TRACE_PROBE)
        self.assertIn("mi_option_disallow_os_alloc", module.C_TRACE_PROBE)
        self.assertIn("mi_arenas_try_find_free", module.C_TRACE_PROBE)
        self.assertIn("mi_arenas_try_alloc", module.C_TRACE_PROBE)

    def test_parser_rejects_mutated_or_out_of_order_relation(self) -> None:
        lines = [module.TRACE_BEGIN]
        lines.extend(f"{key}={value}" for key, value in module.TRACE_VALUES.items())
        lines.append(module.TRACE_END)
        self.assertEqual(module.parse_trace("\n".join(lines), description="valid"), module.TRACE_VALUES)

        mutated = list(lines)
        mutated[2] = mutated[2].rsplit("=", 1)[0] + "=0"
        with self.assertRaises(module.EvidenceError):
            module.validate_trace(module.parse_trace("\n".join(mutated), description="mutated"), description="mutated")

        out_of_order = [lines[0], lines[2], lines[1], *lines[3:]]
        with self.assertRaises(module.EvidenceError):
            module.parse_trace("\n".join(out_of_order), description="out-of-order")

    def test_loader_and_receipt_reject_schema_or_raw_command_drift(self) -> None:
        schema = module.schema_template()
        schema["trace"]["expected_values"]["trace.automatic_arena.valid"] = 0
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad-schema.json"
            path.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaises(module.EvidenceError):
                module.load_schema(path)

        trace_lines = [module.TRACE_BEGIN]
        trace_lines.extend(f"{key}={value}" for key, value in module.TRACE_VALUES.items())
        trace_lines.append(module.TRACE_END)
        trace_output = "\n".join(trace_lines) + "\n"
        header_output = (
            "  Class:                             ELF64\n"
            "  Data:                              2's complement, little endian\n"
            "  Machine:                           Advanced Micro Devices X86-64\n"
        )
        temporary = Path("/temporary-automatic-arena-reservation")
        source = Path("/pinned-mimalloc-source")
        c_command = module.normalize_command(
            module.c_command("musl-gcc", source, temporary / "automatic-arena-reservation.c", temporary / "automatic-arena-reservation-c", module.schema_template()),
            temporary,
            source,
        )
        rust_command = module.normalize_command(
            module.rust_command("cargo", temporary / "rust-target"), temporary,
        )
        record = lambda command, stdout: {"command": command, "status": 0, "stderr": "", "stdout": stdout}
        candidate = module.candidate_snapshot()
        report = {
            "format": 1,
            "kind": "mimalloc-x86_64-automatic-regular-arena-reservation-evidence",
            "profile": module.EXPECTED_PROFILE,
            "status": "passed",
            "target": module.EXPECTED_TARGET,
            "upstream": module.EXPECTED_UPSTREAM,
            "provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
            "candidate_source": {"before": candidate, "after": candidate, "unchanged_during_execution": True},
            "source_anchors": [
                {"member": member, "start_line": start, "end_line": end, "sha256": digest}
                for member, start, end, digest in module.EXPECTED_SOURCE_ANCHORS
            ],
            "c_probe": {
                "build": record(c_command, ""),
                "elf": module.EXPECTED_C_ELF,
                "elf_header": record(["readelf", "-h", f"{module.NORMALIZED_TEMPORARY}/automatic-arena-reservation-c"], header_output),
                "execution": record([f"{module.NORMALIZED_TEMPORARY}/automatic-arena-reservation-c"], trace_output),
                "source_sha256": module.sha256_bytes(module.C_TRACE_PROBE.encode()),
                "trace": dict(module.TRACE_VALUES),
            },
            "rust_probe": {
                "execution": record(rust_command, trace_output + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"),
                "passed_test_count": 1,
                "source": {"path": module.relative(module.RUST_TEST_SOURCE), "sha256": module.sha256_file(module.RUST_TEST_SOURCE)},
                "target_dir": {"isolated": True, "retained": False, "value": f"{module.NORMALIZED_TEMPORARY}/rust-target"},
                "test_filter": module.RUST_TEST_FILTER,
                "trace": dict(module.TRACE_VALUES),
            },
            "comparison": module.compare(module.TRACE_VALUES, module.TRACE_VALUES),
            "scope": module.EXPECTED_SCOPE,
        }
        module.validate_report(report)
        mutations = [
            ("comparison", lambda value: value["comparison"].update({"compared_value_count": 1})),
            ("profile", lambda value: value.update({"profile": "wrong-profile"})),
            ("candidate", lambda value: value["candidate_source"].update({"unchanged_during_execution": False})),
            ("candidate-hash", lambda value: value["candidate_source"]["after"]["files"][0].update({"sha256": "0" * 64})),
            ("anchors", lambda value: value["source_anchors"][0].update({"sha256": "0" * 64})),
            ("c-status", lambda value: value["c_probe"]["execution"].update({"status": 1})),
            ("rust-command", lambda value: value["rust_probe"]["execution"].update({"command": ["true"]})),
            ("rust-output", lambda value: value["rust_probe"]["execution"].update({"stdout": ""})),
            ("rust-count", lambda value: value["rust_probe"].update({"passed_test_count": 0})),
        ]
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                changed = copy.deepcopy(report)
                mutate(changed)
                with self.assertRaises(module.EvidenceError):
                    module.validate_report(changed)


if __name__ == "__main__":
    unittest.main()
