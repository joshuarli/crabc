#!/usr/bin/env python3
"""Contract tests for the AArch64 ABI evidence report."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/scripts/probe_aarch64_abi.py"
SPEC = importlib.util.spec_from_file_location("probe_aarch64_abi", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class ProbeParserTests(unittest.TestCase):
    def test_public_header_inventory_is_derived_and_excludes_private_bits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sys").mkdir()
            (root / "bits").mkdir()
            (root / "stdio.h").write_text("/* public */\n", encoding="utf-8")
            (root / "sys/socket.h").write_text("/* public */\n", encoding="utf-8")
            (root / "bits/hidden.h").write_text("/* private */\n", encoding="utf-8")
            self.assertEqual(
                probe.public_header_names(root),
                ["stdio.h", "sys/socket.h"],
            )

    def test_parser_preserves_values_and_rejects_duplicate_records(self) -> None:
        self.assertEqual(
            probe.parse_probe_output("sizeof_stat=128\noffset=16\n"),
            {"sizeof_stat": "128", "offset": "16"},
        )
        with self.assertRaises(probe.ProbeHarnessError):
            probe.parse_probe_output("field=1\nfield=2\n")
        with self.assertRaises(probe.ProbeHarnessError):
            probe.parse_probe_output("not a record\n")

    def test_compare_values_reports_missing_and_changed_fields(self) -> None:
        comparison = probe.compare_values(
            {"size": "128", "align": "8"},
            {"size": "136", "extra": "1"},
        )
        self.assertEqual(comparison["status"], "mismatch")
        self.assertEqual(comparison["field_count"], 3)
        self.assertEqual(
            comparison["differences"],
            [
                {"key": "align", "reference": "8", "candidate": None},
                {"key": "extra", "reference": None, "candidate": "1"},
                {"key": "size", "reference": "128", "candidate": "136"},
            ],
        )

    def test_header_compile_coverage_counts_are_disjoint(self) -> None:
        payload = probe._header_compile_coverage_payload(
            [
                {"header": "a.h", "status": "compile_ok"},
                {"header": "b.h", "status": "missing_input"},
                {"header": "candidate.h", "status": "candidate_only"},
            ],
            ["a.h", "b.h"],
            ["a.h", "candidate.h"],
        )
        self.assertEqual(payload["pinned_count"], 2)
        self.assertEqual(payload["candidate_count"], 2)
        self.assertEqual(payload["inventory_count"], 3)
        self.assertEqual(payload["compiled_count"], 1)
        self.assertEqual(payload["missing_from_candidate_count"], 1)
        self.assertEqual(payload["candidate_only_count"], 1)
        self.assertEqual(
            payload["summary"],
            {"selected": 2, "by_status": {"compile_ok": 1, "missing_input": 1}},
        )
        self.assertEqual(
            payload["candidate_only_summary"],
            {"selected": 1, "by_status": {"candidate_only": 1}},
        )

    def test_header_compile_reference_errors_are_distinct_from_candidate_gaps(self) -> None:
        self.assertEqual(
            probe._header_compile_coverage_status([{"status": "reference_error"}]),
            "reference_error",
        )
        self.assertEqual(
            probe._header_compile_coverage_status([{"status": "unsupported"}]),
            "header_compile_coverage_incomplete",
        )
        self.assertEqual(
            probe._header_compile_coverage_status(
                [{"status": "reference_error"}, {"status": "unsupported"}]
            ),
            "header_compile_coverage_incomplete",
        )
        self.assertIsNone(probe._header_compile_coverage_status([{"status": "compile_ok"}]))

    def test_compile_coverage_never_claims_layout_parity(self) -> None:
        payload = probe._header_compile_coverage_payload(
            [{"header": "arpa/ftp.h", "status": "compile_ok"}],
            ["arpa/ftp.h"],
            ["arpa/ftp.h"],
        )
        record = payload["records"][0]
        self.assertEqual(record["status"], "compile_ok")
        self.assertNotEqual(record["status"], "match")

    def test_ucontext_probe_covers_named_aarch64_layout(self) -> None:
        source = probe.PROBES["signals-ucontext"]["source"]
        for field in ("fault_address", "regs", "sp", "pc", "pstate"):
            self.assertIn(f"offsetof_mcontext_{field}", source)
        self.assertIn("offsetof_mcontext_reserved", source)
        self.assertEqual(
            probe.HEADER_SYMBOLS["ucontext.h"],
            ("getcontext", "makecontext", "setcontext", "swapcontext"),
        )


class ReportContractTests(unittest.TestCase):
    def test_non_aarch64_report_is_explicitly_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = probe.build_report(
                musl_root=root / "musl-1.2.6",
                candidate_include=root / "include",
                candidate_archive=root / "libc.a",
                compiler="musl-gcc",
                nm="nm",
                machine="x86_64",
                probes=("stat", "fenv"),
            )
        self.assertEqual(report["schema"], "crabc.aarch64-abi-probe/v1")
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["summary"], {"selected": 2, "by_status": {"unsupported": 2}})
        self.assertEqual(report["header_compile_coverage"]["candidate_count"], 0)
        self.assertTrue(all(item["reason"] for item in report["probes"]))
        json.dumps(report)

    def test_missing_inputs_are_not_reported_as_probe_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            uapi = root / "linux-uapi"
            report = probe.build_report(
                musl_root=root / "musl-1.2.6",
                candidate_include=root / "include",
                candidate_archive=root / "libc.a",
                linux_uapi_include=uapi,
                compiler="musl-gcc",
                nm="nm",
                machine="aarch64",
                probes=("termios",),
            )
        self.assertEqual(report["status"], "missing_input")
        self.assertEqual(report["probes"][0]["status"], "missing_input")
        self.assertNotEqual(report["probes"][0]["status"], "match")
        self.assertGreater(len(report["issues"]), 0)
        self.assertEqual(
            report["inputs"]["linux_uapi"],
            {"path": str(uapi.resolve()), "status": "missing"},
        )
        json.dumps(report)


if __name__ == "__main__":
    unittest.main()
