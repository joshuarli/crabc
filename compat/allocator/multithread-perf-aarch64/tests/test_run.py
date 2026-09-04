"""Deterministic contract tests for the AArch64 local scaling smoke."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


SUITE = Path(__file__).resolve().parents[1]
MODULE = SUITE / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_mimalloc_multithread_perf", MODULE)
assert SPEC is not None and SPEC.loader is not None
perf = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = perf
SPEC.loader.exec_module(perf)


class QualificationTests(unittest.TestCase):
    def test_native_linux_aarch64_attestation_is_required(self) -> None:
        accepted, reason = perf.native_aarch64_qualification(
            {
                "execution_mode": "emulated",
                "host_architecture": "aarch64",
                "machine": "aarch64",
                "system": "Linux",
            }
        )
        self.assertFalse(accepted)
        self.assertIn("CRABC_EXECUTION_MODE", str(reason))

    def test_native_linux_aarch64_attestation_is_accepted(self) -> None:
        self.assertEqual(
            perf.native_aarch64_qualification(
                {
                    "execution_mode": "native",
                    "host_architecture": "aarch64",
                    "machine": "aarch64",
                    "system": "Linux",
                }
            ),
            (True, None),
        )

    def test_scales_never_claim_workers_that_the_affinity_mask_cannot_supply(self) -> None:
        self.assertEqual(perf.selected_worker_scales(1), [1])
        self.assertEqual(perf.selected_worker_scales(3), [1, 2])
        self.assertEqual(perf.selected_worker_scales(8), [1, 2, 4, 8])


class FixtureGrammarTests(unittest.TestCase):
    def test_parser_accepts_the_complete_declared_fixture_result(self) -> None:
        self.assertEqual(
            perf.parse_fixture_output(
                "workers=2\niterations=9\noperations=18\nmax_worker_ns=7\nsum_worker_ns=12\nchecksum=4\naffinity=3,5\nok\n",
                workers=2,
                iterations=9,
                cpus=[3, 5],
            ),
            {
                "workers": 2,
                "iterations": 9,
                "operations": 18,
                "max_worker_ns": 7,
                "sum_worker_ns": 12,
                "checksum": 4,
                "affinity": "3,5",
            },
        )

    def test_parser_rejects_affinity_drift_and_extra_output(self) -> None:
        output = "workers=1\niterations=9\noperations=9\nmax_worker_ns=7\nsum_worker_ns=7\nchecksum=4\naffinity=3\nextra\nok\n"
        with self.assertRaisesRegex(perf.HarnessError, "unexpected"):
            perf.parse_fixture_output(output, workers=1, iterations=9, cpus=[3])
        output = "workers=1\niterations=9\noperations=9\nmax_worker_ns=7\nsum_worker_ns=7\nchecksum=4\naffinity=4\nok\n"
        with self.assertRaisesRegex(perf.HarnessError, "affinity"):
            perf.parse_fixture_output(output, workers=1, iterations=9, cpus=[3])
        output = "workers=1,2\niterations=9\noperations=9\nmax_worker_ns=7\nsum_worker_ns=7\nchecksum=4\naffinity=3\nok\n"
        with self.assertRaisesRegex(perf.HarnessError, "non-numeric"):
            perf.parse_fixture_output(output, workers=1, iterations=9, cpus=[3])

    def test_elf_parser_requires_little_endian_aarch64(self) -> None:
        header = "  Class:                             ELF64\n  Data:                              2's complement, little endian\n  Machine:                           AArch64\n"
        self.assertEqual(
            perf.parse_aarch64_elf_header(header),
            {"class": "ELF64", "endianness": "little", "machine": "AArch64"},
        )
        with self.assertRaisesRegex(perf.HarnessError, "AArch64"):
            perf.parse_aarch64_elf_header(header.replace("AArch64", "X86-64"))

    def test_rust_fixture_build_reuses_the_locked_root_engine_dependencies(self) -> None:
        command = perf.rust_engine_cargo_command("cargo", Path("/tmp/rust-target"))
        self.assertEqual(command[:5], ["cargo", "build", "--locked", "--package", "crabc-mimalloc"])
        self.assertIn("--target-dir", command)
        source = (SUITE / "rust-local-scaling.rs").read_text(encoding="utf-8")
        self.assertIn("crabc_mimalloc::__crabc_runtime", source)
        self.assertNotIn("TestAllocatorContext", source)


class ReportContractTests(unittest.TestCase):
    def test_unqualified_host_writes_an_unavailable_aarch64_report(self) -> None:
        host = {
            "execution_mode": "emulated",
            "host_architecture": "aarch64",
            "machine": "aarch64",
            "release": "test",
            "system": "Linux",
            "cpuinfo_sha256": None,
        }
        report = perf.unavailable_report(label="host-smoke", host=host, reason="not native")
        perf.validate_report_contract(report)
        self.assertEqual(report["status"], "unavailable")
        self.assertEqual(report["qualification"]["status"], "unavailable")
        self.assertFalse(report["scope"]["performance_qualification"])

    def test_report_contract_rejects_a_promotion_claim(self) -> None:
        report = perf.empty_report(label="baseline", host={})
        report["scope"]["public_support"] = True
        with self.assertRaisesRegex(perf.HarnessError, "public or promotion"):
            perf.validate_report_contract(report)

    def test_current_friend_boundary_lane_is_diagnostic_and_rejected_as_production_evidence(self) -> None:
        report = perf.empty_report(label="baseline", host={})
        classification = report["evidence_classification"]["current_rust_direct_engine_friend_boundary"]
        self.assertEqual(classification["classification"], "diagnostic-only")
        self.assertEqual(classification["production_scaling_evidence"]["status"], "rejected")
        perf.validate_report_contract(report)

        classification["production_scaling_evidence"]["status"] = "accepted"
        with self.assertRaisesRegex(perf.HarnessError, "friend-boundary"):
            perf.validate_report_contract(report)

    def test_completed_comparison_cannot_relabel_raw_scaling_as_production_evidence(self) -> None:
        report = perf.empty_report(label="baseline", host={})
        report["comparison"] = {"production_scaling_evidence": {"status": "accepted"}, "status": "ok"}
        with self.assertRaisesRegex(perf.HarnessError, "comparison production"):
            perf.validate_report_contract(report)

    def test_serialization_report_marks_a_flat_multithread_throughput_shape(self) -> None:
        scales = {
            "1": {"summary": {"throughput_operations_per_second_median": 100.0}},
            "2": {"summary": {"throughput_operations_per_second_median": 110.0}},
            "4": {"summary": {"throughput_operations_per_second_median": 300.0}},
        }
        signatures = perf.serialization_signatures(scales)
        self.assertEqual(signatures["per_scale"]["2"]["global_serialization_signature"], "flat-throughput-signature")
        self.assertEqual(signatures["per_scale"]["4"]["global_serialization_signature"], "no-flat-throughput-signature")
        self.assertAlmostEqual(signatures["per_scale"]["4"]["parallel_efficiency"], 0.75)

    def test_comparison_records_rust_to_pinned_c_ratios_only_when_both_lanes_measure(self) -> None:
        c_lane = {"scales": {"1": {"summary": {"throughput_operations_per_second_median": 100.0}}}}
        unavailable = perf.compare_lanes(c_lane, {"status": "unavailable"})
        self.assertEqual(unavailable["status"], "unavailable")
        measured = perf.compare_lanes(
            c_lane,
            {"status": "ok", "scales": {"1": {"summary": {"throughput_operations_per_second_median": 300.0}}}},
        )
        self.assertEqual(measured["status"], "ok")
        self.assertEqual(measured["scales"], {"1": {"rust_to_pinned_c_throughput_ratio": 3.0}})
        self.assertEqual(measured["production_scaling_evidence"]["status"], "rejected")

    def test_manifest_is_machine_readable_and_matches_the_report_kind(self) -> None:
        manifest = json.loads((SUITE / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["kind"], perf.KIND)
        self.assertEqual(manifest["workload"]["scales"], [1, 2, 4, 8])
        self.assertFalse(manifest["scope"]["performance_qualification"])

    def test_default_report_path_is_aarch64_allocator_local(self) -> None:
        self.assertEqual(
            perf.default_report_path("baseline"),
            perf.ROOT / "compat/reports/allocator/aarch64/multithread-local/baseline.json",
        )
        with self.assertRaisesRegex(perf.HarnessError, "label"):
            perf.default_report_path("../wrong")


if __name__ == "__main__":
    unittest.main()
