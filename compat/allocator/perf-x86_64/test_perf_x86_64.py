"""Deterministic contract tests for the native x86-64 adapter perf lane."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "perf_x86_64.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_perf_x86_64", MODULE)
assert SPEC is not None and SPEC.loader is not None
perf = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = perf
SPEC.loader.exec_module(perf)


class NativeProvenanceTests(unittest.TestCase):
    def test_requires_dispatcher_native_provenance_before_guest_identity(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(perf.HarnessError, "canonical native provenance"):
                perf.require_native_x86_64()

    def test_accepts_native_x86_64_provenance(self) -> None:
        with patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "x86_64"},
            clear=True,
        ), patch.object(perf.platform, "system", return_value="Linux"), patch.object(
            perf.platform, "machine", return_value="x86_64"
        ):
            self.assertEqual(
                perf.require_native_x86_64(),
                {"execution_mode": "native", "host_architecture": "x86_64"},
            )

    def test_rejects_an_emulated_guest_even_when_it_reports_x86_64(self) -> None:
        with patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "emulated", "CRABC_HOST_ARCH": "aarch64"},
            clear=True,
        ), patch.object(perf.platform, "system", return_value="Linux"), patch.object(
            perf.platform, "machine", return_value="x86_64"
        ):
            with self.assertRaisesRegex(perf.HarnessError, "canonical native provenance"):
                perf.require_native_x86_64()


class BatchResultTests(unittest.TestCase):
    def test_parses_only_the_declared_batch_record(self) -> None:
        self.assertEqual(
            perf.parse_batch_output("batch_ns=17\nbatch_ns=23\nok\n", expected_batches=2),
            [17, 23],
        )

    def test_rejects_bad_batch_result_shape(self) -> None:
        with self.assertRaisesRegex(perf.HarnessError, "expected 2"):
            perf.parse_batch_output("batch_ns=17\nok\n", expected_batches=2)
        with self.assertRaisesRegex(perf.HarnessError, "unexpected"):
            perf.parse_batch_output("batch_ns=17\naddress=0x1\nok\n", expected_batches=1)

    def test_batch_record_keeps_process_resources_separate_from_batch_timing(self) -> None:
        process = {
            "elapsed_wall_ns": 31,
            "resources": {"system_cpu_ns": 7, "user_cpu_ns": 11},
            "status": {"code": 0, "kind": "exit"},
        }
        self.assertEqual(
            perf.batch_sample_record(process, "batch_ns=17\nok\n", expected_batches=1),
            {"batch_ns": [17], "process": process},
        )

    def test_pair_plan_has_one_c_and_one_rust_record_per_sample(self) -> None:
        plan = perf.paired_sample_plan(5, seed=7)
        self.assertEqual(len(plan), 10)
        self.assertEqual(
            sorted((sample, lane) for lane, sample in plan),
            sorted((sample, lane) for sample in range(5) for lane in ("pinned_c", "rust_private_adapter")),
        )


class ReportContractTests(unittest.TestCase):
    def test_x86_report_path_is_allocator_local_and_label_checked(self) -> None:
        self.assertEqual(
            perf.default_report_path(perf.ROOT, "baseline"),
            perf.ROOT / "compat/reports/allocator/x86_64/perf/baseline.json",
        )
        with self.assertRaisesRegex(perf.HarnessError, "label"):
            perf.default_report_path(perf.ROOT, "../wrong")

    def test_memory_delta_uses_only_post_initialization_observations(self) -> None:
        before = {
            "status": "ok",
            "status_memory": {"vm_rss_kib": 12, "vm_size_kib": 30},
            "smaps_rollup": {"rss_kib": 14, "pss_kib": 8, "private_dirty_kib": 2},
            "maps": {"mapping_count": 5, "virtual_bytes": 4096},
        }
        live = {
            "status": "ok",
            "status_memory": {"vm_rss_kib": 44, "vm_size_kib": 62},
            "smaps_rollup": {"rss_kib": 46, "pss_kib": 40, "private_dirty_kib": 34},
            "maps": {"mapping_count": 6, "virtual_bytes": 8192},
        }
        self.assertEqual(
            perf.memory_delta(before, live),
            {
                "maps.mapping_count": 1,
                "maps.virtual_bytes": 4096,
                "smaps_rollup.private_dirty_kib": 32,
                "smaps_rollup.pss_kib": 32,
                "smaps_rollup.rss_kib": 32,
                "status_memory.vm_rss_kib": 32,
                "status_memory.vm_size_kib": 32,
            },
        )

    def test_report_validation_rejects_public_or_unqualified_claims(self) -> None:
        report = perf.empty_report(
            label="baseline",
            native_execution_provenance={"execution_mode": "native", "host_architecture": "x86_64"},
        )
        perf.validate_report_contract(report)

        report["scope"]["public_mi_api"] = True
        with self.assertRaisesRegex(perf.HarnessError, "private-adapter"):
            perf.validate_report_contract(report)


if __name__ == "__main__":
    unittest.main()
