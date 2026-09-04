"""Contract tests for the local Linux/AArch64 allocator performance smoke."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_local_perf_aarch64", MODULE)
assert SPEC is not None and SPEC.loader is not None
perf = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = perf
SPEC.loader.exec_module(perf)


class HostQualificationTests(unittest.TestCase):
    def test_accepts_little_endian_linux_aarch64_only_as_development_smoke(self) -> None:
        with patch.object(perf.platform, "system", return_value="Linux"), patch.object(
            perf.platform, "machine", return_value="aarch64"
        ), patch.object(perf.platform, "release", return_value="6.12"), patch.object(
            perf.sys, "byteorder", "little"
        ):
            observed = perf.require_linux_aarch64()
        self.assertEqual(observed["qualification"], "linux-aarch64-development-smoke-only")
        self.assertTrue(observed["smoke_eligible"])
        self.assertFalse(observed["final_promotion_qualified"])

    def test_rejects_non_aarch64_host(self) -> None:
        with patch.object(perf.platform, "system", return_value="Linux"), patch.object(
            perf.platform, "machine", return_value="x86_64"
        ), patch.object(perf.sys, "byteorder", "little"):
            with self.assertRaisesRegex(perf.HarnessError, "Linux/AArch64"):
                perf.require_linux_aarch64()


class ReportContractTests(unittest.TestCase):
    @staticmethod
    def measured_selected_shadow_report() -> dict[str, object]:
        host = {
            "architecture": "aarch64",
            "final_promotion_qualified": False,
            "qualification": "linux-aarch64-development-smoke-only",
        }
        report = perf.empty_report(label="baseline", host_qualification=host)
        worker_scales = {}
        for worker_count in perf.WORKER_SCALES:
            raw_sample = {
                "batch_ns": [17, 19],
                "elapsed_wall_ns": 31,
                "operations_per_batch": worker_count * 10,
                "sample_index": 0,
                "worker_count": worker_count,
            }
            worker_scales[f"workers_{worker_count}"] = {
                "lanes": {
                    "pinned_c": {"raw_samples": [raw_sample]},
                    "rust_native_shadow": {"raw_samples": [dict(raw_sample)]},
                },
                "throughput_ratio": {"median_rust_over_pinned_c": 1.0},
                "warmup_processes_per_lane": 2,
                "worker_count": worker_count,
            }
        report.update(
            {
                "lanes": {
                    "rust_native_shadow": {
                        "selected_artifact_attestation": {
                            "build_identity": {"algorithm": "sha256-canonical-json", "sha256": "a" * 64},
                            "runtime": {
                                "backend_identity": perf.RUST_SHADOW_BACKEND_IDENTITY,
                                "free_route": perf.RUST_SHADOW_FREE_ROUTE,
                            },
                            "selected_shadow_libc": {
                                "c_backend_relocations": [],
                                "cargo_feature_attestation": {
                                    "fingerprint": {"sha256": "b" * 64},
                                    "required_feature": perf.RUST_SHADOW_FEATURE,
                                },
                                "public_malloc_free_direct_mimalloc_targets": {"free": [], "malloc": []},
                            },
                        }
                    }
                },
                "measurement_contract": {
                    "raw_samples": True,
                    "timing": "batches",
                    "warmup": "fresh processes",
                    "worker_lifecycle": "ordinary pthread workers",
                },
                "reproducible_command": ["python3", "run.py", "--smoke"],
                "status": "measured-architecture-pass",
                "workloads": {
                    "alloc_free_64": {
                        "allocation_sizes_bytes": [64],
                        "worker_scales": worker_scales,
                    }
                },
            }
        )
        return report

    def test_report_path_is_aarch64_local_and_label_checked(self) -> None:
        self.assertEqual(
            perf.default_report_path(perf.ROOT, "baseline"),
            perf.ROOT / "compat/reports/allocator/aarch64/local-perf/baseline.json",
        )
        with self.assertRaisesRegex(perf.HarnessError, "label"):
            perf.default_report_path(perf.ROOT, "../wrong")

    def test_report_rejects_final_promotion_claim(self) -> None:
        host = {
            "architecture": "aarch64",
            "final_promotion_qualified": False,
            "qualification": "linux-aarch64-development-smoke-only",
        }
        report = perf.empty_report(label="baseline", host_qualification=host)
        perf.validate_report_contract(report)
        report["scope"]["final_promotion_qualified"] = True
        with self.assertRaisesRegex(perf.HarnessError, "public or promotion"):
            perf.validate_report_contract(report)

    def test_measured_report_requires_reproducible_command_and_raw_worker_samples(self) -> None:
        host = {
            "architecture": "aarch64",
            "final_promotion_qualified": False,
            "qualification": "linux-aarch64-development-smoke-only",
        }
        report = perf.empty_report(label="baseline", host_qualification=host)
        report["status"] = "measured-architecture-pass"
        with self.assertRaisesRegex(perf.HarnessError, "reproducible command"):
            perf.validate_report_contract(report)

    def test_selected_shadow_report_cannot_qualify_for_promotion(self) -> None:
        report = self.measured_selected_shadow_report()
        perf.validate_report_contract(report)
        self.assertFalse(report["measurement_boundary"]["production_libc_measurement"])
        self.assertFalse(report["measurement_boundary"]["final_promotion_qualification_eligible"])
        report["measurement_boundary"]["final_promotion_qualification_eligible"] = True
        with self.assertRaisesRegex(perf.HarnessError, "cannot qualify for final promotion"):
            perf.validate_report_contract(report)

    def test_selected_shadow_report_rejects_c_fallback_route(self) -> None:
        report = self.measured_selected_shadow_report()
        selected = report["lanes"]["rust_native_shadow"]["selected_artifact_attestation"]["selected_shadow_libc"]
        selected["public_malloc_free_direct_mimalloc_targets"]["free"] = ["mi_free"]
        with self.assertRaisesRegex(perf.HarnessError, "selected native shadow routing"):
            perf.validate_report_contract(report)

    def test_selected_shadow_report_cannot_be_relabelled_as_production_libc_measurement(self) -> None:
        host = {
            "architecture": "aarch64",
            "final_promotion_qualified": False,
            "qualification": "linux-aarch64-development-smoke-only",
        }
        report = perf.empty_report(label="baseline", host_qualification=host)
        report["measurement_boundary"]["production_libc_measurement"] = True
        with self.assertRaisesRegex(perf.HarnessError, "cannot claim production libc"):
            perf.validate_report_contract(report)


class MeasurementContractTests(unittest.TestCase):
    def test_parses_only_declared_batch_grammar(self) -> None:
        self.assertEqual(perf.parse_batch_output("batch_ns=17\nbatch_ns=23\nok\n", expected_batches=2), [17, 23])
        with self.assertRaisesRegex(perf.HarnessError, "unexpected"):
            perf.parse_batch_output("batch_ns=17\naddress=0x1\nok\n", expected_batches=1)

    def test_selected_artifact_attestation_accepts_only_selected_c_abi_identity_and_route(self) -> None:
        self.assertEqual(
            perf.parse_attestation_output(
                "backend_identity=rust-native-shadow-selected-c-abi-v1\nfree_route=free\nok\n",
                expected_identity=perf.RUST_SHADOW_BACKEND_IDENTITY,
                expected_free_route=perf.RUST_SHADOW_FREE_ROUTE,
            ),
            {"backend_identity": perf.RUST_SHADOW_BACKEND_IDENTITY, "free_route": perf.RUST_SHADOW_FREE_ROUTE},
        )
        with self.assertRaisesRegex(perf.HarnessError, "attestation output"):
            perf.parse_attestation_output(
                "backend_identity=pinned-c-mimalloc-v3.5.0\nfree_route=mi_free\nok\n",
                expected_identity=perf.RUST_SHADOW_BACKEND_IDENTITY,
                expected_free_route=perf.RUST_SHADOW_FREE_ROUTE,
            )

    def test_selected_artifact_build_identity_binds_feature_artifact_and_executable_hashes(self) -> None:
        first = perf.selected_artifact_build_identity(
            backend_source={"sha256": "a" * 64},
            selected_libc={"sha256": "b" * 64},
            cargo_fingerprint={"sha256": "c" * 64},
            executable={"sha256": "d" * 64},
        )
        second = perf.selected_artifact_build_identity(
            backend_source={"sha256": "a" * 64},
            selected_libc={"sha256": "b" * 64},
            cargo_fingerprint={"sha256": "c" * 64},
            executable={"sha256": "e" * 64},
        )
        self.assertEqual(first["algorithm"], "sha256-canonical-json")
        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_c_backend_must_reject_selected_shadow_attestation(self) -> None:
        with patch.object(
            perf,
            "run_fixture_attestation",
            return_value={"backend_identity": "pinned-c-mimalloc-v3.5.0", "free_route": "mi_free"},
        ):
            self.assertEqual(
                perf.assert_c_backend_rejects_rust_shadow_attestation(Path("/fixture/c")),
                {
                    "accepted_as_rust_shadow": False,
                    "observed_backend_identity": "pinned-c-mimalloc-v3.5.0",
                    "observed_free_route": "mi_free",
                    "required_rust_shadow_identity": perf.RUST_SHADOW_BACKEND_IDENTITY,
                    "required_rust_shadow_free_route": perf.RUST_SHADOW_FREE_ROUTE,
                },
            )
        with patch.object(
            perf,
            "run_fixture_attestation",
            return_value={"backend_identity": perf.RUST_SHADOW_BACKEND_IDENTITY, "free_route": perf.RUST_SHADOW_FREE_ROUTE},
        ), self.assertRaisesRegex(perf.HarnessError, "selected-artifact attestation changed"):
            perf.assert_c_backend_rejects_rust_shadow_attestation(Path("/fixture/c"))

    def test_ratio_is_rust_throughput_over_pinned_c_throughput(self) -> None:
        ratio = perf.throughput_ratio([50_000_000.0] * 5, [25_000_000.0] * 5, seed=3)
        self.assertEqual(ratio["median_rust_over_pinned_c"], 0.5)
        self.assertEqual(ratio["one_sided_95_lower_rust_over_pinned_c"], 0.5)

    def test_throughput_counts_every_worker_local_operation(self) -> None:
        self.assertEqual(perf.throughput_pairs_per_second(20, 10, 4), 2_000_000_000.0)

    def test_pair_plan_has_one_c_and_one_rust_sample_for_each_index(self) -> None:
        plan = perf.paired_sample_plan(5, seed=7)
        self.assertEqual(len(plan), 10)
        self.assertEqual(
            sorted(plan),
            sorted((lane, sample) for sample in range(5) for lane in ("pinned_c", "rust_native_shadow")),
        )

    def test_selected_shadow_link_command_has_no_default_c_library(self) -> None:
        command = perf.rust_shadow_fixture_command(
            Path("/sysroot/bin/crabc-cc"), Path("/build/selected/libc.so"), Path("/sysroot/libbuiltins.a"), Path("/build/fixture")
        )
        self.assertIn("-nodefaultlibs", command)
        self.assertIn(perf.SELECTED_LIBC_LINK_FLAG, command)
        self.assertNotIn("-lc", command)
        self.assertTrue(all(flag not in command for flag in perf.PINNED_C_SOURCE_CONFIGURATION_FLAGS))

    def test_selected_shadow_cargo_build_uses_release_profile(self) -> None:
        command = perf.rust_shadow_cargo_command(Path("/build/target"))
        self.assertIn("--release", command)
        self.assertIn(perf.RUST_SHADOW_FEATURE, command)

    def test_selected_shadow_cargo_fingerprint_requires_native_feature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            fingerprint = Path(temporary_name) / "release/.fingerprint/crabc-libc-a/lib-c.json"
            fingerprint.parent.mkdir(parents=True)
            fingerprint.write_text(
                json.dumps({"features": json.dumps(["default", perf.RUST_SHADOW_FEATURE])}), encoding="utf-8"
            )
            observed = perf.selected_shadow_cargo_fingerprint(Path(temporary_name))
        self.assertEqual(observed["required_feature"], perf.RUST_SHADOW_FEATURE)
        self.assertEqual(observed["cargo_features"], ["default", perf.RUST_SHADOW_FEATURE])

    def test_worker_scale_retains_machine_readable_raw_samples(self) -> None:
        workload = perf.Workload("tiny", 64, 2, 3)
        calls: list[tuple[Path, int]] = []

        def fake_sample(binary: Path, _workload: perf.Workload, worker_count: int, **_: object) -> dict[str, object]:
            calls.append((binary, worker_count))
            return {
                "batch_ns": [17, 19],
                "elapsed_wall_ns": 31,
                "operations_per_batch": worker_count * 3,
                "worker_count": worker_count,
            }

        with patch.object(perf, "run_batch_sample", side_effect=fake_sample):
            observed = perf.measure_worker_scale(
                {
                    "pinned_c": (Path("/fixture/c"), {"PATH": "/bin"}),
                    "rust_native_shadow": (Path("/fixture/rust"), {"PATH": "/bin"}),
                },
                workload,
                4,
                samples=1,
                warmup=1,
                seed=7,
                timeout=1.0,
            )
        self.assertEqual(observed["worker_count"], 4)
        self.assertEqual(observed["local_allocation_free_pairs_per_batch"], 12)
        self.assertEqual(observed["lanes"]["pinned_c"]["raw_samples"][0]["worker_count"], 4)
        self.assertTrue(all(worker_count == 4 for _, worker_count in calls))

    def test_manifest_retains_sizes_warmup_and_independent_local_worker_scales(self) -> None:
        manifest, workloads = perf.load_manifest()
        self.assertEqual(manifest["mode"]["warmup_processes_per_lane_and_workload_and_worker_scale"], 2)
        self.assertEqual(manifest["fixture"]["local_worker_scales"], [1, 2, 4, 8])
        self.assertFalse(manifest["fixture"]["single_thread_only"])
        self.assertEqual([workload.request_bytes for workload in workloads], [64, 4096])


if __name__ == "__main__":
    unittest.main()
