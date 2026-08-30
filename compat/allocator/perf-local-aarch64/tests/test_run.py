"""Contract tests for the local Linux/AArch64 allocator performance smoke."""

from __future__ import annotations

import importlib.util
import sys
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
    def measured_friend_boundary_report() -> dict[str, object]:
        host = {
            "architecture": "aarch64",
            "final_promotion_qualified": False,
            "qualification": "linux-aarch64-development-smoke-only",
        }
        report = perf.empty_report(label="baseline", host_qualification=host)
        report.update(
            {
                "lanes": {
                    "rust_native_shadow": {
                        "selected_artifact_attestation": {
                            "build_identity": {"algorithm": "sha256-canonical-json", "sha256": "a" * 64},
                            "runtime": {"backend_identity": perf.RUST_SHADOW_BACKEND_IDENTITY, "free_route": perf.RUST_SHADOW_FREE_ROUTE},
                            "symbol_attestation": {
                                "required_rust_shadow_symbol_defined": True,
                                "rejected_c_symbol_defined": False,
                            },
                        }
                    }
                },
                "measurement_contract": {"timing": "batches", "warmup": "fresh processes"},
                "reproducible_command": ["python3", "run.py", "--smoke"],
                "status": "measured-architecture-pass",
                "workloads": {
                    "alloc_free_64": {
                        "allocation_sizes_bytes": [64],
                        "throughput_ratio": {"median_rust_over_pinned_c": 1.0},
                        "warmup_processes_per_lane": 2,
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

    def test_measured_report_requires_reproducible_command_sizes_warmup_and_ratio(self) -> None:
        host = {
            "architecture": "aarch64",
            "final_promotion_qualified": False,
            "qualification": "linux-aarch64-development-smoke-only",
        }
        report = perf.empty_report(label="baseline", host_qualification=host)
        report["status"] = "measured-architecture-pass"
        with self.assertRaisesRegex(perf.HarnessError, "reproducible command"):
            perf.validate_report_contract(report)

    def test_passing_direct_engine_friend_boundary_cannot_qualify_for_promotion(self) -> None:
        report = self.measured_friend_boundary_report()
        perf.validate_report_contract(report)
        self.assertFalse(report["measurement_boundary"]["production_libc_measurement"])
        self.assertFalse(report["measurement_boundary"]["final_promotion_qualification_eligible"])
        report["measurement_boundary"]["final_promotion_qualification_eligible"] = True
        with self.assertRaisesRegex(perf.HarnessError, "cannot qualify for final promotion"):
            perf.validate_report_contract(report)

    def test_friend_boundary_cannot_be_relabelled_as_production_libc_measurement(self) -> None:
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

    def test_selected_artifact_attestation_accepts_only_rust_shadow_identity_and_route(self) -> None:
        self.assertEqual(
            perf.parse_attestation_output(
                "backend_identity=rust-native-shadow-crabc-test-free-v1\nfree_route=crabc_test_free\nok\n",
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

    def test_selected_artifact_rejects_c_or_default_free_symbols(self) -> None:
        self.assertEqual(
            perf.verify_rust_shadow_free_symbols({"crabc_test_free", "other"}),
            {
                "required_rust_shadow_symbol": "crabc_test_free",
                "required_rust_shadow_symbol_defined": True,
                "rejected_c_symbol": "mi_free",
                "rejected_c_symbol_defined": False,
            },
        )
        with self.assertRaisesRegex(perf.HarnessError, "does not define crabc_test_free"):
            perf.verify_rust_shadow_free_symbols({"free"})
        with self.assertRaisesRegex(perf.HarnessError, "rejected pinned-C mi_free"):
            perf.verify_rust_shadow_free_symbols({"crabc_test_free", "mi_free"})

    def test_selected_artifact_build_identity_binds_source_archive_and_executable_hashes(self) -> None:
        first = perf.selected_artifact_build_identity(
            backend_source={"sha256": "a" * 64},
            static_archive={"sha256": "b" * 64},
            executable={"sha256": "c" * 64},
        )
        second = perf.selected_artifact_build_identity(
            backend_source={"sha256": "a" * 64},
            static_archive={"sha256": "b" * 64},
            executable={"sha256": "d" * 64},
        )
        self.assertEqual(first["algorithm"], "sha256-canonical-json")
        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_c_backend_must_reject_rust_shadow_attestation(self) -> None:
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
                    "required_rust_shadow_identity": "rust-native-shadow-crabc-test-free-v1",
                    "required_rust_shadow_free_route": "crabc_test_free",
                },
            )
        with patch.object(
            perf,
            "run_fixture_attestation",
            return_value={"backend_identity": perf.RUST_SHADOW_BACKEND_IDENTITY, "free_route": perf.RUST_SHADOW_FREE_ROUTE},
        ), self.assertRaisesRegex(perf.HarnessError, "selected-artifact attestation changed"):
            perf.assert_c_backend_rejects_rust_shadow_attestation(Path("/fixture/c"))

    def test_ratio_is_rust_throughput_over_pinned_c_throughput(self) -> None:
        # C takes 20ns and Rust takes 40ns for the same one-pair workload.
        ratio = perf.throughput_ratio([50_000_000.0] * 5, [25_000_000.0] * 5, seed=3)
        self.assertEqual(ratio["median_rust_over_pinned_c"], 0.5)
        self.assertEqual(ratio["one_sided_95_lower_rust_over_pinned_c"], 0.5)

    def test_pair_plan_has_one_c_and_one_rust_sample_for_each_index(self) -> None:
        plan = perf.paired_sample_plan(5, seed=7)
        self.assertEqual(len(plan), 10)
        self.assertEqual(
            sorted(plan),
            sorted((lane, sample) for sample in range(5) for lane in ("pinned_c", "rust_native_shadow")),
        )

    def test_musl_fixture_rejects_rust_host_link_hints(self) -> None:
        self.assertEqual(perf.fixture_link_libraries(["-lgcc_s", "-lc"]), [])
        with self.assertRaisesRegex(perf.HarnessError, "native static library contract"):
            perf.fixture_link_libraries(["-lunwind", "-lc"])

    def test_fixture_release_flags_are_shared_but_c_configuration_is_not_applied_to_rust(self) -> None:
        c_command = perf.pinned_c_fixture_command("musl-gcc", Path("/pinned"), Path("/build/c"))
        rust_command = perf.rust_fixture_command(
            "musl-gcc", Path("/build/libshadow.a"), "/rust/self-contained", [], Path("/build/rust")
        )
        self.assertEqual(
            [flag for flag in c_command if flag in perf.FIXTURE_RELEASE_FLAGS],
            list(perf.FIXTURE_RELEASE_FLAGS),
        )
        self.assertEqual(
            [flag for flag in rust_command if flag in perf.FIXTURE_RELEASE_FLAGS],
            list(perf.FIXTURE_RELEASE_FLAGS),
        )
        self.assertTrue(all(flag in c_command for flag in perf.PINNED_C_SOURCE_CONFIGURATION_FLAGS))
        self.assertTrue(all(flag not in rust_command for flag in perf.PINNED_C_SOURCE_CONFIGURATION_FLAGS))

    def test_manifest_retains_sizes_and_warmup_contract(self) -> None:
        manifest, workloads = perf.load_manifest()
        self.assertEqual(manifest["mode"]["warmup_processes_per_lane_and_workload"], 2)
        self.assertEqual([workload.request_bytes for workload in workloads], [64, 4096])


if __name__ == "__main__":
    unittest.main()
