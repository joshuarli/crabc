"""Focused contract tests for the standalone native churn/RSS smoke harness."""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HARNESS_PATH = ROOT / "compat/allocator/native_churn_rss_smoke.py"
SPEC = importlib.util.spec_from_file_location("native_churn_rss_smoke", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


def fixture_result(seed: int = 91, cycles: int = 3) -> dict[str, object]:
    """Return the smallest valid result with observable high-water state."""

    return {
        "schema": HARNESS.FIXTURE_SCHEMA,
        "status": "passed",
        "seed": seed,
        "cycles": cycles,
        "completed_epochs": cycles,
        "owner_exits_with_live_blocks": cycles,
        "successful_cross_thread_handoffs": cycles,
        "post_exit_initial_thread_frees": cycles * 6,
        "requested_bytes_total": 123,
        "requested_bytes_live_final": 0,
        "requested_bytes_live_high_water": 97,
        "usable_bytes_live_final": 0,
        "usable_bytes_live_high_water": 128,
        "live_blocks_final": 0,
        "live_blocks_high_water": 7,
        "rss_initial_bytes": 4096,
        "rss_final_bytes": 8192,
        "rss_high_water_bytes": 12288,
        "rss_warm_quiescent_bytes": 7168,
        "rss_last_quiescent_bytes": 9216,
        "rss_samples": 10,
        "first_fixture_epoch_seed": HARNESS.fixture_epoch_seeds(seed, cycles)[0],
        "last_fixture_epoch_seed": HARNESS.fixture_epoch_seeds(seed, cycles)[-1],
        "thread_fanout": {
            "initial_threads": 1,
            "owner_workers_per_epoch": 1,
            "handoff_workers_per_epoch": 1,
            "worker_threads_per_epoch": 2,
            "peak_threads": 3,
            "worker_threads_created": cycles * 2,
        },
        "live_owner_registry_high_water_entries": None,
        "live_owner_registry_plateau_after_warmup": None,
        "post_exit_registry_high_water_entries": None,
        "post_exit_registry_plateau_after_warmup": None,
        "client_ledger_high_water_entries": None,
        "client_ledger_plateau_after_warmup": None,
        "allocator_metadata_high_water_bytes": None,
        "allocator_metadata_plateau_after_warmup": None,
        "page_map_registered_high_water_entries": None,
        "page_map_plateau_after_warmup": None,
        "arena_registry_high_water_entries": None,
        "arena_plateau_after_warmup": None,
        "abandoned_page_high_water_count": None,
        "abandoned_page_plateau_after_warmup": None,
        "tld_high_water_count": None,
        "tld_plateau_after_warmup": None,
        "theap_high_water_count": None,
        "theap_plateau_after_warmup": None,
        "allocator_metadata_observation": "not-exposed-by-production-shadow-c-api",
        "state_auditor": {
            "status": "incomplete",
            "scope": "production-general-churn",
            "workload_liveness": {
                "status": "passed",
                "snapshot_count": cycles,
                "warmup_epoch": 1,
                "post_warm_snapshot_count": cycles - 1,
                "plateau_after_warmup": True,
            },
            "allocator_state": {
                "status": "unavailable",
                "observation": "not-exposed-by-production-shadow-c-api",
            },
        },
    }


class NativeChurnRssSmokeContractTests(unittest.TestCase):
    """Keep the no-private-hook lifecycle and report boundary durable."""

    def test_fixture_epoch_seed_schedule_is_stable(self) -> None:
        self.assertEqual(
            HARNESS.fixture_epoch_seeds(91, 3),
            [98469508763, 5269175524441963857, 17691037128211053274],
        )

    def test_contract_hashes_fixture_and_requires_production_api_only(self) -> None:
        contract = HARNESS.read_json(HARNESS.CONTRACT_PATH)
        validated = HARNESS.validate_contract(contract)

        self.assertEqual(validated["cycles"], 8)
        self.assertEqual(validated["process_epochs"], 4)
        self.assertEqual(
            contract["production_shadow_boundary"]["allowed_allocation_apis"],
            ["malloc", "free", "posix_memalign", "malloc_usable_size"],
        )
        self.assertFalse(contract["production_shadow_boundary"]["allocator_private_hooks"])
        self.assertFalse(contract["production_shadow_boundary"]["c_backend_fallback"])
        self.assertEqual(
            contract["state_observation"]["allocator_state_categories"],
            [
                "live_owner_registry",
                "post_exit_registry",
                "client_ledger",
                "page_map",
                "metadata",
                "arena",
                "abandoned_page",
                "tld",
                "theap",
            ],
        )
        self.assertEqual(
            contract["failure_contract"]["kinds"],
            ["harness", "prerequisite", "runtime", "evidence"],
        )
        self.assertEqual(
            contract["execution"]["thread_fanout"],
            {
                "initial_threads": 1,
                "owner_workers_per_fixture_epoch": 1,
                "handoff_workers_per_fixture_epoch": 1,
                "peak_threads": 3,
            },
        )
        self.assertEqual(
            contract["execution"]["fixture_elf_identity"],
            {
                "class": "ELF64",
                "data": "little-endian",
                "os_abi": "UNIX - System V",
                "abi_version": "0",
                "type": "DYN",
                "machine": "AArch64",
                "pt_interp": "/lib/ld-crabc-aarch64.so.1",
            },
        )
        self.assertIn(
            "production_shadow_boundary.fixture_elf_attestation.fixture.pt_interp",
            contract["report"]["required_artifact_attestation"],
        )

    def test_contract_requires_selected_shadow_build_and_free_route_attestation(self) -> None:
        contract = HARNESS.read_json(HARNESS.CONTRACT_PATH)
        validated = HARNESS.validate_contract(contract)

        attestation = validated["selected_shadow_artifact_attestation"]
        self.assertEqual(
            attestation["cargo_fingerprint"]["exact_features"],
            ["default", "native-mimalloc-shadow"],
        )
        self.assertEqual(
            attestation["exported_free_route"]["required_callee_suffix"], "native_free>"
        )
        self.assertEqual(
            attestation["rust_cleanup_free_route"]["required_branch_target"], "free@plt>"
        )
        self.assertEqual(validated["rss_threshold_bytes"], 16777216)

    def test_selected_shadow_fingerprint_requires_exact_feature_identity(self) -> None:
        expectation = HARNESS.read_json(HARNESS.CONTRACT_PATH)[
            "selected_shadow_artifact_attestation"
        ]
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "target/debug"
            fingerprint = runtime / ".fingerprint/crabc-libc-selected/lib-c.json"
            fingerprint.parent.mkdir(parents=True)
            fingerprint.write_text(
                json.dumps(
                    {
                        "features": json.dumps(["default", "native-mimalloc-shadow"]),
                        "declared_features": json.dumps(["default", "native-mimalloc-shadow"]),
                    }
                ),
                encoding="utf-8",
            )

            result = HARNESS.selected_shadow_fingerprint(runtime, expectation)

        self.assertEqual(result["features"], ["default", "native-mimalloc-shadow"])
        self.assertEqual(result["path"].endswith("lib-c.json"), True)

    def test_free_route_attestation_rejects_the_c_backend_path(self) -> None:
        dynamic_symbols = "  42: 0000000000001000    16 FUNC    WEAK   DEFAULT   12 free\n"
        native_route = "    1000: 94000000 bl 2000 <_RNvNtCnative_free>\n"
        fallback_route = "    1000: 94000000 bl 2000 <mi_free>\n"

        self.assertEqual(
            HARNESS.attested_free_symbol(dynamic_symbols, "free"),
            {"binding": "WEAK", "visibility": "DEFAULT", "section": "12"},
        )
        HARNESS.require_branch_target(native_route, "native_free>", "exported free")
        with self.assertRaisesRegex(HARNESS.ArtifactAttestationError, "forbidden"):
            HARNESS.require_no_branch_target(fallback_route, "mi_free>", "exported free")

    def test_fixture_elf_attestation_rejects_the_wrong_interpreter(self) -> None:
        header = """ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           AArch64
"""
        program_headers = """Program Headers:
  INTERP         0x0000000000000200 0x0000000000000200 0x0000000000000200
      [Requesting program interpreter: /lib/ld-wrong-aarch64.so.1]
"""

        self.assertEqual(
            HARNESS.attested_elf_identity(header),
            {
                "class": "ELF64",
                "data": "little-endian",
                "os_abi": "UNIX - System V",
                "abi_version": "0",
                "type": "DYN",
                "machine": "AArch64",
            },
        )
        with self.assertRaisesRegex(
            HARNESS.FixtureElfAttestationError, "program interpreter"
        ) as caught:
            HARNESS.attested_program_interpreter(
                program_headers, HARNESS.CANONICAL_LOADER
            )

        report = HARNESS.failure_report(caught.exception)
        self.assertEqual(report["failure"]["kind"], "evidence")
        self.assertEqual(report["failure"]["subtype"], "production_boundary")
        self.assertEqual(report["failure"]["boundary"], "fixture_elf_identity")

    def test_fixture_result_requires_initial_thread_post_exit_frees(self) -> None:
        result = fixture_result()

        parsed = HARNESS.parse_fixture_output(json.dumps(result), seed=91, cycles=3)

        self.assertEqual(parsed["post_exit_initial_thread_frees"], 18)
        self.assertEqual(parsed["owner_exits_with_live_blocks"], 3)
        self.assertEqual(parsed["allocator_metadata_high_water_bytes"], None)
        self.assertEqual(
            parsed["state_auditor"],
            {
                "status": "incomplete",
                "scope": "production-general-churn",
                "workload_liveness": {
                    "status": "passed",
                    "snapshot_count": 3,
                    "warmup_epoch": 1,
                    "post_warm_snapshot_count": 2,
                    "plateau_after_warmup": True,
                },
                "allocator_state": {
                    "status": "unavailable",
                    "observation": "not-exposed-by-production-shadow-c-api",
                },
            },
        )
        self.assertEqual(parsed["thread_fanout"]["peak_threads"], 3)
        self.assertEqual(
            [parsed["first_fixture_epoch_seed"], parsed["last_fixture_epoch_seed"]],
            [HARNESS.fixture_epoch_seeds(91, 3)[0], HARNESS.fixture_epoch_seeds(91, 3)[-1]],
        )

    def test_fixture_result_rejects_hidden_post_exit_release(self) -> None:
        result = fixture_result()
        result["post_exit_initial_thread_frees"] = 0

        with self.assertRaisesRegex(
            HARNESS.AllocatorLivenessError, "post_exit_initial_thread_frees"
        ):
            HARNESS.parse_fixture_output(json.dumps(result), seed=91, cycles=3)

    def test_fixture_result_classifies_unavailable_rss_as_a_prerequisite(self) -> None:
        result = fixture_result()
        result["rss_initial_bytes"] = 0

        with self.assertRaises(HARNESS.PrerequisiteError) as caught:
            HARNESS.parse_fixture_output(json.dumps(result), seed=91, cycles=3)

        self.assertEqual(
            HARNESS.failure_report(caught.exception)["failure"]["kind"],
            "prerequisite",
        )

    def test_high_water_preserves_unknown_allocator_metadata(self) -> None:
        first = fixture_result(seed=91, cycles=3)
        second = fixture_result(seed=92, cycles=3)
        second["rss_high_water_bytes"] = 16384
        second["rss_warm_quiescent_bytes"] = 8192
        second["rss_last_quiescent_bytes"] = 12288
        second["live_blocks_high_water"] = 11

        high_water = HARNESS.high_water(
            [
                {"epoch": 1, "fixture": first},
                {"epoch": 2, "fixture": second},
            ]
        )

        self.assertEqual(high_water["rss_bytes"], 16384)
        self.assertEqual(high_water["live_blocks"], 11)
        self.assertEqual(high_water["state_auditor"]["status"], "incomplete")
        self.assertEqual(
            high_water["state_auditor"]["workload_liveness"]["snapshot_count"], 6
        )
        self.assertTrue(
            high_water["state_auditor"]["workload_liveness"]["plateau_after_warmup"]
        )
        self.assertEqual(
            high_water["rss_slopes"]["within_process_quiescent"][
                "maximum_bytes_per_fixture_epoch"
            ],
            2048.0,
        )
        self.assertEqual(
            high_water["rss_slopes"]["across_process_high_water"]["delta_bytes"],
            4096,
        )
        self.assertEqual(
            set(high_water["allocator_state"]),
            {
                "live_owner_registry",
                "post_exit_registry",
                "client_ledger",
                "page_map",
                "metadata",
                "arena",
                "abandoned_page",
                "tld",
                "theap",
            },
        )
        for observation in high_water["allocator_state"].values():
            self.assertIsNone(observation["high_water"])
            self.assertIsNone(observation["plateau_after_warmup"])
            self.assertFalse(observation["available"])

    def test_fixture_exit_68_records_seed_epoch_and_failure_transition(self) -> None:
        failure = {
            "schema": HARNESS.FIXTURE_SCHEMA,
            "status": "failed",
            "seed": 91,
            "cycles": 8,
            "completed_epochs": 2,
            "root_failure": {
                "domain": "allocator_runtime",
                "exit_status": 68,
                "epoch": 3,
                "epoch_seed": 1234567,
                "transition": "owner_exit_allocation",
                "code": 34,
                "subject_index": 4,
            },
            "state_auditor": {
                "status": "failed",
                "scope": "production-general-churn",
                "snapshot_count": 2,
            },
        }

        error = HARNESS.parse_fixture_failure(
            json.dumps(failure),
            status=68,
            process_epoch=2,
            seed=91,
            cycles=8,
        )
        report = HARNESS.failure_report(error)

        self.assertEqual(
            report["failure"]["root_failure"],
            {
                "process_epoch": 2,
                "process_seed": 91,
                "fixture_epoch": 3,
                "fixture_epoch_seed": 1234567,
                "completed_fixture_epochs": 2,
                "name": "owner_exit_allocation",
                "code": 34,
                "subject_index": 4,
                "exit_status": 68,
                "domain": "allocator_runtime",
                "structured": True,
            },
        )
        self.assertEqual(report["failure"]["kind"], "runtime")
        self.assertEqual(report["failure"]["subtype"], "allocator_liveness")

    def test_fixture_exit_68_preserves_an_opaque_runtime_root_failure(self) -> None:
        error = HARNESS.parse_fixture_failure(
            "",
            status=68,
            process_epoch=1,
            seed=91,
            cycles=8,
        )

        report = HARNESS.failure_report(error)

        self.assertEqual(report["failure"]["kind"], "runtime")
        self.assertEqual(
            report["failure"]["root_failure"],
            {
                "process_epoch": 1,
                "process_seed": 91,
                "exit_status": 68,
                "structured": False,
                "stdout": "",
            },
        )

    def test_failed_preflight_writes_machine_readable_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "failure.json"

            with redirect_stderr(io.StringIO()):
                status = HARNESS.main(["--report", str(report), "--seed", "0"])

            self.assertEqual(status, 1)
            value = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(value["schema"], HARNESS.REPORT_SCHEMA)
            self.assertEqual(value["status"], "failed")
            self.assertEqual(value["failure"]["kind"], "harness")
            self.assertIn("positive", value["error"])

    def test_failure_report_distinguishes_harness_runtime_and_prerequisite(self) -> None:
        liveness = HARNESS.failure_report(HARNESS.AllocatorLivenessError("owner handoff failed"))
        threshold_error = HARNESS.RssThresholdError(observed_bytes=32768, threshold_bytes=16384)
        threshold_error.selected_shadow_artifact_attestation = {"status": "passed"}
        threshold_error.fixture_elf_attestation = {
            "status": "passed",
            "fixture": {"pt_interp": "/lib/ld-crabc-aarch64.so.1"},
        }
        threshold_error.artifact = {"sha256": "a" * 64, "size_bytes": 1}
        threshold_error.dynamic_dependencies = ["libc.so"]
        threshold = HARNESS.failure_report(threshold_error)
        prerequisite = HARNESS.failure_report(
            HARNESS.PrerequisiteError("owned sysroot is unavailable")
        )
        harness = HARNESS.failure_report(HARNESS.SmokeError("contract hash changed"))

        self.assertEqual(liveness["failure"]["kind"], "runtime")
        self.assertEqual(liveness["failure"]["subtype"], "allocator_liveness")
        self.assertEqual(threshold["failure"]["kind"], "runtime")
        self.assertEqual(threshold["failure"]["subtype"], "rss_threshold")
        self.assertEqual(prerequisite["failure"]["kind"], "prerequisite")
        self.assertEqual(harness["failure"]["kind"], "harness")
        self.assertEqual(
            threshold["failure"]["rss"],
            {"observed_high_water_bytes": 32768, "threshold_bytes": 16384},
        )
        self.assertEqual(
            threshold["production_shadow_boundary"]["selected_shadow_artifact_attestation"],
            {"status": "passed"},
        )
        self.assertEqual(
            threshold["production_shadow_boundary"]["fixture_elf_attestation"]["fixture"][
                "pt_interp"
            ],
            "/lib/ld-crabc-aarch64.so.1",
        )
        self.assertEqual(threshold["artifact"], {"sha256": "a" * 64, "size_bytes": 1})

    def test_report_configuration_records_seed_epoch_and_thread_fanout(self) -> None:
        configuration = HARNESS.report_configuration(
            seed=91,
            cycles=3,
            epochs=2,
            watchdog_seconds=30,
            rss_threshold_bytes=16777216,
        )

        self.assertEqual(configuration["process_epoch_seeds"], [91, 92])
        self.assertEqual(configuration["fixture_epochs_per_process"], 3)
        self.assertEqual(configuration["total_fixture_epochs"], 6)
        self.assertEqual(configuration["thread_fanout"]["peak_threads"], 3)
        self.assertEqual(configuration["thread_fanout"]["total_worker_threads"], 12)

    def test_unavailable_allocator_state_fails_as_production_boundary_evidence(self) -> None:
        executions = [
            {"epoch": 1, "seed": 91, "fixture": fixture_result(seed=91, cycles=3)},
            {"epoch": 2, "seed": 92, "fixture": fixture_result(seed=92, cycles=3)},
        ]

        with self.assertRaises(HARNESS.AllocatorStateEvidenceError) as caught:
            HARNESS.require_general_production_state(executions)

        report = HARNESS.failure_report(caught.exception)
        self.assertEqual(report["failure"]["kind"], "evidence")
        self.assertEqual(report["failure"]["subtype"], "production_boundary")
        self.assertEqual(report["failure"]["boundary"], "allocator_internal_state")
        self.assertEqual(len(report["executions"]), 2)
        self.assertEqual(report["high_water"]["state_auditor"]["status"], "incomplete")
        self.assertEqual(
            report["high_water"]["allocator_state"]["client_ledger"]["high_water"],
            None,
        )
        with self.assertRaises(HARNESS.AllocatorStateEvidenceError):
            HARNESS.report_for_success(
                HARNESS.read_json(HARNESS.CONTRACT_PATH),
                {
                    "artifact": {"sha256": "a" * 64, "size_bytes": 1},
                    "build": {
                        "dynamic_dependencies": ["libc.so"],
                        "selected_shadow_artifact_attestation": {"status": "passed"},
                    },
                    "executions": executions,
                },
                seed=91,
                cycles=3,
                epochs=2,
                watchdog_seconds=30,
                rss_threshold_bytes=16777216,
            )


if __name__ == "__main__":
    unittest.main()
