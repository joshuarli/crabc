#!/usr/bin/env python3
"""Focused contract tests for the canonical unmodified upstream stress lane."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "upstream-stress/run.py"
SPEC = importlib.util.spec_from_file_location("crabc_canonical_upstream_stress", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class CanonicalUpstreamStressContractTests(unittest.TestCase):
    @staticmethod
    def native_runtime_inputs(root: Path) -> object:
        return RUNNER.RuntimeInputs(
            sysroot=root / "sysroot",
            compiler=root / "sysroot/bin/crabc-cc",
            target_dir=root / "target",
            manifest_path=root / "sysroot/share/crabc/manifest.json",
            purity_path=root / "sysroot/share/crabc/purity.json",
            purity={
                "crt_sysroot_pure_rust": True,
                "full_runtime_pure_rust": False,
                "full_runtime_purity_status": "blocked_by_native_allocator",
            },
        )

    @staticmethod
    def successful_process(case: dict[str, object]) -> dict[str, object]:
        return {
            "kind": "process",
            "status": case["expected_exit_status"],
            "stdout": RUNNER.bytes_record(str(case["expected_stdout"]).encode()),
            "stderr": RUNNER.bytes_record(str(case["expected_stderr"]).encode()),
        }

    def test_closed_contract_keeps_the_archive_source_unmodified(self) -> None:
        contract, pin = RUNNER.load_contract()
        self.assertEqual(pin, RUNNER.FIXED_PIN)
        self.assertEqual(contract["upstream"]["archive_sha256"], pin["sha256"])
        self.assertEqual(contract["fixture"]["archive_member"], "test/test-stress.c")
        self.assertEqual(
            contract["fixture"]["sha256"],
            "e2bed5f2be12239b1fa696dafffda384d19140cb50a6ee2f6e096f70934d73df",
        )
        self.assertEqual(contract["source_adaptation"]["compile_defines"], ["USE_STD_MALLOC"])
        self.assertEqual(contract["source_adaptation"]["patches"], [])

    def test_contract_has_one_applicable_native_target_and_backend(self) -> None:
        contract, _ = RUNNER.load_contract()
        targets = contract["target_inventory"]
        backends = contract["backend_inventory"]
        self.assertEqual(targets["selected"], "linux-aarch64-little-endian")
        self.assertEqual(
            targets["targets"],
            [
                {
                    "id": "linux-aarch64-little-endian",
                    "architecture": "aarch64",
                    "byte_order": "little",
                    "execution": "native-only",
                    "kernel_baseline": "5.10",
                    "status": "applicable",
                    "system": "Linux",
                }
            ],
        )
        self.assertEqual(backends["selected"], "crabc-libc-native-mimalloc-shadow")
        backend = backends["backends"][0]
        self.assertEqual(backend["target"], targets["selected"])
        self.assertEqual(backend["allocator_feature"], "native-mimalloc-shadow")
        self.assertFalse(backend["c_backend_fallback"])
        self.assertEqual(
            backend["artifact_attestation"]["cargo_fingerprint"]["exact_features"],
            ["default", "native-mimalloc-shadow"],
        )

    def test_contract_records_upstream_seed_watchdog_and_artifact_schemas(self) -> None:
        contract, _ = RUNNER.load_contract()
        execution = contract["execution"]
        self.assertEqual(
            execution["source_randomness"],
            {
                "caller_override": "none",
                "c_library_seed": "0x7feb352d",
                "kind": "upstream-source-fixed",
                "pthread_schedule": "nondeterministic",
                "worker_seed_rule": "(tid + 1) * 43",
            },
        )
        self.assertEqual(
            execution["watchdog"],
            {
                "process_retries": 0,
                "scope": "each fresh matrix process",
                "seconds": 30,
                "timeout_result": "failed",
            },
        )
        report = contract["report"]
        self.assertEqual(report["schema"], "crabc-mimalloc-canonical-upstream-stress-report")
        self.assertEqual(report["format"], 2)
        self.assertEqual(report["file_artifact_record_fields"], ["path", "bytes", "sha256"])
        self.assertEqual(report["byte_stream_record_fields"], ["bytes", "sha256", "hex"])

    def test_capability_policy_is_fail_closed_until_every_native_case_passes(self) -> None:
        contract, _ = RUNNER.load_contract()
        capability = contract["capability"]
        self.assertEqual(capability["checked_in_status"], "not-run")
        self.assertEqual(capability["status_values"], ["not-run", "blocked", "failed", "passed"])
        self.assertEqual(capability["required_worker_counts"], [1, 2, 4, 8])
        self.assertTrue(capability["blocked_is_failure_closed"])
        self.assertIn("all matrix cases", capability["pass_condition"])

    def test_ordered_matrix_preserves_the_smallest_schedule_and_source_cleanup(self) -> None:
        contract, _ = RUNNER.load_contract()
        execution = contract["execution"]
        assertions = execution["scheduler_and_ownership"]
        cases = RUNNER.execution_cases(contract)
        self.assertEqual(cases[0]["arguments"], ["1", "1", "1"])
        self.assertEqual([case["workers"] for case in cases[:4]], [1, 2, 4, 8])
        self.assertEqual(
            {(case["scale"], case["iterations"]) for case in cases},
            {(1, 1), (2, 2)},
        )
        self.assertEqual(execution["process_attempts_per_case"], 1)
        self.assertIn("main_participates value remains false.", assertions[0])
        self.assertIn("creates and joins", assertions[1])
        self.assertIn("initial thread performs free_items cleanup", assertions[3])

    def test_run_command_uses_each_inventory_case_without_a_scheduler_define(self) -> None:
        contract, _ = RUNNER.load_contract()
        binary = Path("/target/compat/allocator/upstream-stress/canonical-upstream-test-stress")
        commands = [RUNNER.run_command(binary, case) for case in RUNNER.execution_cases(contract)]
        self.assertEqual(
            commands[0],
            [str(binary), "1", "1", "1"],
        )
        self.assertEqual(
            commands[-1],
            [str(binary), "8", "2", "2"],
        )
        self.assertTrue(all("-DNTHREADS" not in command for command in commands))

    def test_build_command_contains_only_the_upstream_standard_allocator_selection(self) -> None:
        contract, _ = RUNNER.load_contract()
        command = RUNNER.build_command(
            Path("/sysroot/bin/crabc-cc"),
            Path("/source/mimalloc-3.5.0"),
            "test/test-stress.c",
            Path("/target/debug"),
            Path("/target/compat/allocator/upstream-stress/canonical-upstream-test-stress"),
            contract,
        )
        self.assertIn("-DUSE_STD_MALLOC", command)
        self.assertNotIn("-DNTHREADS=1", command)
        self.assertNotIn("patch", " ".join(command))
        self.assertEqual(command.count("-D" + "USE_STD_MALLOC"), 1)

    def test_runtime_environment_clears_inherited_loader_overrides(self) -> None:
        with mock.patch.dict(
            RUNNER.os.environ,
            {
                "LD_AUDIT": "audit.so",
                "LD_LIBRARY_PATH": "/ambient/lib",
                "LD_PRELOAD": "preload.so",
            },
            clear=False,
        ):
            environment = RUNNER.runtime_environment(Path("/target/debug"))
        self.assertNotIn("LD_AUDIT", environment)
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertEqual(environment["LD_LIBRARY_PATH"], "/target/debug")

    def test_native_target_rejects_a_kernel_below_the_checked_inventory(self) -> None:
        with mock.patch.object(RUNNER.platform, "system", return_value="Linux"), mock.patch.object(
            RUNNER.platform, "machine", return_value="aarch64"
        ), mock.patch.object(
            RUNNER.platform, "release", return_value="5.9.18"
        ), mock.patch.object(
            RUNNER.sys, "byteorder", "little"
        ):
            with self.assertRaises(RUNNER.BlockedPrerequisite) as failure:
                RUNNER.require_native_aarch64()
        self.assertEqual(failure.exception.prerequisite, "native-linux-kernel-baseline")
        self.assertEqual(failure.exception.details["required_kernel_baseline"], "5.10")

    def test_native_backend_fingerprint_requires_one_exact_feature_inventory(self) -> None:
        contract, _ = RUNNER.load_contract()
        expectation = contract["backend_inventory"]["backends"][0]["artifact_attestation"]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            fingerprint = target / ".fingerprint/crabc-libc-native/lib-c.json"
            fingerprint.parent.mkdir(parents=True)
            fingerprint.write_text(
                json.dumps({"features": json.dumps(["default", "native-mimalloc-shadow"])}),
                encoding="utf-8",
            )
            expected_sha256 = RUNNER.sha256_file(fingerprint)
            record, features = RUNNER.selected_backend_fingerprint(target, expectation)
        self.assertEqual(features, ["default", "native-mimalloc-shadow"])
        self.assertEqual(record["sha256"], expected_sha256)

    def test_native_backend_attestation_rejects_a_c_free_route(self) -> None:
        contract, _ = RUNNER.load_contract()
        symbols = {
            "kind": "process",
            "status": 0,
            "stdout": RUNNER.bytes_record(
                b"  42: 0000000000001000 16 FUNC WEAK DEFAULT 12 free\n"
            ),
            "stderr": RUNNER.bytes_record(b""),
        }
        c_route = {
            "kind": "process",
            "status": 0,
            "stdout": RUNNER.bytes_record(
                b"  1000: 94000000 bl 2000 <mi_free>\n"
            ),
            "stderr": RUNNER.bytes_record(b""),
        }
        with mock.patch.object(
            RUNNER,
            "selected_backend_fingerprint",
            return_value=(
                {"bytes": 1, "path": "fingerprint", "sha256": "0" * 64},
                ["default", "native-mimalloc-shadow"],
            ),
        ), mock.patch.object(
            RUNNER.shutil, "which", side_effect=lambda tool: tool
        ), mock.patch.object(
            RUNNER, "command_record", side_effect=[symbols, c_route]
        ):
            with self.assertRaisesRegex(RUNNER.EvidenceError, "does not branch to"):
                RUNNER.attest_selected_backend(Path("/target/debug"), contract)

    def test_tag_attestation_requires_the_annotated_tag_and_peeled_revision(self) -> None:
        _, pin = RUNNER.load_contract()
        reference = f"refs/tags/{pin['tag']}"
        peeled = reference + "^{}"
        probe = {
            "kind": "process",
            "status": 0,
            "stdout": RUNNER.bytes_record(
                f"{pin['tag_object']}\t{reference}\n{pin['revision']}\t{peeled}\n".encode()
            ),
            "stderr": RUNNER.bytes_record(b""),
        }
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            RUNNER, "CACHE", Path(temporary)
        ), mock.patch.object(RUNNER.shutil, "which", return_value="git"), mock.patch.object(
            RUNNER, "command_record", return_value=probe
        ):
            attestation = RUNNER.verify_tag_identity(pin, offline=False)
            self.assertEqual(attestation["tag_object"], pin["tag_object"])
            self.assertEqual(attestation["revision"], pin["revision"])
            self.assertEqual(RUNNER.cached_tag_attestation(pin), attestation)

    def test_failure_report_keeps_the_first_process_observation(self) -> None:
        contract, pin = RUNNER.load_contract()
        case = RUNNER.execution_cases(contract)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = RUNNER.parse_arguments(
                ["--target-dir", str(root / "target"), "--output-dir", str(root / "output")]
            )
            report = RUNNER.report_base(contract, pin, args)
        observation = {
            "kind": "process",
            "status": -6,
            "stdout": RUNNER.bytes_record(b"Using 1 threads with a 1% load-per-thread and 1 iterations\n"),
            "stderr": RUNNER.bytes_record(b""),
        }
        report["execution"]["attempted"] = True
        report["execution"]["attempted_process_count"] = 1
        report["execution"]["case_results"][0] = {
            "case": RUNNER.case_inventory(case),
            "process_attempt": 1,
            "state": "failed",
            "observation": observation,
        }
        report["first_fact"] = {
            "kind": "first-failure",
            "stage": "run",
            "case": RUNNER.case_inventory(case),
            "process_attempt": 1,
            "observation": observation,
        }
        self.assertEqual(report["execution"]["process_attempts_per_case"], 1)
        self.assertEqual(report["execution"]["attempted_process_count"], 1)
        self.assertEqual(report["first_fact"]["observation"]["status"], -6)
        self.assertFalse(RUNNER.successful_run(observation, case))

    def test_execute_classifies_the_first_failed_matrix_case_without_retrying(self) -> None:
        contract, pin = RUNNER.load_contract()
        cases = RUNNER.execution_cases(contract)
        build = {
            "kind": "process",
            "status": 0,
            "stdout": RUNNER.bytes_record(b""),
            "stderr": RUNNER.bytes_record(b""),
        }
        failed_run = {
            "kind": "process",
            "status": -6,
            "stdout": RUNNER.bytes_record(
                str(cases[1]["expected_stdout"]).encode()
            ),
            "stderr": RUNNER.bytes_record(b""),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source = source_root / "test/test-stress.c"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"exact pinned source")
            args = RUNNER.parse_arguments(
                ["--target-dir", str(root / "target"), "--output-dir", str(root / "output")]
            )
            report = RUNNER.report_base(contract, pin, args)
            with mock.patch.object(RUNNER, "require_native_aarch64"), mock.patch.object(
                RUNNER, "fetch_archive", return_value=root / "mimalloc.tar.gz"
            ), mock.patch.object(
                RUNNER,
                "cached_tag_attestation",
                return_value={"format": 1, "revision": pin["revision"]},
            ), mock.patch.object(
                RUNNER,
                "require_runtime_inputs",
                return_value=self.native_runtime_inputs(root),
            ), mock.patch.object(
                RUNNER,
                "attest_selected_backend",
                return_value={
                    "cargo_fingerprint": {
                        "bytes": 1,
                        "path": "fingerprint",
                        "sha256": "0" * 64,
                    },
                    "status": "passed",
                },
            ), mock.patch.object(RUNNER, "extract_exact_archive", return_value=source_root), mock.patch.object(
                RUNNER, "sha256_file", return_value=contract["fixture"]["sha256"]
            ), mock.patch.object(
                RUNNER,
                "file_record",
                return_value={"bytes": 1, "path": "recorded", "sha256": "0" * 64},
            ), mock.patch.object(
                RUNNER,
                "command_record",
                side_effect=[build, self.successful_process(cases[0]), failed_run],
            ) as commands, mock.patch.object(
                RUNNER, "dynamic_dependencies", return_value=["libc.so"]
            ):
                RUNNER.execute(contract, pin, args, report)
        self.assertEqual(commands.call_count, 3)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["first_fact"]["kind"], "first-failure")
        self.assertEqual(report["first_fact"]["stage"], "run")
        self.assertEqual(report["first_fact"]["case"]["id"], cases[1]["id"])
        self.assertEqual(report["first_fact"]["process_attempt"], 2)
        self.assertEqual(report["execution"]["attempted_process_count"], 2)
        self.assertEqual(report["execution"]["case_results"][0]["state"], "passed")
        self.assertEqual(report["execution"]["case_results"][1]["state"], "failed")
        self.assertEqual(report["execution"]["case_results"][2]["state"], "not-attempted")
        self.assertEqual(report["capability"]["status"], "failed")
        self.assertEqual(report["capability"]["passed_case_count"], 1)
        self.assertEqual(report["capability"]["fully_verified_worker_counts"], [])
        self.assertEqual(
            commands.call_args_list[2].args[0],
            RUNNER.run_command(root.resolve() / "output/canonical-upstream-test-stress", cases[1]),
        )

    def test_execute_marks_the_inventory_passed_only_after_every_case_passes(self) -> None:
        contract, pin = RUNNER.load_contract()
        cases = RUNNER.execution_cases(contract)
        build = {
            "kind": "process",
            "status": 0,
            "stdout": RUNNER.bytes_record(b""),
            "stderr": RUNNER.bytes_record(b""),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source = source_root / "test/test-stress.c"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"exact pinned source")
            args = RUNNER.parse_arguments(
                ["--target-dir", str(root / "target"), "--output-dir", str(root / "output")]
            )
            report = RUNNER.report_base(contract, pin, args)
            with mock.patch.object(RUNNER, "require_native_aarch64"), mock.patch.object(
                RUNNER, "fetch_archive", return_value=root / "mimalloc.tar.gz"
            ), mock.patch.object(
                RUNNER,
                "cached_tag_attestation",
                return_value={"format": 1, "revision": pin["revision"]},
            ), mock.patch.object(
                RUNNER,
                "require_runtime_inputs",
                return_value=self.native_runtime_inputs(root),
            ), mock.patch.object(
                RUNNER,
                "attest_selected_backend",
                return_value={
                    "cargo_fingerprint": {
                        "bytes": 1,
                        "path": "fingerprint",
                        "sha256": "0" * 64,
                    },
                    "status": "passed",
                },
            ), mock.patch.object(RUNNER, "extract_exact_archive", return_value=source_root), mock.patch.object(
                RUNNER, "sha256_file", return_value=contract["fixture"]["sha256"]
            ), mock.patch.object(
                RUNNER,
                "file_record",
                return_value={"bytes": 1, "path": "recorded", "sha256": "0" * 64},
            ), mock.patch.object(
                RUNNER,
                "command_record",
                side_effect=[build, *(self.successful_process(case) for case in cases)],
            ) as commands, mock.patch.object(
                RUNNER, "dynamic_dependencies", return_value=["libc.so"]
            ):
                RUNNER.execute(contract, pin, args, report)
        self.assertEqual(commands.call_count, 1 + len(cases))
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["first_fact"], {
            "kind": "pass",
            "stage": "matrix",
            "completed_case_count": len(cases),
        })
        self.assertEqual(report["execution"]["attempted_process_count"], len(cases))
        self.assertTrue(
            all(result["state"] == "passed" for result in report["execution"]["case_results"])
        )
        self.assertEqual(report["capability"]["status"], "passed")
        self.assertTrue(report["capability"]["native_execution_completed"])
        self.assertEqual(report["capability"]["fully_verified_worker_counts"], [1, 2, 4, 8])

    def test_owned_sysroot_prerequisite_is_a_structured_blocked_report(self) -> None:
        contract, pin = RUNNER.load_contract()
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "upstream-stress.json"
            with mock.patch.object(
                RUNNER,
                "execute",
                side_effect=RUNNER.BlockedPrerequisite(
                    "owned-sysroot-manifest",
                    "missing owned sysroot manifest",
                    {"manifest": "/missing/share/crabc/manifest.json", "sysroot": "/missing"},
                ),
            ):
                status = RUNNER.main(["--report", str(report_path)])
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(status, 1)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["capability"]["status"], "blocked")
        self.assertFalse(report["capability"]["native_execution_started"])
        self.assertTrue(report["capability"]["failure_closed"])
        self.assertIsNone(report["first_fact"])
        self.assertFalse(report["execution"]["attempted"])
        self.assertNotIn("attempts", report["execution"])
        self.assertEqual(
            report["blocked"],
            {
                "format": 1,
                "kind": "execution-prerequisite",
                "message": "missing owned sysroot manifest",
                "prerequisite": "owned-sysroot-manifest",
                "details": {
                    "manifest": "/missing/share/crabc/manifest.json",
                    "sysroot": "/missing",
                },
                "stress_process_started": False,
            },
        )
        self.assertNotIn("passed", json.dumps(report["blocked"]))
        self.assertNotIn("skipped", json.dumps(report["blocked"]))

    def test_check_reports_contract_success_without_runtime_capability_success(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = RUNNER.main(["--check"])
        result = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(result["contract_status"], "passed")
        self.assertEqual(result["capability_status"], "not-run")
        self.assertFalse(result["native_execution_started"])

    def test_canonical_dev_dispatch_builds_the_selected_backend_last(self) -> None:
        script = (RUNNER.ROOT / "scripts/dev.sh").read_text(encoding="utf-8")
        start = script.index("    allocator-upstream)")
        end = script.index("    allocator-shadow)", start)
        dispatch = script[start:end]
        sysroot_build = dispatch.index("python3 scripts/build_owned_sysroot.py")
        shadow_build = dispatch.index(
            "cargo build -p crabc-libc --features native-mimalloc-shadow"
        )
        stress_run = dispatch.index("python3 compat/allocator/upstream-stress/run.py")
        self.assertLess(sysroot_build, shadow_build)
        self.assertLess(shadow_build, stress_run)
        self.assertIn("python3 scripts/run_owned_test_suite.py", dispatch)
        self.assertIn('-- python3 compat/allocator/upstream-stress/run.py "$@"', dispatch)

    def test_report_starts_with_closed_artifact_slots_and_no_capability_claim(self) -> None:
        contract, pin = RUNNER.load_contract()
        args = RUNNER.parse_arguments([])
        report = RUNNER.report_base(contract, pin, args)
        self.assertEqual(report["format"], 2)
        self.assertEqual(report["capability"]["status"], "not-run")
        self.assertFalse(report["capability"]["native_execution_started"])
        self.assertEqual(
            set(report["artifacts"]),
            {
                "contract",
                "upstream_archive",
                "source_member",
                "owned_sysroot_manifest",
                "owned_sysroot_purity",
                "owned_compiler",
                "selected_loader",
                "selected_libc",
                "selected_backend_fingerprint",
                "stress_binary",
            },
        )
        self.assertTrue(all(
            value is None or set(value) == {"path", "bytes", "sha256"}
            for value in report["artifacts"].values()
        ))

    def test_missing_owned_sysroot_environment_names_its_prerequisite(self) -> None:
        with mock.patch.dict(RUNNER.os.environ, {}, clear=True):
            with self.assertRaises(RUNNER.BlockedPrerequisite) as failure:
                RUNNER.require_runtime_inputs(Path("/target/debug"))
        self.assertEqual(failure.exception.prerequisite, "owned-test-suite-environment")
        self.assertEqual(
            failure.exception.details["required_launcher"],
            "scripts/run_owned_test_suite.py",
        )

    def test_report_is_atomic_json_with_a_single_fact_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "nested/latest.json"
            value = {"first_fact": {"kind": "pass"}, "status": "passed"}
            RUNNER.write_json(report_path, value)
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), value)


if __name__ == "__main__":
    unittest.main()
