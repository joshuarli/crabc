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
            canonical_loader_path=root / "canonical/ld-crabc-aarch64.so.1",
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
            backend["artifact_attestation"]["cargo_compiler_artifact"]["exact_features"],
            ["default", "native-mimalloc-shadow"],
        )
        self.assertEqual(
            backend["artifact_attestation"]["cargo_compiler_artifact"]["semantic_profile"],
            "dev",
        )

    def test_contract_records_upstream_seed_watchdog_and_artifact_schemas(self) -> None:
        contract, _ = RUNNER.load_contract()
        self.assertEqual(
            contract["upstream"]["archive_path"],
            ".work/allocator-cache/mimalloc-3.5.0.tar.gz",
        )
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
        self.assertEqual(report["format"], 4)
        self.assertEqual(
            report["path"],
            ".work/reports/allocator/upstream-stress/latest.json",
        )
        self.assertEqual(report["file_artifact_record_fields"], ["path", "bytes", "sha256"])
        self.assertEqual(report["byte_stream_record_fields"], ["bytes", "sha256", "hex"])
        self.assertEqual(
            report["fixture_elf_fields"],
            ["dynamic_dependencies", "elf_identity", "interpreter"],
        )
        self.assertEqual(
            report["source_path_normalization"],
            {
                "artifact": "mimalloc-3.5.0/test/test-stress.c",
                "extraction_root": "<pinned-source>/mimalloc-3.5.0",
            },
        )
        self.assertEqual(
            contract["compile_requirements"]["expected_elf_identity"],
            {"class": "ELF64", "endianness": "little", "machine": "AArch64"},
        )
        self.assertEqual(
            contract["compile_requirements"]["expected_interpreter"],
            "/lib/ld-crabc-aarch64.so.1",
        )
        self.assertEqual(
            contract["compile_requirements"]["selected_runtime_directory"],
            "target/debug",
        )
        self.assertEqual(
            contract["compile_requirements"]["selected_libc_build_record"],
            ".work/target/compat/allocator/upstream-stress/selected-libc-build.json",
        )
        self.assertEqual(
            contract["compile_requirements"]["isolated_output_directory"],
            ".work/target/compat/allocator/upstream-stress",
        )

    def test_default_work_root_routes_runner_owned_mutable_artifacts(self) -> None:
        work_root = RUNNER.WORK_ROOT
        self.assertEqual(RUNNER.CACHE, work_root / "allocator-cache")
        self.assertEqual(
            RUNNER.DEFAULT_OUTPUT_DIR,
            work_root / "target/compat/allocator/upstream-stress",
        )
        self.assertEqual(
            RUNNER.DEFAULT_LIBC_BUILD_RECORD,
            work_root / "target/compat/allocator/upstream-stress/selected-libc-build.json",
        )
        self.assertEqual(
            RUNNER.DEFAULT_REPORT,
            work_root / "reports/allocator/upstream-stress/latest.json",
        )
        self.assertEqual(
            RUNNER.DEFAULT_DIAGNOSTIC_REPORT,
            work_root / "reports/allocator/upstream-stress/current-head.json",
        )
        self.assertEqual(
            RUNNER.DEFAULT_POST_OWNER_EXIT_CONCURRENT_FREE_REPORT,
            work_root
            / "reports/allocator/upstream-stress/post-owner-exit-concurrent-free.json",
        )
        self.assertEqual(RUNNER.DEFAULT_TARGET_DIR, RUNNER.ROOT / "target/debug")
        self.assertEqual(
            RUNNER.archive_path(RUNNER.FIXED_PIN),
            work_root / "allocator-cache/mimalloc-3.5.0.tar.gz",
        )

        args = RUNNER.parse_arguments([])
        self.assertEqual(args.output_dir, RUNNER.DEFAULT_OUTPUT_DIR)
        self.assertEqual(args.report, RUNNER.DEFAULT_REPORT)
        self.assertEqual(args.libc_build_record, RUNNER.DEFAULT_LIBC_BUILD_RECORD)
        self.assertEqual(
            args.current_head_build_record,
            work_root
            / "target/compat/allocator/upstream-stress/selected-libc-build-current-head.json",
        )
        self.assertEqual(
            RUNNER.parse_arguments(["--diagnose"]).report,
            RUNNER.DEFAULT_DIAGNOSTIC_REPORT,
        )
        self.assertEqual(
            RUNNER.parse_arguments(["--post-owner-exit-concurrent-free"]).report,
            RUNNER.DEFAULT_POST_OWNER_EXIT_CONCURRENT_FREE_REPORT,
        )

    def test_default_work_root_honors_crabc_work_dir(self) -> None:
        with mock.patch.dict(RUNNER.os.environ, {}, clear=True):
            self.assertEqual(RUNNER.default_work_root(), RUNNER.ROOT / ".work")
        with mock.patch.dict(
            RUNNER.os.environ, {"CRABC_WORK_DIR": "isolated-work"}, clear=True
        ):
            self.assertEqual(
                RUNNER.default_work_root(),
                RUNNER.ROOT / "isolated-work",
            )
        custom = RUNNER.ROOT / ".work/custom-root"
        with mock.patch.dict(
            RUNNER.os.environ, {"CRABC_WORK_DIR": str(custom)}, clear=True
        ):
            self.assertEqual(RUNNER.default_work_root(), custom)

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

    def test_diagnose_selects_only_the_contracts_first_smallest_case(self) -> None:
        contract, _ = RUNNER.load_contract()
        args = RUNNER.parse_arguments(["--diagnose"])

        self.assertEqual(
            RUNNER.diagnostic_case(contract),
            RUNNER.execution_cases(contract)[0],
        )
        self.assertEqual(
            RUNNER.case_inventory(RUNNER.diagnostic_case(contract)),
            {
                "id": "workers-1-scale-1-iterations-1",
                "workers": 1,
                "scale": 1,
                "iterations": 1,
                "arguments": ["1", "1", "1"],
            },
        )
        self.assertEqual(args.report, RUNNER.DEFAULT_DIAGNOSTIC_REPORT)
        self.assertEqual(
            RUNNER.diagnostic_output_dir(args),
            RUNNER.DEFAULT_OUTPUT_DIR / "current-head",
        )

    def test_post_owner_exit_concurrent_free_selects_the_smallest_unmodified_two_worker_case(
        self,
    ) -> None:
        contract, _ = RUNNER.load_contract()
        args = RUNNER.parse_arguments(["--post-owner-exit-concurrent-free"])

        case = RUNNER.post_owner_exit_concurrent_free_case(contract)
        self.assertEqual(case, RUNNER.execution_cases(contract)[1])
        self.assertEqual(
            RUNNER.case_inventory(case),
            {
                "id": "workers-2-scale-1-iterations-1",
                "workers": 2,
                "scale": 1,
                "iterations": 1,
                "arguments": ["2", "1", "1"],
            },
        )
        self.assertEqual(args.report, RUNNER.DEFAULT_POST_OWNER_EXIT_CONCURRENT_FREE_REPORT)
        self.assertEqual(
            RUNNER.diagnostic_output_dir(args),
            RUNNER.DEFAULT_OUTPUT_DIR / "post-owner-exit-concurrent-free",
        )
        self.assertEqual(
            RUNNER.run_command(Path("/tmp/canonical-upstream-test-stress"), case),
            ["/tmp/canonical-upstream-test-stress", "2", "1", "1"],
        )
        self.assertNotIn("-DNTHREADS", " ".join(RUNNER.build_command(
            Path("/sysroot/bin/crabc-cc"),
            Path("/source/mimalloc-3.5.0"),
            "test/test-stress.c",
            Path("/target/debug"),
            Path("/tmp/canonical-upstream-test-stress"),
            contract,
        )))

        report = RUNNER.diagnostic_report_base(contract, RUNNER.FIXED_PIN, args)
        self.assertEqual(report["execution"]["case"], RUNNER.case_inventory(case))
        self.assertEqual(report["diagnostic"]["id"], "post-owner-exit-concurrent-free")
        self.assertEqual(
            report["diagnostic"]["classification"], "one-case-source-shaped-only"
        )
        self.assertEqual(
            report["diagnostic"]["scope"],
            {
                "source_unmodified": True,
                "selected_closed_matrix_case": "workers-2-scale-1-iterations-1",
                "source_worker_count": 2,
                "source_scheduler": "upstream pthread schedule remains nondeterministic",
                "post_owner_exit_cleanup": (
                    "the unmodified upstream initial thread frees surviving transfer entries "
                    "after joining both source workers"
                ),
                "concurrent_free_overlap": "not-instrumented",
                "canonical_matrix": "not-run",
                "m5_accepted": False,
            },
        )
        self.assertEqual(report["canonical_matrix"]["status"], "not-run")
        self.assertFalse(report["canonical_matrix"]["m5_accepted"])

    def test_diagnostic_pass_is_not_a_full_matrix_or_m5_acceptance(self) -> None:
        contract, pin = RUNNER.load_contract()
        case = RUNNER.execution_cases(contract)[0]
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
            build_record = root / "selected-libc-build.json"
            build_record.write_text("{}\n", encoding="utf-8")
            args = RUNNER.parse_arguments(
                [
                    "--diagnose",
                    "--target-dir",
                    str(root / "target"),
                    "--output-dir",
                    str(root / "output"),
                    "--libc-build-record",
                    str(build_record),
                ]
            )
            report = RUNNER.diagnostic_report_base(contract, pin, args)
            backend = {
                "build_record": {
                    "bytes": 1, "path": "build-record", "sha256": "0" * 64
                },
                "artifacts": {
                    "selected_shared_libc": {
                        "bytes": 1, "path": "libc.so", "sha256": "0" * 64
                    },
                    "selected_static_libc": {
                        "bytes": 1, "path": "libc.a", "sha256": "0" * 64
                    },
                },
                "status": "passed",
            }
            current_head = {
                "record": {
                    "bytes": 1,
                    "path": "current-head-build",
                    "sha256": "0" * 64,
                },
                "source": {
                    "kind": "git",
                    "revision": "1" * 40,
                    "worktree_clean": True,
                    "worktree_status": RUNNER.bytes_record(b""),
                },
            }
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
                RUNNER, "attest_selected_backend", return_value=backend
            ), mock.patch.object(
                RUNNER, "attest_current_head_build", return_value=current_head
            ), mock.patch.object(
                RUNNER, "extract_exact_archive", return_value=source_root
            ), mock.patch.object(
                RUNNER,
                "sha256_file",
                return_value=contract["fixture"]["sha256"],
            ), mock.patch.object(
                RUNNER,
                "file_record",
                return_value={"bytes": 1, "path": "recorded", "sha256": "0" * 64},
            ), mock.patch.object(
                RUNNER,
                "command_record",
                side_effect=[build, self.successful_process(case)],
            ) as commands, mock.patch.object(
                RUNNER,
                "audit_fixture_elf",
                return_value={
                    "dynamic_dependencies": ["libc.so"],
                    "elf_identity": {
                        "class": "ELF64",
                        "endianness": "little",
                        "machine": "AArch64",
                    },
                    "interpreter": "/lib/ld-crabc-aarch64.so.1",
                },
            ):
                RUNNER.execute_diagnostic(contract, pin, args, report)

        self.assertEqual(commands.call_count, 2)
        self.assertEqual(
            commands.call_args_list[1].args[0],
            RUNNER.run_command(root.resolve() / "output/current-head/canonical-upstream-test-stress", case),
        )
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["diagnostic"]["status"], "passed")
        self.assertEqual(report["canonical_matrix"]["status"], "not-run")
        self.assertFalse(report["canonical_matrix"]["m5_accepted"])
        self.assertEqual(report["execution"]["case"], RUNNER.case_inventory(case))
        self.assertEqual(report["execution"]["process_attempt_count"], 1)
        self.assertEqual(report["runtime"]["backend_attestation"], backend)
        self.assertEqual(
            report["runtime"]["environment"],
            RUNNER.runtime_environment_record(root / "target"),
        )
        self.assertEqual(report["current_head"]["source"], current_head["source"])

    def test_diagnostic_blocked_prerequisite_never_claims_a_matrix_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "current-head.json"
            with mock.patch.object(
                RUNNER,
                "execute_diagnostic",
                side_effect=RUNNER.BlockedPrerequisite(
                    "current-head-build-record",
                    "missing selected libc current-head companion",
                    {"build_record": "/missing/current-head.json"},
                ),
            ):
                status = RUNNER.main(["--diagnose", "--report", str(report_path)])
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 1)
        self.assertEqual(report["schema"], RUNNER.DIAGNOSTIC_REPORT_SCHEMA)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["diagnostic"]["status"], "blocked")
        self.assertFalse(report["diagnostic"]["native_execution_started"])
        self.assertEqual(report["canonical_matrix"]["status"], "not-run")
        self.assertFalse(report["canonical_matrix"]["m5_accepted"])
        self.assertEqual(report["blocked"]["prerequisite"], "current-head-build-record")

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

    def test_runtime_environment_is_closed_and_reported(self) -> None:
        with mock.patch.dict(
            RUNNER.os.environ,
            {
                "HOME": "/ambient/home",
                "LD_AUDIT": "audit.so",
                "LD_DEBUG": "all",
                "LD_LIBRARY_PATH": "/ambient/lib",
                "LD_PRELOAD": "preload.so",
                "MALLOC_CHECK_": "3",
                "MI_SHOW_STATS": "1",
                "PATH": "/ambient/bin",
            },
            clear=True,
        ):
            environment = RUNNER.runtime_environment(Path("/target/debug"))
        self.assertEqual(
            environment,
            {
                "LC_ALL": "C",
                "LD_LIBRARY_PATH": "/target/debug",
                "TZ": "UTC",
            },
        )
        self.assertEqual(
            RUNNER.runtime_environment_record(Path("/target/debug")),
            {
                "inheritance": "none",
                "variables": {
                    "LC_ALL": "C",
                    "LD_LIBRARY_PATH": "/target/debug",
                    "TZ": "UTC",
                },
            },
        )

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

    def test_selected_dev_build_record_ignores_coexisting_test_fingerprint(self) -> None:
        contract, _ = RUNNER.load_contract()
        expectation = contract["backend_inventory"]["backends"][0]["artifact_attestation"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target/debug"
            target.mkdir(parents=True)
            shared = target / "libc.so"
            static = target / "libc.a"
            shared.write_bytes(b"selected dev shared libc")
            static.write_bytes(b"selected dev static libc")

            for identity in ("dev", "test"):
                fingerprint = target / f".fingerprint/crabc-libc-{identity}/lib-c.json"
                fingerprint.parent.mkdir(parents=True)
                fingerprint.write_text(
                    json.dumps(
                        {"features": json.dumps(["default", "native-mimalloc-shadow"])}
                    ),
                    encoding="utf-8",
                )

            cargo_artifact = {
                "reason": "compiler-artifact",
                "package_id": "path+file:///workspace/libc#crabc-libc@0.3.0",
                "manifest_path": str((RUNNER.ROOT / "libc/Cargo.toml").resolve()),
                "target": {
                    "kind": ["cdylib", "staticlib"],
                    "crate_types": ["cdylib", "staticlib"],
                    "name": "c",
                    "src_path": str((RUNNER.ROOT / "libc/src/lib.rs").resolve()),
                    "edition": "2021",
                    "doc": True,
                    "doctest": False,
                    "test": False,
                },
                "profile": {
                    "opt_level": "2",
                    "debuginfo": 2,
                    "debug_assertions": True,
                    "overflow_checks": False,
                    "test": False,
                },
                "features": ["default", "native-mimalloc-shadow"],
                "filenames": [str(shared.resolve()), str(static.resolve())],
                "executable": None,
                "fresh": True,
            }
            build_record_path = root / "selected-libc-build.json"
            build_record_path.write_text(
                json.dumps(
                    {
                        "format": 1,
                        "schema": "crabc-selected-libc-cargo-build",
                        "cargo_command": [
                            "cargo",
                            "build",
                            "-p",
                            "crabc-libc",
                            "--features",
                            "native-mimalloc-shadow",
                            "--profile",
                            "dev",
                            "--message-format=json-render-diagnostics",
                        ],
                        "semantic_profile": "dev",
                        "compiler_artifact": cargo_artifact,
                        "artifacts": {
                            "selected_shared_libc": RUNNER.file_record(shared, root=RUNNER.ROOT),
                            "selected_static_libc": RUNNER.file_record(static, root=RUNNER.ROOT),
                        },
                    }
                ),
                encoding="utf-8",
            )
            expected_shared_sha256 = RUNNER.sha256_file(shared)
            expected_static_sha256 = RUNNER.sha256_file(static)

            attestation = RUNNER.selected_libc_build_attestation(
                build_record_path, target, expectation
            )
            shared.write_bytes(b"same name, different selected dev artifact")
            with self.assertRaisesRegex(
                RUNNER.EvidenceError, "artifact bytes drifted after build"
            ):
                RUNNER.selected_libc_build_attestation(
                    build_record_path, target, expectation
                )

        self.assertEqual(attestation["semantic_profile"], "dev")
        self.assertEqual(
            attestation["cargo_features"], ["default", "native-mimalloc-shadow"]
        )
        self.assertEqual(
            attestation["artifacts"]["selected_shared_libc"]["sha256"],
            expected_shared_sha256,
        )
        self.assertEqual(
            attestation["artifacts"]["selected_static_libc"]["sha256"],
            expected_static_sha256,
        )

    def test_current_head_companion_binds_the_clean_source_and_selected_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_record = root / "selected-libc-build.json"
            shared = root / "target/libc.so"
            static = root / "target/libc.a"
            shared.parent.mkdir(parents=True)
            shared.write_bytes(b"selected shared libc")
            static.write_bytes(b"selected static libc")
            build_record.write_text("{\"selected\": \"build\"}\n", encoding="utf-8")
            artifacts = {
                "selected_shared_libc": RUNNER.file_record(shared, root=RUNNER.ROOT),
                "selected_static_libc": RUNNER.file_record(static, root=RUNNER.ROOT),
            }
            source = {
                "kind": "git",
                "revision": "a" * 40,
                "worktree_clean": True,
                "worktree_status": RUNNER.bytes_record(b""),
            }
            companion = RUNNER.current_head_build_record_path(build_record)
            companion.write_text(
                json.dumps(
                    {
                        "format": RUNNER.CURRENT_HEAD_BUILD_RECORD_FORMAT,
                        "schema": RUNNER.CURRENT_HEAD_BUILD_RECORD_SCHEMA,
                        "source_before": source,
                        "source_after": source,
                        "source_unchanged_during_build": True,
                        "selected_libc_build_record": RUNNER.file_record(
                            build_record, root=RUNNER.ROOT
                        ),
                        "artifacts": artifacts,
                    }
                ),
                encoding="utf-8",
            )
            backend = {
                "build_record": RUNNER.file_record(build_record, root=RUNNER.ROOT),
                "artifacts": artifacts,
            }
            with mock.patch.object(RUNNER, "current_head_source_state", return_value=source):
                attestation = RUNNER.attest_current_head_build(
                    companion, build_record, backend
                )

            drifted = dict(source)
            drifted["revision"] = "b" * 40
            with mock.patch.object(RUNNER, "current_head_source_state", return_value=drifted):
                with self.assertRaises(RUNNER.BlockedPrerequisite) as failure:
                    RUNNER.attest_current_head_build(companion, build_record, backend)

        self.assertEqual(attestation["source"], source)
        self.assertEqual(attestation["artifacts"], artifacts)
        self.assertEqual(failure.exception.prerequisite, "current-head-source-drift")

    def test_workspace_source_digest_excludes_only_known_generated_and_vcs_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "libc/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"selected source")
            (root / ".git").write_text("gitdir: unavailable\n", encoding="utf-8")
            generated = root / "target/libc.so"
            generated.parent.mkdir(parents=True)
            generated.write_bytes(b"first generated artifact")
            cache = root / "compat/allocator/.cache/mimalloc.tar.gz"
            cache.parent.mkdir(parents=True)
            cache.write_bytes(b"pinned archive")
            report = root / "compat/reports/allocator/latest.json"
            report.parent.mkdir(parents=True)
            report.write_bytes(b"generated report")
            work_artifact = root / ".work/target/libc.so"
            work_artifact.parent.mkdir(parents=True)
            work_artifact.write_bytes(b"repository-local generated artifact")
            with mock.patch.object(RUNNER, "ROOT", root):
                first = RUNNER.workspace_tree_source_state()
                generated.write_bytes(b"second generated artifact")
                work_artifact.write_bytes(b"changed repository-local generated artifact")
                ignored_changed = RUNNER.workspace_tree_source_state()
                source.write_bytes(b"changed selected source")
                source_changed = RUNNER.workspace_tree_source_state()

        self.assertEqual(first["kind"], "workspace-tree-sha256")
        self.assertEqual(first["file_count"], 1)
        self.assertEqual(first, ignored_changed)
        self.assertNotEqual(first, source_changed)

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
            "selected_libc_build_attestation",
            return_value={
                "build_record": {"bytes": 1, "path": "build-record", "sha256": "0" * 64},
                "semantic_profile": "dev",
                "cargo_features": ["default", "native-mimalloc-shadow"],
                "compiler_artifact": {},
                "artifacts": {},
            },
        ), mock.patch.object(
            RUNNER.shutil, "which", side_effect=lambda tool: tool
        ), mock.patch.object(
            RUNNER, "command_record", side_effect=[symbols, c_route]
        ):
            with self.assertRaisesRegex(RUNNER.EvidenceError, "does not branch to"):
                RUNNER.attest_selected_backend(
                    Path("/target/debug"), Path("/build-record.json"), contract
                )

    def test_fixture_elf_attestation_rejects_the_wrong_exact_interpreter(self) -> None:
        contract, _ = RUNNER.load_contract()
        header = {
            "kind": "process",
            "status": 0,
            "stdout": RUNNER.bytes_record(
                b"  Class: ELF64\n  Data: 2's complement, little endian\n  Machine: AArch64\n"
            ),
            "stderr": RUNNER.bytes_record(b""),
        }
        program_headers = {
            "kind": "process",
            "status": 0,
            "stdout": RUNNER.bytes_record(
                b"      [Requesting program interpreter: /lib/ld-wrong-aarch64.so.1]\n"
            ),
            "stderr": RUNNER.bytes_record(b""),
        }
        with mock.patch.object(RUNNER.shutil, "which", return_value="readelf"), mock.patch.object(
            RUNNER, "command_record", side_effect=[header, program_headers]
        ):
            with self.assertRaises(RUNNER.ArtifactContractError) as failure:
                RUNNER.audit_fixture_elf(Path("/output/stress"), contract)
        self.assertEqual(failure.exception.boundary, "pt-interp")
        self.assertEqual(failure.exception.observed, "/lib/ld-wrong-aarch64.so.1")
        self.assertEqual(failure.exception.expected, "/lib/ld-crabc-aarch64.so.1")

    def test_wrong_fixture_interpreter_is_failed_contract_evidence_not_blocked(self) -> None:
        contract, pin = RUNNER.load_contract()
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
            build_record = root / "selected-libc-build.json"
            build_record.write_text("{}\n", encoding="utf-8")
            args = RUNNER.parse_arguments(
                [
                    "--target-dir",
                    str(root / "target"),
                    "--output-dir",
                    str(root / "output"),
                    "--libc-build-record",
                    str(build_record),
                ]
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
                    "build_record": {
                        "bytes": 1, "path": "build-record", "sha256": "0" * 64
                    },
                    "artifacts": {
                        "selected_shared_libc": {
                            "bytes": 1, "path": "libc.so", "sha256": "0" * 64
                        },
                        "selected_static_libc": {
                            "bytes": 1, "path": "libc.a", "sha256": "0" * 64
                        },
                    },
                    "status": "passed",
                },
            ), mock.patch.object(
                RUNNER, "extract_exact_archive", return_value=source_root
            ), mock.patch.object(
                RUNNER, "sha256_file", return_value=contract["fixture"]["sha256"]
            ), mock.patch.object(
                RUNNER,
                "file_record",
                return_value={"bytes": 1, "path": "recorded", "sha256": "0" * 64},
            ), mock.patch.object(
                RUNNER, "command_record", return_value=build
            ) as commands, mock.patch.object(
                RUNNER,
                "audit_fixture_elf",
                side_effect=RUNNER.ArtifactContractError(
                    "pt-interp",
                    "/lib/ld-wrong-aarch64.so.1",
                    "/lib/ld-crabc-aarch64.so.1",
                ),
            ):
                RUNNER.execute(contract, pin, args, report)
        self.assertEqual(commands.call_count, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["first_fact"]["stage"], "artifact-contract")
        self.assertEqual(report["first_fact"]["boundary"], "pt-interp")
        self.assertIsNone(report["blocked"])
        self.assertEqual(report["capability"]["status"], "failed")
        self.assertFalse(report["capability"]["native_execution_started"])
        self.assertFalse(report["execution"]["attempted"])

    def test_ephemeral_source_paths_normalize_to_stable_report_records(self) -> None:
        _, pin = RUNNER.load_contract()
        first_root = Path("/output/pinned-source-first/mimalloc-3.5.0")
        second_root = Path("/output/pinned-source-second/mimalloc-3.5.0")
        member = "test/test-stress.c"
        first = {
            "command": [
                "/sysroot/bin/crabc-cc",
                "-I",
                str(first_root / "include"),
                str(first_root / member),
            ],
            "kind": "process",
            "status": 1,
            "stdout": RUNNER.bytes_record(b""),
            "stderr": RUNNER.bytes_record(
                f"{first_root / member}:1: failure\n".encode()
            ),
        }
        second = {
            "command": [
                "/sysroot/bin/crabc-cc",
                "-I",
                str(second_root / "include"),
                str(second_root / member),
            ],
            "kind": "process",
            "status": 1,
            "stdout": RUNNER.bytes_record(b""),
            "stderr": RUNNER.bytes_record(
                f"{second_root / member}:1: failure\n".encode()
            ),
        }
        normalized_first = RUNNER.normalize_source_paths(first, first_root, pin)
        normalized_second = RUNNER.normalize_source_paths(second, second_root, pin)
        self.assertEqual(normalized_first, normalized_second)
        serialized = json.dumps(normalized_first, sort_keys=True)
        self.assertNotIn("pinned-source-first", serialized)
        self.assertNotIn("pinned-source-second", serialized)
        self.assertIn("<pinned-source>/mimalloc-3.5.0/test/test-stress.c", serialized)
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_source = Path(first) / member
            second_source = Path(second) / member
            first_source.parent.mkdir(parents=True)
            second_source.parent.mkdir(parents=True)
            first_source.write_bytes(b"exact source")
            second_source.write_bytes(b"exact source")
            first_artifact = RUNNER.stable_source_member_record(first_source, pin, member)
            second_artifact = RUNNER.stable_source_member_record(second_source, pin, member)
        self.assertEqual(first_artifact, second_artifact)
        self.assertEqual(first_artifact["path"], "mimalloc-3.5.0/test/test-stress.c")

    def test_canonical_loader_staging_mismatch_remains_a_blocked_prerequisite(self) -> None:
        contract, _ = RUNNER.load_contract()
        requirements = contract["compile_requirements"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = root / "sysroot"
            target = root / "target"
            canonical = root / "canonical/ld-crabc-aarch64.so.1"
            (sysroot / "share/crabc").mkdir(parents=True)
            (sysroot / "share/crabc/manifest.json").write_text("{}\n", encoding="utf-8")
            (sysroot / "share/crabc/purity.json").write_text(
                json.dumps(
                    {
                        "crt_sysroot_pure_rust": True,
                        "full_runtime_pure_rust": False,
                        "full_runtime_purity_status": "blocked_by_native_allocator",
                    }
                ),
                encoding="utf-8",
            )
            compiler = sysroot / "bin/crabc-cc"
            compiler.parent.mkdir(parents=True)
            compiler.write_text("#!/bin/sh\n", encoding="utf-8")
            compiler.chmod(0o755)
            target.mkdir()
            (target / "libc.so").write_bytes(b"selected libc")
            (target / "libldso.so").write_bytes(b"selected loader")
            canonical.parent.mkdir(parents=True)
            canonical.write_bytes(b"different loader")
            with mock.patch.dict(
                RUNNER.os.environ, {"CRABC_TEST_SYSROOT": str(sysroot)}, clear=False
            ), mock.patch.object(RUNNER, "CANONICAL_LOADER", canonical):
                with self.assertRaises(RUNNER.BlockedPrerequisite) as failure:
                    RUNNER.require_runtime_inputs(target, requirements)
        self.assertEqual(failure.exception.prerequisite, "owned-canonical-loader-staging")
        self.assertEqual(
            failure.exception.details["selected_loader"], str((target / "libldso.so").resolve())
        )

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
            build_record = root / "selected-libc-build.json"
            build_record.write_text("{}\n", encoding="utf-8")
            args = RUNNER.parse_arguments(
                [
                    "--target-dir",
                    str(root / "target"),
                    "--output-dir",
                    str(root / "output"),
                    "--libc-build-record",
                    str(build_record),
                ]
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
                    "build_record": {
                        "bytes": 1, "path": "build-record", "sha256": "0" * 64
                    },
                    "artifacts": {
                        "selected_shared_libc": {
                            "bytes": 1, "path": "libc.so", "sha256": "0" * 64
                        },
                        "selected_static_libc": {
                            "bytes": 1, "path": "libc.a", "sha256": "0" * 64
                        },
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
                RUNNER,
                "audit_fixture_elf",
                return_value={
                    "dynamic_dependencies": ["libc.so"],
                    "elf_identity": {
                        "class": "ELF64",
                        "endianness": "little",
                        "machine": "AArch64",
                    },
                    "interpreter": "/lib/ld-crabc-aarch64.so.1",
                },
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
            report["runtime"]["environment"],
            RUNNER.runtime_environment_record(root / "target"),
        )
        self.assertEqual(
            commands.call_args_list[2].args[0],
            RUNNER.run_command(root.resolve() / "output/canonical-upstream-test-stress", cases[1]),
        )
        self.assertEqual(
            commands.call_args_list[2].kwargs["environment"],
            RUNNER.runtime_environment(root / "target"),
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
            build_record = root / "selected-libc-build.json"
            build_record.write_text("{}\n", encoding="utf-8")
            args = RUNNER.parse_arguments(
                [
                    "--target-dir",
                    str(root / "target"),
                    "--output-dir",
                    str(root / "output"),
                    "--libc-build-record",
                    str(build_record),
                ]
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
                    "build_record": {
                        "bytes": 1, "path": "build-record", "sha256": "0" * 64
                    },
                    "artifacts": {
                        "selected_shared_libc": {
                            "bytes": 1, "path": "libc.so", "sha256": "0" * 64
                        },
                        "selected_static_libc": {
                            "bytes": 1, "path": "libc.a", "sha256": "0" * 64
                        },
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
                RUNNER,
                "audit_fixture_elf",
                return_value={
                    "dynamic_dependencies": ["libc.so"],
                    "elf_identity": {
                        "class": "ELF64",
                        "endianness": "little",
                        "machine": "AArch64",
                    },
                    "interpreter": "/lib/ld-crabc-aarch64.so.1",
                },
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
            "--capture-selected-libc-build \"$selected_libc_build_record\""
        )
        stress_run = dispatch.rindex("python3 compat/allocator/upstream-stress/run.py")
        self.assertLess(sysroot_build, shadow_build)
        self.assertLess(shadow_build, stress_run)
        self.assertIn("--message-format=json-render-diagnostics", RUNNER.expected_contract(RUNNER.FIXED_PIN)["backend_inventory"]["backends"][0]["artifact_attestation"]["cargo_compiler_artifact"]["cargo_command"])
        self.assertIn("python3 scripts/run_owned_test_suite.py", dispatch)
        self.assertIn('--libc-build-record "$selected_libc_build_record" "$@"', dispatch)

    def test_report_starts_with_closed_artifact_slots_and_no_capability_claim(self) -> None:
        contract, pin = RUNNER.load_contract()
        args = RUNNER.parse_arguments([])
        report = RUNNER.report_base(contract, pin, args)
        self.assertEqual(report["format"], 4)
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
                "staged_canonical_loader",
                "selected_libc",
                "selected_static_libc",
                "selected_backend_build_record",
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
