#!/usr/bin/env python3
"""Focused contract tests for the canonical unmodified upstream stress lane."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "upstream-stress/run.py"
SPEC = importlib.util.spec_from_file_location("crabc_canonical_upstream_stress", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class CanonicalUpstreamStressContractTests(unittest.TestCase):
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

    def test_smallest_schedule_preserves_worker_exit_then_initial_thread_cleanup(self) -> None:
        contract, _ = RUNNER.load_contract()
        execution = contract["execution"]
        assertions = execution["scheduler_and_ownership"]
        self.assertEqual(execution["arguments"], ["1", "1", "1"])
        self.assertEqual(execution["process_attempt_count"], 1)
        self.assertIn("main_participates value remains false.", assertions[0])
        self.assertIn("creates and joins", assertions[1])
        self.assertIn("initial thread performs free_items cleanup", assertions[3])

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
        report["execution"]["attempts"] = [observation]
        report["first_fact"] = {
            "kind": "first-failure",
            "stage": "run",
            "process_attempt": 1,
            "observation": observation,
        }
        self.assertEqual(report["execution"]["process_attempt_count"], 1)
        self.assertEqual(report["first_fact"]["observation"]["status"], -6)
        self.assertFalse(RUNNER.successful_run(observation, contract["execution"]))

    def test_execute_records_one_first_runtime_failure_without_retrying(self) -> None:
        contract, pin = RUNNER.load_contract()
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
                b"Using 1 threads with a 1% load-per-thread and 1 iterations\n"
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
                return_value=(root / "sysroot", root / "sysroot/bin/crabc-cc", root / "target"),
            ), mock.patch.object(RUNNER, "extract_exact_archive", return_value=source_root), mock.patch.object(
                RUNNER, "sha256_file", return_value=contract["fixture"]["sha256"]
            ), mock.patch.object(
                RUNNER,
                "file_record",
                return_value={"bytes": 1, "path": "recorded", "sha256": "0" * 64},
            ), mock.patch.object(
                RUNNER, "command_record", side_effect=[build, failed_run]
            ) as commands, mock.patch.object(
                RUNNER, "dynamic_dependencies", return_value=["libc.so"]
            ):
                RUNNER.execute(contract, pin, args, report)
        self.assertEqual(commands.call_count, 2)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["first_fact"]["kind"], "first-failure")
        self.assertEqual(report["first_fact"]["stage"], "run")
        self.assertEqual(report["first_fact"]["process_attempt"], 1)
        self.assertEqual(report["execution"]["attempts"], [failed_run])

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
