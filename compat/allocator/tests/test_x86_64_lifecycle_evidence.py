#!/usr/bin/env python3
"""Focused contract tests for the bounded x86-64 lifecycle evidence runner."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "compat/allocator/x86_64_lifecycle_evidence.py"
SPEC = importlib.util.spec_from_file_location("crabc_x86_64_lifecycle_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class NativeBoundaryTests(unittest.TestCase):
    def test_native_gate_rejects_missing_emulated_and_foreign_evidence(self) -> None:
        with mock.patch.object(EVIDENCE.platform, "system", return_value="Linux"), mock.patch.object(
            EVIDENCE.platform, "machine", return_value="x86_64"
        ):
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "canonical native provenance"):
                    EVIDENCE.require_native_x86_64()
            with mock.patch.dict(
                os.environ,
                {"CRABC_EXECUTION_MODE": "emulated", "CRABC_HOST_ARCH": "x86_64"},
                clear=True,
            ):
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "canonical native provenance"):
                    EVIDENCE.require_native_x86_64()

        with mock.patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "x86_64"},
            clear=True,
        ), mock.patch.object(EVIDENCE.platform, "system", return_value="Linux"), mock.patch.object(
            EVIDENCE.platform, "machine", return_value="aarch64"
        ):
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "native Linux/x86-64"):
                EVIDENCE.require_native_x86_64()

    def test_native_gate_records_the_canonical_amd64_alias(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "amd64"},
            clear=True,
        ), mock.patch.object(EVIDENCE.platform, "system", return_value="Linux"), mock.patch.object(
            EVIDENCE.platform, "machine", return_value="x86_64"
        ):
            self.assertEqual(
                EVIDENCE.require_native_x86_64(),
                {"execution_mode": "native", "host_architecture": "amd64"},
            )


class CargoCommandTests(unittest.TestCase):
    def test_each_selection_is_locked_target_specific_and_isolated(self) -> None:
        target_dir = Path("/tmp/private-lifecycle-target")
        for lane in EVIDENCE.TEST_LANES:
            with self.subTest(lane=lane.identifier):
                command = EVIDENCE.cargo_test_command("cargo", lane, target_dir)
                self.assertEqual(command[:3], ["cargo", "test", "--locked"])
                self.assertEqual(
                    command[command.index("--target") + 1], EVIDENCE.TARGET
                )
                self.assertEqual(
                    command[command.index("--target-dir") + 1], str(target_dir)
                )
                self.assertIn("-p", command)
                self.assertEqual(command[command.index("-p") + 1], "crabc-mimalloc")
                if lane.kind == "native-integration":
                    self.assertEqual(
                        command[command.index("--test") + 1],
                        "native_runtime_first_arena_policy",
                    )
                else:
                    self.assertIn("--lib", command)
                delimiter = command.index("--")
                self.assertEqual(command[delimiter + 1], "--test-threads=1")
                self.assertEqual(
                    "--nocapture" in command,
                    lane.identifier
                    in {
                        "runtime-process-policy-first-arena",
                        "runtime-source-environment-thp-ready-configuration-admission",
                    },
                )
                self.assertEqual(command[-1] == "--exact", lane.exact_filter)

    def test_finite_loom_is_explicit_and_the_other_lanes_are_exact(self) -> None:
        loom = next(lane for lane in EVIDENCE.TEST_LANES if lane.kind == "finite-loom")
        self.assertEqual(loom.identifier, "remote-free-finite-loom-page-protocol")
        self.assertEqual(loom.features, ("loom",))
        self.assertFalse(loom.exact_filter)
        self.assertEqual(loom.expected_pass_count, len(loom.source_tests))
        self.assertTrue(
            all(lane.exact_filter for lane in EVIDENCE.TEST_LANES if lane is not loom)
        )

    def test_fixed_selection_expects_every_named_source_test(self) -> None:
        for lane in EVIDENCE.TEST_LANES:
            with self.subTest(lane=lane.identifier):
                self.assertEqual(lane.expected_pass_count, len(lane.source_tests))
        self.assertEqual(
            [lane.identifier for lane in EVIDENCE.TEST_LANES],
            [
                "runtime-process-policy-first-arena",
                "runtime-source-environment-thp-ready-configuration-admission",
                "compiler-tls-fresh-native-thread",
                "compiler-tls-explicit-reset",
                "compiler-tls-overlapping-native-threads",
                "main-heap-thread-overlapping-later-theaps",
                "owned-tls-key-registry-concurrent-claim-release",
                "dynamic-arena-singleton-detached-post-exit-owner",
                "remote-free-joined-multi-producer",
                "remote-free-owner-collection-race",
                "remote-free-finite-loom-page-protocol",
            ],
        )


class ReportTests(unittest.TestCase):
    def complete_lanes(self) -> list[dict[str, object]]:
        target_dir = Path("/tmp/private-lifecycle-target")
        lanes: list[dict[str, object]] = []
        for lane in EVIDENCE.TEST_LANES:
            command = EVIDENCE.cargo_test_command("cargo", lane, target_dir)
            lanes.append(
                {
                    "id": lane.identifier,
                    "kind": lane.kind,
                    "cargo_command": EVIDENCE.normalized_command(command, target_dir),
                    "expected_pass_count": lane.expected_pass_count,
                    "observed": {
                        "passed": lane.expected_pass_count,
                        "failed": 0,
                        "ignored": 0,
                        "measured": 0,
                        "filtered_out": 0,
                    },
                    "source_tests": list(lane.source_tests),
                    "bounded_behavior": list(lane.bounded_behavior),
                }
            )
            if lane.identifier == "runtime-process-policy-first-arena":
                lanes[-1]["initial_tld_numa_trace"] = {
                    "vm_policy_arena_is_numa_local": 1,
                    "vm_policy_use_numa_nodes": 3,
                    "vm_policy_numa_node_count_cache": 3,
                    "ticket_zero_tld_numa_node": 0,
                    "process_arena_numa_node": 0,
                }
            if lane.identifier == "runtime-source-environment-thp-ready-configuration-admission":
                lanes[-1]["runtime_thp_configuration_trace"] = {
                    "disabled": {
                        "selected_allow_thp_raw": 0,
                        "vm_policy_allow_thp": 0,
                        "ready_memory_config_has_transparent_huge_pages": 0,
                    },
                    "mode-two": {
                        "selected_allow_thp_raw": 2,
                        "vm_policy_allow_thp": 1,
                        "ready_memory_config_has_transparent_huge_pages": 1,
                    },
                }
        return lanes

    def complete_report(self) -> dict[str, object]:
        return EVIDENCE.report_from_results(
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            toolchain={
                "cargo": "cargo 1.0.0",
                "rustc_host": EVIDENCE.TARGET,
                "rustc_release": "nightly-test",
            },
            lockfile_sha256="1" * 64,
            lanes=self.complete_lanes(),
        )

    def test_report_is_private_and_records_exact_bounded_counts(self) -> None:
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["scope"]["public_runtime_support"])
        expected = sum(lane.expected_pass_count for lane in EVIDENCE.TEST_LANES)
        self.assertEqual(report["summary"], {
            "expected_pass_count": expected,
            "observed_pass_count": expected,
            "lane_count": len(EVIDENCE.TEST_LANES),
        })
        self.assertTrue(report["cargo"]["locked"])
        self.assertEqual(
            report["cargo"]["target_dir"],
            {
                "isolated": True,
                "retained": False,
                "value": "<isolated-temporary-target-dir>",
            },
        )
        exclusions = " ".join(report["exclusions"])
        self.assertIn("No public mi_*", exclusions)
        self.assertIn("No C-oracle differential", exclusions)

    def test_report_rejects_a_broadened_public_boundary(self) -> None:
        malformed = self.complete_report()
        malformed["scope"]["public_runtime_support"] = True
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "non-public runtime boundary"):
            EVIDENCE.validate_report(malformed)

    def test_report_rejects_an_unlocked_or_wrong_target_command(self) -> None:
        malformed = self.complete_report()
        command = malformed["lanes"][0]["cargo_command"]
        command.remove("--locked")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "Cargo --locked"):
            EVIDENCE.validate_report(malformed)

        malformed = self.complete_report()
        command = malformed["lanes"][0]["cargo_command"]
        command[command.index("--target") + 1] = "aarch64-unknown-linux-musl"
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "not locked to"):
            EVIDENCE.validate_report(malformed)

    def test_report_rejects_a_partial_lifecycle_result(self) -> None:
        malformed = self.complete_report()
        malformed["lanes"][0]["observed"]["passed"] = 0
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "observed count drifted"):
            EVIDENCE.validate_report(malformed)

    def test_atomic_writer_leaves_valid_json(self) -> None:
        report = self.complete_report()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested" / "result.json"
            EVIDENCE.atomic_write_json(output, report)
            serialized = output.read_text(encoding="utf-8")
            self.assertTrue(serialized.endswith("\n"))
            self.assertIn('"status": "passed"', serialized)
            self.assertEqual(json.loads(serialized), report)
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)


class CandidateSourceReceiptTests(unittest.TestCase):
    @staticmethod
    def bytes_record(payload: bytes) -> dict[str, object]:
        return {
            "bytes": len(payload),
            "hex": payload.hex(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def clean_snapshot(self) -> dict[str, object]:
        return {
            "format": 1,
            "git": {
                "revision": "a" * 40,
                "tree": "b" * 40,
                "worktree_clean": True,
                "worktree_status": self.bytes_record(b""),
            },
            "rust_allocator_tree": {
                "object_id": "c" * 40,
                "path": "crabc-mimalloc",
            },
            "inputs": [
                {
                    "bytes": 1,
                    "git_blob": "d" * 40,
                    "path": path,
                    "sha256": "e" * 64,
                }
                for path in EVIDENCE.CANDIDATE_SOURCE_INPUTS
            ],
        }

    def complete_runtime_first_arena_report(self) -> dict[str, object]:
        """Build the smallest structurally complete receipt for reader mutations."""

        c_trace = {
            "source_option_applied": 1,
            "arena_is_numa_local_option_applied": 1,
            "configured_numa_node_count": 3,
            "resolved_numa_node_count": 3,
            "ticket_zero_tld": 1,
            "default_theap_uses_ticket_zero_tld": 1,
            "ticket_zero_tld_numa_node": 0,
            "ticket_zero_tld_numa_in_range": 1,
            "regular_first_arena_is_os": 1,
            "regular_first_arena_numa_node": 1,
            "regular_first_arena_numa_in_range": 1,
            "regular_first_arena_retained_after_free": 1,
        }
        lane = {
            "id": "runtime-process-policy-first-arena",
            "observed": {"passed": 1},
            "initial_tld_numa_trace": {
                "vm_policy_arena_is_numa_local": 1,
                "vm_policy_use_numa_nodes": 3,
                "vm_policy_numa_node_count_cache": 3,
                "ticket_zero_tld_numa_node": 0,
                "process_arena_numa_node": 1,
            },
        }
        c_oracle = {
            "trace": c_trace,
            "upstream": {
                "archive_sha256": "f" * 64,
                "revision": "a" * 40,
            },
            "fixture": {"path": EVIDENCE.relative(EVIDENCE.INITIAL_TLD_NUMA_FIXTURE)},
            "source_files": [
                {"path": path}
                for path in sorted(set(EVIDENCE.INITIAL_TLD_NUMA_C_ORACLE_SOURCE_FILES))
            ],
        }
        thp_lane = {
            "id": "runtime-source-environment-thp-ready-configuration-admission",
            "observed": {"passed": 1},
            "runtime_thp_configuration_trace": {
                "disabled": {
                    "selected_allow_thp_raw": 0,
                    "vm_policy_allow_thp": 0,
                    "ready_memory_config_has_transparent_huge_pages": 0,
                },
                "mode-two": {
                    "selected_allow_thp_raw": 2,
                    "vm_policy_allow_thp": 1,
                    "ready_memory_config_has_transparent_huge_pages": 1,
                },
            },
        }
        thp_c_oracle = {
            "fixture": {
                "bytes": 1,
                "path": EVIDENCE.relative(EVIDENCE.RUNTIME_THP_CONFIGURATION_FIXTURE),
                "sha256": "e" * 64,
            },
            "images": [
                {
                    "binary": {},
                    "build": {},
                    "id": image_id,
                    "run": {},
                    "trace": {
                        "selected_allow_thp_raw": 0 if image_id == "disabled" else 2,
                        "config_has_transparent_huge_pages": 0 if image_id == "disabled" else 1,
                    },
                    "trace_sha256": "e" * 64,
                }
                for image_id in EVIDENCE.RUNTIME_THP_CONFIGURATION_IMAGE_IDS
            ],
            "source_files": [
                {"path": path}
                for path in sorted(set(EVIDENCE.RUNTIME_THP_CONFIGURATION_C_ORACLE_SOURCE_FILES))
            ],
            "upstream": {
                "archive_sha256": "f" * 64,
                "revision": "a" * 40,
            },
        }
        candidate_source = EVIDENCE.candidate_source_attestation(
            self.clean_snapshot(), self.clean_snapshot()
        )
        return {
            "format": 4,
            "kind": "mimalloc-x86_64-runtime-first-arena-policy-evidence",
            "profile": "linux-x86_64-private-engine-runtime-first-arena-policy-witness",
            "status": "passed",
            "target": {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": EVIDENCE.TARGET,
                "system": "linux",
            },
            "native_execution_provenance": {
                "execution_mode": "native",
                "host_architecture": "x86_64",
            },
            "toolchain": {},
            "cargo": {
                "locked": True,
                "target_dir": {
                    "isolated": True,
                    "retained": False,
                    "value": "<isolated-temporary-target-dir>",
                },
            },
            "candidate_source": candidate_source,
            "c_oracle": c_oracle,
            "comparison": EVIDENCE.compare_initial_tld_numa_observations(c_oracle, lane),
            "lane": lane,
            "runtime_thp_configuration": {
                "c_oracle": thp_c_oracle,
                "comparison": EVIDENCE.compare_runtime_thp_configuration_observations(
                    thp_c_oracle, thp_lane
                ),
                "lane": thp_lane,
            },
            "scope": {
                "boundary": "one child-isolated pinned-C and one process-isolated private Rust TLD/regular-first-arena policy witness, plus two fixed child source-environment THP configuration images only",
                "public_runtime_support": False,
                "claim": "focused initial-TLD/regular-first-arena NUMA and retained runtime source-THP configuration witnesses",
            },
            "exclusions": list(EVIDENCE.RUNTIME_FIRST_ARENA_EXCLUSIONS),
        }

    def test_candidate_receipt_requires_identical_clean_before_and_after_sources(self) -> None:
        before = self.clean_snapshot()
        self.assertEqual(
            EVIDENCE.candidate_source_attestation(before, before),
            {
                "after": before,
                "before": before,
                "git_read_environment": {"GIT_OPTIONAL_LOCKS": "0"},
                "unchanged_during_execution": True,
            },
        )

        after = copy.deepcopy(before)
        after["inputs"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "source changed during execution"):
            EVIDENCE.candidate_source_attestation(before, after)

    def test_candidate_receipt_rejects_a_dirty_source_snapshot(self) -> None:
        dirty = self.clean_snapshot()
        dirty["git"]["worktree_clean"] = False
        dirty["git"]["worktree_status"] = self.bytes_record(b" M crabc-mimalloc/src/os.rs\0")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "clean Git source"):
            EVIDENCE.candidate_source_attestation(dirty, dirty)

    @mock.patch.object(
        EVIDENCE,
        "pinned_mimalloc_pin",
        return_value={"sha256": "f" * 64, "revision": "a" * 40},
    )
    def test_report_reader_rejects_noncanonical_candidate_source_scalars(
        self, _pinned_mimalloc_pin: mock.Mock
    ) -> None:
        report = self.complete_runtime_first_arena_report()
        EVIDENCE.validate_runtime_first_arena_policy_report(report)

        for malformed_format in (True, 1.0):
            with self.subTest(candidate_format=malformed_format):
                malformed = copy.deepcopy(report)
                malformed["candidate_source"]["before"]["format"] = malformed_format
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "snapshot format"):
                    EVIDENCE.validate_runtime_first_arena_policy_report(malformed)

        with self.subTest(unchanged_during_execution=1):
            malformed = copy.deepcopy(report)
            malformed["candidate_source"]["unchanged_during_execution"] = 1
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "unchanged"):
                EVIDENCE.validate_runtime_first_arena_policy_report(malformed)

        with self.subTest(report_format=4.0):
            malformed = copy.deepcopy(report)
            malformed["format"] = 4.0
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "format-4"):
                EVIDENCE.validate_runtime_first_arena_policy_report(malformed)

        with self.subTest(runtime_regular_arena_node=True):
            malformed = copy.deepcopy(report)
            malformed["lane"]["initial_tld_numa_trace"]["process_arena_numa_node"] = True
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "Rust NUMA trace relation"):
                EVIDENCE.validate_runtime_first_arena_policy_report(malformed)

        with self.subTest(c_regular_arena_relation=True):
            malformed = copy.deepcopy(report)
            malformed["c_oracle"]["trace"]["regular_first_arena_retained_after_free"] = True
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "exact integer"):
                EVIDENCE.validate_runtime_first_arena_policy_report(malformed)


class ResultParserTests(unittest.TestCase):
    def test_parser_requires_one_clean_exact_summary(self) -> None:
        lane = EVIDENCE.TEST_LANES[0]
        output = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.01s\n"
        self.assertEqual(
            EVIDENCE.parse_test_result(output, lane),
            {
                "passed": 1,
                "failed": 0,
                "ignored": 0,
                "measured": 0,
                "filtered_out": 42,
            },
        )

    def test_parser_rejects_a_count_drift_or_multiple_test_binaries(self) -> None:
        lane = EVIDENCE.TEST_LANES[0]
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "passed 2 tests"):
            EVIDENCE.parse_test_result(
                "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                lane,
            )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "2 lib-test summaries"):
            EVIDENCE.parse_test_result(
                "\n".join(
                    [
                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                    ]
                ),
                lane,
            )

    def test_initial_tld_numa_c_and_runtime_traces_bind_the_option_policy(self) -> None:
        c_trace = {
            "source_option_applied": 1,
            "arena_is_numa_local_option_applied": 1,
            "configured_numa_node_count": 3,
            "resolved_numa_node_count": 3,
            "ticket_zero_tld": 1,
            "default_theap_uses_ticket_zero_tld": 1,
            "ticket_zero_tld_numa_node": 2,
            "ticket_zero_tld_numa_in_range": 1,
            "regular_first_arena_is_os": 1,
            "regular_first_arena_numa_node": 1,
            "regular_first_arena_numa_in_range": 1,
            "regular_first_arena_retained_after_free": 1,
        }
        c_output = "\n".join(
            [
                EVIDENCE.INITIAL_TLD_NUMA_TRACE_BEGIN,
                *(f"{key}={value}" for key, value in c_trace.items()),
                EVIDENCE.INITIAL_TLD_NUMA_TRACE_END,
            ]
        )
        self.assertEqual(
            EVIDENCE.parse_scalar_trace(
                c_output,
                begin=EVIDENCE.INITIAL_TLD_NUMA_TRACE_BEGIN,
                end=EVIDENCE.INITIAL_TLD_NUMA_TRACE_END,
                keys=EVIDENCE.INITIAL_TLD_NUMA_C_TRACE_KEYS,
                source="test C oracle",
            ),
            c_trace,
        )
        EVIDENCE.validate_initial_tld_numa_c_trace(c_trace)

        runtime_output = "\n".join(
            [
                EVIDENCE.RUNTIME_INITIAL_TLD_NUMA_TRACE_BEGIN,
                "vm_policy_arena_is_numa_local=1",
                "vm_policy_use_numa_nodes=3",
                "vm_policy_numa_node_count_cache=3",
                "ticket_zero_tld_numa_node=1",
                "process_arena_numa_node=2",
                EVIDENCE.RUNTIME_INITIAL_TLD_NUMA_TRACE_END,
            ]
        )
        runtime_trace = EVIDENCE.parse_runtime_initial_tld_numa_trace(runtime_output)
        self.assertEqual(runtime_trace["vm_policy_numa_node_count_cache"], 3)
        self.assertEqual(runtime_trace["ticket_zero_tld_numa_node"], 1)

    def test_initial_tld_numa_trace_rejects_a_fixed_cache_or_out_of_range_node(self) -> None:
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "policy count"):
            EVIDENCE.parse_runtime_initial_tld_numa_trace(
                "\n".join(
                    [
                        EVIDENCE.RUNTIME_INITIAL_TLD_NUMA_TRACE_BEGIN,
                        "vm_policy_arena_is_numa_local=1",
                        "vm_policy_use_numa_nodes=3",
                        "vm_policy_numa_node_count_cache=0",
                        "ticket_zero_tld_numa_node=0",
                        "process_arena_numa_node=0",
                        EVIDENCE.RUNTIME_INITIAL_TLD_NUMA_TRACE_END,
                    ]
                )
            )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "normalized"):
            EVIDENCE.validate_initial_tld_numa_c_trace(
                {
                    "source_option_applied": 1,
                    "arena_is_numa_local_option_applied": 1,
                    "configured_numa_node_count": 3,
                    "resolved_numa_node_count": 3,
                    "ticket_zero_tld": 1,
                    "default_theap_uses_ticket_zero_tld": 1,
                    "ticket_zero_tld_numa_node": 3,
                    "ticket_zero_tld_numa_in_range": 1,
                    "regular_first_arena_is_os": 1,
                    "regular_first_arena_numa_node": 0,
                    "regular_first_arena_numa_in_range": 1,
                    "regular_first_arena_retained_after_free": 1,
                }
            )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "first regular arena"):
            EVIDENCE.parse_runtime_initial_tld_numa_trace(
                "\n".join(
                    [
                        EVIDENCE.RUNTIME_INITIAL_TLD_NUMA_TRACE_BEGIN,
                        "vm_policy_arena_is_numa_local=1",
                        "vm_policy_use_numa_nodes=3",
                        "vm_policy_numa_node_count_cache=3",
                        "ticket_zero_tld_numa_node=0",
                        "process_arena_numa_node=3",
                        EVIDENCE.RUNTIME_INITIAL_TLD_NUMA_TRACE_END,
                    ]
                )
            )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "regular_first_arena_retained_after_free"):
            EVIDENCE.validate_initial_tld_numa_c_trace(
                {
                    "source_option_applied": 1,
                    "arena_is_numa_local_option_applied": 1,
                    "configured_numa_node_count": 3,
                    "resolved_numa_node_count": 3,
                    "ticket_zero_tld": 1,
                    "default_theap_uses_ticket_zero_tld": 1,
                    "ticket_zero_tld_numa_node": 0,
                    "ticket_zero_tld_numa_in_range": 1,
                    "regular_first_arena_is_os": 1,
                    "regular_first_arena_numa_node": 0,
                    "regular_first_arena_numa_in_range": 1,
                    "regular_first_arena_retained_after_free": 0,
                }
            )


if __name__ == "__main__":
    unittest.main()
