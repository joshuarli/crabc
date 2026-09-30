"""Fail-closed assembly regressions for native x86 M2 VM evidence."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import tempfile
import json
import sys
import unittest
from unittest import mock

from test_runner import RUNNER


EXPECTED_VM_CHECK_IDS = (
    "native-vm-fixed-lifecycle-differential",
    "source-policy-lazy-environment-retry",
    "normal-release-aligned-hint-cursor-random-and-cas-matrix",
    "normal-release-large-page-retry-suppression-and-ordinary-fallback",
    "large-only-one-gib-failure-no-regular-owner",
    "thp-direct-policy-outcome-matrix",
    "process-main-thp-policy-owner-traversal",
    "runtime-source-environment-thp-ready-configuration-admission",
    "process-thp-madvise-success-c-rust-differential",
    "process-thp-madvise-failure-c-rust-differential",
    "process-thp-disabled-policy-c-rust-differential",
    "process-thp-inherited-disable-advice-c-rust-differential",
    "aligned-hint-source-profile-and-direct-caller-matrix",
    "aligned-overmap-cleanup-c-rust-boundary-matrix",
    "legacy-os-page-suffix-trim-and-raw-release",
    "process-os-page-suffix-trim-and-terminal-release",
    "process-os-page-block-commit-rollback-c-rust-differential",
    "os-page-terminal-unmap-fault-c-rust-differential",
    "os-page-escaped-map-metadata-fault-c-rust-differential",
    "process-policy-first-arena-clean-primary-fallback",
    "process-policy-first-arena-trim-leak",
    "explicit-arena-prefix-trim-c-rust-differential",
    "explicit-arena-suffix-trim-c-rust-differential",
    "explicit-arena-metadata-fault-c-rust-differential",
    "registered-arena-metadata-fault-c-rust-differential",
    "fresh-arena-dual-fault-c-rust-differential",
    "registered-arena-page-map-fault-c-rust-differential",
    "registered-arena-page-map-double-fault-c-rust-differential",
    "registered-arena-terminal-unmap-fault-c-rust-differential",
    "selected-subprocess-statistics-aggregation",
    "process-policy-ticket-zero-live-random",
    "aligned-map-trim-failure-leak",
    "aligned-map-complete-trim-sequence",
    "reset-advice-retry-snapshot",
    "second-arena-reset-advice-c-rust-matrix",
    "aligned-map-os-page-claim-trim-leak",
    "aligned-map-process-os-page-trim-leak",
    "aligned-map-metadata-trim-leak",
    "aligned-map-process-arena-trim-leak",
    "normal-os-offset-full-provenance-and-release-retry",
    "process-offset-prefix-decommit-advisory-owner",
    "normal-no-callback-purge-policy-range-matrix",
    "external-os-purge-commit-c-rust-differential",
    "external-os-commit-failure-c-rust-differential",
    "external-os-reset-policy-c-rust-differential",
    "external-os-reset-fallback-c-rust-differential",
    "external-os-no-advice-policy-c-rust-differential",
    "external-os-reset-retry-c-rust-differential",
    "normal-os-good-size-and-base-provenance",
    "normal-os-offset-zero-delegation-and-geometry",
    "normal-os-aligned-trim-leak",
    "normal-os-source-reservation-caller",
    "linux-os-reuse-contained-range-noop",
    "fixed-no-option-numa-cache-and-current-node-normalization",
    "native-protection-owner-and-retry",
    "process-owned-protect-fault-c-rust-differential",
    "process-owned-unprotect-fault-c-rust-differential",
    "normal-page-extension-direct-commit-failure-and-retry",
)

class NativeVmAssemblyTests(unittest.TestCase):
    def test_delayed_purge_failure_is_a_partial_arena_receiver(self):
        arenas = next(component for component in self.summary()["components"]
                      if component["id"] == "arenas")
        self.assertEqual(arenas["native_status"], "partial")
        self.assertIn({
            "expected_passed_test_count": 1,
            "id": "arena-delayed-purge-decommit-failure-c-rust-differential",
            "kind": "c-rust-arena-delayed-purge-failure-differential",
            "target": "compat/allocator/m2_delayed_purge_failure_x86_64.py",
        }, arenas["checks"])

    def direct_arena_receipts(self, pin, artifact):
        evidence = {}
        for check_id, receiver in RUNNER.M2_X86_64_ARENA_DIRECT_RECEIVERS.items():
            transcript = "".join(
                f"{receiver['trace_prefix']}{field}={value}\n"
                for field, value in receiver["trace"].items()
            )
            evidence[check_id] = {
                "status": "passed", "pinned_revision": pin["revision"],
                "fixture": artifact, "c_executable": artifact,
                "rust_test": receiver["rust_test"], "trace": dict(receiver["trace"]),
                "command": ["python3", receiver["target"], "--offline"],
                "c_stdout": transcript, "c_stderr": "",
                "rust_stdout": "test receiver ... " + transcript, "rust_stderr": "",
            }
        return evidence

    def test_direct_arena_receipt_requires_both_physical_traces_and_source_identity(self):
        summary = self.summary()
        pin = {"revision": "pinned-revision"}
        artifact = {"path": "source-bound", "bytes": 1, "sha256": "a" * 64}
        evidence = self.direct_arena_receipts(pin, artifact)
        with mock.patch.object(RUNNER, "artifact_record", return_value=artifact):
            records = RUNNER._m2_x86_64_arena_direct_check_records(summary, pin, evidence)
            self.assertEqual([record["id"] for record in records], list(evidence))
            for check_id, receiver in RUNNER.M2_X86_64_ARENA_DIRECT_RECEIVERS.items():
                for field in ("status", "pinned_revision", "fixture", "c_executable",
                              "rust_test", "trace", "command", "c_stderr", "rust_stderr"):
                    with self.subTest(check_id=check_id, field=field):
                        changed = copy.deepcopy(evidence)
                        changed[check_id][field] = "stale"
                        with self.assertRaises(RUNNER.HarnessError):
                            RUNNER._m2_x86_64_arena_direct_check_records(summary, pin, changed)
                for side in ("c", "rust"):
                    for field, value in receiver["trace"].items():
                        for mutation in ("missing", "changed", "duplicate"):
                            with self.subTest(check_id=check_id, side=side, field=field, mutation=mutation):
                                changed = copy.deepcopy(evidence)
                                line = f"{receiver['trace_prefix']}{field}={value}\n"
                                replacement = {"missing": "", "changed": f"{receiver['trace_prefix']}{field}={value+1}\n",
                                               "duplicate": line + line}[mutation]
                                changed[check_id][f"{side}_stdout"] = changed[check_id][f"{side}_stdout"].replace(line, replacement)
                                with self.assertRaises(RUNNER.HarnessError):
                                    RUNNER._m2_x86_64_arena_direct_check_records(summary, pin, changed)
                missing = copy.deepcopy(evidence)
                missing.pop(check_id)
                with self.assertRaisesRegex(RUNNER.HarnessError, "inventory"):
                    RUNNER._m2_x86_64_arena_direct_check_records(summary, pin, missing)

    def test_direct_arena_receiver_binds_offline_and_normal_commands(self):
        pin = {"revision": "pinned-revision"}
        artifact = {"path": "source-bound", "bytes": 1, "sha256": "a" * 64}
        expected = self.direct_arena_receipts(pin, artifact)
        RUNNER.WORK_ROOT.mkdir(parents=True, exist_ok=True)
        for offline in (False, True):
            with self.subTest(offline=offline), tempfile.TemporaryDirectory(dir=RUNNER.WORK_ROOT) as temporary:
                root = Path(temporary)
                def execute(command, **kwargs):
                    check_id, receiver = next((key, value) for key, value in RUNNER.M2_X86_64_ARENA_DIRECT_RECEIVERS.items()
                                              if value["target"] == command[1])
                    row = expected[check_id]
                    artifacts = root / "x86_64" / receiver["artifact"]
                    artifacts.mkdir(parents=True)
                    (artifacts / "evidence.json").write_text(json.dumps({key: value for key, value in row.items()
                        if key not in {"command", "c_stdout", "c_stderr", "rust_stdout", "rust_stderr"}}))
                    for side in ("c", "rust"):
                        stem = "pinned-c" if side == "c" else "rust"
                        for stream in ("stdout", "stderr"):
                            (artifacts / f"{stem}.{stream}").write_text(row[f"{side}_{stream}"])
                    return {"command": command, "status": 0, "stdout": "", "stderr": ""}
                with mock.patch.object(RUNNER, "ARTIFACT_ROOT", root), mock.patch.object(
                    RUNNER, "command_record", side_effect=execute
                ) as dispatch, mock.patch.object(RUNNER, "artifact_record", return_value=artifact):
                    evidence = RUNNER._run_m2_x86_64_arena_direct_evidence(offline=offline)
                    records = RUNNER._m2_x86_64_arena_direct_check_records(self.summary(), pin, evidence)
                commands = [["python3", receiver["target"], *(["--offline"] if offline else [])]
                            for receiver in RUNNER.M2_X86_64_ARENA_DIRECT_RECEIVERS.values()]
                self.assertEqual(dispatch.call_args_list, [mock.call(command, cwd=RUNNER.ROOT, timeout_seconds=900)
                                                          for command in commands])
                self.assertEqual([row["command"] for row in evidence.values()], commands)
                self.assertEqual([row["id"] for row in records], list(expected))

    def test_runtime_thp_configuration_producer_registers_its_dataclass_module_before_execution(self):
        """The aggregate loader must make the real lifecycle module importable to dataclasses."""

        producer = RUNNER._m2_x86_64_runtime_thp_configuration_producer()
        self.assertIs(
            sys.modules["crabc_m2_runtime_thp_configuration"],
            producer,
        )

    @staticmethod
    def vm_evidence(summary):
        vm = next(component for component in summary["components"] if component["id"] == "vm-primitives")
        producer = RUNNER._m2_x86_64_vm_producer()
        fragment = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        anchors = []
        seen = set()
        for definition in fragment["component"]["bounded_source_definitions"]:
            anchor = definition["source_anchor"]
            key = (anchor["member"], anchor["start_line"], anchor["end_line"])
            if key not in seen:
                seen.add(key)
                anchors.append({"bytes": 1, **anchor})
        for branch in fragment["component"]["branch_matrix"]:
            for anchor in branch["source_anchors"]:
                key = (anchor["member"], anchor["start_line"], anchor["end_line"])
                if key not in seen:
                    seen.add(key)
                    anchors.append({"bytes": 1, **anchor})
        pin = RUNNER.load_pin()
        rust_binary = (
            RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET
            / RUNNER.X86_64_RUST_TARGET
            / "debug/deps/crabc_mimalloc-0123456789abcdef"
        )
        c_command = [
            "musl-gcc",
            "-std=c11",
            "-fPIC",
            "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB",
            "-DMI_SHARED_LIB_EXPORT",
            "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I",
            "/pinned/include",
            "-I",
            "/pinned/src",
            *RUNNER.CONFIGURATION_PROFILES["release"],
            str(RUNNER.ALLOCATOR_ROOT / "m2_vm_x86_64.c"),
            *(f"/pinned/{path}" for path in RUNNER.M2_X86_64_VM_C_ORACLE_SOURCES),
            "-Wl,--wrap=munmap",
            "-Wl,--wrap=mmap",
            "-Wl,--wrap=madvise",
            "-Wl,--wrap=mprotect",
            "-Wl,--wrap=prctl",
            "-pthread",
            "-o",
            str(
                RUNNER.ARTIFACT_ROOT
                / "x86_64/m2-vm-primitives/m2-vm-primitives-oracle"
            ),
        ]
        profile_c_commands = []
        for profile_id, flags, _ in producer.ALIGNED_HINT_PROFILE_C_CONFIGS:
            profile_c_commands.append(
                {
                    "id": profile_id,
                    "command": [
                        "musl-gcc",
                        "-std=c11",
                        "-fPIC",
                        "-ftls-model=initial-exec",
                        "-DMI_SHARED_LIB",
                        "-DMI_SHARED_LIB_EXPORT",
                        "-DMI_LIBC_MUSL=1",
                        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
                        "-I",
                        "/pinned/include",
                        "-I",
                        "/pinned/src",
                        *flags,
                        str(RUNNER.ALLOCATOR_ROOT / "m2_vm_x86_64.c"),
                        *(f"/pinned/{path}" for path in RUNNER.M2_X86_64_VM_C_ORACLE_SOURCES),
                        "-Wl,--wrap=munmap",
                        "-Wl,--wrap=mmap",
                        "-Wl,--wrap=madvise",
                        "-Wl,--wrap=mprotect",
                        "-Wl,--wrap=prctl",
                        "-pthread",
                        "-o",
                        str(
                            RUNNER.ARTIFACT_ROOT
                            / f"x86_64/m2-vm-primitives/m2-vm-primitives-{profile_id}-oracle"
                        ),
                    ],
                }
            )
        return {
            "aligned_overmap_c_trace_sha256": "f" * 64,
            "aligned_overmap_comparison": dict(producer.ALIGNED_OVERMAP_COMPARISON),
            "aligned_overmap_rust_command": [
                str(rust_binary),
                "os::tests::emit_m2_aligned_overmap_cleanup_c_rust_boundary_trace",
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ],
            "aligned_overmap_rust_passed_test_count": 1,
            "aligned_overmap_rust_trace_sha256": "a" * 64,
            "aligned_hint_profile_c_commands": profile_c_commands,
            "aligned_hint_profile_comparison": {
                "compared_value_count": len(producer.ALIGNED_HINT_PROFILE_TRACE_KEYS),
                "status": "matched",
            },
            "aligned_hint_profile_rust_command": [
                str(rust_binary),
                "os::tests::emit_m2_aligned_hint_source_profile_c_rust_trace",
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ],
            "aligned_hint_profile_rust_passed_test_count": 1,
            "aligned_hint_profile_trace_sha256": "e" * 64,
            "architecture": "x86_64",
            "c_command": c_command,
            "c_source_files": [
                {"path": path, "sha256": "a" * 64, "bytes": 1}
                for path in sorted(producer.SOURCE_UNITS)
            ],
            "compared_value_count": len(producer.TRACE_KEYS),
            "comparison": {"compared_value_count": len(producer.TRACE_KEYS), "status": "matched"},
            "fixture": {"path": "compat/allocator/m2_vm_x86_64.c", "sha256": "b" * 64, "bytes": 1},
            "format": 1,
            "profile": producer.EVIDENCE_PROFILE,
            "legacy_os_page_trim": {
                "command": ["python3", producer.LEGACY_OS_PAGE_TRIM_READER,
                    "--offline", "--rust-test-binary", str(rust_binary)],
                "comparison": {
                    "status": "source-different", "shared_relations": 8,
                    "known_differences": {
                        "reserved_claim": {"c": 196608, "rust": 0},
                        "committed_claim": {"c": 65536, "rust": 0},
                        "mmap_claim": {"c": 2, "rust": 0},
                    },
                },
                "fixture": {"path": "compat/allocator/m2_legacy_os_page_trim_x86_64.c",
                    "bytes": 1, "sha256": "b" * 64},
                "rust_test": "os::tests::emit_legacy_os_page_suffix_trim_trace",
            },
            "process_os_page_trim": {
                "command": ["python3", producer.PROCESS_OS_PAGE_TRIM_READER,
                    "--offline", "--rust-test-binary", str(rust_binary)],
                "comparison": {"status": "matched", "compared_value_count": 17},
                "fixture": {"path": "compat/allocator/m2_legacy_os_page_trim_x86_64.c",
                    "bytes": 1, "sha256": "b" * 64},
                "rust_test": "os::tests::emit_process_os_page_suffix_trim_trace",
            },
            "process_os_page_block_commit": {
                "command": ["python3", producer.PROCESS_OS_PAGE_BLOCK_COMMIT_READER,
                    "--offline", "--rust-test-binary", str(rust_binary)],
                "comparison": {"status": "matched", "compared_value_count": 11},
                "fixture": {"path": "compat/allocator/m2_process_os_page_block_commit_x86_64.c",
                    "bytes": 1, "sha256": "b" * 64},
                "rust_test": "os_page::tests::emit_fresh_os_area_block_commit_cleanup_failure_trace",
            },
            "reset_advice_matrix": {
                "command": [
                    "python3", producer.RESET_ADVICE_MATRIX_READER,
                    "--offline", "--rust-test-binary", str(rust_binary),
                ],
                "comparison": {
                    "compared_value_count": producer.RESET_ADVICE_MATRIX_VALUE_COUNT,
                    "status": "matched",
                },
                "fixture": {
                    "path": "compat/allocator/m2_second_arena_reset_failure_x86_64.c",
                    "bytes": 1, "sha256": "b" * 64,
                },
                "rust_tests": [
                    "process_arena::tests::emit_m2_second_arena_reset_advice_"
                    + profile + "_c_rust_trace"
                    for profile in ("warning_eio", "retry_eagain", "fallback_einval")
                ],
                "rust_commands": [
                    [str(rust_binary),
                     "process_arena::tests::emit_m2_second_arena_reset_advice_"
                     + profile + "_c_rust_trace",
                     "--exact", "--test-threads=1", "--nocapture"]
                    for profile in ("warning_eio", "retry_eagain", "fallback_einval")
                ],
            },
            "rust_build_command": [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--no-default-features",
                "--target",
                RUNNER.X86_64_RUST_TARGET,
                "--locked",
                "--lib",
                "--no-run",
                "--message-format=json",
            ],
            "rust_command": [
                str(rust_binary),
                "os::tests::emit_m2_vm_primitives_c_rust_trace",
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ],
            "rust_execution": RUNNER._m2_x86_64_vm_rust_execution(),
            "rust_test_binary": {
                "bytes": 1,
                "path": RUNNER.relative(rust_binary),
                "sha256": "d" * 64,
            },
            "rust_passed_test_count": 1,
            "schema": "crabc-mimalloc-x86_64-m2-vm-primitives-evidence",
            "source_anchors": anchors,
            "status": "passed",
            "trace_sha256": "c" * 64,
            "upstream": {"revision": pin["revision"], "archive_sha256": pin["sha256"]},
            "nonclaims": list(vm["remaining_conditions"]),
        }

    @staticmethod
    def arena_owned_evidence(summary):
        evidence = NativeVmAssemblyTests.vm_evidence(summary)
        producer = RUNNER._m2_x86_64_vm_producer()
        rust_binary = evidence["rust_command"][0]
        evidence.update(
            {
                "arena_owned_c_command": [
                    "musl-gcc",
                    "-std=c11",
                    "-fPIC",
                    "-ftls-model=initial-exec",
                    "-DMI_SHARED_LIB",
                    "-DMI_SHARED_LIB_EXPORT",
                    "-DMI_LIBC_MUSL=1",
                    "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
                    "-I",
                    "/pinned/include",
                    "-I",
                    "/pinned/src",
                    *RUNNER.CONFIGURATION_PROFILES["release"],
                    str(RUNNER.ALLOCATOR_ROOT / "m2_arena_owned_x86_64.c"),
                    "-pthread",
                    "-o",
                    str(
                        RUNNER.ARTIFACT_ROOT
                        / "x86_64/m2-vm-primitives/m2-arena-owned-oracle"
                    ),
                ],
                "arena_owned_comparison": {
                    "compared_value_count": producer.ARENA_OWNED_EVENT_FIELD_COUNT,
                    "status": "matched",
                },
                "arena_owned_fixture": {
                    "path": "compat/allocator/m2_arena_owned_x86_64.c",
                    "sha256": "9" * 64,
                    "bytes": 1,
                },
                "arena_owned_rust_command": [
                    rust_binary,
                    producer.ARENA_OWNED_TRACE_TARGET,
                    "--exact",
                    "--test-threads=1",
                    "--nocapture",
                ],
                "arena_owned_rust_passed_test_count": 1,
                "arena_owned_trace_sha256": "8" * 64,
            }
        )
        return evidence

    def test_release_fault_trace_schema_requires_the_retained_owner_and_retry(self):
        producer = RUNNER._m2_x86_64_vm_producer()
        self.assertIn(
            "m2.vm.release.failure.full_memid_base_and_size",
            producer.TRACE_KEYS,
        )
        self.assertIn(
            "m2.vm.release.retry.full_memid_base_and_size",
            producer.TRACE_KEYS,
        )
        values = {key: 1 for key in producer.TRACE_KEYS}
        values.update(
            {
                "m2.vm.config.page_size": 4096,
                "m2.vm.config.large_page_size": 2 * 1024 * 1024,
                "m2.vm.config.alloc_granularity": 4096,
                "m2.vm.config.has_transparent_huge_pages": 0,
                "m2.vm.reserved.initially_committed": 0,
                "m2.vm.normal.good_size": 4096,
                "m2.vm.aligned.alignment": 64 * 1024,
                "m2.vm.aligned.good_size": 4096,
                "m2.vm.offset.good_size": 17 * 4096,
                "m2.vm.policy.first_arena_size": 128 * 1024 * 1024,
            }
        )
        trace = "\n".join(
            [producer.TRACE_BEGIN, *(f"{key}={value}" for key, value in values.items()), producer.TRACE_END]
        )
        self.assertEqual(producer.parse_trace(trace, source="test"), values)

        missing_retry = trace.replace(
            "m2.vm.release.retry.real_munmap_success=1\n", "", 1
        )
        with self.assertRaises(ValueError):
            producer.parse_trace(missing_retry, source="test")

    def test_policy_trace_schema_requires_the_bounded_option_hint_large_and_thp_relations(self):
        """Keep the coherent policy slice explicit in the C/Rust record."""

        producer = RUNNER._m2_x86_64_vm_producer()
        for key in (
            "m2.vm.policy.source_options_applied",
            "m2.vm.policy.first_arena_size",
            "m2.vm.policy.first_arena_initially_committed",
            "m2.vm.policy.large_high_hint_failed",
            "m2.vm.policy.large_null_hint_retry_failed",
            "m2.vm.policy.regular_hinted_map_after_large_fallback",
            "m2.vm.policy.thp_advice_failure_ignored",
        ):
            with self.subTest(key=key):
                self.assertIn(key, producer.TRACE_KEYS)

    def test_thp_direct_policy_trace_requires_the_complete_finite_case_roster(self):
        """Keep every selected direct allow_thp control-flow case explicit."""

        producer = RUNNER._m2_x86_64_vm_producer()
        for key in (
            "m2.vm.thp_direct.allow_enabled_zero_calls_and_continues",
            "m2.vm.thp_direct.query_perm_get_only_disabled_and_continues",
            "m2.vm.thp_direct.query_inval_get_only_disabled_and_continues",
            "m2.vm.thp_direct.query_nonzero_one_get_only_disabled_and_continues",
            "m2.vm.thp_direct.query_nonzero_three_get_only_disabled_and_continues",
            "m2.vm.thp_direct.set_success_exact_get_set_disabled_and_continues",
            "m2.vm.thp_direct.set_perm_exact_get_set_disabled_and_continues",
            "m2.vm.thp_direct.set_inval_exact_get_set_disabled_and_continues",
        ):
            with self.subTest(key=key):
                self.assertIn(key, producer.TRACE_KEYS)

    def test_large_page_retry_matrix_binds_direct_normal_release_receivers(self):
        """The finite retry state stays bound to the selected C/Rust policy routes."""

        fragment = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        definition = next(
            definition
            for definition in fragment["component"]["bounded_source_definitions"]
            if definition["id"] == "unix-normal-large-page-retry-suppression"
        )
        self.assertEqual(
            definition["source_anchor"],
            {
                "member": "src/prim/unix/prim.c",
                "start_line": 383,
                "end_line": 486,
                "sha256": "f78d506081775a4fd6ff7eda4c7c52127061b0040b7eacd7d71151b335fc3a87",
            },
        )
        self.assertEqual(
            definition["evidence_check_ids"],
            [
                "native-vm-fixed-lifecycle-differential",
                "normal-release-large-page-retry-suppression-and-ordinary-fallback",
            ],
        )
        producer = RUNNER._m2_x86_64_vm_producer()
        for key in (
            "m2.vm.large_retry.initial_failed_large_regular_owner",
            "m2.vm.large_retry.allow_large_false_preserves_counter",
            "m2.vm.large_retry.ineligible_geometry_preserves_counter",
            "m2.vm.large_retry.option_disabled_preserves_counter",
            "m2.vm.large_retry.eight_suppressed_regular_owners",
            "m2.vm.large_retry.ninth_reopens_large_regular_owner",
            "m2.vm.large_retry.competing_cas_failure_regular_owner",
            "m2.vm.large_retry.competing_cas_seven_then_reopens",
        ):
            with self.subTest(key=key):
                self.assertIn(key, producer.TRACE_KEYS)

    def test_large_only_terminal_map_anchor_includes_its_unix_mmap_definition(self):
        """The one-GiB terminal route starts at the enclosing source function."""

        fragment = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        definition = next(
            definition
            for definition in fragment["component"]["bounded_source_definitions"]
            if definition["id"] == "unix-large-only-one-gib-terminal-map"
        )
        self.assertEqual(
            definition["source_anchor"],
            {
                "member": "src/prim/unix/prim.c",
                "start_line": 383,
                "end_line": 449,
                "sha256": "6305c06b0233856a2fab800243e657b13666f0d04324da6597beee559decc0dd",
            },
        )
        self.assertEqual(
            definition["required_definitions"],
            [
                "static void* unix_mmap",
                "static _Atomic(size_t) mi_huge_1gib_pages_unavailable",
                "MAP_HUGE_1GB",
                "MAP_HUGE_2MB",
            ],
        )
        self.assertEqual(
            definition["evidence_check_ids"],
            [
                "native-vm-fixed-lifecycle-differential",
                "large-only-one-gib-failure-no-regular-owner",
            ],
        )

    def test_aligned_hint_matrix_binds_the_direct_source_definition_and_all_relations(self):
        """Keep the finite normal-release cursor contract explicit in the ledger."""

        fragment = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        definition = next(
            definition
            for definition in fragment["component"]["bounded_source_definitions"]
            if definition["id"] == "os-aligned-hint-cursor-random-and-cas"
        )
        self.assertEqual(
            definition["source_anchor"],
            {
                "member": "src/os.c",
                "start_line": 110,
                "end_line": 158,
                "sha256": "d5855c977e616eca2f5ed2689d566cafedfe3e2743b5b02665db39c9be2043b5",
            },
        )
        self.assertIn(
            "normal-release-aligned-hint-cursor-random-and-cas-matrix",
            definition["evidence_check_ids"],
        )
        producer = RUNNER._m2_x86_64_vm_producer()
        for key in (
            "m2.vm.aligned_hint.cold_missing_default_advances_cursor",
            "m2.vm.aligned_hint.eligibility_and_geometry",
            "m2.vm.aligned_hint.initialized_first_randomized_start",
            "m2.vm.aligned_hint.strict_max_then_wrap_one_draw",
            "m2.vm.aligned_hint.ignored_cas_failure_second_fetch",
        ):
            with self.subTest(key=key):
                self.assertIn(key, producer.TRACE_KEYS)

        direct = next(
            definition
            for definition in fragment["component"]["bounded_source_definitions"]
            if definition["id"] == "unix-aligned-hint-direct-caller"
        )
        self.assertEqual(
            direct["source_anchor"],
            {
                "member": "src/prim/unix/prim.c",
                "start_line": 318,
                "end_line": 365,
                "sha256": "1970adf392c22c9bef4bdcc0456c265c85a9ac53fab95ec5601cc318628381d7",
            },
        )
        self.assertEqual(
            direct["required_definitions"],
            [
                "static void* unix_mmap_prim_aligned",
                "_mi_os_get_aligned_hint",
                "unix_mmap_prim(hint, size, protect_flags, flags, fd)",
                "unix_mmap_prim(addr, size, protect_flags, flags, fd)",
            ],
        )
        self.assertEqual(
            producer.ALIGNED_HINT_PROFILE_TRACE_KEYS,
            (
                "m2.vm.aligned_hint.profile.debug_without_default_random",
                "m2.vm.aligned_hint.profile.secure_requires_default_random",
                "m2.vm.aligned_hint.profile.secure_oversized_skips_cursor_and_random",
                "m2.vm.aligned_hint.profile.secure_exact_boundary_randomizes",
                "m2.vm.aligned_hint.profile.wrapped_direct_caller_hint_then_null_without_owner",
            ),
        )
        profile_trace = "\n".join(
            [
                producer.ALIGNED_HINT_PROFILE_TRACE_BEGIN,
                *(f"{key}=1" for key in producer.ALIGNED_HINT_PROFILE_TRACE_KEYS),
                producer.ALIGNED_HINT_PROFILE_TRACE_END,
            ]
        )
        self.assertEqual(
            producer.parse_aligned_hint_profile_trace(
                profile_trace,
                source="test",
                expected_keys=producer.ALIGNED_HINT_PROFILE_TRACE_KEYS,
            ),
            {key: 1 for key in producer.ALIGNED_HINT_PROFILE_TRACE_KEYS},
        )
        with self.assertRaises(ValueError):
            producer.parse_aligned_hint_profile_trace(
                profile_trace.replace(
                    "m2.vm.aligned_hint.profile.secure_exact_boundary_randomizes=1\n", "", 1
                ),
                source="test",
                expected_keys=producer.ALIGNED_HINT_PROFILE_TRACE_KEYS,
            )

    def test_transition_fault_trace_schema_requires_source_result_and_retry_relations(self):
        """The normal receiver cannot reduce C primitive failures to success counters."""

        producer = RUNNER._m2_x86_64_vm_producer()
        for key in (
            "m2.vm.reserved.commit.failure.one_source_attempt_and_counters_unchanged",
            "m2.vm.reserved.decommit.failure_returns_false",
            "m2.vm.reserved.reset.madv_free_einval_falls_back_to_dontneed",
            "m2.vm.reserved.reset.eagain_retries_initial_madv_free",
            "m2.vm.reserved.reset.fallback_eagain_returns_error_after_one_fallback_attempt",
            "m2.vm.reserved.purge.decommit_failure_no_recommit",
            "m2.vm.reserved.purge.reset_failure_is_consumed",
            "m2.vm.reserved.reset.dontneed_persists_to_no_callback_purge",
            "m2.vm.reserved.purge.reset_eagain_then_error_is_consumed_and_owner_retained",
            "m2.vm.reserved.purge.normal_no_callback_policy_range_matrix",
            "m2.vm.offset.prefix_decommit.success_attempt_and_full_owner",
            "m2.vm.offset.prefix_decommit.failure_attempt_consumed_and_full_owner",
            "m2.vm.reserved.protect.failure_returns_false_and_one_source_attempt",
            "m2.vm.reserved.unprotect.failure_returns_false_and_one_source_attempt",
            "m2.vm.external.page_extension.direct_commit_fault_bypasses_callback",
            "m2.vm.external.page_extension.failure_preserves_unpublished_state",
            "m2.vm.external.page_extension.retry_commits_without_callback",
        ):
            with self.subTest(key=key):
                self.assertIn(key, producer.TRACE_KEYS)

    def summary(self):
        return RUNNER.validate_x86_64_m2_memory_substrate_contract(
            RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT), RUNNER.load_pin()
        )

    def test_partial_vm_fragment_materializes_all_receipts_without_promotion(self):
        summary = self.summary()
        vm = summary["components"][0]
        self.assertEqual(vm["id"], "vm-primitives")
        self.assertEqual(vm["native_status"], "partial")
        self.assertEqual(tuple(check["id"] for check in vm["checks"]), EXPECTED_VM_CHECK_IDS)
        self.assertEqual(len(vm["bounded_source_definitions"]), 21)
        callback_definitions = {
            definition["id"]: definition["source_anchor"]
            for definition in vm["bounded_source_definitions"]
            if definition["id"].startswith("arena-external-callback-")
        }
        self.assertEqual(
            callback_definitions,
            {
                "arena-external-callback-manage": {
                    "member": "src/arena.c",
                    "start_line": 1676,
                    "end_line": 1884,
                    "sha256": "9d2632800cde84ccd0fb702f4b5e7db15c5b94a056aca57d592c41105cb94eeb",
                },
                "arena-external-callback-purge": {
                    "member": "src/arena.c",
                    "start_line": 2257,
                    "end_line": 2282,
                    "sha256": "a1023a8302a3aebf431876baa41fea3ee0809cb0b82276e6482de8134f712ff8",
                },
            },
        )
        self.assertEqual(len(vm["branch_matrix"]), 14)
        self.assertEqual(len(vm["unqualified_failure_matrix"]), 3)
        self.assertEqual(len(vm["remaining_conditions"]), 5)
        self.assertEqual(summary["milestone"]["status"], "partial")

    def test_vm_fragment_reference_and_partial_status_fail_closed(self):
        contract = RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT)
        contract["components"][0]["evidence_fragment"]["path"] = "compat/allocator/other.fragment.json"
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER.validate_x86_64_m2_memory_substrate_contract(contract, RUNNER.load_pin())

        contract = RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT)
        with mock.patch.object(
            RUNNER,
            "_m2_x86_64_vm_component",
            return_value={
                **self.summary()["components"][0],
                "native_status": "complete",
                "remaining_conditions": [],
            },
        ), self.assertRaises(RUNNER.HarnessError):
            RUNNER.validate_x86_64_m2_memory_substrate_contract(contract, RUNNER.load_pin())

    def test_process_thp_checks_keep_allocation_policy_and_release_source_anchors(self):
        producer = RUNNER._m2_x86_64_vm_producer()
        original = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        bindings = (
            ("bounded_source_definitions", "unix-thp-disable-process-policy",
             "process-thp-madvise-success-c-rust-differential"),
            ("bounded_source_definitions", "os-regular-and-aligned-map-owners",
             "process-thp-madvise-failure-c-rust-differential"),
            ("bounded_source_definitions", "os-free-and-full-memory-id-release",
             "process-thp-madvise-success-c-rust-differential"),
            ("branch_matrix", "unix-configuration-and-thp-process-policy",
             "process-thp-madvise-failure-c-rust-differential"),
            ("branch_matrix", "unix-regular-map-large-page-and-thp-routing",
             "process-thp-madvise-success-c-rust-differential"),
            ("bounded_source_definitions", "unix-thp-disable-process-policy",
             "process-thp-disabled-policy-c-rust-differential"),
            ("bounded_source_definitions", "os-regular-and-aligned-map-owners",
             "process-thp-disabled-policy-c-rust-differential"),
            ("bounded_source_definitions", "os-free-and-full-memory-id-release",
             "process-thp-disabled-policy-c-rust-differential"),
            ("branch_matrix", "unix-configuration-and-thp-process-policy",
             "process-thp-disabled-policy-c-rust-differential"),
            ("branch_matrix", "unix-regular-map-large-page-and-thp-routing",
             "process-thp-disabled-policy-c-rust-differential"),
            ("bounded_source_definitions", "unix-thp-disable-process-policy",
             "process-thp-inherited-disable-advice-c-rust-differential"),
            ("bounded_source_definitions", "os-regular-and-aligned-map-owners",
             "process-thp-inherited-disable-advice-c-rust-differential"),
            ("bounded_source_definitions", "os-free-and-full-memory-id-release",
             "process-thp-inherited-disable-advice-c-rust-differential"),
            ("branch_matrix", "unix-configuration-and-thp-process-policy",
             "process-thp-inherited-disable-advice-c-rust-differential"),
            ("branch_matrix", "unix-regular-map-large-page-and-thp-routing",
             "process-thp-inherited-disable-advice-c-rust-differential"),
        )
        for section, row_id, check_id in bindings:
            with self.subTest(section=section, row_id=row_id):
                changed = copy.deepcopy(original)
                row = next(item for item in changed["component"][section] if item["id"] == row_id)
                row["evidence_check_ids"].remove(check_id)
                source = mock.Mock()
                source.read_text.return_value = json.dumps(changed)
                with self.assertRaises(ValueError):
                    producer.load_fragment(source)

    def test_external_os_checks_keep_transition_source_anchors(self):
        producer = RUNNER._m2_x86_64_vm_producer()
        original = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        bindings = (
            ("bounded_source_definitions", "os-fixed-range-transitions"),
            ("bounded_source_definitions", "unix-fixed-transition-primitives"),
            ("branch_matrix", "os-range-transition-policy-and-failure-owners"),
            ("branch_matrix", "unix-commit-decommit-reset-reuse-and-protect"),
        )
        for section, row_id in bindings:
            for check_id in producer.EXTERNAL_OS_CHECK_IDS:
                with self.subTest(section=section, row_id=row_id, check_id=check_id):
                    changed = copy.deepcopy(original)
                    row = next(item for item in changed["component"][section] if item["id"] == row_id)
                    row["evidence_check_ids"].remove(check_id)
                    source = mock.Mock()
                    source.read_text.return_value = json.dumps(changed)
                    with self.assertRaises(ValueError):
                        producer.load_fragment(source)

    def test_process_protection_checks_keep_transition_and_owner_source_anchors(self):
        producer = RUNNER._m2_x86_64_vm_producer()
        original = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        bindings = (
            ("bounded_source_definitions", "os-free-and-full-memory-id-release"),
            ("bounded_source_definitions", "os-regular-and-aligned-map-owners"),
            ("bounded_source_definitions", "os-normal-aligned-and-offset-owners"),
            ("bounded_source_definitions", "os-fixed-range-transitions"),
            ("bounded_source_definitions", "unix-fixed-transition-primitives"),
            ("branch_matrix", "os-free-and-statistics-events"),
            ("branch_matrix", "os-normal-aligned-and-offset-allocation"),
            ("branch_matrix", "os-range-transition-policy-and-failure-owners"),
            ("branch_matrix", "unix-commit-decommit-reset-reuse-and-protect"),
        )
        for section, row_id in bindings:
            for check_id in producer.PROCESS_PROTECTION_SOURCE_CHECK_IDS:
                with self.subTest(section=section, row_id=row_id, check_id=check_id):
                    changed = copy.deepcopy(original)
                    row = next(item for item in changed["component"][section] if item["id"] == row_id)
                    row["evidence_check_ids"].remove(check_id)
                    source = mock.Mock()
                    source.read_text.return_value = json.dumps(changed)
                    with self.assertRaises(ValueError):
                        producer.load_fragment(source)

    def test_explicit_arena_receivers_keep_allocation_and_release_source_anchors(self):
        producer = RUNNER._m2_x86_64_vm_producer()
        original = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        bindings = (
            ("bounded_source_definitions", "os-free-and-full-memory-id-release"),
            ("bounded_source_definitions", "os-regular-and-aligned-map-owners"),
            ("bounded_source_definitions", "os-normal-aligned-and-offset-owners"),
            ("bounded_source_definitions", "arena-policy-regular-map-and-manage"),
            ("bounded_source_definitions", "arena-external-callback-manage"),
            ("branch_matrix", "os-free-and-statistics-events"),
            ("branch_matrix", "os-primitive-regular-and-aligned-allocation"),
            ("branch_matrix", "os-normal-aligned-and-offset-allocation"),
        )
        for section, row_id in bindings:
            for check_id in producer.EXPLICIT_ARENA_SOURCE_CHECK_IDS:
                with self.subTest(section=section, row_id=row_id, check_id=check_id):
                    changed = copy.deepcopy(original)
                    row = next(item for item in changed["component"][section] if item["id"] == row_id)
                    row["evidence_check_ids"].remove(check_id)
                    source = mock.Mock()
                    source.read_text.return_value = json.dumps(changed)
                    with self.assertRaises(ValueError):
                        producer.load_fragment(source)

    def test_terminal_unmap_receivers_keep_owner_and_release_source_anchors(self):
        producer = RUNNER._m2_x86_64_vm_producer()
        original = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        bindings = {
            producer.REGISTERED_ARENA_TERMINAL_UNMAP_CHECK_ID: (
                ("bounded_source_definitions", "os-free-and-full-memory-id-release"),
                ("bounded_source_definitions", "arena-policy-regular-map-and-manage"),
                ("bounded_source_definitions", "arena-terminal-destroy-and-os-release"),
                ("branch_matrix", "os-free-and-statistics-events"),
            ),
            producer.OS_PAGE_TERMINAL_UNMAP_CHECK_ID: (
                ("bounded_source_definitions", "arena-on-demand-page-first-prefix"),
                ("bounded_source_definitions", "os-free-and-full-memory-id-release"),
                ("bounded_source_definitions", "unix-fixed-free-primitive"),
                ("branch_matrix", "os-free-and-statistics-events"),
                ("branch_matrix", "unix-free-primitive"),
            ),
        }
        for check_id, rows in bindings.items():
            for section, row_id in rows:
                with self.subTest(check_id=check_id, section=section, row_id=row_id):
                    changed = copy.deepcopy(original)
                    row = next(item for item in changed["component"][section] if item["id"] == row_id)
                    row["evidence_check_ids"].remove(check_id)
                    source = mock.Mock()
                    source.read_text.return_value = json.dumps(changed)
                    with self.assertRaises(ValueError):
                        producer.load_fragment(source)

    def test_vm_producer_receipt_rejects_missing_comparison_anchors_and_nonclaims(self):
        summary = self.summary()
        for field, replacement in (
            ("status", "partial"),
            ("compared_value_count", 34),
            ("source_anchors", []),
            ("nonclaims", []),
            ("aligned_overmap_comparison", {"status": "matched"}),
            ("aligned_overmap_c_trace_sha256", "not-a-digest"),
            ("reset_advice_matrix", {}),
        ):
            with self.subTest(field=field):
                evidence = self.vm_evidence(summary)
                evidence[field] = replacement
                with self.assertRaises(RUNNER.HarnessError):
                    RUNNER._m2_x86_64_vm_check_records(summary, evidence)

    def test_vm_producer_receipt_accepts_the_exact_c_and_rust_producers(self):
        records = RUNNER._m2_x86_64_vm_check_records(
            self.summary(), self.vm_evidence(self.summary())
        )
        self.assertEqual(len(records), 7)
        self.assertEqual(records[0]["id"], "native-vm-fixed-lifecycle-differential")
        self.assertEqual(records[1]["id"], "aligned-hint-source-profile-and-direct-caller-matrix")
        self.assertEqual(records[2]["id"], "aligned-overmap-cleanup-c-rust-boundary-matrix")
        self.assertEqual(records[2]["comparison_status"], "matched")
        self.assertEqual(records[3]["id"], "second-arena-reset-advice-c-rust-matrix")
        self.assertEqual(records[3]["passed_test_count"], 3)
        self.assertEqual(records[4]["id"], "legacy-os-page-suffix-trim-and-raw-release")
        self.assertEqual(records[4]["comparison_status"], "source-different")
        self.assertEqual(records[5]["id"], "process-os-page-suffix-trim-and-terminal-release")
        self.assertEqual(records[5]["comparison_status"], "matched")
        self.assertEqual(records[6]["id"], "process-os-page-block-commit-rollback-c-rust-differential")
        self.assertEqual(records[6]["comparison_status"], "matched")

    def test_process_thp_receipts_require_complete_c_rust_relations(self):
        summary = self.summary()
        evidence = {}
        for check_id, receiver in RUNNER.M2_X86_64_THP_PROCESS_RECEIVERS.items():
            rust_trace = {field: 1 for field in receiver["fields"]}
            c_trace = {**rust_trace, **{field: 0 for field in receiver["c_extra"]}}
            evidence[check_id] = {
                "c": c_trace,
                "c_commands": {"build_status": 0, "run_status": 0, "stderr": ""},
                "command": ["python3", receiver["target"], "--offline"],
                "mismatches": [],
                "rust": rust_trace,
                "rust_commands": {"build_status": 0, "run_status": 0, "stderr": ""},
                "scope": "one fresh process per side",
                "status": "matched",
            }
        records = RUNNER._m2_x86_64_vm_check_records(
            summary, self.vm_evidence(summary), thp_process_evidence=evidence
        )
        self.assertEqual([record["id"] for record in records[-len(evidence):]], list(evidence))
        self.assertTrue(all(record["comparison_status"] == "matched" for record in records[-len(evidence):]))
        for check_id, receiver in RUNNER.M2_X86_64_THP_PROCESS_RECEIVERS.items():
            field = sorted(receiver["fields"])[0]
            for changed in (
                {"status": "passed"},
                {"mismatches": [field]},
                {"c": {key: value for key, value in evidence[check_id]["c"].items()
                    if key != field}},
                {"rust": {**evidence[check_id]["rust"], field: 2}},
                {"command": ["python3", receiver["target"], "--stale"]},
                {"c_commands": {"build_status": 0, "run_status": 1, "stderr": ""}},
            ):
                with self.subTest(check_id=check_id, changed=next(iter(changed))):
                    broken = copy.deepcopy(evidence)
                    broken[check_id].update(changed)
                    with self.assertRaises(RUNNER.HarnessError):
                        RUNNER._m2_x86_64_vm_check_records(
                            summary, self.vm_evidence(summary), thp_process_evidence=broken
                        )

    def test_process_thp_receivers_bind_offline_and_normal_reader_commands(self):
        receivers = RUNNER.M2_X86_64_THP_PROCESS_RECEIVERS
        for offline in (False, True):
            with self.subTest(offline=offline), mock.patch.object(
                RUNNER, "command_record", return_value={"status": 0}
            ) as execute, mock.patch.object(
                RUNNER, "require_success"
            ) as require, mock.patch.object(
                RUNNER, "read_json", side_effect=[{"status": "matched"} for _ in receivers]
            ) as read:
                evidence = RUNNER._run_m2_x86_64_thp_process_evidence(offline=offline)
            expected_commands = [
                ["python3", receiver["target"], *(["--offline"] if offline else [])]
                for receiver in receivers.values()
            ]
            self.assertEqual(
                execute.call_args_list,
                [mock.call(command, cwd=RUNNER.ROOT, timeout_seconds=1800)
                 for command in expected_commands],
            )
            self.assertEqual(require.call_count, len(receivers))
            self.assertEqual(
                read.call_args_list,
                [mock.call(RUNNER.ARTIFACT_ROOT / "x86_64" / receiver["artifact"] / "evidence.json")
                 for receiver in receivers.values()],
            )
            self.assertEqual(
                [entry["command"] for entry in evidence.values()], expected_commands
            )

    def process_vm_receipts(self):
        evidence = {}
        for check_id, receiver in RUNNER.M2_X86_64_VM_PROCESS_RECEIVERS.items():
            trace = {field: 1 for field in receiver["fields"]}
            trace.update(receiver.get("required_values", {}))
            cases = receiver["cases"]
            if receiver.get("command_receipts") == "nested-runs":
                commands = {"build_status": 0, "runs": {
                    case: {"status": 0, "stderr": ""} for case in cases
                }}
            elif cases:
                commands = {"build_status": 0, **{
                    case: {"run_status": 0, "stderr": ""} for case in cases
                }}
            else:
                commands = {"build_status": 0, "run_status": 0, "stderr": ""}
            observed = {
                "c": {case: dict(trace) for case in cases} if cases else dict(trace),
                "rust": {case: dict(trace) for case in cases} if cases else dict(trace),
                "c_commands": copy.deepcopy(commands),
                "rust_commands": (
                    {"run_status": 0, "stderr": ""}
                    if receiver.get("rust_command_receipt") == "unit-run"
                    else copy.deepcopy(commands)
                ),
                "command": ["python3", receiver["target"], "--offline"],
                "mismatches": [],
                "scope": "one fresh process-owned mapping per side",
                "status": "matched",
            }
            if receiver.get("alignment_fallback_receipt"):
                fallback = receiver["alignment_fallback_receipt"]
                for side, selected in (("c", 0), ("rust", 1)):
                    observed[side].update({
                        "mmap_after_failure": 1 + selected, "recovery_mmap_delta": 2 + selected,
                        "warning_bodies": 3 + selected, "warning_fragments": 3 + selected,
                        "warning_order": 4123 if selected else 123,
                        "recovery_registry": observed[side]["registry_before"] + 1,
                    })
                observed[fallback] = {"c": 0, "rust": 1}
            if receiver.get("stable_fields"):
                for field in receiver["stable_fields"]:
                    observed["rust"][field] = 2
                observed[receiver["stable_receipt"]] = {
                    "c": {field: observed["c"][field] for field in receiver["stable_fields"]},
                    "rust": {field: observed["rust"][field] for field in receiver["stable_fields"]},
                }
            if receiver.get("node_growth"):
                node = receiver["node_growth"]
                for side, growth in (("c", 0), ("rust", 65536)):
                    values = observed[side]
                    values.update(receiver["required_values"])
                    values["first_size"] = values["second_size"] = 589824
                    values[node["live_reserved"]] = values[node["size"]] + growth
                    values[node["live_committed"]] = (
                        values[node["size"]] - node["committed_gap_bytes"] + growth
                    )
                    for field in node["delta_fields"]:
                        values[field] = growth
                observed[node["receipt"]] = {"c": 0, "rust": 65536}
            if receiver["commit_fields"]:
                commit = {field: 1 for field in receiver["commit_fields"]}
                observed.update({
                    "commit_c": dict(commit),
                    "commit_rust": dict(commit),
                    "commit_c_commands": {"build_status": 0, "run_status": 0, "stderr": ""},
                    "commit_rust_commands": {"run_status": 0, "stderr": ""},
                })
            evidence[check_id] = observed
        return evidence

    def test_process_vm_receipts_require_complete_case_and_commit_relations(self):
        summary = self.summary()
        evidence = self.process_vm_receipts()
        records = RUNNER._m2_x86_64_vm_check_records(
            summary, self.vm_evidence(summary), process_vm_evidence=evidence
        )
        self.assertEqual([record["id"] for record in records[-len(evidence):]], list(evidence))
        self.assertTrue(all(record["comparison_status"] == "matched" for record in records[-len(evidence):]))
        for check_id in evidence:
            with self.subTest(missing_receipt=check_id):
                missing = dict(evidence)
                missing.pop(check_id)
                with self.assertRaisesRegex(RUNNER.HarnessError, "inventory"):
                    RUNNER._m2_x86_64_vm_check_records(
                        summary, self.vm_evidence(summary), process_vm_evidence=missing
                    )
        for check_id, receiver in RUNNER.M2_X86_64_VM_PROCESS_RECEIVERS.items():
            field = sorted(receiver["fields"])[0]
            for name in ("status", "mismatches", "command", "field_missing", "field_different", "command_status", "rust_command_status"):
                with self.subTest(check_id=check_id, mutation=name):
                    changed = copy.deepcopy(evidence)
                    row = changed[check_id]
                    if name == "status":
                        row["status"] = "passed"
                    elif name == "mismatches":
                        row["mismatches"] = [field]
                    elif name == "command":
                        row["command"] = ["python3", receiver["target"], "--stale"]
                    elif name == "field_missing":
                        (row["c"][receiver["cases"][0]] if receiver["cases"] else row["c"]).pop(field)
                    elif name == "field_different":
                        (row["rust"][receiver["cases"][0]] if receiver["cases"] else row["rust"])[field] = 2
                    elif name == "command_status":
                        if receiver.get("command_receipts") == "nested-runs":
                            row["c_commands"]["runs"][receiver["cases"][0]]["status"] = 1
                        elif receiver["cases"]:
                            row["c_commands"][receiver["cases"][0]]["run_status"] = 1
                        else:
                            row["c_commands"]["run_status"] = 1
                    elif receiver.get("rust_command_receipt") == "unit-run":
                        row["rust_commands"]["run_status"] = 1
                    elif receiver.get("command_receipts") == "nested-runs":
                        row["rust_commands"]["runs"][receiver["cases"][0]]["status"] = 1
                    elif receiver["cases"]:
                        row["rust_commands"][receiver["cases"][0]]["run_status"] = 1
                    else:
                        row["rust_commands"]["run_status"] = 1
                    with self.assertRaises(RUNNER.HarnessError):
                        RUNNER._m2_x86_64_vm_check_records(
                            summary, self.vm_evidence(summary), process_vm_evidence=changed
                        )
            if receiver["commit_fields"]:
                for name in ("commit_field", "commit_c_command", "commit_rust_command"):
                    with self.subTest(check_id=check_id, mutation=name):
                        changed = copy.deepcopy(evidence)
                        row = changed[check_id]
                        if name == "commit_field":
                            row["commit_rust"][sorted(receiver["commit_fields"])[0]] = 2
                        elif name == "commit_c_command":
                            row["commit_c_commands"]["run_status"] = 1
                        else:
                            row["commit_rust_commands"]["run_status"] = 1
                        with self.assertRaises(RUNNER.HarnessError):
                            RUNNER._m2_x86_64_vm_check_records(
                                summary, self.vm_evidence(summary), process_vm_evidence=changed
                            )
            if receiver.get("stable_fields"):
                for name in ("missing_snapshot", "changed_snapshot", "changed_warning_count"):
                    with self.subTest(check_id=check_id, mutation=name):
                        changed = copy.deepcopy(evidence)
                        row = changed[check_id]
                        if name == "missing_snapshot":
                            row.pop(receiver["stable_receipt"])
                        elif name == "changed_snapshot":
                            row[receiver["stable_receipt"]]["rust"][receiver["stable_fields"][0]] += 1
                        else:
                            row["rust"][receiver["stable_fields"][1]] += 1
                        with self.assertRaises(RUNNER.HarnessError):
                            RUNNER._m2_x86_64_vm_check_records(
                                summary, self.vm_evidence(summary), process_vm_evidence=changed
                            )
            if receiver.get("node_growth"):
                node = receiver["node_growth"]
                for name in ("missing_growth", "stale_growth", "invalid_growth", "broken_counter", "warning_lost", "owner_size"):
                    with self.subTest(check_id=check_id, mutation=name):
                        changed = copy.deepcopy(evidence)
                        row = changed[check_id]
                        if name == "missing_growth":
                            row.pop(node["receipt"])
                        elif name == "stale_growth":
                            row[node["receipt"]]["rust"] = 0
                        elif name == "invalid_growth":
                            row["rust"][node["live_reserved"]] += 4096
                        elif name == "broken_counter":
                            row["rust"][node["delta_fields"][0]] += 1
                        elif name == "warning_lost":
                            row["rust"]["warning_before_stats"] = 0
                        else:
                            row["rust"]["first_size"] += 1
                        with self.assertRaises(RUNNER.HarnessError):
                            RUNNER._m2_x86_64_vm_check_records(
                                summary, self.vm_evidence(summary), process_vm_evidence=changed
                            )

    def test_process_vm_collector_reconstructs_complete_physical_receipts(self):
        summary = self.summary()
        vm_evidence = self.vm_evidence(summary)
        expected = self.process_vm_receipts()
        RUNNER.WORK_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.WORK_ROOT) as temporary:
            root = Path(temporary)
            def execute(command, **kwargs):
                check_id, receiver = next((key, value) for key, value in RUNNER.M2_X86_64_VM_PROCESS_RECEIVERS.items()
                                          if value["target"] == command[1])
                artifact = root / "x86_64" / receiver["artifact"] / "evidence.json"
                artifact.parent.mkdir(parents=True)
                artifact.write_text(json.dumps({key: value for key, value in expected[check_id].items()
                                               if key != "command"}))
                return {"command": command, "status": 0, "stdout": "", "stderr": ""}
            with mock.patch.object(RUNNER, "ARTIFACT_ROOT", root), mock.patch.object(
                RUNNER, "command_record", side_effect=execute
            ) as dispatch:
                observed = RUNNER._run_m2_x86_64_process_vm_evidence(offline=True)
            records = RUNNER._m2_x86_64_vm_check_records(summary, vm_evidence, process_vm_evidence=observed)
            self.assertEqual(observed, expected)
            self.assertEqual([row["id"] for row in records[-len(expected):]], list(expected))
            self.assertEqual(dispatch.call_args_list, [mock.call(
                ["python3", receiver["target"], "--offline"], cwd=RUNNER.ROOT, timeout_seconds=1800
            ) for receiver in RUNNER.M2_X86_64_VM_PROCESS_RECEIVERS.values()])

    def test_process_vm_fault_observations_reject_matching_but_invalid_postconditions(self):
        summary = self.summary()
        vm_evidence = self.vm_evidence(summary)
        evidence = self.process_vm_receipts()
        for check_id, receiver in RUNNER.M2_X86_64_VM_PROCESS_RECEIVERS.items():
            for field in receiver.get("required_values", {}):
                with self.subTest(check_id=check_id, field=field):
                    changed = copy.deepcopy(evidence)
                    for side in ("c", "rust"):
                        changed[check_id][side][field] += 1
                    with self.assertRaises(RUNNER.HarnessError):
                        RUNNER._m2_x86_64_vm_check_records(summary, vm_evidence, process_vm_evidence=changed)
            if receiver.get("alignment_fallback_receipt"):
                receipt = receiver["alignment_fallback_receipt"]
                for mutation in ("missing", "wrong_selection", "unknown_selection", "wrong_warning_order", "wrong_recovery_calls", "wrong_registry"):
                    with self.subTest(check_id=check_id, mutation=mutation):
                        changed = copy.deepcopy(evidence)
                        row = changed[check_id]
                        if mutation == "missing":
                            row.pop(receipt)
                        elif mutation == "wrong_selection":
                            row[receipt]["rust"] = 0
                        elif mutation == "unknown_selection":
                            row[receipt]["rust"] = 2
                        else:
                            field = {"wrong_warning_order": "warning_order", "wrong_recovery_calls": "recovery_mmap_delta",
                                     "wrong_registry": "recovery_registry"}[mutation]
                            row["rust"][field] += 1
                        with self.assertRaises(RUNNER.HarnessError):
                            RUNNER._m2_x86_64_vm_check_records(summary, vm_evidence, process_vm_evidence=changed)

    def test_process_vm_receivers_bind_offline_and_normal_reader_commands(self):
        receivers = RUNNER.M2_X86_64_VM_PROCESS_RECEIVERS
        for offline in (False, True):
            with self.subTest(offline=offline), mock.patch.object(
                RUNNER, "command_record", return_value={"status": 0}
            ) as execute, mock.patch.object(
                RUNNER, "require_success"
            ) as require, mock.patch.object(
                RUNNER, "read_json", side_effect=[{"status": "matched"} for _ in receivers]
            ) as read:
                evidence = RUNNER._run_m2_x86_64_process_vm_evidence(offline=offline)
            expected_commands = [
                ["python3", receiver["target"], *(["--offline"] if offline else [])]
                for receiver in receivers.values()
            ]
            self.assertEqual(
                execute.call_args_list,
                [mock.call(command, cwd=RUNNER.ROOT, timeout_seconds=1800)
                 for command in expected_commands],
            )
            self.assertEqual(require.call_count, len(receivers))
            self.assertEqual(
                read.call_args_list,
                [mock.call(RUNNER.ARTIFACT_ROOT / "x86_64" / receiver["artifact"] / "evidence.json")
                 for receiver in receivers.values()],
            )
            self.assertEqual([entry["command"] for entry in evidence.values()], expected_commands)

    def test_page_map_process_receipts_require_their_exact_trace_shapes(self):
        cases = (
            ("page-map-fallback-trim-fault-c-rust-differential", (
                "output", "initialized", "reserved", "committed", "mmap_calls",
                "commit_calls", "suffix_length", "suffix_live", "allocated", "raw_cleanup",
            )),
            ("page-map-lazy-map-rollback-c-rust-differential", (
                "output", "failed", "empty_after_failure", "map_attempts",
                "reserved_delta", "committed_delta", "mmap_delta", "retry",
                "entry_published", "retry_reused", "cleared", "root_ready",
            )),
        )
        for check_id, names in cases:
            with self.subTest(check_id=check_id):
                check = next(check for check in RUNNER.M2_X86_64_PAGE_MAP_CHECKS
                    if check["id"] == check_id)
                fields = {field: "1" for field in names}
                evidence = {"status": "matched", "mismatches": {}, "c": fields, "rust": fields,
                    "command": ["python3", check["target"], "--offline"]}
                record = RUNNER._m2_x86_64_page_map_fallback_check_record(check, evidence)
                self.assertEqual(record["comparison_status"], "matched")
                older_shape = {"status": "passed", "comparison": {"status": "matched"},
                    "rust_passed_test_count": 1, "rust_command": ["stale"]}
                with self.assertRaises(RUNNER.HarnessError):
                    RUNNER._m2_x86_64_page_map_fallback_check_record(check, older_shape)
                incomplete = dict(evidence, c={key: value for key, value in fields.items()
                    if key != names[-1]})
                with self.assertRaises(RUNNER.HarnessError):
                    RUNNER._m2_x86_64_page_map_fallback_check_record(check, incomplete)

    def test_rust_binary_binding_accepts_both_cargo_profile_layouts_only(self):
        """The pinned nightly's per-unit test executable remains gate-owned."""

        debug = RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET / RUNNER.X86_64_RUST_TARGET / "debug"
        bound = RUNNER._m2_x86_64_vm_rust_binary_path_is_bound
        self.assertTrue(bound(str(debug / "deps/crabc_mimalloc-0123abcd")))
        self.assertTrue(bound(str(debug / "build/crabc-mimalloc/0123abcd/out/crabc_mimalloc-0123abcd")))
        for rejected in (
            debug / "build/crabc-mimalloc/0123abcd/out/crabc_mimalloc-4567ef01",
            debug / "build/crabc-mimalloc/0123abcd/crabc_mimalloc-0123abcd",
            debug / "build/crabc-core/0123abcd/out/crabc_mimalloc-0123abcd",
            debug / "deps/crabc_mimalloc-0123abcd.d",
            debug / "crabc_mimalloc-0123abcd",
            RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET / "debug/deps/crabc_mimalloc-0123abcd",
        ):
            with self.subTest(rejected=rejected):
                self.assertFalse(bound(str(rejected)))

    def test_process_arena_collect_receipt_binds_its_c_rust_pair(self):
        summary = self.summary()
        records = RUNNER._m2_x86_64_process_arena_collect_check_records(
            summary, self.arena_owned_evidence(summary)
        )
        self.assertEqual(
            records,
            [{
                "comparison_status": "matched",
                "component": "arenas",
                "command": self.arena_owned_evidence(summary)["arena_owned_rust_command"],
                "evidence_scope": "bounded-three-regular-arena-pinned-c-rust-process-purge-and-two-slice-reallocation-fallback-relation",
                "id": "process-wide-arena-purge-c-rust-differential",
                "passed_test_count": 1,
                "target": "arena::owned::tests::emit_native_owned_arena_purge_trace",
            }],
        )

    def test_process_arena_collect_receipt_rejects_altered_or_missing_binding(self):
        summary = self.summary()
        producer = RUNNER._m2_x86_64_vm_producer()
        cases = {
            "altered-c-fixture-command": lambda evidence: evidence["arena_owned_c_command"].__setitem__(
                evidence["arena_owned_c_command"].index(
                    str(RUNNER.ALLOCATOR_ROOT / "m2_arena_owned_x86_64.c")
                ),
                str(RUNNER.ALLOCATOR_ROOT / "m2_vm_x86_64.c"),
            ),
            "altered-fixture-receipt": lambda evidence: evidence["arena_owned_fixture"].__setitem__(
                "path", "compat/allocator/m2_vm_x86_64.c"
            ),
            "altered-rust-target": lambda evidence: evidence["arena_owned_rust_command"].__setitem__(
                1, "os::tests::emit_m2_vm_primitives_c_rust_trace"
            ),
            "duplicated-static-source": lambda evidence: evidence["arena_owned_c_command"].insert(
                evidence["arena_owned_c_command"].index("-pthread"), "/pinned/src/arena.c"
            ),
            "altered-comparison-count": lambda evidence: evidence["arena_owned_comparison"].__setitem__(
                "compared_value_count", producer.ARENA_OWNED_EVENT_FIELD_COUNT - 1
            ),
            "dropped-reallocation-fallback-values": lambda evidence: evidence["arena_owned_comparison"].__setitem__(
                "compared_value_count", 80
            ),
            "missing-command": lambda evidence: evidence.pop("arena_owned_c_command"),
            "missing-fixture": lambda evidence: evidence.pop("arena_owned_fixture"),
            "missing-trace-digest": lambda evidence: evidence.pop("arena_owned_trace_sha256"),
            "missing-rust-count": lambda evidence: evidence.pop("arena_owned_rust_passed_test_count"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                evidence = self.arena_owned_evidence(summary)
                mutate(evidence)
                with self.assertRaises(RUNNER.HarnessError):
                    RUNNER._m2_x86_64_process_arena_collect_check_records(summary, evidence)

    def test_m2_runner_excludes_every_custom_vm_receipt_from_focused_batch(self):
        summary = self.summary()
        vm_records = RUNNER._m2_x86_64_vm_check_records(
            summary, self.vm_evidence(summary)
        )
        runtime_check = next(
            check
            for component in summary["components"]
            for check in component["checks"]
            if check["id"] == "runtime-source-environment-thp-ready-configuration-admission"
        )
        vm_records.append(
            {
                "comparison_status": "matched",
                "component": "vm-primitives",
                "command": ["<focused-runtime-thp-configuration-producer>"],
                "evidence_scope": "bounded-c-rust-runtime-source-environment-thp-configuration-admission",
                "id": runtime_check["id"],
                "passed_test_count": runtime_check["expected_passed_test_count"],
                "target": runtime_check["target"],
            }
        )
        for check_id, receiver in RUNNER.M2_X86_64_THP_PROCESS_RECEIVERS.items():
            vm_records.append({
                "comparison_status": "matched",
                "component": "vm-primitives",
                "command": ["python3", receiver["target"], "--offline"],
                "evidence_scope": receiver["scope"],
                "id": check_id,
                "passed_test_count": 1,
                "target": receiver["target"],
            })
        for check_id, receiver in RUNNER.M2_X86_64_VM_PROCESS_RECEIVERS.items():
            vm_records.append({
                "comparison_status": "matched",
                "component": "vm-primitives",
                "command": ["python3", receiver["target"], "--offline"],
                "evidence_scope": receiver["scope"],
                "id": check_id,
                "passed_test_count": 1,
                "target": receiver["target"],
            })
        initialization_records = [
            {
                "comparison_status": "matched",
                "component": "initialization",
                "command": ["<fixed-direct-tld-matrix>"],
                "evidence_scope": "three-fixed-direct-pinned-c-rust-tld-source-matrix",
                "id": check["id"],
                "passed_test_count": check["expected_passed_test_count"],
                "target": check["target"],
            }
            for component in summary["components"]
            if component["id"] == "initialization"
            for check in component["checks"]
        ]
        fault_records = [
            {
                "comparison_status": "source-specific-relation-verified",
                "component": "fault-injection",
                "command": ["<fixed-fault-inventory-profile>"],
                "evidence_scope": "fixed-pinned-c-branch-profile-and-private-rust-fault-plan",
                "id": check["id"],
                "passed_test_count": check["expected_passed_test_count"],
                "target": check["target"],
            }
            for component in summary["components"]
            if component["id"] == "fault-injection"
            for check in component["checks"]
        ]
        arena_check = next(
            check
            for component in summary["components"]
            if component["id"] == "arenas"
            for check in component["checks"]
            if check["id"] == "process-wide-arena-purge-c-rust-differential"
        )
        arena_records = [
            {
                "comparison_status": "matched",
                "component": "arenas",
                "command": ["<process-arena-purge-producer>"],
                "evidence_scope": "bounded-three-regular-arena-pinned-c-rust-process-purge-and-two-slice-reallocation-fallback-relation",
                "id": arena_check["id"],
                "passed_test_count": arena_check["expected_passed_test_count"],
                "target": arena_check["target"],
            }
        ]
        metadata_check = next(
            check
            for component in summary["components"]
            if component["id"] == "metadata"
            for check in component["checks"]
        )
        metadata_records = [
            {
                "comparison_status": "matched",
                "component": "metadata",
                "command": ["<metadata-lifecycle-producer>"],
                "evidence_scope": "bounded-main-subprocess-pinned-c-rust-metadata-publication-and-replacement-lifecycle",
                "id": metadata_check["id"],
                "passed_test_count": metadata_check["expected_passed_test_count"],
                "target": metadata_check["target"],
            }
        ]
        arena_lifecycle_check = next(
            check
            for component in summary["components"]
            if component["id"] == "arenas"
            for check in component["checks"]
            if check["id"] == "arena-reservation-lifecycle-c-rust-differential"
        )
        arena_lifecycle_record = {"id": arena_lifecycle_check["id"]}
        arena_lifecycle_producer = mock.Mock(return_value={})
        vm_check_records_producer = mock.Mock(return_value=vm_records)
        arena_records_producer = mock.Mock(return_value=arena_records)
        direct_arena_records = [
            {"id": check_id, "component": "arenas"}
            for check_id in RUNNER.M2_X86_64_ARENA_DIRECT_RECEIVERS
        ]
        tld_retry_producer = mock.Mock()
        metadata_records_producer = mock.Mock(return_value=metadata_records)
        metadata_lifecycle_producer = mock.Mock(return_value={})
        thp_process_producer = mock.Mock(return_value={})
        process_vm_producer = mock.Mock(return_value={})
        observed = {}

        def focused_checks(_summary, _program, *, already_executed_check_ids, gate_name):
            observed["ids"] = set(already_executed_check_ids)
            observed["gate_name"] = gate_name
            return []

        with (
            mock.patch.object(
                RUNNER,
                "require_native_x86_64",
                return_value={
                    "execution_mode": "native",
                    "host_architecture": "x86_64",
                    "image_id": "sha256:" + "a" * 64,
                },
            ),
            mock.patch.object(
                RUNNER,
                "m2_memory_substrate_source_state",
                side_effect=[{"state": "before"}, {"state": "after"}],
            ),
            mock.patch.object(
                RUNNER,
                "validate_x86_64_m2_memory_substrate_contract",
                return_value=summary,
            ),
            mock.patch.object(RUNNER, "run_milestone0", return_value={}),
            mock.patch.object(
                RUNNER, "_x86_64_source_contract_evidence", return_value={"status": "passed"}
            ),
            mock.patch.object(
                RUNNER, "_m2_x86_64_bounded_source_evidence", return_value={"status": "passed"}
            ),
            mock.patch.object(RUNNER, "_x86_64_unit_test_program", return_value={}),
            mock.patch.multiple(
                RUNNER,
                run_m2_page_map_differential=mock.DEFAULT,
                run_m2_page_map_lazy_commit_failure_differential=mock.DEFAULT,
                run_m2_page_map_cold_init_differential=mock.DEFAULT,
            ),
            mock.patch.object(RUNNER, "_run_m2_x86_64_bitmap_evidence", return_value={}),
            mock.patch.object(RUNNER, "_m2_x86_64_bitmap_check_records", return_value=[]),
            mock.patch.object(
                RUNNER, "_run_m2_x86_64_vm_evidence", return_value={}
            ) as vm_producer,
            mock.patch.object(
                RUNNER,
                "_run_m2_x86_64_runtime_thp_configuration_evidence",
                return_value={},
            ) as runtime_thp_producer,
            mock.patch.multiple(
                RUNNER,
                _run_m2_x86_64_thp_process_evidence=thp_process_producer,
                _run_m2_x86_64_process_vm_evidence=process_vm_producer,
                _m2_x86_64_vm_check_records=vm_check_records_producer,
                _m2_x86_64_process_arena_collect_check_records=arena_records_producer,
                _run_m2_x86_64_arena_direct_evidence=mock.Mock(return_value={}),
                _m2_x86_64_arena_direct_check_records=mock.Mock(
                    return_value=direct_arena_records
                ),
                _run_m2_x86_64_arena_lifecycle_evidence=arena_lifecycle_producer,
                _m2_x86_64_arena_lifecycle_check_record=mock.Mock(
                    return_value=arena_lifecycle_record
                ),
                _m2_x86_64_metadata_check_records=metadata_records_producer,
                run_m2_x86_64_metadata_lifecycle_differential=metadata_lifecycle_producer,
                _run_m2_x86_64_metadata_ownership_evidence=mock.Mock(return_value={}),
                _run_m2_x86_64_initialization_teardown_evidence=mock.Mock(return_value={}),
                _m2_x86_64_init_tld_retry_producer=mock.Mock(return_value=tld_retry_producer),
                _m2_x86_64_init_tld_retry_check_record=mock.Mock(
                    return_value={"id": "initialization-later-tld-metadata-fault-retry-c-rust-differential"}
                ),
                _run_m2_x86_64_exclusive_arena_theap_evidence=mock.Mock(return_value={}),
                _run_m2_x86_64_arena_destruction_evidence=mock.Mock(return_value={}),
                _run_m2_x86_64_recursion_evidence=mock.Mock(return_value={}),
                _run_m2_x86_64_page_map_init_cleanup_evidence=mock.Mock(return_value={}),
                _m2_x86_64_page_map_init_cleanup_check_record=mock.Mock(
                    return_value={"id": "page-map-initialization-cleanup-leak-c-rust-differential"}
                ),
                _run_m2_x86_64_startup_statistics_evidence=mock.Mock(return_value={}),
                _run_m2_x86_64_page_map_fallback_evidence=mock.Mock(return_value={}),
                _m2_x86_64_page_map_fallback_check_record=mock.Mock(
                    side_effect=lambda check, evidence, **kwargs: {"id": check["id"]}
                ),
                _m2_x86_64_startup_statistics_check_record=mock.Mock(
                    return_value={"id": "page-map-startup-statistics-c-rust-differential"}
                ),
                _m2_x86_64_recursion_check_record=mock.Mock(
                    return_value={"id": "recursive-diagnostic-output-c-rust-differential"}
                ),
                _run_m2_x86_64_reservation_warnings_evidence=mock.Mock(return_value={}),
                _m2_x86_64_reservation_warnings_check_record=mock.Mock(
                    return_value={"id": "arena-reservation-warnings-c-rust-differential"}
                ),
                _m2_x86_64_arena_destruction_check_record=mock.Mock(
                    return_value={"id": "arena-destruction-c-rust-differential"}
                ),
            ),
            mock.patch.object(RUNNER, "_run_m2_x86_64_initialization_evidence", return_value={}) as initialization_producer,
            mock.patch.object(RUNNER, "_m2_x86_64_initialization_check_records", return_value=initialization_records),
            mock.patch.object(RUNNER, "_run_m2_x86_64_fault_evidence", return_value={}) as fault_producer,
            mock.patch.object(RUNNER, "_m2_x86_64_fault_check_records", return_value=fault_records),
            mock.patch.object(RUNNER, "_m2_x86_64_differential_check_record", return_value={}),
            mock.patch.object(
                RUNNER, "m2_memory_substrate_source_attestation", return_value={"status": "clean"}
            ),
            mock.patch.object(
                RUNNER, "_run_x86_64_focused_source_checks", side_effect=focused_checks
            ),
            mock.patch.object(
                RUNNER, "m2_x86_64_memory_substrate_report", return_value={"status": "captured"}
            ),
        ):
            self.assertEqual(
                RUNNER.run_x86_64_m2_memory_substrate(offline=True),
                {
                    "status": "captured",
                    "native_execution_provenance": {
                        "execution_mode": "native",
                        "host_architecture": "x86_64",
                        "image_id": "sha256:" + "a" * 64,
                    },
                },
            )

        self.assertEqual(observed["gate_name"], "native x86 M2 focused source evidence")
        vm_producer.assert_called_once_with(
            offline=True, test_program={}, arena_owned_check=arena_check
        )
        vm_check_records_producer.assert_called_once_with(summary, {}, {}, {}, {})
        arena_records_producer.assert_called_once_with(summary, {})
        arena_lifecycle_producer.assert_called_once_with(
            offline=True, test_program={}, check=arena_lifecycle_check
        )
        self.assertIn(arena_lifecycle_check["id"], observed["ids"])
        metadata_lifecycle_producer.assert_called_once()
        metadata_records_producer.assert_called_once_with(summary, {}, {})
        runtime_thp_producer.assert_called_once_with()
        thp_process_producer.assert_called_once_with(offline=True)
        process_vm_producer.assert_called_once_with(offline=True)
        initialization_producer.assert_called_once_with(offline=True)
        fault_producer.assert_called_once_with(offline=True, test_program={}, vm_evidence={})
        self.assertTrue(
            {record["id"] for record in vm_records}.issubset(observed["ids"])
        )
        self.assertTrue(
            {record["id"] for record in initialization_records}.issubset(observed["ids"])
        )
        self.assertTrue({record["id"] for record in fault_records}.issubset(observed["ids"]))
        self.assertTrue({record["id"] for record in arena_records}.issubset(observed["ids"]))
        self.assertTrue({record["id"] for record in direct_arena_records} <= observed["ids"])
        _, tld_retry_check = RUNNER._m2_x86_64_check_by_id(
            summary, "initialization-later-tld-metadata-fault-retry-c-rust-differential"
        )
        tld_retry_producer.run_evidence.assert_called_once_with(
            RUNNER, offline=True, test_program={}, check=tld_retry_check
        )
        self.assertIn(tld_retry_check["id"], observed["ids"])
        self.assertTrue({record["id"] for record in metadata_records}.issubset(observed["ids"]))
        owner_check = next(
            check
            for component in summary["components"]
            for check in component["checks"]
            if check["id"] == "process-main-thp-policy-owner-traversal"
        )
        self.assertEqual(
            owner_check["target"],
            "process_init::tests::process_main_thp_policy_owner_traversal",
        )
        self.assertNotIn(
            owner_check["id"],
            observed["ids"],
            "the full M2 dispatcher must leave this Rust owner check for its focused batch",
        )
        self.assertEqual(
            {
                "native-vm-fixed-lifecycle-differential",
                "aligned-hint-source-profile-and-direct-caller-matrix",
                "aligned-overmap-cleanup-c-rust-boundary-matrix",
                "second-arena-reset-advice-c-rust-matrix",
                "legacy-os-page-suffix-trim-and-raw-release",
                "process-os-page-suffix-trim-and-terminal-release",
                "process-os-page-block-commit-rollback-c-rust-differential",
                "runtime-source-environment-thp-ready-configuration-admission",
                "process-thp-madvise-success-c-rust-differential",
                "process-thp-madvise-failure-c-rust-differential",
                "process-thp-disabled-policy-c-rust-differential",
                "process-thp-inherited-disable-advice-c-rust-differential",
                "external-os-purge-commit-c-rust-differential",
                "external-os-commit-failure-c-rust-differential",
                "external-os-reset-policy-c-rust-differential",
                "external-os-reset-fallback-c-rust-differential",
                "external-os-no-advice-policy-c-rust-differential",
                "external-os-reset-retry-c-rust-differential",
                "explicit-arena-prefix-trim-c-rust-differential",
                "explicit-arena-suffix-trim-c-rust-differential",
                "explicit-arena-metadata-fault-c-rust-differential",
                "registered-arena-metadata-fault-c-rust-differential",
                "fresh-arena-dual-fault-c-rust-differential",
                "registered-arena-page-map-fault-c-rust-differential",
                "registered-arena-page-map-double-fault-c-rust-differential",
                "registered-arena-terminal-unmap-fault-c-rust-differential",
                "os-page-terminal-unmap-fault-c-rust-differential",
                "os-page-escaped-map-metadata-fault-c-rust-differential",
                "process-owned-protect-fault-c-rust-differential",
                "process-owned-unprotect-fault-c-rust-differential",
            },
            {record["id"] for record in vm_records},
        )

    def test_vm_producer_receipt_requires_the_exact_c_and_rust_producers(self):
        summary = self.summary()

        omitted_wrapper = self.vm_evidence(summary)
        omitted_wrapper["c_command"].remove("-Wl,--wrap=munmap")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, omitted_wrapper)

        wrong_source = self.vm_evidence(summary)
        wrong_source["c_command"].append("/pinned/src/os.c")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, wrong_source)

        wrong_profile = self.vm_evidence(summary)
        wrong_profile["aligned_hint_profile_c_commands"][1]["command"].remove(
            "-DMI_SECURE=1"
        )
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, wrong_profile)

        wrong_aligned_overmap_target = self.vm_evidence(summary)
        wrong_aligned_overmap_target["aligned_overmap_rust_command"][1] = (
            "os::tests::emit_m2_vm_primitives_c_rust_trace"
        )
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, wrong_aligned_overmap_target)

        for case, extra_arguments in {
            "extra-debug-macro": ["-DMI_DEBUG=1"],
            "contradictory-musl-macro": ["-DMI_LIBC_MUSL=0"],
            "forced-include": ["-include", "/pinned/unreviewed.h"],
            "extra-object": ["/pinned/unreviewed.o"],
            "extra-archive": ["/pinned/unreviewed.a"],
            "extra-link-option": ["-Wl,--as-needed"],
        }.items():
            with self.subTest(case=case):
                evidence = self.vm_evidence(summary)
                insertion = evidence["c_command"].index("-Wl,--wrap=munmap")
                evidence["c_command"][insertion:insertion] = extra_arguments
                with self.assertRaises(RUNNER.HarnessError):
                    RUNNER._m2_x86_64_vm_check_records(summary, evidence)

        wrong_target = self.vm_evidence(summary)
        target_position = wrong_target["rust_build_command"].index("--target") + 1
        wrong_target["rust_build_command"][target_position] = "aarch64-unknown-linux-musl"
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, wrong_target)

        wrong_features = self.vm_evidence(summary)
        locked_position = wrong_features["rust_build_command"].index("--locked")
        wrong_features["rust_build_command"][locked_position:locked_position] = [
            "--features",
            "native-runtime-test-fault",
        ]
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, wrong_features)

    def test_vm_producer_requires_source_wrappers_and_direct_private_source_closure(self):
        """The C record must observe source mmap, madvise, and mprotect imports."""

        summary = self.summary()

        without_mmap_wrap = self.vm_evidence(summary)
        without_mmap_wrap["c_command"].remove("-Wl,--wrap=mmap")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, without_mmap_wrap)

        without_madvise_wrap = self.vm_evidence(summary)
        without_madvise_wrap["c_command"].remove("-Wl,--wrap=madvise")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, without_madvise_wrap)

        without_mprotect_wrap = self.vm_evidence(summary)
        without_mprotect_wrap["c_command"].remove("-Wl,--wrap=mprotect")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, without_mprotect_wrap)

        without_prctl_wrap = self.vm_evidence(summary)
        without_prctl_wrap["c_command"].remove("-Wl,--wrap=prctl")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, without_prctl_wrap)

        direct_arena_source = self.vm_evidence(summary)
        direct_arena_source["c_command"].append("/pinned/src/arena.c")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, direct_arena_source)

        direct_init_source = self.vm_evidence(summary)
        direct_init_source["c_command"].append("/pinned/src/init.c")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, direct_init_source)

        direct_page_source = self.vm_evidence(summary)
        direct_page_source["c_command"].append("/pinned/src/page.c")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, direct_page_source)

        direct_primitive_source = self.vm_evidence(summary)
        direct_primitive_source["c_command"].append("/pinned/src/prim/prim.c")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, direct_primitive_source)


class ProcessOwnedProtectionFaultProducerTests(unittest.TestCase):
    def producers(self):
        for operation in ("protect", "unprotect"):
            path = RUNNER.ALLOCATOR_ROOT / f"m2_process_owned_{operation}_fault_x86_64.py"
            spec = importlib.util.spec_from_file_location(f"protection_fault_{operation}", path)
            producer = importlib.util.module_from_spec(spec)
            with mock.patch.dict(sys.modules, {"run": RUNNER}):
                spec.loader.exec_module(producer)
            yield operation, producer

    def output(self, operation, producer, language):
        marker = f"CRABC_M2_PROCESS_OWNED_{operation.upper()}_FAULT_{language}_TRACE"
        return (marker + "_BEGIN\n" +
                "\n".join(f"{key}={value}" for key, value in producer.expected().items()) +
                "\n" + marker + "_END\n")

    def test_protection_fault_producers_refuse_non_native_execution_before_building(self):
        for operation, producer in self.producers():
            with self.subTest(operation=operation), mock.patch.object(
                RUNNER, "require_native_x86_64", side_effect=RUNNER.HarnessError("not native")
            ), mock.patch.object(producer, "c_oracle", side_effect=AssertionError("non-native C build reached")) as oracle:
                with self.assertRaisesRegex(RUNNER.HarnessError, "not native"):
                    producer.run(offline=True, c_only=True)
                oracle.assert_not_called()

    def test_protection_fault_c_receipts_retain_commands_and_physical_output(self):
        RUNNER.WORK_ROOT.mkdir(parents=True, exist_ok=True)
        for operation, producer in self.producers():
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(dir=RUNNER.WORK_ROOT) as temporary:
                build = {"command": ["musl-gcc", "fixture.c"], "status": 0, "stdout": "", "stderr": ""}
                execution = {"command": ["pinned-c-oracle"], "status": 0,
                             "stdout": self.output(operation, producer, "C"), "stderr": ""}
                with mock.patch.object(producer, "ARTIFACTS", Path(temporary)), mock.patch.object(
                    RUNNER, "load_pin", return_value={"archive_root": "pinned"}
                ), mock.patch.object(RUNNER, "fetch_archive", return_value=Path(temporary)/"archive"), mock.patch.object(
                    RUNNER, "safe_extract", return_value=Path(temporary)
                ), mock.patch.object(RUNNER, "require_tool", return_value="musl-gcc"), mock.patch.object(
                    RUNNER, "command_record", side_effect=[build, execution]
                ):
                    values, receipt = producer.c_oracle(offline=True)
                self.assertEqual(values, producer.expected())
                self.assertEqual(json.loads((Path(temporary)/"pinned-c-build.json").read_text()), build)
                self.assertEqual(json.loads((Path(temporary)/"pinned-c-run.json").read_text()), execution)

    def test_protection_fault_rust_receipts_retain_exact_test_and_physical_output(self):
        for operation, producer in self.producers():
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(dir=RUNNER.WORK_ROOT) as temporary:
                event = {"reason": "compiler-artifact", "target": {"name": "crabc_mimalloc", "kind": ["lib"]},
                         "profile": {"test": True}, "executable": "/owned/crabc_mimalloc-hash"}
                build = {"command": ["cargo", "test"], "status": 0, "stdout": json.dumps(event), "stderr": ""}
                execution = {"command": [event["executable"], producer.TEST, "--exact", "--nocapture", "--test-threads=1"],
                             "status": 0, "stdout": self.output(operation, producer, "RUST") +
                             "test result: ok. 1 passed; 0 failed\n", "stderr": ""}
                with mock.patch.object(producer, "ARTIFACTS", Path(temporary)), mock.patch.object(
                    RUNNER, "command_record", side_effect=[build, execution]
                ):
                    values, receipt = producer.rust_receiver()
                self.assertEqual(values, producer.expected())
                self.assertEqual(json.loads((Path(temporary)/"rust-build.json").read_text()), build)
                self.assertEqual(json.loads((Path(temporary)/"rust-run.json").read_text()), execution)


if __name__ == "__main__":
    unittest.main()
