"""Fail-closed assembly regressions for native x86 M2 VM evidence."""

from __future__ import annotations

import copy
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
    "aligned-hint-source-profile-and-direct-caller-matrix",
    "aligned-overmap-cleanup-c-rust-boundary-matrix",
    "process-policy-first-arena-clean-primary-fallback",
    "process-policy-first-arena-retained-cleanup-statistics",
    "process-policy-ticket-zero-live-random",
    "aligned-map-direct-cleanup-owner",
    "aligned-map-prefix-cleanup-owner",
    "aligned-map-suffix-cleanup-owner",
    "aligned-map-complete-trim-sequence",
    "reset-advice-retry-snapshot",
    "aligned-map-os-page-claim-owner",
    "aligned-map-process-os-page-suffix-terminal-owner",
    "aligned-map-metadata-owner",
    "aligned-map-process-arena-owner",
    "normal-os-offset-full-provenance-and-release-retry",
    "process-offset-prefix-decommit-advisory-owner",
    "normal-no-callback-purge-policy-range-matrix",
    "normal-os-good-size-and-base-provenance",
    "normal-os-offset-zero-delegation-and-geometry",
    "normal-os-aligned-failure-owner",
    "normal-os-source-reservation-caller",
    "linux-os-reuse-contained-range-noop",
    "fixed-no-option-numa-cache-and-current-node-normalization",
    "native-protection-owner-and-retry",
    "normal-page-extension-direct-commit-failure-and-retry",
)

class NativeVmAssemblyTests(unittest.TestCase):
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
                for path in sorted((
                    "include/mimalloc/prim.h",
                    "src/arena.c",
                    "src/init.c",
                    "src/os.c",
                    "src/page.c",
                    "src/prim/prim.c",
                    "src/prim/unix/prim.c",
                ))
            ],
            "compared_value_count": len(producer.TRACE_KEYS),
            "comparison": {"compared_value_count": len(producer.TRACE_KEYS), "status": "matched"},
            "fixture": {"path": "compat/allocator/m2_vm_x86_64.c", "sha256": "b" * 64, "bytes": 1},
            "format": 1,
            "profile": producer.EVIDENCE_PROFILE,
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
        self.assertEqual(len(vm["checks"]), 33)
        self.assertEqual(len(vm["bounded_source_definitions"]), 20)
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
        contract["components"][0]["evidence_fragment"]["inventory_sha256"] = "0" * 64
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

    def test_vm_producer_receipt_rejects_missing_comparison_anchors_and_nonclaims(self):
        summary = self.summary()
        for field, replacement in (
            ("status", "partial"),
            ("compared_value_count", 34),
            ("source_anchors", []),
            ("nonclaims", []),
            ("aligned_overmap_comparison", {"status": "matched"}),
            ("aligned_overmap_c_trace_sha256", "not-a-digest"),
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
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["id"], "native-vm-fixed-lifecycle-differential")
        self.assertEqual(records[1]["id"], "aligned-hint-source-profile-and-direct-caller-matrix")
        self.assertEqual(records[2]["id"], "aligned-overmap-cleanup-c-rust-boundary-matrix")
        self.assertEqual(records[2]["comparison_status"], "expected-divergence-verified")

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
        observed = {}

        def focused_checks(_summary, _program, *, already_executed_check_ids, gate_name):
            observed["ids"] = set(already_executed_check_ids)
            observed["gate_name"] = gate_name
            return []

        with (
            mock.patch.object(RUNNER, "require_native_x86_64"),
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
            mock.patch.object(RUNNER, "run_m2_page_map_differential", return_value={}),
            mock.patch.object(
                RUNNER, "run_m2_page_map_lazy_commit_failure_differential", return_value={}
            ),
            mock.patch.object(RUNNER, "run_m2_page_map_cold_init_differential", return_value={}),
            mock.patch.object(RUNNER, "_run_m2_x86_64_bitmap_evidence", return_value={}),
            mock.patch.object(RUNNER, "_m2_x86_64_bitmap_check_records", return_value=[]),
            mock.patch.object(RUNNER, "_run_m2_x86_64_vm_evidence", return_value={}),
            mock.patch.object(
                RUNNER,
                "_run_m2_x86_64_runtime_thp_configuration_evidence",
                return_value={},
            ) as runtime_thp_producer,
            mock.patch.object(RUNNER, "_m2_x86_64_vm_check_records", return_value=vm_records),
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
                {"status": "captured"},
            )

        self.assertEqual(observed["gate_name"], "native x86 M2 focused source evidence")
        runtime_thp_producer.assert_called_once_with()
        self.assertTrue(
            {record["id"] for record in vm_records}.issubset(observed["ids"])
        )
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
                "runtime-source-environment-thp-ready-configuration-admission",
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


if __name__ == "__main__":
    unittest.main()
