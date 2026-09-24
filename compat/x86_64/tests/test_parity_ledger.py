#!/usr/bin/env python3
"""Focused contract tests for the x86 runtime-parity ledger."""

from __future__ import annotations

import copy
import importlib.util
import importlib
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "validate_parity_ledger.py"
SPEC = importlib.util.spec_from_file_location("x86_parity_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)
UNPATCHED_LOAD_TOML = ledger.load_toml


class X86ParityLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """Parse immutable checked inputs once; each test still owns a deep copy."""

        cls._ledger_template = ledger.load_toml(ledger.LEDGER_PATH)
        cls._header_template = ledger.load_toml(ledger.HEADER_LAYOUT_MANIFEST_PATH)
        cls._header_foundation_template = ledger.load_toml(
            ledger.HEADER_LAYOUT_FOUNDATION_MANIFEST_PATH
        )

    def data(self) -> dict[str, object]:
        if ledger.load_toml is UNPATCHED_LOAD_TOML:
            return copy.deepcopy(self._ledger_template)
        return copy.deepcopy(ledger.load_toml(ledger.LEDGER_PATH))

    def header_manifest(self) -> dict[str, object]:
        if ledger.load_toml is UNPATCHED_LOAD_TOML:
            return copy.deepcopy(self._header_template)
        return copy.deepcopy(ledger.load_toml(ledger.HEADER_LAYOUT_MANIFEST_PATH))

    def header_foundation_manifest(self) -> dict[str, object]:
        if ledger.load_toml is UNPATCHED_LOAD_TOML:
            return copy.deepcopy(self._header_foundation_template)
        return copy.deepcopy(ledger.load_toml(ledger.HEADER_LAYOUT_FOUNDATION_MANIFEST_PATH))

    def assert_source_contains(self, source: str, phrase: str, source_name: str) -> None:
        """Keep a missing source-contract phrase concise instead of dumping a runner."""

        self.assertTrue(phrase in source, f"{source_name} is missing {phrase!r}")

    def replace_required(
        self, source: str, old: str, new: str, source_name: str
    ) -> str:
        """Change a known contract phrase, never a silently absent substring."""

        self.assert_source_contains(source, old, source_name)
        changed = source.replace(old, new)
        self.assertNotEqual(changed, source, f"{source_name} replacement made no change")
        return changed

    @staticmethod
    def static_c_abi_exports() -> set[str]:
        """Read symbols through the validator's comment-aware export ratchet parser."""

        return set(
            ledger.static_c_abi_export_names(
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            )
        )

    def verified_artifact(
        self, family: dict[str, object], identifier: str
    ) -> dict[str, object]:
        """Find one leaf without coupling its test to siblings' progress count."""

        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        matching = [
            artifact
            for artifact in artifacts
            if isinstance(artifact, dict) and artifact.get("id") == identifier
        ]
        self.assertEqual(len(matching), 1, f"expected one verified artifact: {identifier}")
        return matching[0]

    @staticmethod
    def verified_records(data: dict[str, object]) -> dict[str, dict[str, object]]:
        records: dict[str, dict[str, object]] = {}
        families = data["family"]
        assert isinstance(families, list)
        for family in families:
            assert isinstance(family, dict)
            for kind in ("verified_artifact", "verified_slice"):
                entries = family.get(kind, [])
                assert isinstance(entries, list)
                for entry in entries:
                    assert isinstance(entry, dict)
                    records[entry["id"]] = entry
        return records

    @classmethod
    def select_process_globals_elsewhere(
        cls, data: dict[str, object], displaced: list[str]
    ) -> None:
        """Give the process.globals slice another slice's capabilities.

        Each c-abi-compat capability is selected once, so a test that points
        one slice at process.globals must swap, not duplicate, the selection
        to reach that slice's own exact-capability check.
        """
        slices = cls.family(data, "libc.c-abi-compat")["verified_slice"]
        assert isinstance(slices, list)
        target = next(entry for entry in slices if entry["id"] == "process.globals")
        target["capabilities"] = displaced

    @staticmethod
    def family(data: dict[str, object], identifier: str) -> dict[str, object]:
        entries = data["family"]
        assert isinstance(entries, list)
        for entry in entries:
            assert isinstance(entry, dict)
            if entry["id"] == identifier:
                return entry
        raise AssertionError(f"missing family: {identifier}")

    def test_checked_in_ledger_is_closed_and_not_a_public_support_claim(self) -> None:
        report = ledger.validate_ledger(self.data())
        self.assertEqual(report["schema"], "crabc.x86_64-runtime-parity/v3")
        self.assertEqual(report["family_count"], 26)
        self.assertEqual(report["capability_count"], 223)
        self.assertEqual(len(report["capability_owners"]), 223)
        self.assertEqual(
            report["feature_archive_count"],
            report["verified_feature_archive_count"] + report["planned_feature_archive_count"],
        )
        self.assertEqual(report["header_layout_probe_count"], 55)
        self.assertEqual(report["public_header_inventory_count"], 183)
        self.assertEqual(report["header_foundation_header_count"], 191)
        self.assertEqual(report["header_foundation_pinned_header_count"], 183)
        self.assertEqual(report["header_foundation_project_only_header_count"], 8)
        self.assertEqual(report["header_foundation_uapi_path_count"], 3)
        self.assertEqual(report["header_foundation_uapi_wrapper_matrix_row_count"], 21)
        self.assertEqual(report["header_foundation_ioctl_header_profile_matrix_row_count"], 7)
        self.assertEqual(report["header_foundation_sys_io_header_profile_matrix_row_count"], 7)
        self.assertEqual(report["header_foundation_epoll_header_profile_matrix_row_count"], 7)
        self.assertEqual(
            report["header_foundation_event_descriptors_header_profile_matrix_row_count"],
            16,
        )
        self.assertEqual(
            report["header_foundation_dirent_header_profile_matrix_row_count"],
            11,
        )
        self.assertEqual(
            report["header_foundation_stdlib_header_profile_matrix_row_count"],
            12,
        )
        self.assertEqual(
            report["header_foundation_timeval_transitive_header_profile_matrix_row_count"],
            35,
        )
        self.assertEqual(
            report["header_foundation_sys_time_direct_header_profile_matrix_row_count"],
            7,
        )
        self.assertEqual(
            report["header_foundation_access_header_profile_matrix_row_count"],
            8,
        )
        self.assertEqual(
            report["header_foundation_xattr_header_profile_matrix_row_count"],
            11,
        )
        self.assertEqual(
            report["header_foundation_feature_visibility_matrix_row_count"],
            1337,
        )
        self.assertEqual(
            report["header_foundation_prototype_layout_matrix_row_count"],
            1337,
        )
        self.assertEqual(
            report["header_foundation_record_layout_matrix_row_count"],
            1337,
        )
        self.assertEqual(report["header_foundation_language_profile_count"], 7)
        self.assertEqual(report["header_foundation_profile_obligation_count"], 21)
        self.assertEqual(report["header_foundation_profile_matrix_row_count"], 1337)
        self.assertEqual(report["header_foundation_abi_facet_count"], 25)
        self.assertEqual(report["header_foundation_linkage_owner_count"], 3)
        self.assertGreater(report["header_foundation_static_export_count"], 0)
        self.assertFalse(report["promotion_ready"])
        self.assertFalse(report["public_support"])

    def test_test_input_templates_are_isolated_and_honor_a_patched_loader(self) -> None:
        original = self.data()
        original["family"] = []
        self.assertNotEqual(self.data()["family"], [])

        header = self.header_manifest()
        header["probe"] = []
        self.assertNotEqual(self.header_manifest()["probe"], [])

        foundation = self.header_foundation_manifest()
        foundation["language_profile"] = []
        self.assertNotEqual(self.header_foundation_manifest()["language_profile"], [])

        replacement: dict[str, object] = {"family": []}
        with mock.patch.object(ledger, "load_toml", return_value=replacement) as load:
            self.assertEqual(self.data(), replacement)
        load.assert_called_once_with(ledger.LEDGER_PATH)
        with mock.patch.object(ledger, "load_toml", return_value=replacement) as load:
            self.assertEqual(self.header_manifest(), replacement)
            self.assertEqual(self.header_foundation_manifest(), replacement)
        self.assertEqual(
            load.call_args_list,
            [
                mock.call(ledger.HEADER_LAYOUT_MANIFEST_PATH),
                mock.call(ledger.HEADER_LAYOUT_FOUNDATION_MANIFEST_PATH),
            ],
        )

    def test_source_build_family_requires_both_owned_lua_product_lanes(self) -> None:
        family = self.family(self.data(), "consumer.source-build")
        evidence = family["native_evidence"]
        self.assertIsInstance(evidence, list)
        commands = {
            entry["command"]
            for entry in evidence
            if isinstance(entry, dict) and entry.get("state") == "required"
        }
        self.assertEqual(
            commands,
            {
                "./scripts/dev-x86_64.sh lua-source-build-admission",
            },
        )

    def test_source_build_foundation_replays_physical_lane_admission(self) -> None:
        source_build_root = ROOT / "compat" / "lua"
        if str(source_build_root) not in sys.path:
            sys.path.insert(0, str(source_build_root))
        import source_build_admission

        family = {
            "native_evidence": [
                {
                    "state": "verified",
                    "command": "./scripts/dev-x86_64.sh lua-source-build-admission",
                    "scope": "Both native Lua products.",
                }
            ]
        }
        with mock.patch.object(
            source_build_admission,
            "validate",
            side_effect=source_build_admission.LUA.RunnerError("missing physical lane receipt"),
        ):
            with self.assertRaisesRegex(ledger.LedgerError, "missing physical lane receipt"):
                ledger.require_lua_source_build_admission(family)

    def test_validate_ledger_reuses_successful_artifact_owner_checks_within_one_call(
        self,
    ) -> None:
        data = self.data()
        families = data["family"]
        assert isinstance(families, list)
        expected_checks = sum(
            len(artifact["source_owners"])
            for family in families
            if isinstance(family, dict)
            for artifact in family.get("verified_artifact", [])
            if isinstance(artifact, dict)
        )
        observed_checks = 0
        original_repository_path = ledger.repository_path

        def count_artifact_owner_path_checks(path_text: str, location: str) -> Path:
            nonlocal observed_checks
            if ".verified_artifact[" in location and ".source_owners[" in location:
                observed_checks += 1
            return original_repository_path(path_text, location)

        with mock.patch.object(
            ledger, "repository_path", count_artifact_owner_path_checks
        ):
            ledger.validate_ledger(data)

        self.assertEqual(observed_checks, expected_checks)

    def test_validate_ledger_rechecks_mutated_artifacts_on_a_later_call(self) -> None:
        data = self.data()
        ledger.validate_ledger(data)

        family = self.family(data, "libc.pthread-tls")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = artifacts[0]
        assert isinstance(artifact, dict)
        owners = artifact["source_owners"]
        assert isinstance(owners, list)
        owners.append("compat/x86_64/not-a-real-artifact-owner")

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "does not exist: compat/x86_64/not-a-real-artifact-owner",
        ):
            ledger.validate_ledger(data)

    def test_direct_artifact_validation_does_not_reuse_a_prior_result(self) -> None:
        data = self.data()
        family = self.family(data, "libc.pthread-tls")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        ledger.require_verified_artifacts(
            artifacts, "direct.verified_artifact", str(family["status"])
        )

        artifact = artifacts[0]
        assert isinstance(artifact, dict)
        owners = artifact["source_owners"]
        assert isinstance(owners, list)
        owners.append("compat/x86_64/not-a-real-direct-artifact-owner")
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "does not exist: compat/x86_64/not-a-real-direct-artifact-owner",
        ):
            ledger.require_verified_artifacts(
                artifacts, "direct.verified_artifact", str(family["status"])
            )

    def test_validate_ledger_restores_artifact_cache_after_reentrant_validation(self) -> None:
        data = self.data()
        nested_data = self.data()
        nested_family = self.family(nested_data, "libc.headers-layouts")
        nested_artifacts = nested_family["verified_artifact"]
        assert isinstance(nested_artifacts, list)
        nested_artifact = nested_artifacts[0]
        assert isinstance(nested_artifact, dict)
        nested_owners = nested_artifact["source_owners"]
        assert isinstance(nested_owners, list)
        nested_owners.append("compat/x86_64/not-a-real-reentrant-artifact-owner")

        original_validate_header_layout_manifest = ledger.validate_header_layout_manifest
        reentered = False

        def validate_header_layout_manifest_with_reentrant_failure(
            family: object, manifest: object
        ) -> dict[str, int]:
            nonlocal reentered
            if not reentered:
                reentered = True
                with self.assertRaisesRegex(
                    ledger.LedgerError,
                    "does not exist: compat/x86_64/not-a-real-reentrant-artifact-owner",
                ):
                    ledger.validate_ledger(nested_data)
            return original_validate_header_layout_manifest(family, manifest)

        with mock.patch.object(
            ledger,
            "validate_header_layout_manifest",
            validate_header_layout_manifest_with_reentrant_failure,
        ):
            ledger.validate_ledger(data)

        self.assertTrue(reentered)


    def test_feature_archive_roster_rejects_unverified_or_default_surface_confusion(self) -> None:
        data = self.data()
        report = ledger.validate_feature_archive_roster(
            data, self.verified_records(data)
        )
        feature_archives = data["feature_archive"]
        assert isinstance(feature_archives, list)
        self.assertEqual(report["feature_archive_count"], len(feature_archives))
        self.assertEqual(
            report["planned_feature_archive_count"],
            sum(entry["state"] == "planned" for entry in feature_archives),
        )
        self.assertEqual(
            report["verified_feature_archive_count"],
            sum(entry["state"] == "verified" for entry in feature_archives),
        )
        self.assertEqual(
            report["feature_archive_count"],
            report["planned_feature_archive_count"]
            + report["verified_feature_archive_count"],
        )
        string_duplication = next(
            entry for entry in feature_archives
            if entry["id"] == "x86-allocator-string-duplication"
        )
        assert isinstance(string_duplication, dict)
        string_duplication["baseline_features"] = []
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "baseline does not match its Cargo feature dependency closure",
        ):
            ledger.validate_feature_archive_roster(data, self.verified_records(data))

        data = self.data()
        feature_archives = data["feature_archive"]
        assert isinstance(feature_archives, list)
        a64l = next(
            entry for entry in feature_archives if entry["id"] == "x86-a64l"
        )
        assert isinstance(a64l, dict)
        a64l["additive_callables"] = ["clearenv"]
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "already default-static",
        ):
            ledger.validate_feature_archive_roster(data, self.verified_records(data))

        data = self.data()
        feature_archives = data["feature_archive"]
        assert isinstance(feature_archives, list)
        resolver = next(
            entry for entry in feature_archives
            if entry["id"] == "x86-resolver-runtime"
        )
        assert isinstance(resolver, dict)
        resolver.pop("evidence_record")
        with self.assertRaisesRegex(ledger.LedgerError, "keys drifted"):
            ledger.validate_feature_archive_roster(data, self.verified_records(data))


    def test_process_exec_artifact_stays_opt_in_and_non_promoting(self) -> None:
        family = self.family(self.data(), "libc.posix-runtime")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(entry for entry in artifacts if entry["id"] == "static-c-process-exec")
        assert isinstance(artifact, dict)
        self.assertNotIn("capabilities", artifact)
        description = artifact["description"]
        for phrase in (
            "x86-process-exec",
            "execve=59",
            "execveat=322",
            "AT_EMPTY_PATH=0x1000",
            "/proc/self/fd",
            "ENOSYS",
            "default `environment.rs`",
            "1,048,576-entry getenv lookup",
            "bounded mutation semantics",
            "unrestricted musl environment parity is not claimed",
            "strong",
            "weak same-address",
            "all `process.control`",
            "public x86 support",
        ):
            self.assertIn(phrase, description)
        self.assertEqual(
            artifact["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-process-exec",
        )

        archives = self.data()["feature_archive"]
        assert isinstance(archives, list)
        feature = next(entry for entry in archives if entry["id"] == "x86-process-exec")
        self.assertEqual(feature["enabled_features"], ["x86-process-exec"])
        self.assertEqual(
            feature["additive_callables"],
            ["execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe", "fexecve"],
        )
        self.assertEqual(
            feature["aliases"],
            [{"name": "execvpe", "target": "__execvpe", "binding": "weak-same-address"}],
        )


    def test_verified_artifact_rejects_duplicate_native_evidence_command(self) -> None:
        data = self.data()
        family = self.family(data, "libc.c-abi-compat")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry for entry in artifacts if entry["id"] == "static-c-error-strings"
        )
        assert isinstance(artifact, dict)
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and evidence
        record = evidence[0]
        assert isinstance(record, dict)
        evidence.append(copy.deepcopy(record))

        with self.assertRaisesRegex(
            ledger.LedgerError, "duplicates a native evidence command"
        ):
            ledger.validate_ledger(data)


    def test_planned_family_evidence_allows_completed_records_without_promotion(self) -> None:
        evidence = [
            {"state": "verified", "command": "completed", "scope": "completed"},
            {"state": "required", "command": "remaining", "scope": "remaining"},
        ]
        records, states = ledger.require_evidence(
            evidence, "family[fixture].native_evidence", "planned"
        )
        self.assertEqual(records, evidence)
        self.assertEqual(states, {"required", "verified"})
        with self.assertRaisesRegex(ledger.LedgerError, "must be a non-empty array"):
            ledger.require_evidence([], "family[fixture].native_evidence", "planned")
        with self.assertRaisesRegex(ledger.LedgerError, "state is invalid"):
            ledger.require_evidence(
                [{"state": "complete", "command": "fixture", "scope": "fixture"}],
                "family[fixture].native_evidence",
                "planned",
            )
        with self.assertRaisesRegex(ledger.LedgerError, "must be entirely verified"):
            ledger.require_evidence(
                [{"state": "required", "command": "remaining", "scope": "remaining"}],
                "family[fixture].native_evidence",
                "foundation-verified",
            )


    def test_allocator_wrapper_stays_mixed_runtime_and_non_promoting(self) -> None:
        data = self.data()
        family = self.family(data, "libc.posix-runtime")
        self.assertEqual(family["status"], "planned")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry for entry in artifacts if entry["id"] == "static-c-allocator-wrapper"
        )
        assert isinstance(artifact, dict)
        self.assertNotIn("capabilities", artifact)
        for phrase in (
            "mixed-runtime",
            "libmimalloc-sys` 0.1.49",
            "bundled mimalloc v3.3.2",
            "pinned musl 1.2.6",
            "reject every pinned-musl",
            "paused fixed-v3.5.0 Rust-port evidence",
            "not an owned runtime",
            "private `mi_*` globals",
            "all nine observed allocation calls",
            "reallocarray",
            "zero-alignment memalign",
            "4-KiB valloc",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])
        self.assertEqual(
            {entry["command"] for entry in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-allocator-runtime"},
        )

        changed = self.data()
        changed_artifacts = self.family(changed, "libc.posix-runtime")[
            "verified_artifact"
        ]
        assert isinstance(changed_artifacts, list)
        changed_artifact = next(
            entry
            for entry in changed_artifacts
            if entry["id"] == "static-c-allocator-wrapper"
        )
        changed_artifact["native_evidence"][0]["command"] = (
            "./scripts/dev-x86_64.sh libc-allocator-runtime-broad"
        )
        with self.assertRaisesRegex(
            ledger.LedgerError, "does not run libc-allocator-runtime"
        ):
            ledger.validate_ledger(changed)

    def test_allocator_string_duplication_stays_a_nonpromoting_client(self) -> None:
        data = self.data()
        family = self.family(data, "libc.posix-runtime")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if entry["id"] == "static-c-allocator-string-duplication"
        )
        assert isinstance(artifact, dict)
        self.assertNotIn("capabilities", artifact)
        for phrase in (
            "mixed-runtime",
            "`strdup`/`strndup`",
            "weak `malloc` ABI",
            "pinned musl",
            "allocator lifecycle",
            "`memory.allocator-basic`",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])
        self.assertEqual(
            {entry["command"] for entry in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-allocator-string-duplication"},
        )

        changed = self.data()
        changed_artifacts = self.family(changed, "libc.posix-runtime")[
            "verified_artifact"
        ]
        assert isinstance(changed_artifacts, list)
        changed_artifact = next(
            entry
            for entry in changed_artifacts
            if entry["id"] == "static-c-allocator-string-duplication"
        )
        changed_artifact["native_evidence"][0]["command"] = (
            "./scripts/dev-x86_64.sh libc-allocator-string-duplication-broad"
        )
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "does not run libc-allocator-string-duplication",
        ):
            ledger.validate_ledger(changed)


    def test_allocator_observability_is_exact_and_non_promoting(self) -> None:
        data = self.data()
        family = self.family(data, "libc.c-abi-compat")
        self.assertEqual(family["status"], "planned")
        slices = family["verified_slice"]
        assert isinstance(slices, list)
        slice_entry = next(
            entry for entry in slices if entry["id"] == "allocator-observability"
        )
        assert isinstance(slice_entry, dict)
        self.assertEqual(
            slice_entry["capabilities"], ["memory.allocator-observability"]
        )
        self.assertIn("strong `malloc_usable_size`", slice_entry["description"])
        self.assertIn("exact eleven-object pinned-musl support tail", slice_entry["description"])
        self.assertIn(
            "crabc ownership of `fputs`, `sleep`, and `__stack_chk_fail`",
            slice_entry["description"],
        )
        self.assertIn("`memory.allocator-basic`", slice_entry["description"])
        self.assertIn(
            "does not itself select `memory.allocator-basic`",
            slice_entry["description"],
        )
        self.assertIn("public x86 support", slice_entry["description"])
        self.assertEqual(
            {entry["command"] for entry in slice_entry["native_evidence"]},
            {
                "./scripts/dev-x86_64.sh libc-allocator-observability",
                "./scripts/dev-x86_64.sh owned-native-allocator-policy",
            },
        )

        changed = self.data()
        changed_slices = self.family(changed, "libc.c-abi-compat")[
            "verified_slice"
        ]
        assert isinstance(changed_slices, list)
        changed_slice = next(
            entry for entry in changed_slices if entry["id"] == "allocator-observability"
        )
        changed_slice["native_evidence"][0]["command"] = (
            "./scripts/dev-x86_64.sh libc-allocator-observability-broad"
        )
        with self.assertRaisesRegex(
            ledger.LedgerError, "does not run libc-allocator-observability"
        ):
            ledger.validate_ledger(changed)


    def test_stack_check_failure_stays_a_private_terminal_archive_pair(self) -> None:
        data = self.data()
        family = self.family(data, "libc.c-abi-compat")
        self.assertEqual(family["status"], "planned")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if entry["id"] == "static-c-stack-check-failure"
        )
        assert isinstance(artifact, dict)
        self.assertNotIn("capabilities", artifact)
        for owner in (
            "compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/stack_chk_fail.rs",
            "libc/src/c_abi/x86_64/static_startup.rs",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_stack_chk_fail_probe.c",
            "compat/x86_64/libc_stack_chk_fail_start.S",
            "compat/x86_64/run_libc_stack_chk_fail.sh",
            "compat/x86_64/aarch64_parity_inventory.py",
            "compat/x86_64/aarch64_parity_inventory.json",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(owner, artifact["source_owners"])
        for phrase in (
            "`__stack_chk_fail`",
            "`__stack_chk_fail_local`",
            "hidden weak same-address",
            "status 139 (`128 + SIGSEGV`)",
            "x86 `hlt`",
            "`__stack_chk_guard`",
            "`__init_ssp`",
            "terminal pair",
            "error.reporting-termination",
            "stack-protector startup policy",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])
        self.assertEqual(
            {entry["command"] for entry in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-stack-chk-fail"},
        )

        runner = (ROOT / "compat" / "x86_64" / "run_libc_stack_chk_fail.sh").read_text(
            encoding="utf-8"
        )
        for phrase in (
            "for unselected in __stack_chk_guard __init_ssp abort raise _Exit exit dlopen dlsym",
            "candidate accidentally selects ${unselected}",
            "__stack_chk_fail does not retain musl x86 hlt termination",
        ):
            self.assert_source_contains(runner, phrase, "run_libc_stack_chk_fail.sh")


    def test_public_fixed_graph_dlfcn_bridge_is_explicitly_non_promoting(self) -> None:
        data = self.data()
        family = self.family(data, "ldso.dynamic-runtime")
        self.assertEqual(family["status"], "planned")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry for entry in artifacts
            if entry["id"] == "ldso-public-fixed-graph-dlfcn"
        )
        assert isinstance(artifact, dict)
        self.assertNotIn("capabilities", artifact)
        for phrase in (
            "public-C dlfcn bridge artifact",
            "staged static `libc.a`",
            "weak_alias(static_dl_iterate_phdr, dl_iterate_phdr)",
            "normal/malformed isolated candidates retain default-visible `STB_WEAK`",
            "caller strong definition wins after a retained `dlopen` address forces bridge extraction",
            "weak_alias(stub_dlopen, dlopen)",
            "normal/malformed isolated candidates retain that weak `dlopen` binding",
            "caller strong `dlopen` definition wins after a retained `dlsym` address extracts the bridge",
            "weak_alias(stub_dladdr, dladdr)",
            "normal/malformed isolated candidates retain that weak `dladdr` binding",
            "caller strong `dladdr` definition wins after a retained `dlsym` address extracts the bridge",
            "All three are static-link ABI ratchets only",
            "real ET_DYN main",
            "never falls back to an ambient loader",
            "32-live-thread",
            "one-shot `dlerror`",
            "without PT_TLS",
            "exact one-shot `Unsupported request %d` diagnostic",
            "a subsequent valid link-map query preserves that pending error",
            "`dlclose` returns exactly one",
            "exact `Invalid library handle 0`",
            "The bridge admits only this null close diagnostic",
            "exact one-shot `Symbol not found: `",
            "loader failure reports `loader symbol name is invalid`",
            "non-empty missing names, null symbol pointers, and invalid handles retain their existing loader paths",
            "`dladdr(NULL)` returns zero",
            "caller’s `Dl_info` untouched",
            "leaves `dlerror` clear",
            "The bridge preserves that no-image result also for an admitted non-null address outside every retained fixed-image PT_LOAD",
            "non-null address outside every retained fixed-image PT_LOAD",
            "`addr2dso` yields no DSO",
            "`loader address not found`",
            "other non-null failure and unavailable-record paths retain their existing output-clearing fail-closed handling",
            "`dlopen(NULL, RTLD_NOLOAD)` returns the same permanent main handle",
            "`if (!file) return head`",
            "before inspecting `mode`",
            "only that exact flags value into its existing local main-token open",
            "`crabc_bounded_runtime_dlopen`",
            "bare-null `RTLD_NOLOAD` rejection",
            "`ldso/dynlink.c:dl_iterate_phdr`",
            "the first callback may consume its nonempty same-thread pending `dlerror`",
            "callback-driven mapping, graph mutation, or a general reentrant loader",
            "`RTLD_NEXT`",
            "`RTLD_GLOBAL`",
            "neither `loader.dlfcn-basic` nor `loader.dlfcn-introspection` is selected",
            "public x86 support is not promoted",
        ):
            self.assertIn(phrase, artifact["description"])
        self.assertEqual(
            {entry["command"] for entry in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh ldso-public-dlfcn"},
        )
        prerequisites = " ".join(artifact["x86_abi_prerequisites"])
        for phrase in (
            "AArch64 libc.so and libc.a ABI manifests retain dl_iterate_phdr, dladdr, dlclose, dlinfo, dlerror, dlsym, and dlopen exports",
            "src/ldso/dlinfo.c:dlinfo",
            "Unsupported request %d",
            "does not consume that pending state",
            "src/ldso/dlclose.c:dlclose",
            "ldso/dynlink.c:__dl_invalid_handle",
            "Invalid library handle 0",
            "non-null forged/stale close handling remains loader-owned",
            "src/ldso/dlsym.c:dlsym",
            "ldso/dynlink.c:do_dlsym",
            "Symbol not found: ",
            "loader symbol name is invalid",
            "non-empty missing names, null symbol pointers, and invalid handles retain their existing loader paths",
            "ldso/dynlink.c:dladdr",
            "if (!p) return 0",
            "dladdr(NULL)",
            "Dl_info",
            "p = addr2dso(addr)",
            "nonnull address outside every retained PT_LOAD",
            "loader address not found",
            "output-clearing fail-closed handling",
            "ldso/dynlink.c:dlopen",
            "if (!file) return head",
            "before inspecting `mode`",
            "dlopen(NULL, RTLD_NOLOAD=4)",
            "same permanent main token",
            "existing `RTLD_NOW` main route",
            "run_ldso_bounded_dlopen.sh",
            "crabc_bounded_runtime_dlopen",
            "bare `NULL RTLD_NOLOAD` retains the runtime sibling's initial-object rejection",
            "ldso/dynlink.c:dl_iterate_phdr",
            "before taking the reader lock for the next image",
            "consume an already-pending same-thread `dlerror` once",
            "callback-driven mapping, graph mutation, or general loader reentrancy",
        ):
            self.assertIn(phrase, prerequisites)
        scope = artifact["native_evidence"][0]["scope"]
        for phrase in (
            "request -7",
            "leaves its result pointer untouched",
            "exact `Unsupported request -7`",
            "valid RTLD_DI_LINKMAP query leaves that error pending",
            "dlclose(NULL) returns exactly one",
            "exact `Invalid library handle 0`",
            "non-null forged/stale close handling remains loader-owned",
            "empty-name dlsym branch",
            "exact `Symbol not found: `",
            "loader-confirmed `loader symbol name is invalid` failure",
            "seeded writable `Dl_info`",
            "dladdr(NULL)",
            "preserve it",
            "leave `dlerror` clear",
            "non-null address outside every graph PT_LOAD",
            "loader-confirmed `loader address not found`",
            "`dlopen(NULL, RTLD_NOLOAD)`",
            "both executions return the same main handle",
            "existing unknown-object failure",
            "first dl_iterate_phdr callback consumes its nonempty pending dlerror",
            "returns `74`",
            "leaves the next dlerror null",
            "callback-driven mapping",
        ):
            self.assertIn(phrase, scope)
        self.assertTrue(
            any(
                entry["kind"] == "aarch64-contract"
                and "aarch64/libc.so.dynamic.tsv" in entry["source"]
                and "dl_iterate_phdr, dladdr, dlclose, dlinfo, dlerror, dlsym, and dlopen exports" in entry["role"]
                and "not a behavioral fallback" in entry["role"]
                for entry in artifact["oracle"]
            )
        )
        self.assertTrue(
            any(
                entry["kind"] == "c-posix"
                and "ldso/dynlink.c" in entry["source"]
                and "callback-before-next-lock same-thread pending-dlerror consumption"
                in entry["role"]
                for entry in artifact["oracle"]
            )
        )
        self.assertEqual(
            set(artifact["source_owners"]),
            {
                "ldso/src/x86_64_initial_graph_source_root.rs",
                "ldso/src/x86_64_initial_graph.rs",
                "libc/src/c_abi/x86_64/fixed_graph_dlfcn.rs",
                "libc/src/c_abi/x86_64/fixed_graph_dlfcn_runtime.rs",
                "libc/src/c_abi/x86_64/static_c_abi.rs",
                "compat/x86_64/static_c_abi_exports.txt",
                "include/dlfcn.h",
                "include/link.h",
                "compat/x86_64/ldso_initial_graph_leaf.c",
                "compat/x86_64/ldso_initial_graph_mid.c",
                "compat/x86_64/ldso_public_dlfcn_start.S",
                "compat/x86_64/ldso_public_dlfcn_probe.c",
                "compat/x86_64/ldso_public_dlfcn_header_probe.cpp",
                "compat/x86_64/run_ldso_public_dlfcn.sh",
                "compat/x86_64/ldso_bounded_dlopen_probe.c",
                "compat/x86_64/run_ldso_bounded_dlopen.sh",
                "scripts/dev-x86_64.sh",
            },
        )

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "ldso.dynamic-runtime")["verified_artifact"]
        assert isinstance(changed_artifacts, list)
        changed_artifact = next(
            entry for entry in changed_artifacts
            if entry["id"] == "ldso-public-fixed-graph-dlfcn"
        )
        assert isinstance(changed_artifact, dict)
        changed_artifact["capabilities"] = ["loader.dlfcn-basic"]
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "must not carry capabilities",
        ):
            ledger.validate_ledger(changed)

    def test_fixed_graph_dladdr_symbol_bounds_stays_private_and_non_promoting(self) -> None:
        data = self.data()
        family = self.family(data, "ldso.dynamic-runtime")
        self.assertEqual(family["status"], "planned")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if entry["id"] == "ldso-fixed-graph-dladdr-symbol-bounds"
        )
        assert isinstance(artifact, dict)
        self.assertNotIn("capabilities", artifact)
        for phrase in (
            "finite-symbol `dladdr` metadata artifact",
            "no-TLS main PIE -> mid.so -> leaf.so graph",
            "four-byte `.dynsym` object",
            "local mapped padding",
            "first one-past byte",
            "zero-sized-symbol open-ended rule",
            "null symbol result rather than borrowing an empty string",
            "exact seven public `dl*` exports",
            "malformed/absent-record fail-closure",
            "does not select `dlopen`",
            "either dlfcn capability",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])
        self.assertEqual(
            {entry["command"] for entry in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh ldso-dladdr-symbol-bounds"},
        )
        self.assertEqual(
            set(artifact["source_owners"]),
            {
                "ldso/src/x86_64_initial_graph_source_root.rs",
                "ldso/src/x86_64_initial_graph.rs",
                "libc/src/c_abi/x86_64/fixed_graph_dlfcn.rs",
                "libc/src/c_abi/x86_64/fixed_graph_dlfcn_runtime.rs",
                "libc/src/c_abi/x86_64/static_c_abi.rs",
                "include/dlfcn.h",
                "compat/x86_64/static_c_abi_exports.txt",
                "compat/x86_64/ldso_public_dlfcn_start.S",
                "compat/x86_64/ldso_dladdr_symbol_bounds_dso.c",
                "compat/x86_64/ldso_dladdr_symbol_bounds_mid.c",
                "compat/x86_64/ldso_dladdr_symbol_bounds_probe.c",
                "compat/x86_64/run_ldso_dladdr_symbol_bounds.sh",
                "scripts/dev-x86_64.sh",
            },
        )

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "ldso.dynamic-runtime")["verified_artifact"]
        assert isinstance(changed_artifacts, list)
        changed_artifact = next(
            entry
            for entry in changed_artifacts
            if entry["id"] == "ldso-fixed-graph-dladdr-symbol-bounds"
        )
        assert isinstance(changed_artifact, dict)
        changed_artifact["capabilities"] = ["loader.dlfcn-introspection"]
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "must not carry capabilities",
        ):
            ledger.validate_ledger(changed)

    def test_bounded_runtime_dlopen_is_real_mapping_but_non_promoting(self) -> None:
        data = self.data()
        family = self.family(data, "ldso.dynamic-runtime")
        self.assertEqual(family["status"], "planned")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry for entry in artifacts
            if entry["id"] == "ldso-bounded-runtime-dlopen"
        )
        assert isinstance(artifact, dict)
        self.assertNotIn("capabilities", artifact)
        for phrase in (
            "bounded runtime-mapping artifact",
            "one append-only graph mutation",
            "real ELF64 ET_DYN DSO",
            "at most one nonzero executable `DT_INIT` entry",
            "at most one nonzero executable `DT_FINI` target",
            "initial main/mid/leaf `DT_INIT` remains reject-only",
            "initial main/mid/leaf `DT_FINI` remains reject-only",
            "exactly one nonempty aligned 1–16-entry load-contained `DT_PREINIT_ARRAY`/`DT_PREINIT_ARRAYSZ` pair",
            "matching pinned musl's inert runtime-DSO behavior",
            "initial main/mid/leaf preinit tags remain reject-only",
            "generation/additions one",
            "Two concurrent raw-clone callers",
            "RTLD_NOLOAD=4",
            "without a path lookup",
            "bare `dlopen(NULL, RTLD_NOLOAD)`",
            "RTLD_NODELETE=4096",
            "lifecycle-neutral flag",
            "PT_TLS",
            "DT_FINI_ARRAY",
            "a second runtime object",
            "legacy `DT_FINI` inert ordinary-close/reopen behavior",
            "neither `loader.dlfcn-basic` nor `loader.dlfcn-introspection` is selected",
            "public x86 support is not promoted",
        ):
            self.assertIn(phrase, artifact["description"])
        self.assertEqual(
            {entry["command"] for entry in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh ldso-bounded-dlopen"},
        )
        self.assertIn(
            "candidate copied-snapshot invariance and pinned-musl dlpi_adds reference difference",
            artifact["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "both RTLD_NOW and RTLD_LAZY",
            artifact["native_evidence"][0]["scope"],
        )
        for phrase in (
            "one executable `DT_INIT` entry before its bounded `DT_INIT_ARRAY`",
            "one executable `DT_FINI` entry without `DT_FINI_ARRAY`",
            "legacy `DT_FINI` remains inert across each final explicit close",
            "malformed non-executable runtime `DT_INIT`",
            "malformed non-executable runtime `DT_FINI`",
            "initial-DSO `DT_INIT` status-127 rejection",
            "initial-DSO `DT_FINI` status-127 rejection",
            "paired `DT_PREINIT_ARRAY`/`DT_PREINIT_ARRAYSZ` storage",
            "marker inert",
            "out-of-load pair fails before publication",
        ):
            self.assertIn(phrase, artifact["native_evidence"][0]["scope"])

        for phrase in (
            "NULL RTLD_NOLOAD",
            "bare `dlopen(NULL, RTLD_NOLOAD)`",
            "NULL RTLD_NODELETE",
            "named-initial-object RTLD_NODELETE",
            "RTLD_NOLOAD|RTLD_NODELETE",
            "RTLD_NODELETE close/reopen residency",
        ):
            self.assertIn(phrase, artifact["native_evidence"][0]["scope"])
        prerequisites = " ".join(artifact["x86_abi_prerequisites"])
        for phrase in (
            "private `crabc_bounded_runtime_dlopen`",
            "bare `dlopen(NULL, RTLD_NOLOAD)`",
            "NULL initial-object rejection",
        ):
            self.assertIn(phrase, prerequisites)
        self.assertEqual(
            set(artifact["source_owners"]),
            {
                "ldso/src/x86_64_initial_graph_source_root.rs",
                "ldso/src/x86_64_initial_graph.rs",
                "libc/src/c_abi/x86_64/fixed_graph_dlfcn.rs",
                "libc/src/c_abi/x86_64/fixed_graph_dlfcn_runtime.rs",
                "compat/x86_64/ldso_initial_graph_leaf.c",
                "compat/x86_64/ldso_initial_graph_mid.c",
                "compat/x86_64/ldso_public_dlfcn_start.S",
                "compat/x86_64/ldso_bounded_dlopen_plugin.c",
                "compat/x86_64/ldso_bounded_dlopen_preinit_plugin.c",
                "compat/x86_64/ldso_bounded_dlopen_tls.c",
                "compat/x86_64/ldso_bounded_dlopen_probe.c",
                "compat/x86_64/ldso_bounded_dlopen_preinit_probe.c",
                "compat/x86_64/ldso_bounded_dlopen_fini_probe.c",
                "compat/x86_64/run_ldso_bounded_dlopen.sh",
                "scripts/dev-x86_64.sh",
            },
        )

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "ldso.dynamic-runtime")["verified_artifact"]
        assert isinstance(changed_artifacts, list)
        changed_artifact = next(
            entry for entry in changed_artifacts
            if entry["id"] == "ldso-bounded-runtime-dlopen"
        )
        assert isinstance(changed_artifact, dict)
        changed_artifact["capabilities"] = ["loader.dlfcn-introspection"]
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "must not carry capabilities",
        ):
            ledger.validate_ledger(changed)


    def test_header_layout_manifest_is_a_closed_direct_probe_inventory(self) -> None:
        data = self.data()
        manifest = self.header_manifest()
        report = ledger.validate_ledger(data, header_layout_manifest=manifest)
        headers_layouts = self.family(data, "libc.headers-layouts")

        self.assertEqual(report["header_layout_probe_count"], 55)
        self.assertEqual(manifest["schema"], "crabc.x86_64-headers-layouts/v1")
        self.assertEqual(manifest["status"], "planned")
        self.assertEqual(manifest["family"], "libc.headers-layouts")
        self.assertEqual(
            headers_layouts["header_manifest"],
            "compat/x86_64/headers-layouts.toml",
        )
        self.assertIn(
            "compat/x86_64/headers-layouts.toml", headers_layouts["source_owners"]
        )
        self.assertNotIn("include", headers_layouts["source_owners"])
        for owner in (
            "compat/x86_64/stddef_header_abi_probe.c",
            "compat/x86_64/stddef_header_abi_probe.cpp",
            "compat/x86_64/run_stddef_header_abi.sh",
            "compat/x86_64/tests/test_stddef_header_abi.py",
            "compat/x86_64/tests/test_wchar_uchar_header_source.py",
            "include/stddef.h",
            "compat/x86_64/sys_io_header_abi_probe.c",
            "compat/x86_64/sys_io_header_abi_probe.cpp",
            "compat/x86_64/run_sys_io_header_abi.sh",
            "compat/x86_64/tests/test_sys_io_header_abi.py",
            "include/sys/io.h",
            "include/bits/io.h",
            "compat/x86_64/quota_header_abi_probe.c",
            "compat/x86_64/quota_header_abi_probe.cpp",
            "compat/x86_64/run_quota_header_abi.sh",
            "include/sys/quota.h",
            "compat/x86_64/sched_cpu_macros_header_abi_probe.c",
            "compat/x86_64/sched_cpu_macros_header_abi_probe.cpp",
            "compat/x86_64/run_sched_cpu_macros_header_abi.sh",
            "include/sched.h",
            "compat/x86_64/fanotify_header_abi_probe.c",
            "compat/x86_64/fanotify_header_abi_probe.cpp",
            "compat/x86_64/run_fanotify_header_abi.sh",
            "include/sys/fanotify.h",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])

        probes = manifest["probe"]
        assert isinstance(probes, list)
        self.assertEqual(
            [probe["id"] for probe in probes],
            list(ledger.EXPECTED_HEADER_LAYOUT_PROBES),
        )
        stddef = next(probe for probe in probes if probe["id"] == "stddef")
        assert isinstance(stddef, dict)
        self.assertEqual(stddef["kind"], "compile-only")
        self.assertEqual(stddef["headers"], ["include/stddef.h"])
        self.assertEqual(
            stddef["sources"],
            [
                "compat/x86_64/stddef_header_abi_probe.c",
                "compat/x86_64/stddef_header_abi_probe.cpp",
                "compat/x86_64/run_stddef_header_abi.sh",
            ],
        )
        stdio_standard = next(
            probe for probe in probes if probe["id"] == "stdio-standard"
        )
        assert isinstance(stdio_standard, dict)
        self.assertEqual(stdio_standard["kind"], "compile-only")
        self.assertEqual(stdio_standard["headers"], ["include/stdio.h"])
        self.assertEqual(
            stdio_standard["sources"],
            [
                "compat/x86_64/stdio_standard_header_abi_probe.c",
                "compat/x86_64/stdio_standard_header_abi_probe.cpp",
                "compat/x86_64/run_stdio_standard_header_abi.sh",
            ],
        )
        socket = next(probe for probe in probes if probe["id"] == "socket")
        assert isinstance(socket, dict)
        self.assertEqual(socket["kind"], "macro-runtime")
        self.assertEqual(
            socket["sources"],
            [
                "compat/x86_64/socket_header_abi_probe.c",
                "compat/x86_64/socket_header_abi_probe.cpp",
                "compat/x86_64/socket_header_ipv6_macro_probe.c",
                "compat/x86_64/run_socket_header_abi.sh",
            ],
        )
        tcp = next(probe for probe in probes if probe["id"] == "tcp")
        assert isinstance(tcp, dict)
        self.assertEqual(tcp["kind"], "compile-only")
        self.assertEqual(tcp["headers"], ["include/netinet/tcp.h"])
        self.assertEqual(
            tcp["sources"],
            [
                "compat/x86_64/tcp_header_abi_probe.c",
                "compat/x86_64/tcp_header_abi_probe.cpp",
                "compat/x86_64/run_tcp_header_abi.sh",
            ],
        )
        nameser = next(probe for probe in probes if probe["id"] == "nameser")
        assert isinstance(nameser, dict)
        self.assertEqual(nameser["kind"], "compile-only")
        self.assertEqual(nameser["headers"], ["include/resolv.h"])
        self.assertEqual(
            nameser["sources"],
            [
                "compat/x86_64/nameser_header_abi_probe.c",
                "compat/x86_64/nameser_header_abi_probe.cpp",
                "compat/x86_64/run_nameser_header_abi.sh",
            ],
        )
        quota = next(probe for probe in probes if probe["id"] == "quota")
        assert isinstance(quota, dict)
        self.assertEqual(quota["kind"], "compile-only")
        self.assertEqual(
            quota["headers"], ["include/stddef.h", "include/sys/quota.h"]
        )
        self.assertEqual(
            quota["sources"],
            [
                "compat/x86_64/quota_header_abi_probe.c",
                "compat/x86_64/quota_header_abi_probe.cpp",
                "compat/x86_64/run_quota_header_abi.sh",
            ],
        )
        sched_cpu_macros = next(
            probe for probe in probes if probe["id"] == "sched-cpu-macros"
        )
        assert isinstance(sched_cpu_macros, dict)
        self.assertEqual(sched_cpu_macros["kind"], "compile-only")
        self.assertEqual(sched_cpu_macros["headers"], ["include/sched.h"])
        self.assertEqual(
            sched_cpu_macros["sources"],
            [
                "compat/x86_64/sched_cpu_macros_header_abi_probe.c",
                "compat/x86_64/sched_cpu_macros_header_abi_probe.cpp",
                "compat/x86_64/run_sched_cpu_macros_header_abi.sh",
            ],
        )
        fanotify = next(probe for probe in probes if probe["id"] == "fanotify")
        assert isinstance(fanotify, dict)
        self.assertEqual(fanotify["kind"], "compile-only")
        self.assertEqual(
            fanotify["headers"], ["include/stddef.h", "include/sys/fanotify.h"]
        )
        self.assertEqual(
            fanotify["sources"],
            [
                "compat/x86_64/fanotify_header_abi_probe.c",
                "compat/x86_64/fanotify_header_abi_probe.cpp",
                "compat/x86_64/run_fanotify_header_abi.sh",
            ],
        )
        inet_address = next(probe for probe in probes if probe["id"] == "inet-address")
        assert isinstance(inet_address, dict)
        self.assertEqual(inet_address["kind"], "compile-only")
        self.assertEqual(
            inet_address["headers"], ["include/arpa/inet.h", "include/stddef.h"]
        )
        self.assertEqual(
            inet_address["sources"],
            [
                "compat/x86_64/inet_address_header_abi_probe.c",
                "compat/x86_64/inet_address_header_abi_probe.cpp",
                "compat/x86_64/run_inet_address_header_abi.sh",
            ],
        )
        math_complex = next(probe for probe in probes if probe["id"] == "math-complex")
        assert isinstance(math_complex, dict)
        self.assertEqual(math_complex["kind"], "macro-runtime")
        self.assertEqual(
            math_complex["headers"],
            [
                "include/complex.h",
                "include/float.h",
                "include/math.h",
                "include/tgmath.h",
            ],
        )
        self.assertEqual(
            math_complex["sources"],
            [
                "compat/x86_64/math_complex_header_abi_probe.c",
                "compat/x86_64/math_complex_header_abi_probe.cpp",
                "compat/x86_64/run_math_complex_header_abi.sh",
            ],
        )
        ioctl = next(probe for probe in probes if probe["id"] == "ioctl")
        assert isinstance(ioctl, dict)
        self.assertEqual(ioctl["kind"], "compile-only")
        self.assertEqual(ioctl["headers"], ["include/sys/ioctl.h"])
        self.assertEqual(
            ioctl["sources"],
            [
                "compat/x86_64/ioctl_header_abi_probe.c",
                "compat/x86_64/ioctl_header_abi_probe.cpp",
                "compat/x86_64/run_ioctl_header_abi.sh",
            ],
        )
        sys_io = next(probe for probe in probes if probe["id"] == "sys-io")
        assert isinstance(sys_io, dict)
        self.assertEqual(sys_io["kind"], "compile-only")
        self.assertEqual(sys_io["headers"], ["include/sys/io.h"])
        self.assertEqual(
            sys_io["sources"],
            [
                "compat/x86_64/sys_io_header_abi_probe.c",
                "compat/x86_64/sys_io_header_abi_probe.cpp",
                "compat/x86_64/run_sys_io_header_abi.sh",
            ],
        )
        epoll = next(probe for probe in probes if probe["id"] == "epoll")
        assert isinstance(epoll, dict)
        self.assertEqual(epoll["kind"], "compile-only")
        self.assertEqual(
            epoll["headers"],
            ["include/stddef.h", "include/sys/epoll.h", "include/sys/ioctl.h"],
        )
        self.assertEqual(
            epoll["sources"],
            [
                "compat/x86_64/epoll_header_abi_probe.c",
                "compat/x86_64/epoll_header_abi_probe.cpp",
                "compat/x86_64/run_epoll_header_abi.sh",
            ],
        )
        timeval_transitive = next(
            probe for probe in probes if probe["id"] == "timeval-transitive"
        )
        assert isinstance(timeval_transitive, dict)
        self.assertEqual(timeval_transitive["kind"], "compile-only")
        self.assertEqual(
            timeval_transitive["headers"],
            [
                "include/lastlog.h",
                "include/stddef.h",
                "include/sys/time.h",
                "include/sys/timex.h",
                "include/utmp.h",
                "include/utmpx.h",
            ],
        )
        self.assertEqual(
            timeval_transitive["sources"],
            [
                "compat/x86_64/timeval_transitive_header_abi_probe.c",
                "compat/x86_64/timeval_transitive_header_abi_probe.cpp",
                "compat/x86_64/run_timeval_transitive_header_abi.sh",
            ],
        )
        sys_time_direct = next(probe for probe in probes if probe["id"] == "sys-time-direct")
        assert isinstance(sys_time_direct, dict)
        self.assertEqual(sys_time_direct["kind"], "compile-only")
        self.assertEqual(
            sys_time_direct["headers"],
            ["include/stddef.h", "include/sys/time.h"],
        )
        self.assertEqual(
            sys_time_direct["sources"],
            [
                "compat/x86_64/sys_time_direct_header_abi_probe.c",
                "compat/x86_64/sys_time_direct_header_abi_probe.cpp",
                "compat/x86_64/run_sys_time_direct_header_abi.sh",
            ],
        )
        access_header = next(probe for probe in probes if probe["id"] == "access-header")
        assert isinstance(access_header, dict)
        self.assertEqual(access_header["kind"], "compile-only")
        self.assertEqual(
            access_header["headers"], ["include/fcntl.h", "include/unistd.h"]
        )
        self.assertEqual(
            access_header["sources"],
            [
                "compat/x86_64/access_header_abi_probe.c",
                "compat/x86_64/access_header_abi_probe.cpp",
                "compat/x86_64/run_access_header_abi.sh",
            ],
        )
        machine_context = next(
            probe for probe in probes if probe["id"] == "machine-context"
        )
        assert isinstance(machine_context, dict)
        self.assertEqual(machine_context["kind"], "compile-only")
        self.assertEqual(
            machine_context["headers"],
            [
                "include/stddef.h",
                "include/sys/auxv.h",
                "include/sys/ptrace.h",
                "include/sys/reg.h",
                "include/sys/user.h",
                "include/sys/procfs.h",
                "include/sys/ucontext.h",
            ],
        )
        self.assertEqual(
            machine_context["sources"],
            [
                "compat/x86_64/machine_context_header_abi_probe.c",
                "compat/x86_64/machine_context_header_abi_probe.cpp",
                "compat/x86_64/run_machine_context_header_abi.sh",
            ],
        )
        event_descriptors = next(
            probe for probe in probes if probe["id"] == "event-descriptors"
        )
        assert isinstance(event_descriptors, dict)
        self.assertEqual(event_descriptors["kind"], "compile-only")
        self.assertEqual(
            event_descriptors["headers"],
            [
                "include/stddef.h",
                "include/stdint.h",
                "include/sys/eventfd.h",
                "include/sys/inotify.h",
            ],
        )
        self.assertEqual(
            event_descriptors["sources"],
            [
                "compat/x86_64/event_descriptors_header_abi_probe.c",
                "compat/x86_64/event_descriptors_header_abi_probe.cpp",
                "compat/x86_64/run_event_descriptors_header_abi.sh",
            ],
        )
        aio_error = next(probe for probe in probes if probe["id"] == "aio-error")
        assert isinstance(aio_error, dict)
        self.assertEqual(aio_error["kind"], "compile-only")
        self.assertEqual(aio_error["headers"], ["include/aio.h"])
        self.assertEqual(
            aio_error["sources"],
            [
                "compat/x86_64/aio_error_header_abi_probe.c",
                "compat/x86_64/aio_error_header_abi_probe.cpp",
                "compat/x86_64/run_aio_error_header_abi.sh",
            ],
        )
        dirent = next(probe for probe in probes if probe["id"] == "dirent")
        assert isinstance(dirent, dict)
        self.assertEqual(dirent["kind"], "compile-only")
        self.assertEqual(
            dirent["headers"], ["include/dirent.h", "include/stddef.h"]
        )
        self.assertEqual(
            dirent["sources"],
            [
                "compat/x86_64/dirent_header_abi_probe.c",
                "compat/x86_64/dirent_header_abi_probe.cpp",
                "compat/x86_64/run_dirent_header_abi.sh",
            ],
        )

    def test_header_layout_manifest_rejects_scope_or_probe_drift(self) -> None:
        data = self.data()
        manifest = self.header_manifest()
        manifest["status"] = "foundation-verified"
        with self.assertRaisesRegex(ledger.LedgerError, "must remain planned"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

        data = self.data()
        manifest = self.header_manifest()
        probes = manifest["probe"]
        assert isinstance(probes, list)
        probes.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "probe count drifted"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

        data = self.data()
        manifest = self.header_manifest()
        probes = manifest["probe"]
        assert isinstance(probes, list) and isinstance(probes[0], dict)
        probes[0]["headers"] = ["include/time.h"]
        with self.assertRaisesRegex(ledger.LedgerError, "direct C/C\\+\\+ includes"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

        data = self.data()
        manifest = self.header_manifest()
        probes = manifest["probe"]
        assert isinstance(probes, list) and isinstance(probes[0], dict)
        probes[0]["sources"][-1] = "compat/x86_64/run_time_header_abi.sh"
        with self.assertRaisesRegex(ledger.LedgerError, "sources drifted"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

        data = self.data()
        manifest = self.header_manifest()
        probes = manifest["probe"]
        assert isinstance(probes, list) and isinstance(probes[0], dict)
        probes[0]["command"] = "./scripts/dev-x86_64.sh libc-foundation"
        with self.assertRaisesRegex(ledger.LedgerError, "command drifted"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

    def test_inet_address_header_gate_stays_compile_only_and_non_promoting(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        self.assertEqual(headers_layouts["status"], "foundation-verified")
        self.assertIn(
            "./scripts/dev-x86_64.sh header-declaration-macro-visibility-matrix",
            {entry["command"] for entry in headers_layouts["native_evidence"]},
        )
        for owner in (
            "include/arpa/inet.h",
            "include/stddef.h",
            "compat/x86_64/inet_address_header_abi_probe.c",
            "compat/x86_64/inet_address_header_abi_probe.cpp",
            "compat/x86_64/run_inet_address_header_abi.sh",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"] == "./scripts/dev-x86_64.sh inet-address-header-abi"
        )
        self.assertEqual(evidence["state"], "required")
        for phrase in (
            "default/GNU/strict C/C++",
            "<arpa/inet.h>",
            "`inet_pton`/`inet_ntop`/`inet_aton`/`inet_addr`/`inet_ntoa`/`inet_makeaddr`/`inet_lnaof`",
            "`in_addr_t`/`in_port_t`/`struct in_addr`",
            "archive linkage",
            "address-conversion runtime behavior",
            "DNS/resolver state",
            "netdb",
            "public x86 support",
        ):
            self.assertIn(phrase, evidence["scope"])

        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        header_evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"] == "./scripts/dev-x86_64.sh inet-address-header-abi"
        )
        header_evidence["scope"] = "header completion"
        with self.assertRaisesRegex(
            ledger.LedgerError, "inet-address-header-abi evidence must retain"
        ):
            ledger.validate_ledger(data)

    def test_socket_header_macro_gate_stays_header_only_and_non_promoting(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"] == "./scripts/dev-x86_64.sh socket-header-abi"
        )
        self.assertEqual(evidence["state"], "required")
        for phrase in (
            "project-first/pinned-musl C/C++",
            "IPv4/IPv6 address-equality/classification",
            "`__ARE_4_EQUAL`/`IN6_ARE_ADDR_EQUAL`",
            "`IN_CLASSA`/`IN_CLASSB`/`IN_CLASSC`/`IN_CLASSD`/`IN_MULTICAST`/`IN_EXPERIMENTAL`/`IN_BADCLASS`",
            "GNU/BSD `IP_MSFILTER_SIZE`/`GROUP_FILTER_SIZE`",
            "socket membership",
            "packet I/O",
            "resolver/netdb",
            "C networking runtime behavior",
        ):
            self.assertIn(phrase, evidence["scope"])

        ledger.require_socket_header_evidence(headers_layouts)

        evidence["scope"] = "header completion"
        with self.assertRaisesRegex(
            ledger.LedgerError, "socket-header-abi evidence must retain"
        ):
            ledger.require_socket_header_evidence(headers_layouts)

    def test_tcp_header_gate_stays_compile_only_and_non_promoting(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"] == "./scripts/dev-x86_64.sh tcp-header-abi"
        )
        self.assertEqual(evidence["state"], "required")
        for phrase in (
            "project-first/pinned-musl seven-profile C/C++",
            "`<netinet/tcp.h>`",
            "unconditional TCP option/state and netlink vocabulary",
            "GNU/BSD option-parser constants",
            "`tcp_seq`",
            "`struct tcphdr` 20-byte/align-4 legacy layout",
            "GNU-only `tcp_info`",
            "`tcp_md5sig`",
            "`tcp_diag_md5sig`",
            "`tcp_repair_window`",
            "`tcp_zerocopy_receive`",
            "anonymous GNU `tcphdr` aliases",
            "archive linkage",
            "TCP socket-option behavior",
            "TCP transport behavior",
            "socket runtime behavior",
            "installed-header completion",
            "family completion",
            "public x86 support",
        ):
            self.assertIn(phrase, evidence["scope"])

        for owner in (
            "include/netinet/tcp.h",
            "compat/x86_64/tcp_header_abi_probe.c",
            "compat/x86_64/tcp_header_abi_probe.cpp",
            "compat/x86_64/run_tcp_header_abi.sh",
            "compat/x86_64/tests/test_tcp_header_abi.py",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])

        ledger.require_tcp_header_evidence(headers_layouts)

        evidence["scope"] = "header completion"
        with self.assertRaisesRegex(
            ledger.LedgerError, "tcp-header-abi evidence must retain"
        ):
            ledger.require_tcp_header_evidence(headers_layouts)

    def test_stddef_header_gate_stays_compile_only_and_non_promoting(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"] == "./scripts/dev-x86_64.sh stddef-header-abi"
        )
        self.assertEqual(evidence["state"], "required")
        for phrase in (
            "project-first/pinned-musl seven-profile C/C++",
            "`<stddef.h>`",
            "`_STDDEF_H`",
            "`NULL`",
            "`__NEED_ptrdiff_t`/`__NEED_size_t`/`__NEED_wchar_t`/`__NEED_max_align_t`",
            "`bits/alltypes.h`",
            "LP64 `size_t`/`ptrdiff_t`/`wchar_t`",
            "`max_align_t`",
            "`offsetof`",
            "archive linkage",
            "allocation behavior",
            "installed-header completion",
            "family completion",
            "public x86 support",
        ):
            self.assertIn(phrase, evidence["scope"])

        for owner in (
            "include/stddef.h",
            "compat/x86_64/stddef_header_abi_probe.c",
            "compat/x86_64/stddef_header_abi_probe.cpp",
            "compat/x86_64/run_stddef_header_abi.sh",
            "compat/x86_64/tests/test_stddef_header_abi.py",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])

        ledger.require_stddef_header_evidence(headers_layouts)

        evidence["scope"] = "header completion"
        with self.assertRaisesRegex(
            ledger.LedgerError, "stddef-header-abi evidence must retain"
        ):
            ledger.require_stddef_header_evidence(headers_layouts)


    def test_nameser_record_classification_macro_gate_stays_header_only(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"] == "./scripts/dev-x86_64.sh nameser-header-abi"
        )
        self.assertEqual(evidence["state"], "required")
        for phrase in (
            "project-first/pinned-musl C/C++",
            "exact unconditional `ns_t_qt_p`/`ns_t_mrr_p`/`ns_t_rr_p`/`ns_t_udp_p`/`ns_t_xfr_p`",
            "`NS_NXT_BIT_SET`/`NS_NXT_BIT_CLEAR`/`NS_NXT_BIT_ISSET`",
            "record-classification macros",
            "strict C project-header trace exactly owns",
            "`bits/stdint.h`",
            "`bits/socket.h`",
            "rejects `sys/types.h`",
            "resolver state",
            "DNS packet I/O",
            "archive linkage",
            "installed-header completion",
            "family completion",
            "public x86 support",
        ):
            self.assertIn(phrase, evidence["scope"])

        ledger.require_nameser_header_evidence(headers_layouts)

        for owner in (
            "include/resolv.h",
            "include/stdint.h",
            "include/bits/alltypes.h",
            "include/bits/stdint.h",
            "include/arpa/nameser.h",
            "include/stddef.h",
            "include/netinet/in.h",
            "include/features.h",
            "include/inttypes.h",
            "include/sys/socket.h",
            "include/bits/socket.h",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])

        changed = copy.deepcopy(data)
        changed_headers_layouts = self.family(changed, "libc.headers-layouts")
        changed_headers_layouts["source_owners"].remove("include/bits/socket.h")
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "nameser-header-abi source owners omit include/bits/socket.h",
        ):
            ledger.require_nameser_header_evidence(changed_headers_layouts)

        evidence["scope"] = "header completion"
        with self.assertRaisesRegex(
            ledger.LedgerError, "nameser-header-abi evidence must retain"
        ):
            ledger.require_nameser_header_evidence(headers_layouts)

    def test_nameser_header_evidence_rejects_strict_trace_runner_drift(self) -> None:
        """The ledger must validate the runner's exact musl-owned trace."""
        headers_layouts = self.family(self.data(), "libc.headers-layouts")
        trace_headers = tuple(
            header.removeprefix("include/")
            for header in ledger.EXPECTED_NAMESER_STRICT_C_TRACE_HEADERS
        )

        def write_runner(
            root: Path,
            headers: tuple[str, ...],
            forbidden: tuple[str, ...],
        ) -> None:
            runner = root / "compat" / "x86_64" / "run_nameser_header_abi.sh"
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text(
                "readonly STRICT_C_PROJECT_HEADERS=(\n"
                + "".join(f'    "{header}"\n' for header in headers)
                + ")\nreadonly STRICT_C_FORBIDDEN_HEADERS=(\n"
                + "".join(f'    "{header}"\n' for header in forbidden)
                + ")\n"
                + 'fail "strict C probe unexpectedly used project <$header>"\n'
                + 'fail "strict C trace project header closure diverges from pinned musl"\n',
                encoding="utf-8",
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(ledger, "ROOT", root):
                write_runner(root, trace_headers[:-1], ("sys/types.h",))
                with self.assertRaisesRegex(
                    ledger.LedgerError,
                    "strict C nameser project-header trace drifted",
                ):
                    ledger.require_nameser_header_evidence(headers_layouts)

                write_runner(root, trace_headers, ())
                with self.assertRaisesRegex(
                    ledger.LedgerError,
                    "strict C nameser forbidden-header trace drifted",
                ):
                    ledger.require_nameser_header_evidence(headers_layouts)

                write_runner(
                    root,
                    trace_headers + ("sys/types.h",),
                    ("sys/types.h",),
                )
                with self.assertRaisesRegex(
                    ledger.LedgerError,
                    "strict C nameser project-header trace drifted",
                ):
                    ledger.require_nameser_header_evidence(headers_layouts)

                write_runner(
                    root,
                    trace_headers,
                    ("sys/types.h", "unexpected.h"),
                )
                with self.assertRaisesRegex(
                    ledger.LedgerError,
                    "strict C nameser forbidden-header trace drifted",
                ):
                    ledger.require_nameser_header_evidence(headers_layouts)

    def test_complete_quota_header_gate_stays_header_only(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"] == "./scripts/dev-x86_64.sh quota-header-abi"
        )
        self.assertEqual(evidence["state"], "required")
        for phrase in (
            "project-first/pinned-musl C/C++",
            "full pinned-musl quota header",
            "exact unconditional `dbtob`/`btodb`/`fs_to_dq_blocks`/`dqoff`",
            "quota constants/masks",
            "legacy `dq_*` aliases",
            "`dqblk`/`dqinfo` LP64 layouts",
            "C/C++ `quotactl` declaration",
            "compile-only",
            "quotactl archive/runtime behavior",
            "quota policy/accounting",
            "filesystem/kernel state",
            "system.kernel-admin",
            "installed-header completion",
            "family completion",
            "public support",
        ):
            self.assertIn(phrase, evidence["scope"])

        ledger.require_quota_header_evidence(headers_layouts)

        evidence["scope"] = "header completion"
        with self.assertRaisesRegex(
            ledger.LedgerError, "quota-header-abi evidence must retain"
        ):
            ledger.require_quota_header_evidence(headers_layouts)

    def test_sched_cpu_macro_gate_stays_header_only(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"]
            == "./scripts/dev-x86_64.sh sched-cpu-macros-header-abi"
        )
        self.assertEqual(evidence["state"], "required")
        for phrase in (
            "project-first/pinned-musl C/C++",
            "<sched.h>",
            "exact GNU `__CPU_op_S`/`CPU_SET_S`/`CPU_CLR_S`/`CPU_ISSET_S`",
            "`CPU_ALLOC_SIZE`/`CPU_ALLOC`/`CPU_FREE`",
            "generated `__CPU_AND_S`/`__CPU_OR_S`/`__CPU_XOR_S`",
            "`CPU_SETSIZE`",
            "canonical C++ strict visibility",
            "forced-macro-hidden negative selection",
            "archive linkage",
            "allocator runtime behavior",
            "byte-string runtime behavior",
            "scheduler policy/affinity",
            "installed-header completion",
            "family completion",
            "public x86 support",
        ):
            self.assertIn(phrase, evidence["scope"])

        ledger.require_sched_cpu_macros_header_evidence(headers_layouts)

        evidence["scope"] = "header completion"
        with self.assertRaisesRegex(
            ledger.LedgerError, "sched-cpu-macros-header-abi evidence must retain"
        ):
            ledger.require_sched_cpu_macros_header_evidence(headers_layouts)

    def test_fanotify_traversal_macro_gate_stays_header_only(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"] == "./scripts/dev-x86_64.sh fanotify-header-abi"
        )
        self.assertEqual(evidence["state"], "required")
        for phrase in (
            "project-first/pinned-musl",
            "seven-profile C/C++",
            "<sys/fanotify.h>",
            "Linux 5.10",
            "`fanotify_event_metadata` LP64 layout",
            "`FAN_EVENT_METADATA_LEN`",
            "exact unconditional `FAN_EVENT_NEXT`/`FAN_EVENT_OK`",
            "C/C++ result types",
            "canonical strict C++ visibility",
            "record traversal macros",
            "archive linkage",
            "fanotify_init/fanotify_mark archive/runtime behavior",
            "descriptor creation",
            "kernel watcher state",
            "watcher policy",
            "installed-header completion",
            "family completion",
            "public x86 support",
        ):
            self.assertIn(phrase, evidence["scope"])

        ledger.require_fanotify_header_evidence(headers_layouts)

        evidence["scope"] = "header completion"
        with self.assertRaisesRegex(
            ledger.LedgerError, "fanotify-header-abi evidence must retain"
        ):
            ledger.require_fanotify_header_evidence(headers_layouts)

    def test_ctype_header_macro_gate_stays_header_only_and_non_promoting(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        evidence = next(
            entry
            for entry in headers_layouts["native_evidence"]
            if entry["command"] == "./scripts/dev-x86_64.sh ctype-header-abi"
        )
        self.assertEqual(evidence["state"], "required")
        for phrase in (
            "project-first/pinned-musl C/C++",
            "fourteen ordinary ctype declarations",
            "C-only `__isspace` inline",
            "exact `isalpha`/`isdigit`/`islower`/`isupper`/`isprint`/`isgraph`/`isspace`",
            "all C feature profiles",
            "C++-hidden",
            "C-only exact `isascii` macro",
            "`toascii` declaration",
            "exact bitwise `_tolower`/`_toupper`",
            "POSIX/XOPEN/GNU/BSD C-visible",
            "strict-C-hidden",
            "compiler-native C++17",
            "archive linkage",
            "C-locale runtime behavior",
            "header-family completion",
            "public support",
        ):
            self.assertIn(phrase, evidence["scope"])

        family_header_prerequisites = headers_layouts["x86_header_prerequisites"]
        assert isinstance(family_header_prerequisites, list)
        family_header_contract = "\n".join(family_header_prerequisites)
        for phrase in (
            "POSIX/XOPEN/GNU/BSD C-visible and strict-C-hidden `toascii` declaration",
            "C-only exact `isascii` macro",
            "exact bitwise _tolower/_toupper macro replacements",
            "compiler-native C++17 profile",
            "macros select no archive linkage",
        ):
            self.assertIn(phrase, family_header_contract)

        ledger.require_ctype_header_evidence(headers_layouts)

        posix_runtime = self.family(data, "libc.posix-runtime")
        ctype_artifact = next(
            entry
            for entry in posix_runtime["verified_artifact"]
            if entry["id"] == "static-c-ctype"
        )
        header_prerequisites = ctype_artifact["x86_header_prerequisites"]
        assert isinstance(header_prerequisites, list)
        header_contract = "\n".join(header_prerequisites)
        for phrase in (
            "exact bitwise `_tolower`/`_toupper`",
            "POSIX/XOPEN/GNU/BSD C-visible",
            "strict-C-hidden",
            "compiler-native C++17",
            "no archive linkage",
        ):
            self.assertIn(phrase, header_contract)

        evidence["scope"] = "header completion"
        with self.assertRaisesRegex(
            ledger.LedgerError, "ctype-header-abi evidence must retain"
        ):
            ledger.require_ctype_header_evidence(headers_layouts)

    def test_header_foundation_manifest_accounts_for_all_paths_without_promotion(self) -> None:
        data = self.data()
        manifest = self.header_foundation_manifest()
        report = ledger.validate_ledger(
            data, header_layout_foundation_manifest=manifest
        )
        headers_layouts = self.family(data, "libc.headers-layouts")

        # The aggregate is the foundation proof.  The family-level entries
        # deliberately keep the C-ABI and runtime leaves required so this
        # header-only transition cannot imply their completion.
        self.assertEqual(headers_layouts["status"], "foundation-verified")
        self.assertEqual(
            {entry["state"] for entry in headers_layouts["native_evidence"]},
            {"required"},
        )

        self.assertEqual(
            manifest["schema"], "crabc.x86_64-headers-layouts-foundation/v19"
        )
        self.assertEqual(manifest["status"], "foundation-verified")
        self.assertEqual(manifest["family"], "libc.headers-layouts")
        self.assertEqual(
            headers_layouts["header_foundation_manifest"],
            "compat/x86_64/headers-layouts-foundation.toml",
        )
        self.assertIn(
            "compat/x86_64/headers-layouts-foundation.toml",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/headers_layouts_aggregate.py",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/run_headers_layouts_aggregate.sh",
            headers_layouts["source_owners"],
        )
        self.assertIn("compat/upstreams.toml", headers_layouts["source_owners"])
        self.assertIn(
            "compat/x86_64/header_callable_visibility_matrix.toml",
            headers_layouts["source_owners"],
        )
        for owner in (
            "compat/x86_64/header_callable_extension_contract.toml",
            "compat/x86_64/header_callable_extension_contract.py",
            "compat/x86_64/tests/test_header_callable_extension_contract.py",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        self.assertIn(
            "compat/x86_64/header_callable_disposition.toml",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/header_callable_disposition.py",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/header_callable_disposition.json",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/run_header_callable_disposition.sh",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/run_header_callable_visibility_matrix.sh",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/header_abi_matrix.toml",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/header_record_layout_matrix.toml",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/header_record_layout_matrix.py",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/run_header_record_layout_matrix.sh",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/run_header_abi_matrix.sh",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/tests/test_event_descriptors_header_abi.py",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/tests/test_dirent_header_abi.py",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/run_stdlib_header_abi.sh",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/stdlib_header_abi_probe.c",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/stdlib_header_abi_probe.cpp",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/run_xattr_header_abi.sh",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/xattr_header_abi_probe.c",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/xattr_header_abi_probe.cpp",
            headers_layouts["source_owners"],
        )
        self.assertEqual(report["header_foundation_header_count"], 191)
        self.assertEqual(report["header_foundation_profile_matrix_row_count"], 1337)
        self.assertEqual(report["header_foundation_uapi_wrapper_matrix_row_count"], 21)
        self.assertEqual(report["header_foundation_ioctl_header_profile_matrix_row_count"], 7)
        self.assertEqual(report["header_foundation_sys_io_header_profile_matrix_row_count"], 7)
        self.assertEqual(report["header_foundation_epoll_header_profile_matrix_row_count"], 7)
        self.assertEqual(
            report["header_foundation_event_descriptors_header_profile_matrix_row_count"],
            16,
        )
        self.assertEqual(
            report["header_foundation_dirent_header_profile_matrix_row_count"],
            11,
        )
        self.assertEqual(
            report["header_foundation_stdlib_header_profile_matrix_row_count"],
            12,
        )
        self.assertEqual(
            report["header_foundation_timeval_transitive_header_profile_matrix_row_count"],
            35,
        )
        self.assertEqual(
            report["header_foundation_sys_time_direct_header_profile_matrix_row_count"],
            7,
        )
        self.assertEqual(
            report["header_foundation_xattr_header_profile_matrix_row_count"],
            11,
        )
        self.assertEqual(
            report["header_foundation_callable_feature_visibility_matrix_row_count"],
            1337,
        )
        self.assertEqual(
            report["header_foundation_feature_visibility_matrix_row_count"],
            1337,
        )
        self.assertEqual(
            report["header_foundation_prototype_layout_matrix_row_count"],
            1337,
        )
        self.assertEqual(
            report["header_foundation_record_layout_matrix_row_count"],
            1337,
        )
        aggregate_control = manifest["aggregate_control"]
        assert isinstance(aggregate_control, dict)
        self.assertEqual(
            aggregate_control["command"],
            "./scripts/dev-x86_64.sh headers-layouts-aggregate",
        )
        self.assertEqual(
            aggregate_control["completion_algorithm"], "header-foundation-v1"
        )
        self.assertNotIn("family_completion", aggregate_control)
        self.assertFalse(aggregate_control["family_promotion"])
        self.assertFalse(aggregate_control["public_support"])
        self.assertEqual(aggregate_control["direct_probe_count"], 55)
        self.assertEqual(aggregate_control["profile_obligation_count"], 21)
        header_completion_assessment = manifest["header_completion_assessment"]
        assert isinstance(header_completion_assessment, dict)
        self.assertEqual(
            header_completion_assessment["algorithm"], "header-foundation-v1"
        )
        self.assertEqual(
            header_completion_assessment["required_dimensions"],
            [
                "installed-surface",
                "declaration-identity",
                "declaration-source-forms",
                "callable-visibility",
                "prototype-or-named-declarations",
                "record-byte-layouts",
                "callable-ownership-routing",
            ],
        )
        self.assertEqual(
            header_completion_assessment["deferred_linkage_owner_family"],
            "libc.c-abi-compat",
        )
        self.assertEqual(
            header_completion_assessment["deferred_linkage_owner_obligation"],
            "final-callable-provider-archive-closure",
        )
        feature_visibility = manifest["feature_visibility_matrix"]
        assert isinstance(feature_visibility, dict)
        self.assertEqual(
            feature_visibility["command"],
            "./scripts/dev-x86_64.sh header-declaration-macro-visibility-matrix",
        )
        self.assertEqual(feature_visibility["required_result"], "checked-finite-report")
        self.assertEqual(
            feature_visibility["comparison_counts"],
            {
                "candidate-only-reviewed-native-callable-extension": 28,
                "candidate-only-reviewed-project-c-abi-extension": 56,
                "matched": 1252,
                "oracle-not-applicable": 1,
            },
        )
        self.assertEqual(
            feature_visibility["identity_difference_counts"],
            {"candidate_only": 0, "reference_only": 0},
        )
        callable_visibility = manifest["callable_feature_visibility_matrix"]
        assert isinstance(callable_visibility, dict)
        self.assertEqual(
            callable_visibility["command"],
            "./scripts/dev-x86_64.sh header-callable-visibility-matrix",
        )
        self.assertEqual(callable_visibility["required_result"], "checked-finite-report")
        prototype_layout = manifest["prototype_layout_matrix"]
        assert isinstance(prototype_layout, dict)
        self.assertEqual(
            prototype_layout["command"],
            "./scripts/dev-x86_64.sh header-abi-matrix",
        )
        self.assertEqual(prototype_layout["required_result"], "checked-finite-report")
        self.assertEqual(
            prototype_layout["comparison_counts"],
            {
                "candidate-only-reviewed-native-callable-extension": 28,
                "candidate-only-reviewed-project-c-abi-extension": 56,
                "matched": 1252,
                "oracle-not-applicable": 1,
            },
        )
        record_layout = manifest["record_layout_matrix"]
        assert isinstance(record_layout, dict)
        self.assertEqual(
            record_layout["command"],
            "./scripts/dev-x86_64.sh header-record-layout-matrix",
        )
        self.assertEqual(record_layout["required_result"], "checked-finite-report")
        self.assertEqual(
            record_layout["comparison_counts"],
            {
                "candidate-only-reviewed-project-c-abi-extension": 56,
                "matched": 1280,
                "oracle-not-applicable": 1,
            },
        )
        disposition = manifest["callable_disposition"]
        assert isinstance(disposition, dict)
        self.assertEqual(
            disposition["command"],
            "./scripts/dev-x86_64.sh header-callable-disposition",
        )
        self.assertEqual(disposition["candidate_external_callable_count"], 1526)
        self.assertEqual(disposition["default_static_callable_count"], 1123)
        self.assertEqual(disposition["verified_feature_callable_count"], 78)
        for field in (
            "declared_unverified_feature_callable_count",
            "unprovided_callable_count",
        ):
            self.assertNotIn(field, disposition)
        self.assertEqual(disposition["missing_reference_declaration_name_count"], 0)
        self.assertEqual(disposition["missing_reference_declaration_record_count"], 0)
        self.assertTrue(disposition["missing_reference_declaration_routing_complete"])
        self.assertTrue(disposition["header_ownership_routing_complete"])
        self.assertFalse(disposition["header_declaration_parity_complete"])
        self.assertFalse(disposition["final_provider_archive_closure_complete"])
        self.assertFalse(disposition["family_promotion"])
        self.assertFalse(disposition["public_support"])
        provider_audit = manifest["selected_callable_provider_linkage_audit"]
        assert isinstance(provider_audit, dict)
        self.assertEqual(
            provider_audit["command"],
            "./scripts/dev-x86_64.sh header-callable-provider-linkage-audit",
        )
        self.assertEqual(provider_audit["candidate_external_callable_count"], 1526)
        self.assertEqual(provider_audit["default_static_callable_count"], 1123)
        self.assertEqual(provider_audit["verified_feature_callable_count"], 78)
        self.assertEqual(provider_audit["verified_feature_profile_count"], 28)
        for field in (
            "declared_unverified_feature_callable_count",
            "unprovided_callable_count",
        ):
            self.assertNotIn(field, provider_audit)
        self.assertEqual(provider_audit["topology_only_profile_count"], 1)
        self.assertTrue(provider_audit["ordinary_archive_extraction"])
        self.assertFalse(provider_audit["uses_whole_archive"])
        self.assertFalse(provider_audit["full_callable_closure"])
        self.assertFalse(provider_audit["family_promotion"])
        self.assertFalse(provider_audit["public_support"])
        self.assertIn(
            "compat/x86_64/header_callable_provider_linkage_audit.py",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/run_header_callable_provider_linkage_audit.sh",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/tests/test_header_callable_provider_linkage_audit.py",
            headers_layouts["source_owners"],
        )

        classes = manifest["header_class"]
        assert isinstance(classes, list)
        self.assertEqual(
            [entry["id"] for entry in classes],
            [
                "pinned-non-uapi",
                "pinned-uapi-inputs",
                "project-only-extensions",
            ],
        )
        uapi = classes[1]
        project_only = classes[2]
        assert isinstance(uapi, dict) and isinstance(project_only, dict)
        for entry in classes:
            assert isinstance(entry, dict)
            self.assertEqual(
                entry["language_profiles"],
                list(ledger.EXPECTED_HEADER_FOUNDATION_CLOSURE_PROFILES),
            )
            self.assertEqual(entry["future_feature_profiles"], [])
        self.assertEqual(uapi["paths"], ["sys/kd.h", "sys/soundcard.h", "sys/vt.h"])
        self.assertEqual(
            project_only["paths"],
            [
                "daemon.h",
                "dn_expand.h",
                "linux/capability.h",
                "lrand48.h",
                "pthread_atfork.h",
                "stdatomic.h",
                "strverscmp.h",
                "sys/module.h",
            ],
        )

        inputs = manifest["uapi_input"]
        assert isinstance(inputs, list) and len(inputs) == 1 and isinstance(inputs[0], dict)
        self.assertEqual(inputs[0]["id"], "linux-5.10-uapi")
        self.assertEqual(inputs[0]["state"], "pinned-verified")
        self.assertEqual(
            inputs[0]["upstream_pin"], "compat/upstreams.toml#linux_5_10_uapi"
        )
        self.assertEqual(inputs[0]["version"], "5.10")
        self.assertEqual(
            inputs[0]["source_sha256"],
            "dcdf99e43e98330d925016985bfbc7b83c66d367b714b2de0cbbfcbf83d8ca43",
        )
        self.assertEqual(inputs[0]["exported_header_count"], 935)
        self.assertEqual(
            inputs[0]["exported_header_manifest_sha256"],
            "00cdc98ceb35926f68dc57dc0d84a989a6df4f60f84b1ae5981b54bb1088eb0e",
        )
        self.assertEqual(
            inputs[0]["provenance_verifier"],
            "compat/x86_64/run_linux_5_10_uapi.sh",
        )
        self.assertEqual(
            inputs[0]["paths"], ["linux/kd.h", "linux/soundcard.h", "linux/vt.h"]
        )

        matrix = manifest["uapi_wrapper_matrix"]
        assert isinstance(matrix, dict)
        self.assertEqual(matrix["id"], "linux-5.10-uapi-wrapper-profile-matrix")
        self.assertEqual(matrix["state"], "partial-verified")
        self.assertEqual(matrix["required_result"], "pass")
        self.assertEqual(
            matrix["command"], "./scripts/dev-x86_64.sh uapi-wrapper-matrix"
        )
        self.assertEqual(matrix["header_class"], "pinned-uapi-inputs")
        self.assertEqual(matrix["headers"], ["sys/kd.h", "sys/soundcard.h", "sys/vt.h"])
        self.assertEqual(
            matrix["profiles"],
            [
                "c11-gnu",
                "cxx17-gnu",
                "c11-strict",
                "c11-posix-2008",
                "c11-xopen-700",
                "c11-bsd",
                "cxx17-strict",
            ],
        )
        self.assertEqual(matrix["row_count"], 21)
        rows = matrix["row"]
        assert isinstance(rows, list)
        self.assertEqual(len(rows), 21)
        self.assertEqual(
            [
                (row["header"], row["dependency"], row["profile"])
                for row in rows
                if isinstance(row, dict)
            ],
            [
                (header, dependency, profile)
                for header, dependency in ledger.EXPECTED_PUBLIC_HEADER_UAPI_GAPS.items()
                for profile in ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES
            ],
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in rows
            )
        )
        ioctl_matrix = manifest["ioctl_header_profile_matrix"]
        assert isinstance(ioctl_matrix, dict)
        self.assertEqual(ioctl_matrix["id"], "x86-ioctl-header-profile-matrix")
        self.assertEqual(ioctl_matrix["state"], "partial-verified")
        self.assertEqual(ioctl_matrix["required_result"], "pass")
        self.assertEqual(
            ioctl_matrix["command"], "./scripts/dev-x86_64.sh ioctl-header-abi"
        )
        self.assertEqual(ioctl_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(ioctl_matrix["subject_header"], "sys/ioctl.h")
        self.assertEqual(
            ioctl_matrix["profiles"], list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES)
        )
        self.assertEqual(ioctl_matrix["row_count"], 7)
        ioctl_rows = ioctl_matrix["row"]
        assert isinstance(ioctl_rows, list)
        self.assertEqual(len(ioctl_rows), 7)
        self.assertEqual(
            [row["profile"] for row in ioctl_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in ioctl_rows
            )
        )
        sys_io_matrix = manifest["sys_io_header_profile_matrix"]
        assert isinstance(sys_io_matrix, dict)
        self.assertEqual(sys_io_matrix["id"], "x86-sys-io-header-profile-matrix")
        self.assertEqual(sys_io_matrix["state"], "partial-verified")
        self.assertEqual(sys_io_matrix["required_result"], "pass")
        self.assertEqual(
            sys_io_matrix["command"], "./scripts/dev-x86_64.sh sys-io-header-abi"
        )
        self.assertEqual(sys_io_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(sys_io_matrix["subject_headers"], ["sys/io.h", "bits/io.h"])
        self.assertEqual(
            sys_io_matrix["profiles"],
            list(ledger.EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertEqual(sys_io_matrix["row_count"], 7)
        sys_io_rows = sys_io_matrix["row"]
        assert isinstance(sys_io_rows, list)
        self.assertEqual(len(sys_io_rows), 7)
        self.assertEqual(
            [row["profile"] for row in sys_io_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in sys_io_rows
            )
        )
        epoll_matrix = manifest["epoll_header_profile_matrix"]
        assert isinstance(epoll_matrix, dict)
        self.assertEqual(epoll_matrix["id"], "x86-epoll-header-profile-matrix")
        self.assertEqual(epoll_matrix["state"], "partial-verified")
        self.assertEqual(epoll_matrix["required_result"], "pass")
        self.assertEqual(
            epoll_matrix["command"], "./scripts/dev-x86_64.sh epoll-header-abi"
        )
        self.assertEqual(epoll_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(epoll_matrix["subject_header"], "sys/epoll.h")
        self.assertEqual(epoll_matrix["direct_macro_header"], "sys/ioctl.h")
        self.assertEqual(
            epoll_matrix["profiles"], list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES)
        )
        self.assertEqual(epoll_matrix["row_count"], 7)
        epoll_rows = epoll_matrix["row"]
        assert isinstance(epoll_rows, list)
        self.assertEqual(len(epoll_rows), 7)
        self.assertEqual(
            [row["profile"] for row in epoll_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in epoll_rows
            )
        )
        event_descriptor_matrix = manifest["event_descriptors_header_profile_matrix"]
        assert isinstance(event_descriptor_matrix, dict)
        self.assertEqual(
            event_descriptor_matrix["id"],
            "x86-event-descriptors-header-profile-matrix",
        )
        self.assertEqual(event_descriptor_matrix["state"], "partial-verified")
        self.assertEqual(event_descriptor_matrix["required_result"], "pass")
        self.assertEqual(
            event_descriptor_matrix["command"],
            "./scripts/dev-x86_64.sh event-descriptors-header-abi",
        )
        self.assertEqual(event_descriptor_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(
            event_descriptor_matrix["subject_headers"],
            ["sys/eventfd.h", "sys/inotify.h"],
        )
        self.assertEqual(event_descriptor_matrix["immediate_feature_header"], "fcntl.h")
        self.assertEqual(
            event_descriptor_matrix["profiles"],
            list(ledger.EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertEqual(event_descriptor_matrix["direct_surface_visibility"], "unconditional")
        self.assertEqual(
            event_descriptor_matrix["at_empty_path_visible_profiles"],
            list(
                ledger.EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_AT_EMPTY_PATH_VISIBLE_PROFILES
            ),
        )
        self.assertEqual(
            event_descriptor_matrix["at_empty_path_hidden_profiles"],
            list(
                ledger.EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_AT_EMPTY_PATH_HIDDEN_PROFILES
            ),
        )
        self.assertEqual(event_descriptor_matrix["row_count"], 16)
        event_descriptor_rows = event_descriptor_matrix["row"]
        assert isinstance(event_descriptor_rows, list)
        self.assertEqual(len(event_descriptor_rows), 16)
        self.assertEqual(
            [
                (row["header"], row["profile"])
                for row in event_descriptor_rows
                if isinstance(row, dict)
            ],
            [
                (header, profile)
                for header in ledger.EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_SUBJECT_HEADERS
                for profile in ledger.EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_PROFILES
            ],
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in event_descriptor_rows
            )
        )
        dirent_matrix = manifest["dirent_header_profile_matrix"]
        assert isinstance(dirent_matrix, dict)
        self.assertEqual(dirent_matrix["id"], "x86-dirent-header-profile-matrix")
        self.assertEqual(dirent_matrix["state"], "partial-verified")
        self.assertEqual(dirent_matrix["required_result"], "pass")
        self.assertEqual(
            dirent_matrix["command"], "./scripts/dev-x86_64.sh dirent-header-abi"
        )
        self.assertEqual(dirent_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(dirent_matrix["subject_header"], "dirent.h")
        self.assertEqual(
            dirent_matrix["base_profiles"],
            list(ledger.EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_BASE_PROFILES),
        )
        self.assertEqual(
            dirent_matrix["largefile64_profiles"],
            list(ledger.EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_LARGEFILE64_PROFILES),
        )
        self.assertEqual(
            dirent_matrix["seek_tell_visible_profiles"],
            list(ledger.EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_SEEK_TELL_VISIBLE_PROFILES),
        )
        self.assertEqual(
            dirent_matrix["getdents_type_macros_visible_profiles"],
            list(
                ledger.EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_GETDENTS_TYPE_MACROS_VISIBLE_PROFILES
            ),
        )
        self.assertEqual(
            dirent_matrix["versionsort_visible_profiles"],
            list(ledger.EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_VERSIONSORT_VISIBLE_PROFILES),
        )
        self.assertEqual(
            dirent_matrix["largefile64_alias_visible_profiles"],
            list(ledger.EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_LARGEFILE64_PROFILES),
        )
        self.assertEqual(dirent_matrix["row_count"], 11)
        dirent_rows = dirent_matrix["row"]
        assert isinstance(dirent_rows, list)
        self.assertEqual(
            [row["profile"] for row in dirent_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_BASE_PROFILES)
            + list(ledger.EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_LARGEFILE64_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in dirent_rows
            )
        )
        stdlib_matrix = manifest["stdlib_header_profile_matrix"]
        assert isinstance(stdlib_matrix, dict)
        self.assertEqual(stdlib_matrix["id"], "x86-stdlib-header-profile-matrix")
        self.assertEqual(stdlib_matrix["state"], "partial-verified")
        self.assertEqual(stdlib_matrix["required_result"], "pass")
        self.assertEqual(
            stdlib_matrix["command"], "./scripts/dev-x86_64.sh stdlib-header-abi"
        )
        self.assertEqual(stdlib_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(stdlib_matrix["subject_header"], "stdlib.h")
        self.assertEqual(
            stdlib_matrix["profiles"],
            list(ledger.EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertEqual(stdlib_matrix["row_count"], 12)
        stdlib_rows = stdlib_matrix["row"]
        assert isinstance(stdlib_rows, list)
        self.assertEqual(
            [row["profile"] for row in stdlib_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in stdlib_rows
            )
        )
        timeval_matrix = manifest["timeval_transitive_header_profile_matrix"]
        assert isinstance(timeval_matrix, dict)
        self.assertEqual(
            timeval_matrix["id"], "x86-timeval-transitive-header-profile-matrix"
        )
        self.assertEqual(timeval_matrix["state"], "partial-verified")
        self.assertEqual(timeval_matrix["required_result"], "pass")
        self.assertEqual(
            timeval_matrix["command"],
            "./scripts/dev-x86_64.sh timeval-transitive-header-abi",
        )
        self.assertEqual(timeval_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(
            timeval_matrix["subject_headers"],
            ["sys/time.h", "utmpx.h", "utmp.h", "lastlog.h", "sys/timex.h"],
        )
        self.assertEqual(
            timeval_matrix["sys_time_required_transitive_header"], "sys/select.h"
        )
        self.assertEqual(
            timeval_matrix["profiles"],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertEqual(timeval_matrix["row_count"], 35)
        timeval_rows = timeval_matrix["row"]
        assert isinstance(timeval_rows, list)
        self.assertEqual(len(timeval_rows), 35)
        self.assertEqual(
            [
                (row["header"], row["profile"])
                for row in timeval_rows
                if isinstance(row, dict)
            ],
            [
                (header, profile)
                for header in ledger.EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_HEADERS
                for profile in ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES
            ],
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in timeval_rows
            )
        )
        sys_time_direct_matrix = manifest["sys_time_direct_header_profile_matrix"]
        assert isinstance(sys_time_direct_matrix, dict)
        self.assertEqual(
            sys_time_direct_matrix["id"],
            "x86-sys-time-direct-header-profile-matrix",
        )
        self.assertEqual(sys_time_direct_matrix["state"], "partial-verified")
        self.assertEqual(sys_time_direct_matrix["required_result"], "pass")
        self.assertEqual(
            sys_time_direct_matrix["command"],
            "./scripts/dev-x86_64.sh sys-time-direct-header-abi",
        )
        self.assertEqual(sys_time_direct_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(sys_time_direct_matrix["subject_header"], "sys/time.h")
        self.assertEqual(
            sys_time_direct_matrix["profiles"],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertEqual(sys_time_direct_matrix["row_count"], 7)
        sys_time_direct_rows = sys_time_direct_matrix["row"]
        assert isinstance(sys_time_direct_rows, list)
        self.assertEqual(len(sys_time_direct_rows), 7)
        self.assertEqual(
            [row["profile"] for row in sys_time_direct_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in sys_time_direct_rows
            )
        )
        access_header_matrix = manifest["access_header_profile_matrix"]
        assert isinstance(access_header_matrix, dict)
        self.assertEqual(
            access_header_matrix["id"], "x86-access-header-profile-matrix"
        )
        self.assertEqual(access_header_matrix["state"], "partial-verified")
        self.assertEqual(access_header_matrix["required_result"], "pass")
        self.assertEqual(
            access_header_matrix["command"], "./scripts/dev-x86_64.sh access-header-abi"
        )
        self.assertEqual(access_header_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(access_header_matrix["subject_headers"], ["fcntl.h", "unistd.h"])
        self.assertEqual(
            access_header_matrix["profiles"],
            list(ledger.EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertEqual(access_header_matrix["row_count"], 8)
        access_header_rows = access_header_matrix["row"]
        assert isinstance(access_header_rows, list)
        self.assertEqual(len(access_header_rows), 8)
        self.assertEqual(
            [row["profile"] for row in access_header_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in access_header_rows
            )
        )
        xattr_matrix = manifest["xattr_header_profile_matrix"]
        assert isinstance(xattr_matrix, dict)
        self.assertEqual(xattr_matrix["id"], "x86-xattr-header-profile-matrix")
        self.assertEqual(xattr_matrix["state"], "partial-verified")
        self.assertEqual(xattr_matrix["required_result"], "pass")
        self.assertEqual(
            xattr_matrix["command"], "./scripts/dev-x86_64.sh xattr-header-abi"
        )
        self.assertEqual(xattr_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(xattr_matrix["subject_header"], "sys/xattr.h")
        self.assertEqual(
            xattr_matrix["profiles"],
            list(ledger.EXPECTED_XATTR_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertEqual(xattr_matrix["row_count"], 11)
        xattr_rows = xattr_matrix["row"]
        assert isinstance(xattr_rows, list)
        self.assertEqual(len(xattr_rows), 11)
        self.assertEqual(
            [row["profile"] for row in xattr_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_XATTR_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in xattr_rows
            )
        )
        completion = manifest["completion"]
        assert isinstance(completion, dict)
        policy = manifest["policy"]
        assert isinstance(policy, dict)
        self.assertTrue(policy["candidate_transitive_include_closure"])
        self.assertTrue(policy["full_c11_consumer_matrix"])
        self.assertTrue(policy["full_cxx17_consumer_matrix"])
        self.assertTrue(policy["feature_visibility_matrix"])
        self.assertTrue(completion["uapi_wrapper_profile_matrix_slice"])
        self.assertTrue(completion["ioctl_header_profile_matrix_slice"])
        self.assertTrue(completion["sys_io_header_profile_matrix_slice"])
        self.assertTrue(completion["epoll_header_profile_matrix_slice"])
        self.assertTrue(completion["event_descriptors_header_profile_matrix_slice"])
        self.assertTrue(completion["dirent_header_profile_matrix_slice"])
        self.assertTrue(completion["stdlib_header_profile_matrix_slice"])
        self.assertTrue(completion["timeval_transitive_header_profile_matrix_slice"])
        self.assertTrue(completion["sys_time_direct_header_profile_matrix_slice"])
        self.assertTrue(completion["access_header_profile_matrix_slice"])
        self.assertTrue(completion["xattr_header_profile_matrix_slice"])
        self.assertTrue(completion["candidate_transitive_include_closure"])
        self.assertTrue(completion["c11_consumer_matrix"])
        self.assertTrue(completion["cxx17_consumer_matrix"])
        self.assertTrue(completion["feature_visibility_matrix"])
        self.assertFalse(completion["family_promotion"])
        self.assertFalse(completion["public_support"])

        diagnostics = manifest["closure_diagnostic"]
        assert (
            isinstance(diagnostics, list)
            and len(diagnostics) == 1
            and isinstance(diagnostics[0], dict)
        )
        self.assertEqual(diagnostics[0]["id"], "isolated-candidate-header-closure")
        self.assertEqual(diagnostics[0]["state"], "partial-verified")
        self.assertEqual(diagnostics[0]["required_result"], "pass")
        self.assertEqual(
            diagnostics[0]["command"],
            "./scripts/dev-x86_64.sh candidate-header-closure",
        )
        self.assertEqual(
            diagnostics[0]["profiles"],
            list(ledger.EXPECTED_HEADER_FOUNDATION_CLOSURE_PROFILES),
        )
        self.assertEqual(diagnostics[0]["record_count"], 1337)
        self.assertEqual(
            diagnostics[0]["oracle_not_applicable_rows"],
            list(ledger.EXPECTED_CANDIDATE_HEADER_CLOSURE_ORACLE_NOT_APPLICABLE_ROWS),
        )
        obligations = manifest["profile_obligation"]
        assert isinstance(obligations, list)
        self.assertEqual(len(obligations), 21)
        current = next(
            obligation
            for obligation in obligations
            if obligation["header_class"] == "pinned-non-uapi"
            and obligation["profile"] == "c11-gnu"
        )
        assert isinstance(current, dict)
        self.assertEqual(current["applicability"], "applicable")
        self.assertEqual(current["state"], "partial-verified")
        self.assertEqual(
            current["evidence"],
            ["public-header-c-consumability", "public-header-profile-consumability"],
        )
        uapi_current = next(
            obligation
            for obligation in obligations
            if obligation["header_class"] == "pinned-uapi-inputs"
            and obligation["profile"] == "c11-gnu"
        )
        assert isinstance(uapi_current, dict)
        self.assertEqual(uapi_current["applicability"], "applicable")
        self.assertEqual(uapi_current["state"], "partial-verified")
        self.assertEqual(
            uapi_current["evidence"],
            [
                "pinned-linux-5.10-uapi-input",
                "linux-5.10-uapi-wrapper-profile-matrix",
                "public-header-profile-consumability",
            ],
        )
        strict = next(
            obligation
            for obligation in obligations
            if obligation["header_class"] == "pinned-non-uapi"
            and obligation["profile"] == "c11-strict"
        )
        assert isinstance(strict, dict)
        self.assertEqual(strict["applicability"], "mixed-applicability")
        self.assertEqual(strict["state"], "partial-verified")
        self.assertEqual(strict["evidence"], ["public-header-profile-consumability"])
        project_only_strict = next(
            obligation
            for obligation in obligations
            if obligation["header_class"] == "project-only-extensions"
            and obligation["profile"] == "cxx17-strict"
        )
        assert isinstance(project_only_strict, dict)
        self.assertEqual(project_only_strict["applicability"], "candidate-only")
        self.assertEqual(project_only_strict["state"], "partial-verified")

        owners = manifest["linkage_owner"]
        assert isinstance(owners, list)
        self.assertEqual(
            [entry["id"] for entry in owners],
            [
                "current-static-c-exports",
                "header-callable-disposition",
                "noncallable-header-abi",
            ],
        )

    def test_header_foundation_manifest_rejects_false_closure_or_accounting_drift(self) -> None:
        data = self.data()
        manifest = self.header_foundation_manifest()
        provider_audit = manifest["selected_callable_provider_linkage_audit"]
        assert isinstance(provider_audit, dict)
        provider_audit["full_callable_closure"] = True
        with self.assertRaisesRegex(
            ledger.LedgerError, "selected provider audit contract drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        completion = manifest["completion"]
        assert isinstance(completion, dict)
        completion["family_promotion"] = True
        with self.assertRaisesRegex(ledger.LedgerError, "completion drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        matrix = manifest["uapi_wrapper_matrix"]
        assert isinstance(matrix, dict)
        rows = matrix["row"]
        assert isinstance(rows, list)
        rows.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "matrix row roster drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        matrix = manifest["uapi_wrapper_matrix"]
        assert isinstance(matrix, dict)
        rows = matrix["row"]
        assert isinstance(rows, list) and isinstance(rows[0], dict)
        rows[0]["dependency"] = "linux/input.h"
        with self.assertRaisesRegex(ledger.LedgerError, "Linux-UAPI dependency drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        matrix = manifest["uapi_wrapper_matrix"]
        assert isinstance(matrix, dict)
        rows = matrix["row"]
        assert isinstance(rows, list) and isinstance(rows[0], dict)
        rows[0]["candidate"] = "incomplete"
        with self.assertRaisesRegex(ledger.LedgerError, "resolved compile-only result"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        ioctl_matrix = manifest["ioctl_header_profile_matrix"]
        assert isinstance(ioctl_matrix, dict)
        ioctl_rows = ioctl_matrix["row"]
        assert isinstance(ioctl_rows, list)
        ioctl_rows.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "ioctl header matrix row roster drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        ioctl_matrix = manifest["ioctl_header_profile_matrix"]
        assert isinstance(ioctl_matrix, dict)
        ioctl_matrix["subject_header"] = "sys/socket.h"
        with self.assertRaisesRegex(ledger.LedgerError, "ioctl header matrix subject header drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        sys_io_matrix = manifest["sys_io_header_profile_matrix"]
        assert isinstance(sys_io_matrix, dict)
        sys_io_rows = sys_io_matrix["row"]
        assert isinstance(sys_io_rows, list)
        sys_io_rows.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "sys/io header matrix row roster drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        sys_io_matrix = manifest["sys_io_header_profile_matrix"]
        assert isinstance(sys_io_matrix, dict)
        sys_io_matrix["subject_headers"] = ["sys/io.h", "bits/fcntl.h"]
        with self.assertRaisesRegex(
            ledger.LedgerError, "sys/io header matrix subject headers drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        epoll_matrix = manifest["epoll_header_profile_matrix"]
        assert isinstance(epoll_matrix, dict)
        epoll_rows = epoll_matrix["row"]
        assert isinstance(epoll_rows, list)
        epoll_rows.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "epoll header matrix row roster drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        epoll_matrix = manifest["epoll_header_profile_matrix"]
        assert isinstance(epoll_matrix, dict)
        epoll_matrix["direct_macro_header"] = "sys/socket.h"
        with self.assertRaisesRegex(ledger.LedgerError, "direct macro header drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        event_descriptor_matrix = manifest["event_descriptors_header_profile_matrix"]
        assert isinstance(event_descriptor_matrix, dict)
        event_descriptor_rows = event_descriptor_matrix["row"]
        assert isinstance(event_descriptor_rows, list)
        event_descriptor_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "event-descriptor header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        event_descriptor_matrix = manifest["event_descriptors_header_profile_matrix"]
        assert isinstance(event_descriptor_matrix, dict)
        event_descriptor_matrix["at_empty_path_visible_profiles"] = ["c11-gnu"]
        with self.assertRaisesRegex(
            ledger.LedgerError, "AT_EMPTY_PATH visible profile roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        dirent_matrix = manifest["dirent_header_profile_matrix"]
        assert isinstance(dirent_matrix, dict)
        dirent_rows = dirent_matrix["row"]
        assert isinstance(dirent_rows, list)
        dirent_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "dirent header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        dirent_matrix = manifest["dirent_header_profile_matrix"]
        assert isinstance(dirent_matrix, dict)
        dirent_matrix["getdents_type_macros_visible_profiles"] = ["c11-gnu"]
        with self.assertRaisesRegex(
            ledger.LedgerError, "getdents_type_macros_visible_profiles drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        stdlib_matrix = manifest["stdlib_header_profile_matrix"]
        assert isinstance(stdlib_matrix, dict)
        stdlib_rows = stdlib_matrix["row"]
        assert isinstance(stdlib_rows, list)
        stdlib_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "stdlib header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        timeval_matrix = manifest["timeval_transitive_header_profile_matrix"]
        assert isinstance(timeval_matrix, dict)
        timeval_rows = timeval_matrix["row"]
        assert isinstance(timeval_rows, list)
        timeval_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "timeval transitive-header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        timeval_matrix = manifest["timeval_transitive_header_profile_matrix"]
        assert isinstance(timeval_matrix, dict)
        timeval_matrix["sys_time_required_transitive_header"] = "sys/socket.h"
        with self.assertRaisesRegex(
            ledger.LedgerError, "required dependency drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        sys_time_direct_matrix = manifest["sys_time_direct_header_profile_matrix"]
        assert isinstance(sys_time_direct_matrix, dict)
        sys_time_direct_rows = sys_time_direct_matrix["row"]
        assert isinstance(sys_time_direct_rows, list)
        sys_time_direct_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "direct sys/time header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        sys_time_direct_matrix = manifest["sys_time_direct_header_profile_matrix"]
        assert isinstance(sys_time_direct_matrix, dict)
        sys_time_direct_matrix["subject_header"] = "sys/socket.h"
        with self.assertRaisesRegex(
            ledger.LedgerError, "direct sys/time header matrix subject header drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        access_header_matrix = manifest["access_header_profile_matrix"]
        assert isinstance(access_header_matrix, dict)
        access_header_rows = access_header_matrix["row"]
        assert isinstance(access_header_rows, list)
        access_header_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "access header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        access_header_matrix = manifest["access_header_profile_matrix"]
        assert isinstance(access_header_matrix, dict)
        access_header_matrix["subject_headers"] = ["sys/socket.h"]
        with self.assertRaisesRegex(
            ledger.LedgerError, "access header matrix subject headers drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        xattr_header_matrix = manifest["xattr_header_profile_matrix"]
        assert isinstance(xattr_header_matrix, dict)
        xattr_header_rows = xattr_header_matrix["row"]
        assert isinstance(xattr_header_rows, list)
        xattr_header_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "xattr header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        xattr_header_matrix = manifest["xattr_header_profile_matrix"]
        assert isinstance(xattr_header_matrix, dict)
        xattr_header_matrix["subject_header"] = "sys/socket.h"
        with self.assertRaisesRegex(
            ledger.LedgerError, "xattr header matrix subject header drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        uapi_paths = manifest["uapi_path"]
        assert isinstance(uapi_paths, list) and isinstance(uapi_paths[0], dict)
        uapi_paths[0]["dependency"] = "linux/input.h"
        with self.assertRaisesRegex(ledger.LedgerError, "Linux-UAPI dependency"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        inputs = manifest["uapi_input"]
        assert isinstance(inputs, list) and isinstance(inputs[0], dict)
        inputs[0]["upstream_pin"] = "compat/upstreams.toml#musl"
        with self.assertRaisesRegex(ledger.LedgerError, "upstream pin drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        diagnostics = manifest["closure_diagnostic"]
        assert isinstance(diagnostics, list) and isinstance(diagnostics[0], dict)
        diagnostics[0]["required_result"] = "incomplete"
        with self.assertRaisesRegex(ledger.LedgerError, "require a live pass"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        diagnostics = manifest["closure_diagnostic"]
        assert isinstance(diagnostics, list) and isinstance(diagnostics[0], dict)
        diagnostics[0]["oracle_not_applicable_rows"] = ["aio.h:c11-strict"]
        with self.assertRaisesRegex(ledger.LedgerError, "oracle-not-applicable rows drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        feature_visibility = manifest["feature_visibility_matrix"]
        assert isinstance(feature_visibility, dict)
        feature_visibility["record_count"] = 1336
        with self.assertRaisesRegex(
            ledger.LedgerError, "declaration/macro visibility matrix count contract drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        callable_visibility = manifest["callable_feature_visibility_matrix"]
        assert isinstance(callable_visibility, dict)
        callable_visibility["record_count"] = 1336
        with self.assertRaisesRegex(
            ledger.LedgerError, "callable visibility matrix count contract drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        classes = manifest["header_class"]
        assert isinstance(classes, list) and isinstance(classes[2], dict)
        paths = classes[2]["paths"]
        assert isinstance(paths, list)
        paths.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "project-only public header"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        obligations = manifest["profile_obligation"]
        assert isinstance(obligations, list) and isinstance(obligations[2], dict)
        obligations[2]["applicability"] = "applicable"
        with self.assertRaisesRegex(ledger.LedgerError, "applicability drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        owners = manifest["linkage_owner"]
        assert isinstance(owners, list) and isinstance(owners[1], dict)
        owners[1]["family"] = "libc.c-abi-compat"
        with self.assertRaisesRegex(ledger.LedgerError, "family drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

    def test_protocol_database_work_package_targets_active_header_linkage_owners(self) -> None:
        provider = ledger.load_toml(ledger.PROTOCOL_DATABASE_PROVIDER_PATH)
        package = provider["work_package"]
        assert isinstance(package, dict)
        manifest = self.header_foundation_manifest()
        owners = manifest["linkage_owner"]
        assert isinstance(owners, list)
        owner_ids = {
            owner["id"]
            for owner in owners
            if isinstance(owner, dict) and isinstance(owner.get("id"), str)
        }

        self.assertEqual(
            package["target_obligations"],
            ["header-callable-disposition", "current-static-c-exports"],
        )
        self.assertTrue(set(package["target_obligations"]) <= owner_ids)

    def test_public_header_surface_inventory_is_a_checked_partial_artifact(self) -> None:
        """Every pinned public header must be visible before ABI closure is claimed."""

        inventory = ROOT / "compat" / "x86_64" / "public_headers.txt"
        headers = inventory.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(headers), 183)
        self.assertEqual(headers, sorted(headers))
        self.assertEqual(len(headers), len(set(headers)))
        self.assertIn("pthread.h", headers)
        self.assertIn("stdio.h", headers)
        self.assertIn("sys/ucontext.h", headers)
        self.assertIn("sys/vt.h", headers)

        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        artifacts = headers_layouts["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if entry["id"] == "public-header-c-consumability"
        )
        assert isinstance(artifact, dict)
        self.assertEqual(
            {evidence["command"] for evidence in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh public-header-surface"},
        )
        self.assertIn("compat/x86_64/public_headers.txt", artifact["source_owners"])
        self.assertIn(
            "compat/x86_64/run_public_header_surface.sh", artifact["source_owners"]
        )
        self.assertIn(
            "without declaration, layout, linkage, runtime, or public-support parity",
            artifact["description"],
        )
        self.assertIn(
            "legacy runner deliberately omits the image's declared `/opt/linux-5.10-uapi/include` root",
            artifact["description"],
        )


    def test_all_header_callable_visibility_is_a_reviewable_non_abi_artifact(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        artifacts = headers_layouts["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 17
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "all-header-callable-feature-visibility"
        )
        self.assertNotIn("capabilities", artifact)
        self.assertEqual(
            {evidence["command"] for evidence in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh header-callable-visibility-matrix"},
        )
        for phrase in (
            "foundation-verified `libc.headers-layouts`",
            "1,337-row direct-public-include C11/C++17 matrix",
            "zero current comparable callable name/class mismatch rows",
            "one current oracle-not-applicable `aio.h` row",
            "56 project-only header/profile rows",
            "28 reviewed native callable extension rows",
            "does not compare prototypes or macro replacements, noncallable declarations, type/layout ABI, archive linkage, runtime behavior, family promotion, or public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])


    def test_posix_native_requires_the_finite_companion_and_source_contracts(self) -> None:
        data = self.data()
        family = self.family(data, "libc.posix-runtime")
        for owner in (
            "compat/x86_64/native-strptime-reference/strptime.c",
            "compat/x86_64/native-strptime-reference/COPYRIGHT",
            "compat/x86_64/native-strptime-reference/README.md",
            "compat/x86_64/owned_wordexp_upstream_policy.py",
            "compat/x86_64/owned_wordexp_upstream_policy_diagnostics.json",
            "compat/x86_64/owned_wordexp_source_policy_probe.c",
            "compat/x86_64/owned-wordexp-upstream-policy.md",
            "compat/x86_64/owned_wordexp_evidence.py",
            "compat/x86_64/tests/test_owned_wordexp_upstream_policy.py",
            "compat/x86_64/atomic_addressable_abi_dynamic_main.c",
            "compat/x86_64/run_owned_atomic_addressable_profile.sh",
            "compat/x86_64/owned_atomic_addressable_profile.py",
            "compat/x86_64/owned-atomic-addressable-profile.md",
            "compat/x86_64/tests/test_owned_atomic_addressable_profile.py",
            "compat/x86_64/tests/test_owned_atomic_addressable_profile_dispatch.py",
            "compat/x86_64/tests/test_owned_posix_native_dispatch.py",
            "compat/x86_64/tests/test_dynamic_loader_dispatch.py",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(owner, family["source_owners"])
        self.assertEqual(
            family["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh owned-posix-native --family-execution FILE --crypt-profile FILE "
            "--atomic-addressable-profile FILE --wordexp-profile FILE --wordexp-expected-native-inputs FILE --output NEW_DIR",
        )
        for phrase in (
            "credential, crypt, and addressable-atomic",
            "fixed strptime source-and-POSIX contract",
            "twenty candidate and 104 oracle wordexp diagnostics",
            "independently captured native-input seal",
            "56 retained-reviewed-project-c-abi-extension rows",
            "Musl or C++ header parity",
        ):
            self.assertIn(phrase, family["native_evidence"][0]["scope"])

        changed = self.data()
        changed_family = self.family(changed, "libc.posix-runtime")
        changed_family["native_evidence"][0]["command"] = (
            "./scripts/dev-x86_64.sh owned-posix-native --family-execution FILE --crypt-profile FILE --output NEW_DIR"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "finite native profile command"):
            ledger.validate_ledger(changed)

        changed = self.data()
        self.family(changed, "libc.posix-runtime")["source_owners"].remove(
            "compat/x86_64/native-strptime-reference/strptime.c"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "must own .*strptime.c"):
            ledger.validate_ledger(changed)

        for argument in ("--wordexp-profile FILE ", "--wordexp-expected-native-inputs FILE "):
            changed = self.data()
            changed_family = self.family(changed, "libc.posix-runtime")
            changed_family["native_evidence"][0]["command"] = family["native_evidence"][0]["command"].replace(argument, "")
            with self.subTest(argument=argument), self.assertRaisesRegex(ledger.LedgerError, "finite native profile command"):
                ledger.require_posix_native_profile_companions(changed_family)

        for owner in ("compat/x86_64/owned_wordexp_upstream_policy_diagnostics.json",
                      "compat/x86_64/owned_wordexp_source_policy_probe.c"):
            changed = self.data()
            changed_family = self.family(changed, "libc.posix-runtime")
            changed_family["source_owners"].remove(owner)
            with self.subTest(owner=owner), self.assertRaisesRegex(ledger.LedgerError, "must own"):
                ledger.require_posix_native_profile_companions(changed_family)

    def test_posix_foundation_status_needs_a_physical_family_admission_receipt(self) -> None:
        changed = self.data()
        family = self.family(changed, "libc.posix-runtime")
        family["status"] = "foundation-verified"
        evidence = family["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["state"] = "verified"
        with self.assertRaisesRegex(ledger.LedgerError, "needs a family admission receipt"):
            ledger.require_posix_runtime_family_admission(family)

        evidence[0]["receipt"] = ".work/x86_64/nonphysical-family-admission.json"
        with self.assertRaisesRegex(ledger.LedgerError, "physical checkout .work file"):
            ledger.require_posix_runtime_family_admission(family)


    def test_math_fenv_rounding_keeps_selected_siblings_out_of_its_leaf_candidate_only(
        self,
    ) -> None:
        """The aggregate must be able to rerun this leaf after sibling selection."""
        runner = (
            ROOT / "compat/x86_64/run_libc_fenv_rounding.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "readonly OPT_IN_BINARY80_MATH_SYMBOLS=(exp10l fdiml pow10l)",
            runner,
        )
        self.assertIn(
            'for unselected in "${OPT_IN_BINARY80_MATH_SYMBOLS[@]}"; do',
            runner,
        )
        self.assertIn(
            "exp10 exp10f exp10l pow10 pow10f pow10l fdim fdimf fdiml",
            runner,
        )


    def test_math_log2_remains_a_closed_non_capability_artifact(self) -> None:
        data = self.data()
        text_math = self.family(data, "libc.text-math-locale-stdio")
        self.assertEqual(text_math["status"], "planned")
        artifacts = text_math["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 77
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-math-log2"
        )
        self.assertNotIn("capabilities", artifact)
        for owner in (
            "compat/upstreams.toml",
            "docker/Dockerfile.x86_64",
            "libc/src/lib.rs",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/fenv.rs",
            "libc/src/c_abi/x86_64/math_log2.rs",
            "libc/src/c_abi/x86_64/math_log2_musl_x86_64.S",
            "compat/x86_64/generate_libc_math_log2.py",
            "compat/x86_64/math_log2_header_abi_probe.cpp",
            "compat/x86_64/libc_math_log2_probe.c",
            "compat/x86_64/libc_math_log2_start.S",
            "compat/x86_64/run_libc_math_log2.sh",
            "compat/x86_64/aarch64_parity_inventory.json",
            "compat/x86_64/tests/test_runner.py",
            "compat/x86_64/validate_parity_ledger.py",
            "plan.md",
            "scripts/check_structure.py",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(owner, artifact["source_owners"])
        for phrase in (
            "binary32/binary64 logarithm-base-two artifact",
            "`log2`",
            "`log2f`",
            "GCC 15.2.0",
            "close-to-one reconstruction",
            "subnormal normalization",
            "table reduction",
            "localized data/error closure",
            "no undefined callable symbols",
            "requested/observed rounding directions",
            "divide-by-zero/invalid",
            "compiler-builtins",
            "binary80 `log2l`",
            "fenv API/policy",
            "log/log1p/log10 and exp/expm1 families",
            "`exp2`",
            "special and complex functions",
            "binary80/x87 math",
            "family completion",
            "promotion",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])
        self.assertEqual(
            {evidence["command"] for evidence in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-math-log2"},
        )

        changed = self.data()
        changed_artifacts = self.family(
            changed, "libc.text-math-locale-stdio"
        )["verified_artifact"]
        assert isinstance(changed_artifacts, list)
        changed_artifact = next(
            entry
            for entry in changed_artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-math-log2"
        )
        changed_artifact["description"] = changed_artifact["description"].replace(
            "public x86 support", "x86 support"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "public x86 support"):
            ledger.validate_ledger(changed)

        changed = self.data()
        changed_artifacts = self.family(
            changed, "libc.text-math-locale-stdio"
        )["verified_artifact"]
        assert isinstance(changed_artifacts, list)
        changed_artifact = next(
            entry
            for entry in changed_artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-math-log2"
        )
        evidence = changed_artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh libc-fenv"
        with self.assertRaisesRegex(ledger.LedgerError, "closed libc-math-log2 command"):
            ledger.validate_ledger(changed)


    def test_foundations_remain_narrow_and_source_or_artifact_scoped(self) -> None:
        data = self.data()
        direct = self.family(data, "facade.direct")
        remaining = self.family(data, "facade.record-owning")
        direct_slices = direct["verified_slice"]
        assert isinstance(direct_slices, list)
        direct_slices_by_id = {
            slice_entry["id"]: slice_entry
            for slice_entry in direct_slices
            if isinstance(slice_entry, dict)
        }
        fnmatch_slice = direct_slices_by_id["pattern.fnmatch"]
        glob_slice = direct_slices_by_id["pattern.glob"]
        assert isinstance(fnmatch_slice, dict)
        assert isinstance(glob_slice, dict)
        self.assertEqual(fnmatch_slice["capabilities"], ["pattern.fnmatch"])
        for owner in (
            "crabc-core/src/pattern.rs",
            "crabc-rs/src/pattern_x86_64.rs",
            "crabc-rs/tests/x86_64_fnmatch.rs",
            "crabc-rs/examples/fnmatch_direct_probe.rs",
            "compat/x86_64/verify_fnmatch_direct.sh",
        ):
            self.assertIn(owner, fnmatch_slice["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in fnmatch_slice["native_evidence"]},
            {"./scripts/dev-x86_64.sh facade"},
        )
        self.assertIn("separate alloc-gated", fnmatch_slice["description"])

        self.assertEqual(glob_slice["capabilities"], ["pattern.glob"])
        for owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/pattern.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/src/raw_dir.rs",
            "crabc-rs/src/pattern_x86_64.rs",
            "crabc-rs/tests/x86_64_glob.rs",
            "crabc-rs/examples/glob_direct_probe.rs",
            "compat/x86_64/verify_glob_direct.sh",
        ):
            self.assertIn(owner, glob_slice["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in glob_slice["native_evidence"]},
            {"./scripts/dev-x86_64.sh facade"},
        )
        self.assertIn("explicit `PathArg` root", glob_slice["description"])
        self.assertIn("fixed custom Rust allocator", glob_slice["x86_abi_prerequisites"][0])
        self.assertIn("glob_t", glob_slice["x86_header_prerequisites"][0])
        self.assertIn("pattern.fnmatch", direct["capabilities"])
        self.assertIn("pattern.glob", direct["capabilities"])
        self.assertNotIn("pattern.glob", fnmatch_slice["capabilities"])
        self.assertEqual(self.family(data, "libc.raw-syscall")["status"], "foundation-verified")
        errno_tls = self.family(data, "libc.errno-tls")
        self.assertEqual(errno_tls["status"], "foundation-verified")
        self.assertIn("oracle.musl-toolchain", errno_tls["depends_on"])
        self.assertIn(
            "libc/src/c_abi/x86_64/foundation.rs", errno_tls["source_owners"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/thread_pointer.rs", errno_tls["source_owners"]
        )
        self.assertTrue(
            any("pthread_arch.h::__get_tp" in item for item in errno_tls["x86_abi_prerequisites"])
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-foundation",
            {evidence["command"] for evidence in errno_tls["native_evidence"]},
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-thread-pointer",
            {evidence["command"] for evidence in errno_tls["native_evidence"]},
        )
        posix_runtime = self.family(data, "libc.posix-runtime")
        self.assertEqual(posix_runtime["status"], "planned")
        headers_layouts = self.family(data, "libc.headers-layouts")
        self.assertIn(
            "./scripts/dev-x86_64.sh socket-messages-header-abi",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        slices = posix_runtime["verified_slice"]
        assert isinstance(slices, list)
        slices_by_id = {slice_entry["id"]: slice_entry for slice_entry in slices}
        self.assertEqual(len(slices_by_id), len(slices))
        self.assertIn("filesystem.stat-compat", slices_by_id)
        self.assertIn("process.credentials", slices_by_id)
        stat_compat = slices_by_id["filesystem.stat-compat"]
        assert isinstance(stat_compat, dict)
        self.assertEqual(stat_compat["id"], "filesystem.stat-compat")
        self.assertEqual(stat_compat["capabilities"], ["filesystem.stat-compat"])
        self.assertIn(
            "libc/src/c_abi/x86_64/stat_compat.rs",
            stat_compat["source_owners"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            stat_compat["source_owners"],
        )
        stat_commands = {
            evidence["command"] for evidence in stat_compat["native_evidence"]
        }
        self.assertEqual(
            stat_commands, {"./scripts/dev-x86_64.sh libc-stat-compat"}
        )
        self.assertIn("freestanding fixture", stat_compat["description"])
        self.assertIn("does not select libc.so", stat_compat["native_evidence"][0]["scope"])
        credentials = slices_by_id["process.credentials"]
        assert isinstance(credentials, dict)
        self.assertEqual(credentials["capabilities"], ["process.credentials"])
        for owner in (
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/credentials.rs",
            "compat/x86_64/libc_credentials_probe.c",
            "compat/x86_64/libc_credentials_start.S",
            "compat/x86_64/run_libc_credentials.sh",
        ):
            self.assertIn(owner, credentials["source_owners"])
        credential_commands = {
            evidence["command"] for evidence in credentials["native_evidence"]
        }
        self.assertEqual(
            credential_commands, {"./scripts/dev-x86_64.sh libc-credentials"}
        )
        self.assertIn("EOPNOTSUPP", credentials["description"])
        self.assertIn(
            "does not select libc.so", credentials["native_evidence"][0]["scope"]
        )
        posix_artifacts = posix_runtime["verified_artifact"]
        assert isinstance(posix_artifacts, list)
        self.assertTrue(all(isinstance(artifact, dict) for artifact in posix_artifacts))
        artifacts_by_id = {
            artifact["id"]: artifact
            for artifact in posix_artifacts
            if isinstance(artifact, dict)
        }
        self.assertEqual(len(artifacts_by_id), len(posix_artifacts))
        filesystem_capacity = artifacts_by_id["static-c-filesystem-capacity"]
        assert isinstance(filesystem_capacity, dict)
        self.assertNotIn("capabilities", filesystem_capacity)
        for owner in (
            "libc/src/c_abi/x86_64/filesystem_capacity.rs",
            "compat/x86_64/run_filesystem_capacity_header_abi.sh",
            "compat/x86_64/run_libc_filesystem_capacity.sh",
        ):
            self.assertIn(owner, filesystem_capacity["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in filesystem_capacity["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-filesystem-capacity"},
        )
        self.assertIn("src/stat/statvfs.c", str(filesystem_capacity["oracle"]))
        self.assertIn("public x86 support", filesystem_capacity["description"])
        vector_io = artifacts_by_id["static-c-vector-io"]
        assert isinstance(vector_io, dict)
        self.assertNotIn("capabilities", vector_io)
        for owner in (
            "libc/src/c_abi/x86_64/vector_io.rs",
            "compat/x86_64/run_vector_io_header_abi.sh",
            "compat/x86_64/run_libc_vector_io.sh",
        ):
            self.assertIn(owner, vector_io["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in vector_io["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-vector-io"},
        )
        self.assertIn("src/unistd/pwritev.c", str(vector_io["oracle"]))
        self.assertIn("above 4 GiB", vector_io["description"])
        self.assertIn("public x86 support", vector_io["description"])
        socket_messages = artifacts_by_id["static-c-socket-messages"]
        assert isinstance(socket_messages, dict)
        self.assertNotIn("capabilities", socket_messages)
        for owner in (
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/socket_messages.rs",
            "compat/x86_64/run_socket_messages_header_abi.sh",
            "compat/x86_64/libc_socket_messages_probe.c",
            "compat/x86_64/libc_socket_messages_start.S",
            "compat/x86_64/run_libc_socket_messages.sh",
        ):
            self.assertIn(owner, socket_messages["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in socket_messages["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-socket-messages"},
        )
        self.assertIn("src/network/sendmmsg.c", str(socket_messages["oracle"]))
        for phrase in (
            "still-planned `libc.posix-runtime`",
            "padded",
            "cancellation",
            "public x86 support",
        ):
            self.assertIn(phrase, socket_messages["description"])
        self.assertIn(
            "SYS_sendmmsg=307",
            socket_messages["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/socket_messages.rs",
            posix_runtime["source_owners"],
        )
        signal_control = artifacts_by_id["static-c-signal-control"]
        assert isinstance(signal_control, dict)
        self.assertNotIn("capabilities", signal_control)
        for owner in (
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/signal_foundation.rs",
            "libc/src/c_abi/x86_64/signal_control.rs",
            "libc/src/c_abi/x86_64/signal_pending.rs",
            "libc/src/c_abi/x86_64/signal_set_mutation.rs",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_signal_control_probe.c",
            "compat/x86_64/libc_signal_control_start.S",
            "compat/x86_64/run_libc_signal_control.sh",
        ):
            self.assertIn(owner, signal_control["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in signal_control["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-signal-control"},
        )
        self.assertIn("does not select process.signal", signal_control["description"])
        self.assertIn("partial output writes", signal_control["description"])
        self.assertIn(
            "does not select process.signal", signal_control["native_evidence"][0]["scope"]
        )
        self.assertIn(
            "direct null pending EFAULT",
            signal_control["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/signal_control.rs",
            posix_runtime["source_owners"],
        )
        termios_control = artifacts_by_id["static-c-termios-control"]
        assert isinstance(termios_control, dict)
        self.assertNotIn("capabilities", termios_control)
        for owner in (
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/termios_control.rs",
            "include/termios.h",
            "compat/x86_64/termios_header_abi_probe.c",
            "compat/x86_64/termios_header_abi_probe.cpp",
            "compat/x86_64/run_termios_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_termios_control_probe.c",
            "compat/x86_64/libc_termios_control_start.S",
            "compat/x86_64/run_libc_termios_control.sh",
        ):
            self.assertIn(owner, termios_control["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in termios_control["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-termios-control"},
        )
        self.assertIn("does not select a generic ioctl", termios_control["description"])
        self.assertIn("60-byte", termios_control["description"])
        self.assertIn("byte-preserved public tails", termios_control["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/termios_control.rs",
            posix_runtime["source_owners"],
        )
        ctermid = artifacts_by_id["static-c-ctermid"]
        assert isinstance(ctermid, dict)
        self.assertNotIn("capabilities", ctermid)
        for owner in (
            "libc/src/c_abi/x86_64/ctermid.rs",
            "include/stdio.h",
            "compat/x86_64/ctermid_header_abi_probe.c",
            "compat/x86_64/ctermid_header_abi_probe.cpp",
            "compat/x86_64/run_ctermid_header_abi.sh",
            "compat/x86_64/libc_ctermid_probe.c",
            "compat/x86_64/libc_ctermid_start.S",
            "compat/x86_64/run_libc_ctermid.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, ctermid["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in ctermid["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-ctermid"},
        )
        for phrase in (
            "historical `ctermid` pathname-spelling boundary",
            "selected-private leaf",
            "borrowed immutable `/dev/tty` spelling",
            "`L_ctermid=20`",
            "remaining eleven bytes caller-resident",
            "no syscall, allocation, errno/TLS",
            "terminal policy",
            "temporary-file creation or pathname families",
            "authority-bearing filesystem handle APIs",
            "family completion",
            "promotion",
            "public x86 support",
        ):
            self.assertIn(phrase, ctermid["description"])
        ctermid_scope = ctermid["native_evidence"][0]["scope"]
        for phrase in (
            "L_ctermid=20",
            "unmangled C++ reference",
            "caller-buffer result-pointer identity",
            "untouched caller tail",
            "no TLS/errno path",
            "no syscall instruction",
            "mktemp/tempnam/tmpnam/mkstemp/mkdtemp/tmpfile",
            "authority-bearing filesystem handles",
        ):
            self.assertIn(phrase, ctermid_scope)
        self.assertIn(
            "libc/src/c_abi/x86_64/ctermid.rs",
            posix_runtime["source_owners"],
        )
        isatty = artifacts_by_id["static-c-isatty"]
        assert isinstance(isatty, dict)
        self.assertNotIn("capabilities", isatty)
        for owner in (
            "libc/src/c_abi/x86_64/isatty.rs",
            "compat/x86_64/isatty_header_abi_probe.c",
            "compat/x86_64/isatty_header_abi_probe.cpp",
            "compat/x86_64/run_isatty_header_abi.sh",
            "compat/x86_64/libc_isatty_probe.c",
            "compat/x86_64/libc_isatty_start.S",
            "compat/x86_64/run_libc_isatty.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, isatty["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in isatty["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-isatty"},
        )
        for phrase in (
            "`isatty` descriptor-observation boundary",
            "`ioctl=16`/`TIOCGWINSZ=0x5413`",
            "`syscall(...) + 1`",
            "terminal discovery",
            "termios mutation/control",
            "PTY/session policy",
            "`ttyname`",
            "`getpass`",
            "family completion",
            "promotion",
            "public x86 support",
        ):
            self.assertIn(phrase, isatty["description"])
        isatty_scope = isatty["native_evidence"][0]["scope"]
        for phrase in (
            "tty success",
            "stale-errno preservation",
            "EBADF",
            "ENOTTY",
            "ioctl=16/TIOCGWINSZ=0x5413",
            "TCGETS/TCSETS",
            "terminal discovery",
            "termios mutation/control",
            "PTY/session policy",
            "ttyname",
            "getpass",
        ):
            self.assertIn(phrase, isatty_scope)
        ttyname_r = artifacts_by_id["static-c-ttyname-r"]
        assert isinstance(ttyname_r, dict)
        self.assertNotIn("capabilities", ttyname_r)
        for owner in (
            "libc/src/c_abi/x86_64/ttyname_r.rs",
            "compat/x86_64/ttyname_r_header_abi_probe.c",
            "compat/x86_64/ttyname_r_header_abi_probe.cpp",
            "compat/x86_64/run_ttyname_r_header_abi.sh",
            "compat/x86_64/libc_ttyname_r_probe.c",
            "compat/x86_64/libc_ttyname_r_start.S",
            "compat/x86_64/run_libc_ttyname_r.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, ttyname_r["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in ttyname_r["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-ttyname-r"},
        )
        for phrase in (
            "`ttyname_r` caller-buffered terminal-name boundary",
            "exactly `int ttyname_r(int, char *, size_t)`",
            "`/proc/self/fd/<fd>`",
            "zero-capacity dummy-byte compatibility path",
            "`ERANGE`",
            "`EFAULT`, `EBADF`, and `ENOTTY`",
            "neither exports `ttyname`",
            "generic `readlink`/`stat`/`fstat`",
            "terminal/session policy",
            "family completion",
            "promotion",
            "public x86 support",
        ):
            self.assertIn(phrase, ttyname_r["description"])
        ttyname_r_scope = ttyname_r["native_evidence"][0]["scope"]
        for phrase in (
            "devpts terminal name",
            "stale-errno preservation",
            "ERANGE",
            "EFAULT",
            "EBADF",
            "ENOTTY",
            "readlink=89/fstat=5/newfstatat=262",
            "isatty ioctl=16/TIOCGWINSZ=0x5413",
            "public readlink/stat/fstat/ttyname",
            "generic filesystem/path completion",
            "terminal/session policy",
            "ttyname static storage",
        ):
            self.assertIn(phrase, ttyname_r_scope)
        tcgetpgrp = artifacts_by_id["static-c-tcgetpgrp"]
        assert isinstance(tcgetpgrp, dict)
        self.assertNotIn("capabilities", tcgetpgrp)
        for owner in (
            "libc/src/c_abi/x86_64/tcgetpgrp.rs",
            "compat/x86_64/tcgetpgrp_header_abi_probe.c",
            "compat/x86_64/tcgetpgrp_header_abi_probe.cpp",
            "compat/x86_64/run_tcgetpgrp_header_abi.sh",
            "compat/x86_64/libc_tcgetpgrp_probe.c",
            "compat/x86_64/libc_tcgetpgrp_start.S",
            "compat/x86_64/run_libc_tcgetpgrp.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, tcgetpgrp["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in tcgetpgrp["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-tcgetpgrp"},
        )
        for phrase in (
            "`tcgetpgrp` foreground-group-observation boundary",
            "`ioctl=16`/`TIOCGPGRP=0x540f`",
            "private four-byte int scratch",
            "fork/setsid/TIOCSCTTY",
            "session/process-control policy",
            "terminal discovery",
            "termios mutation/control",
            "PTY/session policy",
            "`tcsetpgrp`",
            "`tcgetsid`",
            "`ttyname`",
            "`getpass`",
            "family completion",
            "promotion",
            "public x86 support",
        ):
            self.assertIn(phrase, tcgetpgrp["description"])
        tcgetpgrp_scope = tcgetpgrp["native_evidence"][0]["scope"]
        for phrase in (
            "foreground-pid success",
            "stale-errno preservation",
            "EBADF",
            "ENOTTY",
            "fork/setsid/TIOCSCTTY",
            "ioctl=16/TIOCGPGRP=0x540f",
            "TIOCSPGRP",
            "TIOCGSID",
            "tcsetpgrp",
            "tcgetsid",
        ):
            self.assertIn(phrase, tcgetpgrp_scope)
        tcsetpgrp = artifacts_by_id["static-c-tcsetpgrp"]
        assert isinstance(tcsetpgrp, dict)
        self.assertNotIn("capabilities", tcsetpgrp)
        for owner in (
            "libc/src/c_abi/x86_64/tcsetpgrp.rs",
            "compat/x86_64/tcsetpgrp_header_abi_probe.c",
            "compat/x86_64/tcsetpgrp_header_abi_probe.cpp",
            "compat/x86_64/run_tcsetpgrp_header_abi.sh",
            "compat/x86_64/libc_tcsetpgrp_probe.c",
            "compat/x86_64/libc_tcsetpgrp_start.S",
            "compat/x86_64/run_libc_tcsetpgrp.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, tcsetpgrp["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in tcsetpgrp["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-tcsetpgrp"},
        )
        for phrase in (
            "`tcsetpgrp` foreground-group-assignment boundary",
            "`ioctl=16`/`TIOCSPGRP=0x5410`",
            "private four-byte int",
            "fork/setsid/TIOCSCTTY/setpgid",
            "session/process-control policy",
            "terminal discovery",
            "termios mutation/control",
            "PTY/session policy",
            "`tcgetpgrp`",
            "`tcgetsid`",
            "`ttyname`",
            "`getpass`",
            "family completion",
            "promotion",
            "public x86 support",
        ):
            self.assertIn(phrase, tcsetpgrp["description"])
        tcsetpgrp_scope = tcsetpgrp["native_evidence"][0]["scope"]
        for phrase in (
            "distinct in-session foreground-group assignment",
            "stale-errno preservation",
            "EBADF",
            "ENOTTY",
            "fork/setsid/TIOCSCTTY/setpgid",
            "ioctl=16/TIOCSPGRP=0x5410",
            "TIOCGPGRP",
            "TCGETS/TCSETS",
            "TIOCGSID",
            "tcgetpgrp",
            "tcgetsid",
        ):
            self.assertIn(phrase, tcsetpgrp_scope)
        getpass = artifacts_by_id["static-c-getpass"]
        assert isinstance(getpass, dict)
        self.assertNotIn("capabilities", getpass)
        for owner in (
            "libc/src/c_abi/x86_64/getpass.rs",
            "libc/src/c_abi/x86_64/termios_control.rs",
            "compat/x86_64/getpass_header_abi_probe.c",
            "compat/x86_64/getpass_header_abi_probe.cpp",
            "compat/x86_64/run_getpass_header_abi.sh",
            "compat/x86_64/libc_getpass_probe.c",
            "compat/x86_64/libc_getpass_start.S",
            "compat/x86_64/run_libc_getpass.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, getpass["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in getpass["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-getpass"},
        )
        for phrase in (
            "historical `getpass` terminal-input boundary",
            "128-byte C static result buffer",
            "`O_RDWR|O_NOCTTY|O_CLOEXEC`",
            "`TCSAFLUSH`",
            "private fixed `TCSBRK` drain request",
            "no-controlling-terminal `ENXIO`",
            "Rust secret type",
            "account database",
            "generic ioctl",
            "C PTY allocator",
            "secret-memory erasure",
            "family completion",
            "promotion",
            "public x86 support",
        ):
            self.assertIn(phrase, getpass["description"])
        getpass_scope = getpass["native_evidence"][0]["scope"]
        for phrase in (
            "no echo",
            "127-byte truncation",
            "36-byte terminal-record restoration",
            "open=2/O_CLOEXEC",
            "private TCSBRK drain composition",
            "forkpty/openpty/login_tty/vhangup/TIOCGPTPEER",
            "Rust secret APIs",
        ):
            self.assertIn(phrase, getpass_scope)
        self.assertIn(
            "libc/src/c_abi/x86_64/getpass.rs",
            posix_runtime["source_owners"],
        )
        mktemp = artifacts_by_id["static-c-mktemp"]
        assert isinstance(mktemp, dict)
        self.assertNotIn("capabilities", mktemp)
        for owner in (
            "COMPATIBILITY-PROFILE.md",
            "libc/src/c_abi/x86_64/mktemp.rs",
            "compat/x86_64/mktemp_header_abi_probe.c",
            "compat/x86_64/mktemp_header_abi_probe.cpp",
            "compat/x86_64/run_mktemp_header_abi.sh",
            "compat/x86_64/libc_mktemp_probe.c",
            "compat/x86_64/libc_mktemp_start.S",
            "compat/x86_64/run_libc_mktemp.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, mktemp["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in mktemp["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-mktemp"},
        )
        for phrase in (
            "historical `mktemp` pathname-selection boundary",
            "trailing `XXXXXX`",
            "CLOCK_REALTIME-plus-TID",
            "`newfstatat(AT_FDCWD, path, scratch, 0)`",
            "inherently racy",
            "no security or ownership guarantee",
            "`tmpnam`",
            "`tempnam`",
            "`name_to_handle_at`/`open_by_handle_at`",
            "family completion",
            "promotion",
            "public x86 support",
        ):
            self.assertIn(phrase, mktemp["description"])
        mktemp_scope = mktemp["native_evidence"][0]["scope"]
        for phrase in (
            "EINVAL-first-byte clearing",
            "six-byte musl alphabet output",
            "ENOENT",
            "ELOOP-first-byte clearing",
            "clock_gettime=228",
            "gettid=186",
            "newfstatat=262",
            "neither creates/reserves/opens",
            "tmpnam/tempnam",
            "name-to-handle/open-by-handle",
        ):
            self.assertIn(phrase, mktemp_scope)
        self.assertIn(
            "libc/src/c_abi/x86_64/mktemp.rs",
            posix_runtime["source_owners"],
        )
        process_context = artifacts_by_id["static-c-process-context"]
        assert isinstance(process_context, dict)
        self.assertNotIn("capabilities", process_context)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/process_context.rs",
            "include/unistd.h",
            "include/sys/stat.h",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_process_context_probe.c",
            "compat/x86_64/libc_process_context_start.S",
            "compat/x86_64/run_libc_process_context.sh",
        ):
            self.assertIn(owner, process_context["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in process_context["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-process-context"},
        )
        self.assertIn("narrower than `process.control`", process_context["description"])
        self.assertIn("does not select C fork", process_context["description"])
        self.assertIn("raw-fork-contained", process_context["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/process_context.rs",
            posix_runtime["source_owners"],
        )
        environment = slices_by_id["static-c-environment"]
        assert isinstance(environment, dict)
        self.assertEqual(
            environment["capabilities"], ["process.environment-mutation"]
        )
        for owner in (
            "compat/upstreams.toml",
            "compat/crabc-rs/coverage.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/static_tls.rs",
            "libc/src/c_abi/x86_64/static_startup.rs",
            "libc/src/c_abi/x86_64/environment.rs",
            "libc/src/c_abi/x86_64/environment_runtime.rs",
            "libc/src/allocator_mimalloc.rs",
            "crt/src/x86_64_crt1.rs",
            "crt/src/x86_64_startup.rs",
            "crt/src/x86_64_array_boundaries.rs",
            "crt/src/x86_64_crti.rs",
            "crt/src/x86_64_crtn.rs",
            "include/stdlib.h",
            "include/unistd.h",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_environment_probe.c",
            "compat/x86_64/run_libc_environment.sh",
            "compat/x86_64/aarch64_parity_inventory.py",
            "compat/x86_64/aarch64_parity_inventory.json",
            "compat/x86_64/tests/test_aarch64_parity_inventory.py",
            "plan.md",
        ):
            self.assertIn(owner, environment["source_owners"])
        self.assertNotIn(
            "compat/x86_64/libc_environment_start.S", environment["source_owners"]
        )
        self.assertEqual(
            {evidence["command"] for evidence in environment["native_evidence"]},
            {
                "./scripts/dev-x86_64.sh stdlib-header-abi",
                "./scripts/dev-x86_64.sh unistd-header-abi",
                "./scripts/dev-x86_64.sh libc-environment",
            },
        )
        for phrase in (
            "Private selected `static-c-environment` slice",
            "exactly `process.environment-mutation`",
            "`clearenv`, `setenv`, and `unsetenv`",
            "do not select `process.globals`",
            "one-object `__environ`/`environ`/`_environ`/`___environ` aliases",
            "`x86-environment-runtime`",
            "`oldenv`",
            "`__env_rm_add`",
            "eleven-member",
            "pinned-musl backend-support tail",
            "async-signal safety",
            "secure_getenv",
            "memory.allocator-basic",
            "public x86 support",
        ):
            self.assertIn(phrase, environment["description"])
        environment_evidence = {
            evidence["command"]: evidence["scope"]
            for evidence in environment["native_evidence"]
        }
        self.assertIn(
            "C++ linkage",
            environment_evidence["./scripts/dev-x86_64.sh stdlib-header-abi"],
        )
        self.assertIn(
            "`environ` object",
            environment_evidence["./scripts/dev-x86_64.sh unistd-header-abi"],
        )
        self.assertIn(
            "in-place direct-vector replacement/removal",
            environment_evidence["./scripts/dev-x86_64.sh libc-environment"],
        )
        self.assertIn(
            "direct reassignment after an owned oldenv vector",
            environment_evidence["./scripts/dev-x86_64.sh libc-environment"],
        )
        self.assertIn(
            "constructor-before-main initial-environment publication",
            environment_evidence["./scripts/dev-x86_64.sh libc-environment"],
        )
        self.assertIn(
            "replacement copied-string malloc",
            environment_evidence["./scripts/dev-x86_64.sh libc-environment"],
        )
        self.assertIn(
            "direct-vector append allocation",
            environment_evidence["./scripts/dev-x86_64.sh libc-environment"],
        )
        self.assertIn(
            "owned-vector append realloc",
            environment_evidence["./scripts/dev-x86_64.sh libc-environment"],
        )
        self.assertIn(
            "post-publication ownership-registry allocation failure",
            environment_evidence["./scripts/dev-x86_64.sh libc-environment"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/environment.rs",
            posix_runtime["source_owners"],
        )
        login_name = artifacts_by_id["static-c-login-name"]
        assert isinstance(login_name, dict)
        self.assertNotIn("capabilities", login_name)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/environment.rs",
            "libc/src/c_abi/x86_64/login_name.rs",
            "include/unistd.h",
            "compat/x86_64/login_name_header_abi_probe.c",
            "compat/x86_64/login_name_header_abi_probe.cpp",
            "compat/x86_64/run_login_name_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_login_name_probe.c",
            "compat/x86_64/libc_login_name_start.S",
            "compat/x86_64/run_libc_login_name.sh",
        ):
            self.assertIn(owner, login_name["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in login_name["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-login-name"},
        )
        for phrase in (
            "first `LOGNAME`",
            "borrowed value pointer",
            "`ENXIO` directly",
            "`ERANGE` without writing",
            "caller-coordinated environment writers",
            "passwd or utmp",
            "public x86 support",
        ):
            self.assertIn(phrase, login_name["description"])
        self.assertIn(
            "borrowed caller-owned putenv alias plus subsequent mutation",
            login_name["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/login_name.rs",
            posix_runtime["source_owners"],
        )
        descriptor_io = artifacts_by_id["static-c-descriptor-io"]
        assert isinstance(descriptor_io, dict)
        self.assertNotIn("capabilities", descriptor_io)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/descriptor_io.rs",
            "include/fcntl.h",
            "include/unistd.h",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_descriptor_io_probe.c",
            "compat/x86_64/libc_descriptor_io_start.S",
            "compat/x86_64/run_libc_descriptor_io.sh",
        ):
            self.assertIn(owner, descriptor_io["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in descriptor_io["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-descriptor-io"},
        )
        self.assertIn("pwrite", descriptor_io["description"])
        self.assertIn(
            "does not select C open/path, generic fcntl command",
            descriptor_io["description"],
        )
        self.assertIn("EBUSY loops", descriptor_io["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/descriptor_io.rs",
            posix_runtime["source_owners"],
        )
        descriptor_lifecycle = artifacts_by_id["static-c-descriptor-lifecycle"]
        assert isinstance(descriptor_lifecycle, dict)
        self.assertNotIn("capabilities", descriptor_lifecycle)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/stat_compat.rs",
            "libc/src/c_abi/x86_64/descriptor_entry.rs",
            "libc/src/c_abi/x86_64/descriptor_control.rs",
            "libc/src/c_abi/x86_64/descriptor_io.rs",
            "include/fcntl.h",
            "include/stddef.h",
            "include/sys/stat.h",
            "compat/x86_64/fcntl_header_abi_probe.c",
            "compat/x86_64/run_fcntl_header_abi.sh",
            "compat/x86_64/stat_header_abi_probe.c",
            "compat/x86_64/run_stat_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_descriptor_lifecycle_probe.c",
            "compat/x86_64/libc_descriptor_lifecycle_start.S",
            "compat/x86_64/run_libc_descriptor_lifecycle.sh",
        ):
            self.assertIn(owner, descriptor_lifecycle["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in descriptor_lifecycle["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-descriptor-lifecycle"},
        )
        self.assertIn(
            "descriptor-lifecycle composition", descriptor_lifecycle["description"]
        )
        self.assertIn(
            "does not establish a general C runtime",
            descriptor_lifecycle["description"],
        )
        self.assertIn(
            "fdatasync", descriptor_lifecycle["native_evidence"][0]["scope"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/stat_compat.rs",
            posix_runtime["source_owners"],
        )
        process_resources = artifacts_by_id["static-c-process-resources"]
        assert isinstance(process_resources, dict)
        self.assertNotIn("capabilities", process_resources)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/process_resources.rs",
            "include/sys/resource.h",
            "include/sys/time.h",
            "compat/x86_64/resource_header_abi_probe.c",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_process_resources_probe.c",
            "compat/x86_64/libc_process_resources_start.S",
            "compat/x86_64/run_libc_process_resources.sh",
        ):
            self.assertIn(owner, process_resources["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in process_resources["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-process-resources"},
        )
        self.assertIn("narrower than process-resource capabilities", process_resources["description"])
        self.assertIn("capability-conditional", process_resources["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/process_resources.rs",
            posix_runtime["source_owners"],
        )
        sched_yield = artifacts_by_id["static-c-sched-yield"]
        assert isinstance(sched_yield, dict)
        self.assertNotIn("capabilities", sched_yield)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/sched_yield.rs",
            "include/sched.h",
            "compat/x86_64/sched_yield_header_abi_probe.c",
            "compat/x86_64/sched_yield_header_abi_probe.cpp",
            "compat/x86_64/run_sched_yield_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_sched_yield_probe.c",
            "compat/x86_64/libc_sched_yield_start.S",
            "compat/x86_64/run_libc_sched_yield.sh",
        ):
            self.assertIn(owner, sched_yield["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in sched_yield["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-sched-yield"},
        )
        for phrase in (
            "POSIX `sched_yield`",
            "raw Linux `-EPERM`",
            "`-1` with `errno=EPERM`",
            "C11 `thrd_yield`",
            "scheduler policy/parameter API",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, sched_yield["description"])
        self.assertIn(
            "libc/src/c_abi/x86_64/sched_yield.rs",
            posix_runtime["source_owners"],
        )
        sched_getcpu = artifacts_by_id["static-c-sched-getcpu"]
        assert isinstance(sched_getcpu, dict)
        self.assertNotIn("capabilities", sched_getcpu)
        for owner in (
            "compat/upstreams.toml",
            "crabc-core/src/thread.rs",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/sched_getcpu.rs",
            "include/sched.h",
            "compat/x86_64/sched_getcpu_header_abi_probe.c",
            "compat/x86_64/sched_getcpu_header_abi_probe.cpp",
            "compat/x86_64/run_sched_getcpu_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_sched_getcpu_probe.c",
            "compat/x86_64/libc_sched_getcpu_start.S",
            "compat/x86_64/run_libc_sched_getcpu.sh",
        ):
            self.assertIn(owner, sched_getcpu["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in sched_getcpu["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-sched-getcpu"},
        )
        for phrase in (
            "GNU `sched_getcpu`",
            "src/sched/sched_getcpu.c::sched_getcpu",
            "VDSO_GETCPU_SYM",
            "candidate-only",
            "strict/POSIX/XOPEN",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, sched_getcpu["description"])
        sched_cpucount = artifacts_by_id["static-c-sched-cpucount"]
        assert isinstance(sched_cpucount, dict)
        self.assertNotIn("capabilities", sched_cpucount)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/sched_cpucount.rs",
            "include/sched.h",
            "compat/x86_64/sched_cpucount_header_abi_probe.c",
            "compat/x86_64/sched_cpucount_header_abi_probe.cpp",
            "compat/x86_64/run_sched_cpucount_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_sched_cpucount_probe.c",
            "compat/x86_64/libc_sched_cpucount_start.S",
            "compat/x86_64/run_libc_sched_cpucount.sh",
        ):
            self.assertIn(owner, sched_cpucount["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in sched_cpucount["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-sched-cpucount"},
        )
        for phrase in (
            "GNU `__sched_cpucount`",
            "src/sched/sched_cpucount.c::__sched_cpucount",
            "CPU_COUNT_S",
            "CPU_COUNT",
            "strict/POSIX/XOPEN",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, sched_cpucount["description"])
        sched_priority_bounds = artifacts_by_id["static-c-sched-priority-bounds"]
        assert isinstance(sched_priority_bounds, dict)
        self.assertNotIn("capabilities", sched_priority_bounds)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/sched_priority_bounds.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sched.h",
            "compat/x86_64/sched_priority_bounds_header_abi_probe.c",
            "compat/x86_64/sched_priority_bounds_header_abi_probe.cpp",
            "compat/x86_64/run_sched_priority_bounds_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_sched_priority_bounds_probe.c",
            "compat/x86_64/libc_sched_priority_bounds_start.S",
            "compat/x86_64/run_libc_sched_priority_bounds.sh",
        ):
            self.assertIn(owner, sched_priority_bounds["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in sched_priority_bounds["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-sched-priority-bounds"},
        )
        for phrase in (
            "`sched_get_priority_max` and `sched_get_priority_min`",
            "src/sched/sched_get_priority_max.c",
            "SCHED_OTHER/FIFO/RR",
            "`-1` with `errno=EINVAL`",
            "strict/POSIX/XOPEN",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, sched_priority_bounds["description"])
        self.assertIn(
            "libc/src/c_abi/x86_64/sched_priority_bounds.rs",
            posix_runtime["source_owners"],
        )
        readiness_waits = artifacts_by_id["static-c-readiness-signal-waits"]
        assert isinstance(readiness_waits, dict)
        self.assertNotIn("capabilities", readiness_waits)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/readiness_waits.rs",
            "include/poll.h",
            "include/sys/select.h",
            "compat/x86_64/poll_header_abi_probe.c",
            "compat/x86_64/poll_header_abi_probe.cpp",
            "compat/x86_64/run_poll_header_abi.sh",
            "compat/x86_64/select_header_abi_probe.c",
            "compat/x86_64/select_header_abi_probe.cpp",
            "compat/x86_64/run_select_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_readiness_waits_probe.c",
            "compat/x86_64/libc_readiness_waits_start.S",
            "compat/x86_64/run_libc_readiness_waits.sh",
        ):
            self.assertIn(owner, readiness_waits["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in readiness_waits["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-readiness-waits"},
        )
        self.assertIn(
            "does not exercise epoll/eventfd; a separate artifact owns those archive exports",
            readiness_waits["description"],
        )
        self.assertIn(
            "temporary-mask delivery/restoration",
            readiness_waits["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/readiness_waits.rs",
            posix_runtime["source_owners"],
        )
        socket_transport = artifacts_by_id["static-c-socket-transport"]
        assert isinstance(socket_transport, dict)
        self.assertNotIn("capabilities", socket_transport)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/socket_transport.rs",
            "include/fcntl.h",
            "include/bits/fcntl.h",
            "include/netinet/in.h",
            "include/sys/socket.h",
            "compat/x86_64/socket_header_abi_probe.c",
            "compat/x86_64/socket_header_abi_probe.cpp",
            "compat/x86_64/socket_header_ipv6_macro_probe.c",
            "compat/x86_64/run_socket_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_socket_transport_probe.c",
            "compat/x86_64/libc_socket_transport_start.S",
            "compat/x86_64/run_libc_socket_transport.sh",
        ):
            self.assertIn(owner, socket_transport["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in socket_transport["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-socket-transport"},
        )
        self.assertIn("socketpair", socket_transport["description"])
        self.assertIn("cancellation-point machinery", socket_transport["description"])
        self.assertIn("does not select resolver/netdb", socket_transport["description"])
        self.assertIn("cancellation semantics", socket_transport["native_evidence"][0]["scope"])
        self.assertIn("atomic CLOEXEC/NONBLOCK", socket_transport["native_evidence"][0]["scope"])
        self.assertIn(
            "aggregate archive also carries independently selected interface-discovery exports",
            socket_transport["native_evidence"][0]["scope"],
        )
        self.assertIn("null-output socketpair EFAULT", socket_transport["native_evidence"][0]["scope"])
        self.assertIn(
            "IPv4/IPv6 address-equality/classification and GNU/BSD multicast source-filter layout/size macros",
            socket_transport["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/socket_transport.rs",
            posix_runtime["source_owners"],
        )
        byte_strings = artifacts_by_id["static-c-byte-strings"]
        assert isinstance(byte_strings, dict)
        self.assertNotIn("capabilities", byte_strings)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/byte_strings.rs",
            "include/string.h",
            "include/strverscmp.h",
            "include/strings.h",
            "compat/x86_64/byte_strings_header_abi_probe.c",
            "compat/x86_64/byte_strings_header_abi_probe.cpp",
            "compat/x86_64/run_byte_strings_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_byte_strings_probe.c",
            "compat/x86_64/libc_byte_strings_start.S",
            "compat/x86_64/run_libc_byte_strings.sh",
        ):
            self.assertIn(owner, byte_strings["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in byte_strings["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-byte-strings"},
        )
        self.assertIn("public `index` and `rindex` forwarding wrappers", byte_strings["description"])
        self.assertIn("private `__strchrnul`/`__memrchr`", byte_strings["description"])
        self.assertIn("GNU `strverscmp`", byte_strings["description"])
        self.assertIn("scalar fallback", byte_strings["description"])
        self.assertIn("GNU-gated `strverscmp`", byte_strings["x86_header_prerequisites"][0])
        self.assertIn("src/string/index.c", byte_strings["oracle"][0]["role"])
        self.assertIn("src/string/strverscmp.c", byte_strings["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            posix_runtime["source_owners"],
        )
        legacy_memory = artifacts_by_id["static-c-legacy-memory"]
        assert isinstance(legacy_memory, dict)
        self.assertNotIn("capabilities", legacy_memory)
        for owner in (
            "compat/upstreams.toml",
            "compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/legacy_memory.rs",
            "libc/src/c_abi/x86_64/memory.rs",
            "include/string.h",
            "include/strings.h",
            "compat/x86_64/byte_strings_header_abi_probe.c",
            "compat/x86_64/byte_strings_header_abi_probe.cpp",
            "compat/x86_64/run_byte_strings_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_legacy_memory_probe.c",
            "compat/x86_64/libc_legacy_memory_start.S",
            "compat/x86_64/run_libc_legacy_memory.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, legacy_memory["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in legacy_memory["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-legacy-memory"},
        )
        for phrase in (
            "legacy-memory adapter",
            "exactly one adapter object exporting only `bcopy` and `bzero`",
            "overlap-safe",
            "Rust-subsumed `memory.bytes-basic`",
            "allocator lifecycle/interposition",
            "public x86 support",
        ):
            self.assertIn(phrase, legacy_memory["description"])
        self.assertIn(
            "rsi to memset's rdx", legacy_memory["x86_abi_prerequisites"][0]
        )
        self.assertIn(
            "src/string/bcopy.c", legacy_memory["x86_abi_prerequisites"][1]
        )
        self.assertIn(
            "src/string/bzero.c", legacy_memory["x86_abi_prerequisites"][1]
        )
        legacy_scope = legacy_memory["native_evidence"][0]["scope"]
        for phrase in (
            "adapter exports only bcopy/bzero",
            "0..48-byte overlapping bcopy",
            "0..64-byte caller-buffer bzero",
            "memccpy/mempcpy/explicit_bzero",
        ):
            self.assertIn(phrase, legacy_scope)
        self.assertIn(
            "libc/src/c_abi/x86_64/legacy_memory.rs",
            posix_runtime["source_owners"],
        )
        memccpy = artifacts_by_id["static-c-memccpy"]
        assert isinstance(memccpy, dict)
        self.assertNotIn("capabilities", memccpy)
        for owner in (
            "compat/upstreams.toml",
            "compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/memccpy.rs",
            "include/string.h",
            "compat/x86_64/memccpy_header_abi_probe.c",
            "compat/x86_64/memccpy_header_abi_probe.cpp",
            "compat/x86_64/run_memccpy_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_memccpy_probe.c",
            "compat/x86_64/libc_memccpy_start.S",
            "compat/x86_64/run_libc_memccpy.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, memccpy["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in memccpy["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-memccpy"},
        )
        for phrase in (
            "exactly one Rust object exporting only `memccpy`",
            "same-alignment",
            "Rust-subsumed `memory.bytes-basic`",
            "allocator lifecycle/interposition",
            "public x86 support",
        ):
            self.assertIn(phrase, memccpy["description"])
        self.assertIn("rdi/rsi/edx/rcx", memccpy["x86_abi_prerequisites"][0])
        self.assertIn(
            "src/string/memccpy.c", memccpy["x86_abi_prerequisites"][1]
        )
        memccpy_scope = memccpy["native_evidence"][0]["scope"]
        for phrase in (
            "source/destination residues 0..7",
            "signed/wide `int c` narrowing",
            "mempcpy/explicit_bzero",
        ):
            self.assertIn(phrase, memccpy_scope)
        self.assertIn(
            "libc/src/c_abi/x86_64/memccpy.rs",
            posix_runtime["source_owners"],
        )
        mempcpy = artifacts_by_id["static-c-mempcpy"]
        assert isinstance(mempcpy, dict)
        self.assertNotIn("capabilities", mempcpy)
        for owner in (
            "compat/upstreams.toml",
            "compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/memory.rs",
            "libc/src/c_abi/x86_64/mempcpy.rs",
            "include/string.h",
            "compat/x86_64/mempcpy_header_abi_probe.c",
            "compat/x86_64/mempcpy_header_abi_probe.cpp",
            "compat/x86_64/run_mempcpy_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_mempcpy_probe.c",
            "compat/x86_64/libc_mempcpy_start.S",
            "compat/x86_64/run_libc_mempcpy.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, mempcpy["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in mempcpy["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-mempcpy"},
        )
        for phrase in (
            "exactly one adapter object exporting only `mempcpy`",
            "non-overlapping `memcpy(destination, source, count)` mapping",
            "callee-saved rbx",
            "Rust-subsumed `memory.bytes-basic`",
            "allocator lifecycle/interposition",
            "public x86 support",
        ):
            self.assertIn(phrase, mempcpy["description"])
        self.assertIn("rdi/rsi/rdx", mempcpy["x86_abi_prerequisites"][0])
        self.assertIn(
            "src/string/mempcpy.c", mempcpy["x86_abi_prerequisites"][1]
        )
        mempcpy_scope = mempcpy["native_evidence"][0]["scope"]
        for phrase in (
            "source/destination residues 0..7",
            "including zero length",
            "memccpy/explicit_bzero",
        ):
            self.assertIn(phrase, mempcpy_scope)
        strsep = artifacts_by_id["static-c-strsep"]
        assert isinstance(strsep, dict)
        self.assertNotIn("capabilities", strsep)
        for owner in (
            "compat/upstreams.toml",
            "compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/strsep.rs",
            "libc/src/string_exports.rs",
            "include/string.h",
            "compat/x86_64/strsep_header_abi_probe.c",
            "compat/x86_64/strsep_header_abi_probe.cpp",
            "compat/x86_64/run_strsep_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_strsep_probe.c",
            "compat/x86_64/libc_strsep_start.S",
            "compat/x86_64/run_libc_strsep.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, strsep["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in strsep["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-strsep"},
        )
        for phrase in (
            "exactly one Rust object exporting only `strsep`",
            "caller-owned `char **` slot",
            "local scalar byte traversal",
            "Rust-subsumed `memory.bytes-basic`",
            "general string/tokenization behavior",
            "allocator lifecycle/interposition",
            "public x86 support",
        ):
            self.assertIn(phrase, strsep["description"])
        self.assertIn("rdi/rsi", strsep["x86_abi_prerequisites"][0])
        self.assertIn("src/string/strsep.c", strsep["x86_abi_prerequisites"][1])
        strsep_scope = strsep["native_evidence"][0]["scope"]
        for phrase in (
            "leading/consecutive/trailing delimiter empty tokens",
            "empty delimiter/no-match final-state clearing",
            "high-bit delimiter byte matching",
            "caller-buffer NUL mutation",
            "caller `char **` state-slot mutation",
        ):
            self.assertIn(phrase, strsep_scope)
        self.assertIn(
            "libc/src/c_abi/x86_64/strsep.rs",
            posix_runtime["source_owners"],
        )
        strtok = artifacts_by_id["static-c-strtok"]
        assert isinstance(strtok, dict)
        self.assertNotIn("capabilities", strtok)
        for owner in (
            "compat/upstreams.toml",
            "compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv",
            "libc/src/c_abi.rs",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/strtok.rs",
            "include/string.h",
            "compat/x86_64/strtok_header_abi_probe.c",
            "compat/x86_64/strtok_header_abi_probe.cpp",
            "compat/x86_64/run_strtok_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_strtok_probe.c",
            "compat/x86_64/libc_strtok_start.S",
            "compat/x86_64/run_libc_strtok.sh",
            "compat/x86_64/validate_parity_ledger.py",
            "scripts/check_structure.py",
        ):
            self.assertIn(owner, strtok["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in strtok["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-strtok"},
        )
        for phrase in (
            "exactly one Rust object exporting only `strtok`",
            "one shared process-global non-TLS continuation cursor",
            "Interleaved sequences deliberately overwrite that one cursor",
            "concurrent unsynchronized calls remain outside the historical C contract",
            "generic AArch64 `strtok` export remains unchanged",
            "Rust-subsumed `memory.bytes-basic`",
            "general string/tokenization or thread-safe text behavior",
            "allocator lifecycle/interposition",
            "public x86 support",
        ):
            self.assertIn(phrase, strtok["description"])
        self.assertIn("rdi/rsi", strtok["x86_abi_prerequisites"][0])
        self.assertIn("src/string/strtok.c", strtok["x86_abi_prerequisites"][1])
        strtok_scope = strtok["native_evidence"][0]["scope"]
        for phrase in (
            "leading delimiter skipping",
            "in-place NUL splitting",
            "empty input and empty delimiters",
            "high-bit delimiter matching",
            "non-null replacement of a prior continuation",
            "one shared cursor when sequences interleave",
        ):
            self.assertIn(phrase, strtok_scope)
        self.assertIn(
            "libc/src/c_abi/x86_64/strtok.rs",
            posix_runtime["source_owners"],
        )
        random_entropy = artifacts_by_id["static-c-random-entropy"]
        assert isinstance(random_entropy, dict)
        self.assertNotIn("capabilities", random_entropy)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/random_entropy.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sys/random.h",
            "include/unistd.h",
            "compat/x86_64/random_entropy_header_abi_probe.c",
            "compat/x86_64/random_entropy_header_abi_probe.cpp",
            "compat/x86_64/run_random_entropy_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_random_entropy_probe.c",
            "compat/x86_64/libc_random_entropy_start.S",
            "compat/x86_64/run_libc_random_entropy.sh",
        ):
            self.assertIn(owner, random_entropy["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in random_entropy["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-random-entropy"},
        )
        self.assertIn("pthread cancellation point", random_entropy["description"])
        self.assertIn("disables cancellation", random_entropy["description"])
        self.assertIn("omits pthread cancellation", random_entropy["description"])
        self.assertIn("initial-TLS errno", random_entropy["description"])
        self.assertIn("syscall_cp", random_entropy["x86_abi_prerequisites"][1])
        self.assertIn("disables cancellation", random_entropy["x86_abi_prerequisites"][1])
        memory_search = artifacts_by_id["static-c-memory-search"]
        assert isinstance(memory_search, dict)
        self.assertNotIn("capabilities", memory_search)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/memory_search.rs",
            "include/string.h",
            "compat/x86_64/memory_search_header_abi_probe.c",
            "compat/x86_64/memory_search_header_abi_probe.cpp",
            "compat/x86_64/run_memory_search_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_memory_search_probe.c",
            "compat/x86_64/libc_memory_search_start.S",
            "compat/x86_64/run_libc_memory_search.sh",
        ):
            self.assertIn(owner, memory_search["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in memory_search["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-memory-search"},
        )
        self.assertIn("private `__memrchr` helper", memory_search["description"])
        self.assertIn("stateless", memory_search["description"])
        self.assertIn("allocation-free", memory_search["description"])
        self.assertIn("POSIX/GNU-gated", memory_search["x86_header_prerequisites"][0])
        self.assertIn("src/string/memchr.c", memory_search["oracle"][0]["role"])
        string_copy = artifacts_by_id["static-c-string-copy"]
        assert isinstance(string_copy, dict)
        self.assertNotIn("capabilities", string_copy)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/string_copy.rs",
            "include/string.h",
            "compat/x86_64/string_copy_header_abi_probe.c",
            "compat/x86_64/string_copy_header_abi_probe.cpp",
            "compat/x86_64/run_string_copy_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_string_copy_probe.c",
            "compat/x86_64/libc_string_copy_start.S",
            "compat/x86_64/run_libc_string_copy.sh",
        ):
            self.assertIn(owner, string_copy["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in string_copy["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-string-copy"},
        )
        self.assertIn(
            "private `__stpcpy`/`__stpncpy` helpers", string_copy["description"]
        )
        self.assertIn("stateless", string_copy["description"])
        self.assertIn("allocation-free", string_copy["description"])
        self.assertIn("POSIX/XOPEN/GNU/BSD-gated", string_copy["x86_header_prerequisites"][0])
        self.assertIn("src/string/stpcpy.c", string_copy["oracle"][0]["role"])
        ctype = artifacts_by_id["static-c-ctype"]
        assert isinstance(ctype, dict)
        self.assertNotIn("capabilities", ctype)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/ctype.rs",
            "include/ctype.h",
            "compat/x86_64/ctype_header_abi_probe.c",
            "compat/x86_64/ctype_header_abi_probe.cpp",
            "compat/x86_64/run_ctype_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_ctype_probe.c",
            "compat/x86_64/libc_ctype_start.S",
            "compat/x86_64/run_libc_ctype.sh",
        ):
            self.assertIn(owner, ctype["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in ctype["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-ctype"},
        )
        self.assertIn("fixed-C-locale ctype", ctype["description"])
        self.assertIn("stateless", ctype["description"])
        self.assertIn("allocation-free", ctype["description"])
        for phrase in (
            "POSIX/XOPEN/GNU/BSD C-visible",
            "strict-C-hidden",
        ):
            self.assertIn(phrase, ctype["x86_header_prerequisites"][0])
        self.assertIn("src/ctype/isalnum.c", ctype["oracle"][0]["role"])
        integer_arithmetic = artifacts_by_id["static-c-integer-arithmetic"]
        assert isinstance(integer_arithmetic, dict)
        self.assertNotIn("capabilities", integer_arithmetic)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/integer_arithmetic.rs",
            "include/stdlib.h",
            "compat/x86_64/integer_arithmetic_header_abi_probe.c",
            "compat/x86_64/integer_arithmetic_header_abi_probe.cpp",
            "compat/x86_64/run_integer_arithmetic_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_integer_arithmetic_probe.c",
            "compat/x86_64/libc_integer_arithmetic_start.S",
            "compat/x86_64/run_libc_integer_arithmetic.sh",
        ):
            self.assertIn(owner, integer_arithmetic["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in integer_arithmetic["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-integer-arithmetic"},
        )
        self.assertIn("integer-arithmetic block", integer_arithmetic["description"])
        self.assertIn("stateless", integer_arithmetic["description"])
        self.assertIn("allocation-free", integer_arithmetic["description"])
        self.assertIn("unconditional", integer_arithmetic["x86_header_prerequisites"][0])
        self.assertIn("src/stdlib/abs.c", integer_arithmetic["oracle"][0]["role"])
        integer_parse = artifacts_by_id["static-c-integer-parse"]
        assert isinstance(integer_parse, dict)
        self.assertNotIn("capabilities", integer_parse)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/integer_parse.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "include/errno.h",
            "include/inttypes.h",
            "include/stdlib.h",
            "compat/x86_64/integer_parse_header_abi_probe.c",
            "compat/x86_64/integer_parse_header_abi_probe.cpp",
            "compat/x86_64/run_integer_parse_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_integer_parse_probe.c",
            "compat/x86_64/libc_integer_parse_start.S",
            "compat/x86_64/run_libc_integer_parse.sh",
        ):
            self.assertIn(owner, integer_parse["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in integer_parse["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-integer-parse"},
        )
        self.assertIn("integer-parsing block", integer_parse["description"])
        self.assertIn("defined-input", integer_parse["description"])
        self.assertIn("allocation-free", integer_parse["description"])
        self.assertIn("unconditional", integer_parse["x86_header_prerequisites"][0])
        self.assertIn("src/internal/intscan.c", integer_parse["oracle"][0]["role"])
        intmax_arithmetic = artifacts_by_id["static-c-intmax-arithmetic"]
        assert isinstance(intmax_arithmetic, dict)
        self.assertNotIn("capabilities", intmax_arithmetic)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/intmax_arithmetic.rs",
            "include/inttypes.h",
            "compat/x86_64/intmax_arithmetic_header_abi_probe.c",
            "compat/x86_64/intmax_arithmetic_header_abi_probe.cpp",
            "compat/x86_64/run_intmax_arithmetic_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_intmax_arithmetic_probe.c",
            "compat/x86_64/libc_intmax_arithmetic_start.S",
            "compat/x86_64/run_libc_intmax_arithmetic.sh",
        ):
            self.assertIn(owner, intmax_arithmetic["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in intmax_arithmetic["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-intmax-arithmetic"},
        )
        self.assertIn("intmax-arithmetic block", intmax_arithmetic["description"])
        self.assertIn("stateless", intmax_arithmetic["description"])
        self.assertIn("allocation-free", intmax_arithmetic["description"])
        self.assertIn("unconditional", intmax_arithmetic["x86_header_prerequisites"][0])
        self.assertIn("src/stdlib/imaxabs.c", intmax_arithmetic["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/intmax_arithmetic.rs",
            posix_runtime["source_owners"],
        )
        credential_observation = artifacts_by_id["static-c-credential-observation"]
        assert isinstance(credential_observation, dict)
        self.assertNotIn("capabilities", credential_observation)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/credential_observation.rs",
            "include/unistd.h",
            "compat/x86_64/credential_observation_header_abi_probe.c",
            "compat/x86_64/credential_observation_header_abi_probe.cpp",
            "compat/x86_64/run_credential_observation_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_credential_observation_probe.c",
            "compat/x86_64/libc_credential_observation_start.S",
            "compat/x86_64/run_libc_credential_observation.sh",
        ):
            self.assertIn(owner, credential_observation["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in credential_observation["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-credential-observation"},
        )
        self.assertIn(
            "credential-observation block", credential_observation["description"]
        )
        self.assertIn("read-only", credential_observation["description"])
        self.assertIn(
            "query-then-fill race", credential_observation["description"]
        )
        self.assertIn("GNU", credential_observation["x86_header_prerequisites"][0])
        self.assertIn(
            "src/unistd/getgroups.c", credential_observation["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/credential_observation.rs",
            posix_runtime["source_owners"],
        )
        child_reaping = artifacts_by_id["static-c-child-reaping"]
        assert isinstance(child_reaping, dict)
        self.assertNotIn("capabilities", child_reaping)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/child_reaping.rs",
            "include/sys/wait.h",
            "compat/x86_64/child_reaping_header_abi_probe.c",
            "compat/x86_64/child_reaping_header_abi_probe.cpp",
            "compat/x86_64/run_child_reaping_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_child_reaping_probe.c",
            "compat/x86_64/libc_child_reaping_start.S",
            "compat/x86_64/run_libc_child_reaping.sh",
        ):
            self.assertIn(owner, child_reaping["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in child_reaping["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-child-reaping"},
        )
        self.assertIn("child-reaping block", child_reaping["description"])
        self.assertIn("WNOHANG", child_reaping["description"])
        self.assertIn("WNOWAIT", child_reaping["description"])
        self.assertIn("cancellation", child_reaping["description"])
        self.assertIn("wait4=61", child_reaping["x86_abi_prerequisites"][0])
        self.assertIn(
            "libc/src/c_abi/x86_64/child_reaping.rs",
            posix_runtime["source_owners"],
        )
        immediate_termination = artifacts_by_id["static-c-immediate-termination"]
        assert isinstance(immediate_termination, dict)
        self.assertNotIn("capabilities", immediate_termination)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/immediate_termination.rs",
            "include/stdlib.h",
            "compat/x86_64/immediate_termination_header_abi_probe.c",
            "compat/x86_64/immediate_termination_header_abi_probe.cpp",
            "compat/x86_64/run_immediate_termination_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_immediate_termination_probe.c",
            "compat/x86_64/libc_immediate_termination_start.S",
            "compat/x86_64/run_libc_immediate_termination.sh",
        ):
            self.assertIn(owner, immediate_termination["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in immediate_termination["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-immediate-termination"},
        )
        self.assertIn(
            "immediate-termination block", immediate_termination["description"]
        )
        self.assertIn("exit_group=231", immediate_termination["description"])
        self.assertIn("quick_exit", immediate_termination["description"])
        self.assertIn(
            "libc/src/c_abi/x86_64/immediate_termination.rs",
            posix_runtime["source_owners"],
        )
        posix_exit = artifacts_by_id["static-c-posix-exit"]
        assert isinstance(posix_exit, dict)
        self.assertNotIn("capabilities", posix_exit)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/posix_exit.rs",
            "libc/src/c_abi/x86_64/immediate_termination.rs",
            "include/unistd.h",
            "compat/x86_64/posix_exit_header_abi_probe.c",
            "compat/x86_64/posix_exit_header_abi_probe.cpp",
            "compat/x86_64/run_posix_exit_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_posix_exit_probe.c",
            "compat/x86_64/libc_posix_exit_start.S",
            "compat/x86_64/run_libc_posix_exit.sh",
        ):
            self.assertIn(owner, posix_exit["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in posix_exit["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-posix-exit"},
        )
        self.assertIn("POSIX `_exit` forwarding artifact", posix_exit["description"])
        self.assertIn("src/unistd/_exit.c", posix_exit["description"])
        self.assertIn("_Exit", posix_exit["description"])
        self.assertIn("no raw syscall", posix_exit["description"])
        self.assertIn("clone=56", posix_exit["x86_abi_prerequisites"][1])
        self.assertIn(
            "libc/src/c_abi/x86_64/posix_exit.rs",
            posix_runtime["source_owners"],
        )
        callback_algorithms = artifacts_by_id["static-c-callback-algorithms"]
        assert isinstance(callback_algorithms, dict)
        self.assertNotIn("capabilities", callback_algorithms)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/bsearch.rs",
            "libc/src/c_abi/x86_64/qsort.rs",
            "libc/src/c_abi/x86_64/callback_algorithms.rs",
            "include/stdlib.h",
            "compat/x86_64/callback_algorithms_header_abi_probe.c",
            "compat/x86_64/callback_algorithms_header_abi_probe.cpp",
            "compat/x86_64/run_callback_algorithms_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_callback_algorithms_probe.c",
            "compat/x86_64/libc_callback_algorithms_start.S",
            "compat/x86_64/run_libc_callback_algorithms.sh",
        ):
            self.assertIn(owner, callback_algorithms["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in callback_algorithms["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-callback-algorithms"},
        )
        self.assertIn(
            "callback-algorithms block", callback_algorithms["description"]
        )
        self.assertIn("smoothsort", callback_algorithms["description"])
        self.assertIn("same-address", callback_algorithms["description"])
        self.assertIn("stateless", callback_algorithms["description"])
        self.assertIn("src/stdlib/qsort.c", callback_algorithms["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/callback_algorithms.rs",
            posix_runtime["source_owners"],
        )
        clock_gettime = artifacts_by_id["static-c-clock-gettime"]
        assert isinstance(clock_gettime, dict)
        self.assertNotIn("capabilities", clock_gettime)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/clock_gettime.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/time.h",
            "compat/x86_64/time_header_abi_probe.c",
            "compat/x86_64/time_header_abi_probe.cpp",
            "compat/x86_64/run_time_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_clock_gettime_probe.c",
            "compat/x86_64/libc_clock_gettime_start.S",
            "compat/x86_64/run_libc_clock_gettime.sh",
        ):
            self.assertIn(owner, clock_gettime["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in clock_gettime["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-clock-gettime"},
        )
        for phrase in (
            "POSIX clock_gettime block",
            "-1/errno",
            "initial-TLS errno",
            "vDSO resolver",
            "clock_getres",
            "clock_settime",
        ):
            self.assertIn(phrase, clock_gettime["description"])
        self.assertIn(
            "src/time/clock_gettime.c", clock_gettime["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/clock_gettime.rs",
            posix_runtime["source_owners"],
        )
        clock_adjtime = artifacts_by_id["static-c-clock-adjtime-error-abi"]
        assert isinstance(clock_adjtime, dict)
        self.assertNotIn("capabilities", clock_adjtime)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/clock_adjtime.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sys/timex.h",
            "include/bits/alltypes.h",
            "compat/x86_64/clock_adjtime_header_abi_probe.c",
            "compat/x86_64/clock_adjtime_header_abi_probe.cpp",
            "compat/x86_64/run_clock_adjtime_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_clock_adjtime_probe.c",
            "compat/x86_64/libc_clock_adjtime_start.S",
            "compat/x86_64/run_libc_clock_adjtime.sh",
        ):
            self.assertIn(owner, clock_adjtime["source_owners"])
        self.assertNotIn("include/sys/types.h", clock_adjtime["source_owners"])
        self.assertIn("sys/timex.h", clock_adjtime["x86_header_prerequisites"][1])
        self.assertIn(
            "bits/alltypes.h", clock_adjtime["x86_header_prerequisites"][1]
        )
        self.assertNotIn(
            "sys/types.h", clock_adjtime["x86_header_prerequisites"][1]
        )
        self.assertEqual(
            {evidence["command"] for evidence in clock_adjtime["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-clock-adjtime"},
        )
        for phrase in (
            "rejected-ID error-ABI artifact",
            "src/linux/clock_adjtime.c",
            "CLOCK_MONOTONIC",
            "never calls valid `CLOCK_REALTIME`",
            "`EINVAL`, capability-first `EPERM`, or direct `EOPNOTSUPP`",
            "does not install an authority guard",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, clock_adjtime["description"])
        self.assertIn(
            "src/linux/clock_adjtime.c", clock_adjtime["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/clock_adjtime.rs",
            posix_runtime["source_owners"],
        )
        clock_settime = artifacts_by_id["static-c-clock-settime-error-abi"]
        assert isinstance(clock_settime, dict)
        self.assertNotIn("capabilities", clock_settime)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/clock_settime.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/time.h",
            "compat/x86_64/clock_settime_header_abi_probe.c",
            "compat/x86_64/clock_settime_header_abi_probe.cpp",
            "compat/x86_64/run_clock_settime_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_clock_settime_probe.c",
            "compat/x86_64/libc_clock_settime_start.S",
            "compat/x86_64/run_libc_clock_settime.sh",
        ):
            self.assertIn(owner, clock_settime["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in clock_settime["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-clock-settime"},
        )
        for phrase in (
            "rejected-request error-ABI artifact",
            "src/time/clock_settime.c",
            "CLOCK_MONOTONIC",
            "never calls valid `CLOCK_REALTIME`",
            "`EINVAL` or `EPERM`",
            "does not install an authority guard",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, clock_settime["description"])
        self.assertIn(
            "src/time/clock_settime.c", clock_settime["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/clock_settime.rs",
            posix_runtime["source_owners"],
        )
        timer_getoverrun = artifacts_by_id["static-c-timer-getoverrun-error-abi"]
        assert isinstance(timer_getoverrun, dict)
        self.assertNotIn("capabilities", timer_getoverrun)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/timer_getoverrun.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/time.h",
            "compat/x86_64/timer_getoverrun_header_abi_probe.c",
            "compat/x86_64/timer_getoverrun_header_abi_probe.cpp",
            "compat/x86_64/run_timer_getoverrun_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_timer_getoverrun_probe.c",
            "compat/x86_64/libc_timer_getoverrun_start.S",
            "compat/x86_64/run_libc_timer_getoverrun.sh",
        ):
            self.assertIn(owner, timer_getoverrun["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in timer_getoverrun["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-timer-getoverrun"},
        )
        for phrase in (
            "rejected-handle error-ABI artifact",
            "src/time/timer_getoverrun.c",
            "timer_t 0",
            "INT_MAX",
            "negative `timer_t`",
            "pthread_impl",
            "does not decode or dereference",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, timer_getoverrun["description"])
        self.assertIn(
            "src/time/timer_getoverrun.c", timer_getoverrun["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/timer_getoverrun.rs",
            posix_runtime["source_owners"],
        )
        timer_delete = artifacts_by_id["static-c-timer-delete-raw-error-abi"]
        assert isinstance(timer_delete, dict)
        self.assertNotIn("capabilities", timer_delete)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/timer_delete.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/time.h",
            "compat/x86_64/timer_delete_header_abi_probe.c",
            "compat/x86_64/timer_delete_header_abi_probe.cpp",
            "compat/x86_64/run_timer_delete_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_timer_delete_probe.c",
            "compat/x86_64/libc_timer_delete_start.S",
            "compat/x86_64/run_libc_timer_delete.sh",
        ):
            self.assertIn(owner, timer_delete["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in timer_delete["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-timer-delete"},
        )
        for phrase in (
            "raw-error ABI artifact",
            "src/time/timer_delete.c",
            "timer_t 0",
            "INT_MAX",
            "raw `-EINVAL`",
            "errno sentinel to remain unchanged",
            "negative `timer_t`",
            "pthread_impl",
            "SIGTIMER",
            "does not decode or dereference",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, timer_delete["description"])
        self.assertIn(
            "src/time/timer_delete.c", timer_delete["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/timer_delete.rs",
            posix_runtime["source_owners"],
        )
        timer_gettime = artifacts_by_id["static-c-timer-gettime-error-abi"]
        assert isinstance(timer_gettime, dict)
        self.assertNotIn("capabilities", timer_gettime)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/timer_gettime.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/time.h",
            "compat/x86_64/timer_gettime_header_abi_probe.c",
            "compat/x86_64/timer_gettime_header_abi_probe.cpp",
            "compat/x86_64/run_timer_gettime_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_timer_gettime_probe.c",
            "compat/x86_64/libc_timer_gettime_start.S",
            "compat/x86_64/run_libc_timer_gettime.sh",
        ):
            self.assertIn(owner, timer_gettime["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in timer_gettime["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-timer-gettime"},
        )
        for phrase in (
            "rejected-handle output-preservation error-ABI artifact",
            "src/time/timer_gettime.c",
            "timer_t 0",
            "INT_MAX",
            "`-1`/`EINVAL`",
            "record to remain unchanged",
            "negative `timer_t`",
            "pthread_impl",
            "does not decode or dereference",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, timer_gettime["description"])
        self.assertIn(
            "src/time/timer_gettime.c", timer_gettime["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/timer_gettime.rs",
            posix_runtime["source_owners"],
        )
        timer_settime = artifacts_by_id["static-c-timer-settime-error-abi"]
        assert isinstance(timer_settime, dict)
        self.assertNotIn("capabilities", timer_settime)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/timer_settime.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/time.h",
            "compat/x86_64/timer_settime_header_abi_probe.c",
            "compat/x86_64/timer_settime_header_abi_probe.cpp",
            "compat/x86_64/run_timer_settime_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_timer_settime_probe.c",
            "compat/x86_64/libc_timer_settime_start.S",
            "compat/x86_64/run_libc_timer_settime.sh",
        ):
            self.assertIn(owner, timer_settime["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in timer_settime["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-timer-settime"},
        )
        for phrase in (
            "rejected-handle input/output-preservation error-ABI artifact",
            "src/time/timer_settime.c",
            "timer_t 0",
            "INT_MAX",
            "flags zero",
            "`-1`/`EINVAL`",
            "both records to remain unchanged",
            "negative `timer_t`",
            "pthread_impl",
            "does not decode or dereference",
            "family completion, promotion, or public x86 support",
        ):
            self.assertIn(phrase, timer_settime["description"])
        self.assertIn(
            "src/time/timer_settime.c", timer_settime["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/timer_settime.rs",
            posix_runtime["source_owners"],
        )
        system_configuration = artifacts_by_id["static-c-system-configuration"]
        assert isinstance(system_configuration, dict)
        self.assertNotIn("capabilities", system_configuration)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "libc/src/c_abi/x86_64/process_resources.rs",
            "libc/src/c_abi/x86_64/system_configuration.rs",
            "libc/src/regression_stubs.rs",
            "include/unistd.h",
            "include/sys/resource.h",
            "compat/x86_64/unistd_header_abi_probe.c",
            "compat/x86_64/unistd_header_abi_probe.cpp",
            "compat/x86_64/run_unistd_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_system_configuration_probe.c",
            "compat/x86_64/libc_system_configuration_start.S",
            "compat/x86_64/run_libc_system_configuration.sh",
            "tests/fixtures/path_configuration_exports_test.c",
            "tests/path_configuration_exports.rs",
        ):
            self.assertIn(owner, system_configuration["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in system_configuration["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-system-configuration"},
        )
        for phrase in (
            "system-configuration block",
            "path- and fd-independent",
            "corresponding AArch64",
            "focused dynamic fixture",
            "full musl sysconf table",
            "separate direct `getauxval` lookup",
        ):
            self.assertIn(phrase, system_configuration["description"])
        self.assertIn(
            "src/conf/sysconf.c", system_configuration["oracle"][0]["role"]
        )
        self.assertIn(
            "src/conf/fpathconf.c", system_configuration["oracle"][0]["role"]
        )
        self.assertIn(
            "prlimit64=302", system_configuration["x86_abi_prerequisites"][3]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/system_configuration.rs",
            posix_runtime["source_owners"],
        )
        memory_sync = artifacts_by_id["static-c-memory-sync"]
        assert isinstance(memory_sync, dict)
        self.assertNotIn("capabilities", memory_sync)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/memory_sync.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sys/mman.h",
            "include/bits/mman.h",
            "compat/x86_64/memory_sync_header_abi_probe.c",
            "compat/x86_64/memory_sync_header_abi_probe.cpp",
            "compat/x86_64/run_memory_sync_header_abi.sh",
            "compat/x86_64/x86_msync_reference_probe.c",
            "compat/x86_64/run_x86_msync_reference.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_memory_sync_probe.c",
            "compat/x86_64/libc_memory_sync_start.S",
            "compat/x86_64/run_libc_memory_sync.sh",
            "compat/x86_64/tests/test_memory_sync.py",
        ):
            self.assertIn(owner, memory_sync["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in memory_sync["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-memory-sync"},
        )
        for phrase in (
            "mapping-synchronization block",
            "`msync=26`",
            "syscall_cp",
            "no-cancellation direct Linux path",
            "full musl `msync` parity",
            "private anonymous mapping",
            "invalid-flag-before-zero-length",
            "unaligned-address-before-zero-length",
            "file-backed shared-map writeback",
            "persistence or durability",
            "public x86 support",
        ):
            self.assertIn(phrase, memory_sync["description"])
        self.assertIn("src/mman/msync.c", memory_sync["oracle"][0]["role"])
        self.assertIn(
            "src/thread/x86_64/syscall_cp.s", memory_sync["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/memory_sync.rs",
            posix_runtime["source_owners"],
        )
        memfd_create = artifacts_by_id["static-c-memfd-create"]
        assert isinstance(memfd_create, dict)
        self.assertNotIn("capabilities", memfd_create)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/memfd_create.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sys/mman.h",
            "include/bits/mman.h",
            "compat/x86_64/memfd_create_header_abi_probe.c",
            "compat/x86_64/memfd_create_header_abi_probe.cpp",
            "compat/x86_64/run_memfd_create_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_memfd_create_probe.c",
            "compat/x86_64/libc_memfd_create_start.S",
            "compat/x86_64/run_libc_memfd_create.sh",
            "compat/x86_64/tests/test_memfd_create_c_abi.py",
        ):
            self.assertIn(owner, memfd_create["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in memfd_create["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-memfd-create"},
        )
        for phrase in (
            "GNU memory-file-descriptor creation block",
            "`memfd_create=319`",
            "249-byte",
            "250-byte-label EINVAL",
            "UINT_MAX flag EINVAL",
            "inaccessible non-null label-pointer EFAULT",
            "C `fcntl`",
            "MFD_HUGETLB resource/page-size policy",
            "memfd_secret",
            "public x86 support",
        ):
            self.assertIn(phrase, memfd_create["description"])
        self.assertIn(
            "src/linux/memfd_create.c", memfd_create["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/memfd_create.rs",
            posix_runtime["source_owners"],
        )
        mapping_core = artifacts_by_id["static-c-mman-mapping-core"]
        assert isinstance(mapping_core, dict)
        self.assertNotIn("capabilities", mapping_core)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/memory_mapping.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sys/mman.h",
            "include/bits/mman.h",
            "compat/x86_64/mman_header_abi_probe.c",
            "compat/x86_64/mman_header_abi_probe.cpp",
            "compat/x86_64/run_mman_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_mapping_core_probe.c",
            "compat/x86_64/libc_mapping_core_start.S",
            "compat/x86_64/run_libc_mapping_core.sh",
        ):
            self.assertIn(owner, mapping_core["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in mapping_core["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-mapping-core"},
        )
        for phrase in (
            "mapping-core block",
            "`mmap`",
            "`munmap`",
            "`mprotect`",
            "`madvise`",
            "`posix_madvise`",
            "`mincore`",
            "PTRDIFF_MAX",
            "page-rounded",
            "__vm_wait",
            "`msync`",
            "`mremap`",
            "`mlock*`",
            "planned `libc.posix-runtime`",
            "public x86 support",
        ):
            self.assertIn(phrase, mapping_core["description"])
        self.assertTrue(
            any(
                "mmap=9" in prerequisite
                and "mprotect=10" in prerequisite
                and "munmap=11" in prerequisite
                and "mincore=27" in prerequisite
                and "madvise=28" in prerequisite
                for prerequisite in mapping_core["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "PTRDIFF_MAX" in prerequisite and "EPERM" in prerequisite
                for prerequisite in mapping_core["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "local no-op" in prerequisite and "__vm_wait" in prerequisite
                for prerequisite in mapping_core["x86_abi_prerequisites"]
            )
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/memory_mapping.rs",
            posix_runtime["source_owners"],
        )
        clock_nanosleep = artifacts_by_id["static-c-clock-nanosleep"]
        assert isinstance(clock_nanosleep, dict)
        self.assertNotIn("capabilities", clock_nanosleep)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/clock_nanosleep.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/signal_control.rs",
            "include/time.h",
            "compat/x86_64/time_header_abi_probe.c",
            "compat/x86_64/time_header_abi_probe.cpp",
            "compat/x86_64/run_time_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_clock_nanosleep_probe.c",
            "compat/x86_64/libc_clock_nanosleep_start.S",
            "compat/x86_64/run_libc_clock_nanosleep.sh",
        ):
            self.assertIn(owner, clock_nanosleep["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in clock_nanosleep["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-clock-nanosleep"},
        )
        self.assertIn("positive errno", clock_nanosleep["description"])
        self.assertIn("__syscall_cp", clock_nanosleep["description"])
        self.assertIn("CLOCK_REALTIME", clock_nanosleep["description"])
        self.assertIn(
            "separately selected nanosleep leaf", clock_nanosleep["description"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/clock_nanosleep.rs",
            posix_runtime["source_owners"],
        )
        nanosleep = artifacts_by_id["static-c-nanosleep"]
        assert isinstance(nanosleep, dict)
        self.assertNotIn("capabilities", nanosleep)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/nanosleep.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/signal_control.rs",
            "include/time.h",
            "compat/x86_64/time_header_abi_probe.c",
            "compat/x86_64/time_header_abi_probe.cpp",
            "compat/x86_64/run_time_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_nanosleep_probe.c",
            "compat/x86_64/libc_nanosleep_start.S",
            "compat/x86_64/run_libc_nanosleep.sh",
        ):
            self.assertIn(owner, nanosleep["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in nanosleep["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-nanosleep"},
        )
        for phrase in (
            "POSIX nanosleep block",
            "-1/errno",
            "initial-TLS errno",
            "__syscall_cp",
            "omits cancellation",
        ):
            self.assertIn(phrase, nanosleep["description"])
        self.assertIn(
            "src/time/nanosleep.c", nanosleep["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/nanosleep.rs",
            posix_runtime["source_owners"],
        )
        descriptor_entry = artifacts_by_id["static-c-descriptor-entry"]
        assert isinstance(descriptor_entry, dict)
        self.assertNotIn("capabilities", descriptor_entry)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/descriptor_entry.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "include/fcntl.h",
            "include/bits/fcntl.h",
            "include/sys/stat.h",
            "compat/x86_64/fcntl_header_abi_probe.c",
            "compat/x86_64/fcntl_header_abi_probe.cpp",
            "compat/x86_64/run_fcntl_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_descriptor_entry_probe.c",
            "compat/x86_64/libc_descriptor_entry_start.S",
            "compat/x86_64/run_libc_descriptor_entry.sh",
        ):
            self.assertIn(owner, descriptor_entry["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in descriptor_entry["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-descriptor-entry"},
        )
        self.assertIn("descriptor-entry block", descriptor_entry["description"])
        self.assertIn("O_CLOEXEC", descriptor_entry["description"])
        self.assertIn(
            "does not expand C fcntl beyond", descriptor_entry["description"]
        )
        self.assertIn("src/fcntl/open.c", descriptor_entry["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/descriptor_entry.rs",
            posix_runtime["source_owners"],
        )
        fcntl_status_control = artifacts_by_id["static-c-fcntl-status-control"]
        assert isinstance(fcntl_status_control, dict)
        self.assertNotIn("capabilities", fcntl_status_control)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/descriptor_control.rs",
            "libc/src/c_abi/x86_64/record_locks.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "include/fcntl.h",
            "include/bits/fcntl.h",
            "compat/x86_64/fcntl_header_abi_probe.c",
            "compat/x86_64/fcntl_header_abi_probe.cpp",
            "compat/x86_64/run_fcntl_header_abi.sh",
            "compat/x86_64/run_x86_fcntl_status_reference.sh",
            "compat/x86_64/x86_fcntl_status_reference_probe.c",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_fcntl_status_control_probe.c",
            "compat/x86_64/libc_fcntl_status_control_start.S",
            "compat/x86_64/run_libc_fcntl_status_control.sh",
        ):
            self.assertIn(owner, fcntl_status_control["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in fcntl_status_control["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-fcntl-status-control"},
        )
        for phrase in (
            "fcntl status-control block",
            "`F_GETFD`",
            "`F_SETFD`",
            "`F_GETFL`",
            "`F_SETFL`",
            "O_LARGEFILE",
            "-1/EINVAL",
            "does not select generic C fcntl",
        ):
            self.assertIn(phrase, fcntl_status_control["description"])
        self.assertIn(
            "src/fcntl/fcntl.c", fcntl_status_control["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/descriptor_control.rs",
            posix_runtime["source_owners"],
        )
        record_locks = artifacts_by_id["static-c-fcntl-record-locks"]
        assert isinstance(record_locks, dict)
        self.assertNotIn("capabilities", record_locks)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/descriptor_control.rs",
            "libc/src/c_abi/x86_64/record_locks.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "include/fcntl.h",
            "include/bits/fcntl.h",
            "include/unistd.h",
            "compat/x86_64/fcntl_header_abi_probe.c",
            "compat/x86_64/fcntl_header_abi_probe.cpp",
            "compat/x86_64/run_fcntl_header_abi.sh",
            "compat/x86_64/run_x86_fcntl_getlk_reference.sh",
            "compat/x86_64/x86_fcntl_getlk_reference_probe.c",
            "compat/x86_64/libc_fcntl_record_locks_probe.c",
            "compat/x86_64/libc_fcntl_record_locks_start.S",
            "compat/x86_64/run_libc_fcntl_record_locks.sh",
        ):
            self.assertIn(owner, record_locks["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in record_locks["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-fcntl-record-locks"},
        )
        for phrase in (
            "nonblocking fcntl record-lock block",
            "F_GETLK",
            "F_SETLK",
            "32-byte",
            "EACCES/EAGAIN",
            "F_SETLKW cancellation",
            "does not select F_SETLKW cancellation",
        ):
            self.assertIn(phrase, record_locks["description"])
        self.assertIn(
            "src/fcntl/fcntl.c", record_locks["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/record_locks.rs",
            posix_runtime["source_owners"],
        )
        flock = artifacts_by_id["static-c-flock"]
        assert isinstance(flock, dict)
        self.assertNotIn("capabilities", flock)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/flock.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sys/file.h",
            "compat/x86_64/flock_header_abi_probe.c",
            "compat/x86_64/flock_header_abi_probe.cpp",
            "compat/x86_64/run_flock_header_abi.sh",
            "compat/x86_64/run_x86_flock_reference.sh",
            "compat/x86_64/x86_flock_reference_probe.c",
            "compat/x86_64/libc_flock_probe.c",
            "compat/x86_64/libc_flock_start.S",
            "compat/x86_64/run_libc_flock.sh",
        ):
            self.assertIn(owner, flock["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in flock["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-flock"},
        )
        for phrase in (
            "advisory whole-file flock block",
            "flock=73",
            "`LOCK_SH`/`LOCK_EX`/`LOCK_NB`/`LOCK_UN`",
            "open-file-description association",
            "EWOULDBLOCK/EAGAIN",
            "fcntl record-lock interaction",
            "`lockf`",
            "public x86 support",
        ):
            self.assertIn(phrase, flock["description"])
        self.assertIn("src/linux/flock.c", flock["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/flock.rs", posix_runtime["source_owners"]
        )
        sendfile = artifacts_by_id["static-c-sendfile"]
        assert isinstance(sendfile, dict)
        self.assertNotIn("capabilities", sendfile)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/sendfile.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sys/sendfile.h",
            "include/unistd.h",
            "compat/x86_64/sendfile_header_abi_probe.c",
            "compat/x86_64/sendfile_header_abi_probe.cpp",
            "compat/x86_64/run_sendfile_header_abi.sh",
            "compat/x86_64/run_x86_sendfile_reference.sh",
            "compat/x86_64/x86_sendfile_reference_probe.c",
            "compat/x86_64/libc_sendfile_probe.c",
            "compat/x86_64/libc_sendfile_start.S",
            "compat/x86_64/run_libc_sendfile.sh",
        ):
            self.assertIn(owner, sendfile["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in sendfile["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-sendfile"},
        )
        for phrase in (
            "regular-file sendfile transfer block",
            "sendfile=40",
            "rdi/rsi/rdx/r10",
            "explicit signed `off_t`",
            "input open-file-description position remains unchanged",
            "null offset advances the shared input position",
            "copy_file_range",
            "public x86 support",
        ):
            self.assertIn(phrase, sendfile["description"])
        self.assertIn("src/linux/sendfile.c", sendfile["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/sendfile.rs", posix_runtime["source_owners"]
        )
        posix_fallocate = artifacts_by_id["static-c-posix-fallocate"]
        assert isinstance(posix_fallocate, dict)
        self.assertNotIn("capabilities", posix_fallocate)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/posix_fallocate.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/fcntl.h",
            "include/features.h",
            "include/bits/fcntl.h",
            "include/stddef.h",
            "include/stdint.h",
            "include/unistd.h",
            "compat/x86_64/fcntl_header_abi_probe.c",
            "compat/x86_64/fcntl_header_abi_probe.cpp",
            "compat/x86_64/fcntl_posix_fallocate_strict_probe.c",
            "compat/x86_64/fcntl_posix_fallocate_strict_probe.cpp",
            "compat/x86_64/fcntl_posix_fallocate_largefile64_probe.c",
            "compat/x86_64/fcntl_posix_fallocate_largefile64_probe.cpp",
            "compat/x86_64/run_fcntl_header_abi.sh",
            "compat/x86_64/run_x86_posix_fallocate_reference.sh",
            "compat/x86_64/x86_posix_fallocate_reference_probe.c",
            "compat/x86_64/libc_posix_fallocate_probe.c",
            "compat/x86_64/libc_posix_fallocate_start.S",
            "compat/x86_64/run_libc_posix_fallocate.sh",
        ):
            self.assertIn(owner, posix_fallocate["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in posix_fallocate["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-posix-fallocate"},
        )
        for phrase in (
            "mode-zero POSIX range-allocation block",
            "fallocate=285",
            "rdi/rsi/rdx/r10",
            "positive `int` error directly",
            "never changing `errno`",
            "8192 bytes",
            "general `fallocate` flags",
            "public x86 support",
        ):
            self.assertIn(phrase, posix_fallocate["description"])
        self.assertIn(
            "src/fcntl/posix_fallocate.c", posix_fallocate["oracle"][0]["role"]
        )
        for phrase in (
            "unconditional",
            "neither `_GNU_SOURCE` nor `_LARGEFILE64_SOURCE`",
            "`_LARGEFILE64_SOURCE`-only",
            "posix_fallocate64",
        ):
            self.assertIn(phrase, posix_fallocate["x86_header_prerequisites"][0])
        self.assertIn(
            "libc/src/c_abi/x86_64/posix_fallocate.rs",
            posix_runtime["source_owners"],
        )
        descriptor_advice = artifacts_by_id["static-c-descriptor-advice"]
        assert isinstance(descriptor_advice, dict)
        self.assertNotIn("capabilities", descriptor_advice)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/descriptor_advice.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/fcntl.h",
            "include/features.h",
            "include/bits/fcntl.h",
            "include/stddef.h",
            "include/stdint.h",
            "include/sys/types.h",
            "include/unistd.h",
            "compat/x86_64/descriptor_advice_header_abi_probe.c",
            "compat/x86_64/descriptor_advice_header_abi_probe.cpp",
            "compat/x86_64/run_descriptor_advice_header_abi.sh",
            "compat/x86_64/run_x86_fs_advice_reference.sh",
            "compat/x86_64/x86_fs_advice_reference_probe.c",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_descriptor_advice_probe.c",
            "compat/x86_64/libc_descriptor_advice_start.S",
            "compat/x86_64/run_libc_descriptor_advice.sh",
        ):
            self.assertIn(owner, descriptor_advice["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in descriptor_advice["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-descriptor-advice"},
        )
        for phrase in (
            "descriptor-advice block",
            "unconditional POSIX `posix_fadvise`",
            "GNU-only `readahead`",
            "fadvise64=221",
            "readahead=187",
            "positive direct `int`",
            "initial-TLS `errno`",
            "all six `POSIX_FADV_*`",
            "no cache-residency or cache-effect claim",
            "public x86 support",
        ):
            self.assertIn(phrase, descriptor_advice["description"])
        for phrase in (
            "strict/no-feature",
            "GNU-only",
            "large-file-only",
            "`ssize_t readahead(int, off_t, size_t)` remains hidden",
            "posix_fadvise64",
            "not an archive export",
            "-H traces",
        ):
            self.assertIn(
                phrase, descriptor_advice["x86_header_prerequisites"][0]
            )
        self.assertIn(
            "src/fcntl/posix_fadvise.c", descriptor_advice["oracle"][0]["role"]
        )
        self.assertIn(
            "src/linux/readahead.c", descriptor_advice["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/descriptor_advice.rs",
            posix_runtime["source_owners"],
        )
        ffs = artifacts_by_id["static-c-ffs"]
        assert isinstance(ffs, dict)
        self.assertNotIn("capabilities", ffs)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/ffs.rs",
            "include/strings.h",
            "compat/x86_64/ffs_header_abi_probe.c",
            "compat/x86_64/ffs_header_abi_probe.cpp",
            "compat/x86_64/run_ffs_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_ffs_probe.c",
            "compat/x86_64/libc_ffs_start.S",
            "compat/x86_64/run_libc_ffs.sh",
        ):
            self.assertIn(owner, ffs["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in ffs["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-ffs"},
        )
        self.assertIn("find-first-set block", ffs["description"])
        self.assertIn("stateless", ffs["description"])
        self.assertIn("allocation-free", ffs["description"])
        self.assertIn("XOPEN/GNU/BSD-gated", ffs["x86_header_prerequisites"][0])
        self.assertIn("src/misc/ffs.c", ffs["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/ffs.rs", posix_runtime["source_owners"]
        )
        system_observation = artifacts_by_id["static-c-system-observation"]
        assert isinstance(system_observation, dict)
        self.assertNotIn("capabilities", system_observation)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/system_observation.rs",
            "include/sys/sysinfo.h",
            "include/sys/utsname.h",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_system_observation_probe.c",
            "compat/x86_64/libc_system_observation_start.S",
            "compat/x86_64/run_libc_system_observation.sh",
        ):
            self.assertIn(owner, system_observation["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in system_observation["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-system-observation"},
        )
        self.assertIn("112-byte", system_observation["description"])
        self.assertIn("252 compatibility bytes", system_observation["description"])
        self.assertIn(
            "does not select hostname/domain lookup or mutation",
            system_observation["description"],
        )
        self.assertIn(
            "src/misc/uname.c and src/linux/sysinfo.c",
            system_observation["oracle"][0]["role"],
        )
        self.assertIn(
            "sysinfo=99", system_observation["x86_abi_prerequisites"][0]
        )
        self.assertIn(
            "remaining 252-byte public compatibility tail is preserved",
            system_observation["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/system_observation.rs",
            posix_runtime["source_owners"],
        )
        system_information = artifacts_by_id["static-c-system-information"]
        assert isinstance(system_information, dict)
        self.assertNotIn("capabilities", system_information)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/system_observation.rs",
            "libc/src/c_abi/x86_64/system_configuration.rs",
            "libc/src/c_abi/x86_64/system_information.rs",
            "include/sys/prctl.h",
            "include/sys/sysinfo.h",
            "compat/x86_64/system_header_abi_probe.c",
            "compat/x86_64/system_header_abi_probe.cpp",
            "compat/x86_64/libc_system_information_probe.c",
            "compat/x86_64/libc_system_information_start.S",
            "compat/x86_64/run_libc_system_information.sh",
        ):
            self.assertIn(owner, system_information["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in system_information["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-system-information"},
        )
        for phrase in (
            "128-byte",
            "sched_getaffinity",
            "CPU-zero",
            "wrapping",
            "LONG_MAX",
            "getloadavg",
            "general `sysconf`",
        ):
            self.assertIn(phrase, system_information["description"])
        self.assertIn(
            "sched_getaffinity=204",
            system_information["x86_abi_prerequisites"][0],
        )
        self.assertIn(
            "failed C page-helper read",
            system_information["oracle"][0]["role"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/system_information.rs",
            posix_runtime["source_owners"],
        )
        uts_identity = artifacts_by_id["static-c-uts-identity"]
        assert isinstance(uts_identity, dict)
        self.assertNotIn("capabilities", uts_identity)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "libc/src/c_abi/x86_64/system_observation.rs",
            "libc/src/c_abi/x86_64/uts_identity.rs",
            "include/errno.h",
            "include/stddef.h",
            "include/sys/syscall.h",
            "include/bits/syscall.h",
            "include/sys/utsname.h",
            "include/unistd.h",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_uts_identity_probe.c",
            "compat/x86_64/libc_uts_identity_start.S",
            "compat/x86_64/run_libc_uts_identity.sh",
        ):
            self.assertIn(owner, uts_identity["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in uts_identity["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-uts-identity"},
        )
        self.assertIn("fresh fixture-local UTS namespace", uts_identity["description"])
        self.assertIn("CAP_SYS_ADMIN", uts_identity["description"])
        self.assertIn(
            "does not select UTS namespace creation, entry, or control",
            uts_identity["description"],
        )
        self.assertIn(
            "src/unistd/gethostname.c, src/linux/sethostname.c, "
            "src/misc/getdomainname.c, and src/misc/setdomainname.c",
            uts_identity["oracle"][0]["role"],
        )
        uts_abi = " ".join(uts_identity["x86_abi_prerequisites"])
        for detail in (
            "uname=63",
            "sethostname=170",
            "setdomainname=171",
            "390-byte align-1",
            "65-byte",
            "rdi/rsi",
            "CAP_SYS_ADMIN",
        ):
            self.assertIn(detail, uts_abi)
        uts_scope = uts_identity["native_evidence"][0]["scope"]
        self.assertIn("unshare --uts --fork", uts_scope)
        self.assertIn("CAP_SYS_ADMIN", uts_scope)
        self.assertIn("container or host identity", uts_scope)
        self.assertIn(
            "libc/src/c_abi/x86_64/uts_identity.rs",
            posix_runtime["source_owners"],
        )
        self.assertEqual(self.family(data, "ldso.relative-relocation")["status"], "foundation-verified")
        static_pie = self.family(data, "crt.static-pie")
        self.assertEqual(static_pie["status"], "foundation-verified")
        for owner in (
            "crt/build_x86_64.py",
            "crt/src/x86_64_startup.rs",
            "libc/src/c_abi/x86_64/static_tls.rs",
            "libc/src/c_abi/x86_64/static_startup.rs",
            "crt/fixtures/static_pie_fixture_x86_64.rs",
            "crt/tests/test_x86_64_static_pie.py",
            "crt/x86_64-static-pie.md",
            "compat/x86_64/run_libc_crt_static_tls.sh",
            "compat/x86_64/README.md",
        ):
            self.assertIn(owner, static_pie["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in static_pie["native_evidence"]},
            {"./crt/run-x86_64.sh static-pie"},
        )
        static_pie_abi = " ".join(static_pie["x86_abi_prerequisites"])
        for detail in (
            "hidden static-link call",
            "R_X86_64_RELATIVE slot",
            "__crabc_x86_static_tls_bootstrap",
            "no-PT_TLS",
            "static-c-crt-initial-tls-handoff",
        ):
            self.assertIn(detail, static_pie_abi)
        static_pie_scope = static_pie["native_evidence"][0]["scope"]
        for detail in ("no-PT_TLS", "test-local", "TLS materialization", "public x86 support"):
            self.assertIn(detail, static_pie_scope)
        builtins_bundle = next(
            artifact
            for artifact in static_pie["verified_artifact"]
            if artifact["id"] == "static-pie-rust-builtins-bundle"
        )
        self.assertEqual(
            {evidence["command"] for evidence in builtins_bundle["native_evidence"]},
            {"./crt/run-x86_64.sh static-pie-bundle"},
        )
        bundle_description = builtins_bundle["description"]
        for detail in (
            "Rust-only `libcrabc-builtins.a`",
            "`__udivti3`",
            "ambient CRT objects",
            "compiler-runtime archives",
            "sysroot",
            "public x86 support",
        ):
            self.assertIn(detail, bundle_description)
        for owner in (
            "builtins/build_x86_64.py",
            "builtins/src/lib.rs",
            "builtins/README.md",
            "crt/fixtures/static_pie_builtins_bundle_x86_64.rs",
            "crt/tests/test_x86_64_static_pie.py",
            "crt/run-x86_64.sh",
        ):
            self.assertIn(owner, builtins_bundle["source_owners"])
        headers_layouts = self.family(data, "libc.headers-layouts")
        self.assertEqual(headers_layouts["status"], "foundation-verified")
        for owner in (
            "include/arpa/inet.h",
            "include/netinet/in.h",
            "include/sys/socket.h",
            "compat/x86_64/socket_header_abi_probe.c",
            "compat/x86_64/socket_header_abi_probe.cpp",
            "compat/x86_64/socket_header_ipv6_macro_probe.c",
            "compat/x86_64/run_socket_header_abi.sh",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        socket_header_evidence = next(
            evidence
            for evidence in headers_layouts["native_evidence"]
            if evidence["command"] == "./scripts/dev-x86_64.sh socket-header-abi"
        )
        self.assertEqual(socket_header_evidence["state"], "required")
        for detail in (
            "IPv4/IPv6 address-equality/classification",
            "`__ARE_4_EQUAL`/`IN6_ARE_ADDR_EQUAL`",
            "`IN_CLASSA`/`IN_CLASSB`/`IN_CLASSC`/`IN_CLASSD`/`IN_MULTICAST`/`IN_EXPERIMENTAL`/`IN_BADCLASS`",
            "GNU/BSD `IP_MSFILTER_SIZE`/`GROUP_FILTER_SIZE`",
            "socket membership",
            "packet I/O",
            "resolver/netdb",
            "C networking runtime behavior",
        ):
            self.assertIn(detail, socket_header_evidence["scope"])
        artifacts = headers_layouts["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 17
        bootstrap = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-bootstrap-primitives"
        )
        assert isinstance(bootstrap, dict)
        self.assertEqual(bootstrap["id"], "static-c-bootstrap-primitives")
        self.assertNotIn("capabilities", bootstrap)
        for owner in (
            "libc/src/c_abi/x86_64/memory.rs",
            "libc/src/c_abi/x86_64/fenv.rs",
            "libc/src/c_abi/x86_64/setjmp.rs",
            "compat/x86_64/libc_bootstrap_primitives_probe.c",
            "compat/x86_64/libc_bootstrap_primitives_start.S",
            "compat/x86_64/run_libc_bootstrap_primitives.sh",
            "compat/x86_64/static_c_abi_exports.txt",
        ):
            self.assertIn(owner, bootstrap["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in bootstrap["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-bootstrap-primitives"},
        )
        self.assertIn("does not select libc.so", bootstrap["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/fenv.rs", headers_layouts["source_owners"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/memory.rs", headers_layouts["source_owners"]
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-fenv",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-memory",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/signal_foundation.rs",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-signal-foundation",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "include/termios.h", headers_layouts["source_owners"]
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh termios-header-abi",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        for owner in (
            "include/sys/resource.h",
            "compat/x86_64/resource_header_abi_probe.c",
            "compat/x86_64/resource_header_abi_probe.cpp",
            "compat/x86_64/run_resource_header_abi.sh",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        self.assertIn(
            "./scripts/dev-x86_64.sh resource-header-abi",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        for owner in (
            "include/poll.h",
            "compat/x86_64/poll_header_abi_probe.c",
            "compat/x86_64/poll_header_abi_probe.cpp",
            "compat/x86_64/run_poll_header_abi.sh",
            "include/sys/select.h",
            "compat/x86_64/select_header_abi_probe.c",
            "compat/x86_64/select_header_abi_probe.cpp",
            "compat/x86_64/run_select_header_abi.sh",
            "compat/x86_64/byte_strings_header_abi_probe.c",
            "compat/x86_64/byte_strings_header_abi_probe.cpp",
            "compat/x86_64/run_byte_strings_header_abi.sh",
            "include/inttypes.h",
            "compat/x86_64/integer_parse_header_abi_probe.c",
            "compat/x86_64/integer_parse_header_abi_probe.cpp",
            "compat/x86_64/run_integer_parse_header_abi.sh",
            "compat/x86_64/intmax_arithmetic_header_abi_probe.c",
            "compat/x86_64/intmax_arithmetic_header_abi_probe.cpp",
            "compat/x86_64/run_intmax_arithmetic_header_abi.sh",
            "compat/x86_64/credential_observation_header_abi_probe.c",
            "compat/x86_64/credential_observation_header_abi_probe.cpp",
            "compat/x86_64/run_credential_observation_header_abi.sh",
            "compat/x86_64/immediate_termination_header_abi_probe.c",
            "compat/x86_64/immediate_termination_header_abi_probe.cpp",
            "compat/x86_64/run_immediate_termination_header_abi.sh",
            "compat/x86_64/callback_algorithms_header_abi_probe.c",
            "compat/x86_64/callback_algorithms_header_abi_probe.cpp",
            "compat/x86_64/run_callback_algorithms_header_abi.sh",
            "compat/x86_64/ffs_header_abi_probe.c",
            "compat/x86_64/ffs_header_abi_probe.cpp",
            "compat/x86_64/run_ffs_header_abi.sh",
            "compat/x86_64/memccpy_header_abi_probe.c",
            "compat/x86_64/memccpy_header_abi_probe.cpp",
            "compat/x86_64/run_memccpy_header_abi.sh",
            "include/aio.h",
            "compat/x86_64/aio_error_header_abi_probe.c",
            "compat/x86_64/aio_error_header_abi_probe.cpp",
            "compat/x86_64/run_aio_error_header_abi.sh",
            "compat/x86_64/memory_search_header_abi_probe.c",
            "compat/x86_64/memory_search_header_abi_probe.cpp",
            "compat/x86_64/run_memory_search_header_abi.sh",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        header_commands = {
            evidence["command"] for evidence in headers_layouts["native_evidence"]
        }
        self.assertIn("./scripts/dev-x86_64.sh poll-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh select-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh byte-strings-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh memccpy-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh aio-error-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh integer-parse-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh intmax-arithmetic-header-abi", header_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh credential-observation-header-abi",
            header_commands,
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh immediate-termination-header-abi",
            header_commands,
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh callback-algorithms-header-abi",
            header_commands,
        )
        self.assertIn("./scripts/dev-x86_64.sh ffs-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh memory-search-header-abi", header_commands)
        self.assertIn(
            "libc/src/c_abi/x86_64/process_context.rs",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/libc_process_context_probe.c",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-process-context",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/descriptor_io.rs",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/libc_descriptor_io_probe.c",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-descriptor-io",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/process_resources.rs",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/libc_process_resources_probe.c",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-process-resources",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        for owner in (
            "libc/src/c_abi/x86_64/readiness_waits.rs",
            "compat/x86_64/libc_readiness_waits_probe.c",
            "compat/x86_64/libc_readiness_waits_start.S",
            "compat/x86_64/run_libc_readiness_waits.sh",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-readiness-waits",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertEqual(self.family(data, "ldso.dynamic-runtime")["status"], "planned")
        self.assertEqual(self.family(data, "sysroot.owned-artifact")["status"], "planned")
        for capability in (
            "io.readiness-poll",
            "io.readiness-ppoll",
            "event.pause",
            "process.pid-observation",
            "process.identity-triples",
            "process.identity",
            "process.session-observation",
            "process.fs-credentials",
            "process.supplementary-groups",
            "process.pidfd-open",
            "process.resource-limits",
            "process.resource-limits-targeted",
            "process.resource-usage",
            "process.resource-limit-mutation",
            "process.umask",
            "thread.futex-basic",
            "thread.identity",
            "thread.credentials-res",
            "thread.cpu-observation",
            "thread.scheduler-rr-interval",
            "thread.cpu-affinity-observation",
            "thread.cpu-affinity-mutation",
            "io.readiness-epoll",
            "io.readiness",
            "system.load-average",
            "system.name-observation",
            "system.identity-info",
            "memory.mapping-remap",
            "memory.mapping-locking",
            "memory.mapping-sync",
            "memory.advice",
            "memory.residency",
            "filesystem.access-advice",
            "filesystem.readahead",
            "filesystem.memory-file",
            "filesystem.seal-observation",
            "filesystem.seal-mutation",
            "filesystem.cwd",
            "filesystem.path-metadata",
            "filesystem.fd-timestamps",
            "filesystem.directory-relative-timestamps",
            "filesystem.cwd-timestamps",
            "filesystem.symlink-timestamps",
            "filesystem.second-resolution-timestamps",
            "io.file-position",
            "filesystem.global-sync",
            "io.syncfs",
            "io.range-sync",
            "io.status-flags",
            "io.advisory-flock",
            "filesystem.descriptor-transfer",
            "filesystem.descriptor-range-copy",
            "process.fcntl-lock-observation",
            "process.scheduling-priority",
            "process.scheduling-priority-mutation",
            "process.scheduler-priority-bounds",
            "time.realtime-millis",
            "time.timespec-get",
            "time.process-cpu-observation",
            "time.process-accounting",
            "time.interval-timer-query",
            "time.timerfd",
            "time.relative-sleep",
            "time.sleep-aliases",
            "time.clock-sleep",
        ):
            self.assertIn(capability, direct["capabilities"])
            self.assertNotIn(capability, remaining["capabilities"])
        self.assertIn("crabc-rs/tests/futex.rs", direct["source_owners"])
        self.assertIn("crabc-core/src/thread.rs", direct["source_owners"])
        self.assertIn("crabc-core/src/io.rs", direct["source_owners"])
        for source_owner in (
            "crabc-rs/tests/x86_64_posix_fallocate.rs",
            "crabc-rs/tests/x86_64_fallocate.rs",
            "crabc-rs/tests/x86_64_ftruncate.rs",
            "crabc-rs/tests/x86_64_futimens.rs",
            "crabc-rs/tests/x86_64_timestamp_paths.rs",
            "crabc-rs/tests/x86_64_fcntl_flags.rs",
            "crabc-rs/tests/x86_64_flock.rs",
            "crabc-rs/tests/x86_64_sendfile.rs",
            "crabc-rs/tests/x86_64_copy_file_range.rs",
            "crabc-rs/tests/x86_64_epoll.rs",
            "crabc-rs/tests/x86_64_pselect.rs",
            "crabc-rs/tests/x86_64_file_position.rs",
            "crabc-rs/tests/x86_64_sync.rs",
            "crabc-rs/tests/x86_64_syncfs.rs",
            "crabc-rs/tests/x86_64_sync_file_range.rs",
            "crabc-rs/tests/x86_64_memfd.rs",
            "crabc-rs/tests/x86_64_thread_credentials.rs",
            "crabc-rs/tests/x86_64_fs_credentials.rs",
            "crabc-rs/tests/x86_64_getgroups.rs",
            "crabc-rs/tests/x86_64_getitimer.rs",
            "crabc-rs/tests/x86_64_timerfd.rs",
            "crabc-rs/tests/x86_64_getcwd.rs",
            "crabc-rs/tests/x86_64_current_dir_name.rs",
            "crabc-rs/tests/x86_64_clock_nanosleep.rs",
            "crabc-rs/tests/x86_64_sched_rr_interval.rs",
            "crabc-rs/tests/x86_64_sched_affinity.rs",
            "crabc-rs/tests/x86_64_sched_setaffinity.rs",
            "crabc-rs/tests/x86_64_setpriority.rs",
            "crabc-rs/tests/x86_64_rlimit.rs",
            "crabc-rs/tests/x86_64_rlimit_targeted.rs",
            "crabc-rs/tests/x86_64_setrlimit.rs",
            "crabc-rs/tests/x86_64_umask.rs",
            "compat/x86_64/run_x86_ftruncate_reference.sh",
            "compat/x86_64/x86_ftruncate_reference_probe.c",
            "compat/x86_64/run_x86_timestamp_reference.sh",
            "compat/x86_64/x86_timestamp_reference_probe.c",
            "compat/x86_64/run_x86_posix_fallocate_reference.sh",
            "compat/x86_64/x86_posix_fallocate_reference_probe.c",
            "compat/x86_64/run_x86_fallocate_reference.sh",
            "compat/x86_64/x86_fallocate_reference_probe.c",
            "compat/x86_64/run_x86_fcntl_status_reference.sh",
            "compat/x86_64/x86_fcntl_status_reference_probe.c",
            "compat/x86_64/run_x86_flock_reference.sh",
            "compat/x86_64/x86_flock_reference_probe.c",
            "compat/x86_64/run_x86_sendfile_reference.sh",
            "compat/x86_64/x86_sendfile_reference_probe.c",
            "compat/x86_64/run_x86_copy_file_range_reference.sh",
            "compat/x86_64/x86_copy_file_range_reference_probe.c",
            "compat/x86_64/run_x86_epoll_reference.sh",
            "compat/x86_64/x86_epoll_reference_probe.c",
            "compat/x86_64/run_x86_pselect_reference.sh",
            "compat/x86_64/x86_pselect_reference_probe.c",
            "compat/x86_64/run_x86_memfd_reference.sh",
            "compat/x86_64/x86_memfd_reference_probe.c",
            "compat/x86_64/run_x86_file_position_reference.sh",
            "compat/x86_64/x86_file_position_reference_probe.c",
            "compat/x86_64/run_x86_sync_reference.sh",
            "compat/x86_64/x86_sync_reference_probe.c",
            "compat/x86_64/run_x86_syncfs_reference.sh",
            "compat/x86_64/x86_syncfs_reference_probe.c",
            "compat/x86_64/run_x86_sync_file_range_reference.sh",
            "compat/x86_64/x86_sync_file_range_reference_probe.c",
            "compat/x86_64/run_x86_thread_credentials_reference.sh",
            "compat/x86_64/x86_thread_credentials_reference_probe.c",
            "compat/x86_64/run_x86_fs_credentials_reference.sh",
            "compat/x86_64/x86_fs_credentials_reference_probe.c",
            "compat/x86_64/run_x86_getgroups_reference.sh",
            "compat/x86_64/x86_getgroups_reference_probe.c",
            "compat/x86_64/run_x86_getitimer_reference.sh",
            "compat/x86_64/x86_getitimer_reference_probe.c",
            "compat/x86_64/run_x86_timerfd_reference.sh",
            "compat/x86_64/x86_timerfd_reference_probe.c",
            "compat/x86_64/run_x86_getcwd_reference.sh",
            "compat/x86_64/x86_getcwd_reference_probe.c",
            "compat/x86_64/run_x86_clock_nanosleep_reference.sh",
            "compat/x86_64/x86_clock_nanosleep_reference_probe.c",
            "compat/x86_64/run_x86_sched_rr_interval_reference.sh",
            "compat/x86_64/x86_sched_rr_interval_reference_probe.c",
            "compat/x86_64/run_x86_sched_affinity_reference.sh",
            "compat/x86_64/x86_sched_affinity_reference_probe.c",
            "compat/x86_64/run_x86_sched_setaffinity_reference.sh",
            "compat/x86_64/x86_sched_setaffinity_reference_probe.c",
            "compat/x86_64/run_x86_setpriority_reference.sh",
            "compat/x86_64/x86_setpriority_reference_probe.c",
            "compat/x86_64/run_x86_rlimit_reference.sh",
            "compat/x86_64/x86_rlimit_reference_probe.c",
            "compat/x86_64/run_x86_rlimit_targeted_reference.sh",
            "compat/x86_64/x86_rlimit_targeted_reference_probe.c",
            "crabc-rs/tests/x86_64_rusage.rs",
            "compat/x86_64/run_x86_rusage_reference.sh",
            "compat/x86_64/x86_rusage_reference_probe.c",
            "compat/x86_64/run_x86_setrlimit_reference.sh",
            "compat/x86_64/x86_setrlimit_reference_probe.c",
            "compat/x86_64/run_x86_umask_reference.sh",
            "compat/x86_64/x86_umask_reference_probe.c",
            "crabc-rs/tests/x86_64_times.rs",
            "compat/x86_64/run_x86_times_reference.sh",
            "compat/x86_64/x86_times_reference_probe.c",
        ):
            self.assertIn(source_owner, direct["source_owners"])
        direct_commands = {
            evidence["command"] for evidence in direct["native_evidence"]
        }
        facade_evidence = next(
            evidence
            for evidence in direct["native_evidence"]
            if evidence["command"] == "./scripts/dev-x86_64.sh facade"
        )
        self.assertIn("timestamp-mutation family", facade_evidence["scope"])
        self.assertIn(
            "fs::{Timespec, Timestamps, UTIME_NOW, UTIME_OMIT, futimens}",
            facade_evidence["scope"],
        )
        self.assertIn("filesystem.path-core", facade_evidence["scope"])
        self.assertIn(
            "./scripts/dev-x86_64.sh posix-fallocate-reference", direct_commands
        )
        self.assertIn("./scripts/dev-x86_64.sh fallocate-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh ftruncate-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh timestamp-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh memfd-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh file-position-reference", direct_commands
        )
        self.assertIn("./scripts/dev-x86_64.sh sync-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh syncfs-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh sync-file-range-reference", direct_commands
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sync=162")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct syncfs=306")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sync_file_range=277")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct posix_fallocate=285")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct fallocate=285")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct timestamp mutation through utimensat=280")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh thread-credentials-reference",
            direct_commands,
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh fs-credentials-reference",
            direct_commands,
        )
        self.assertIn("./scripts/dev-x86_64.sh getgroups-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh getitimer-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh setitimer-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh timerfd-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh getcwd-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh access-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh fcntl-status-reference", direct_commands
        )
        self.assertIn("./scripts/dev-x86_64.sh flock-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh sendfile-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh copy-file-range-reference", direct_commands
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct flock=73")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sendfile=40")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct copy_file_range=326")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertIn("./scripts/dev-x86_64.sh clock-nanosleep-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh rr-interval-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh sched-affinity-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh sched-affinity-set-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh epoll-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh pselect-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh setpriority-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh rlimit-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh rlimit-targeted-reference", direct_commands
        )
        self.assertIn("./scripts/dev-x86_64.sh rusage-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh setrlimit-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh umask-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh times-reference", direct_commands)
        self.assertEqual(remaining["status"], "foundation-verified")
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in remaining["native_evidence"])
        )
        self.assertEqual(
            {evidence["command"] for evidence in remaining["native_evidence"]},
            {"./scripts/dev-x86_64.sh facade-record-owning"},
        )
        verified_slices = remaining["verified_slice"]
        assert isinstance(verified_slices, list)
        self.assertEqual(len(verified_slices), 24)
        slices_by_id = {}
        for slice_entry in verified_slices:
            assert isinstance(slice_entry, dict)
            slices_by_id[slice_entry["id"]] = slice_entry
        self.assertEqual(
            set(slices_by_id),
            {
                "network.interface-device",
                "network.resolver-transport",
                "network.resolver",
                "network.netdb",
                "users.databases",
                "mount.basic",
                "filesystem.path-core",
                "filesystem.xattr",
                "filesystem.directory",
                "filesystem.temporary-objects",
                "filesystem.extended-metadata",
                "filesystem.cwd-canonicalize",
                "ipc.posix-mqueue",
                "ipc.posix-shm",
                "system.inotify",
                "time.civil-calendar",
                "time.advanced-clocks-posix-timers",
                "process.root-change",
                "process.child-ownership",
                "process.thread-kill",
                "memory.mapping",
                "memory.vm",
                "terminal.pty-basic",
                "terminal.session-control",
            },
        )
        family_capabilities = remaining["capabilities"]
        assert isinstance(family_capabilities, list)
        slice_capabilities = {
            capability
            for slice_entry in verified_slices
            for capability in slice_entry["capabilities"]
        }
        self.assertEqual(slice_capabilities, set(family_capabilities))
        root_change = slices_by_id["process.root-change"]
        self.assertEqual(root_change["capabilities"], ["process.root-change"])
        self.assertEqual(
            root_change["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh root-change-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in root_change["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/process.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/process_x86_64.rs",
            "crabc-rs/tests/x86_64_chroot.rs",
            "crabc-rs/examples/process_chroot_direct_probe.rs",
            "compat/x86_64/run_x86_root_change_reference.sh",
            "compat/x86_64/x86_root_change_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, root_change["source_owners"])
        self.assertTrue(
            any(
                "chroot=161" in prerequisite
                for prerequisite in root_change["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "CAP_SYS_CHROOT" in prerequisite and "without changing CWD" in prerequisite
                for prerequisite in root_change["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "pivot_root" in prerequisite
                and "mount or namespace control" in prerequisite
                and "confinement/security framework" in prerequisite
                for prerequisite in root_change["x86_header_prerequisites"]
            )
        )
        self.assertIn("process.root-change", remaining["capabilities"])
        child_ownership = slices_by_id["process.child-ownership"]
        self.assertEqual(child_ownership["capabilities"], ["process.child-ownership"])
        self.assertEqual(
            child_ownership["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh child-ownership-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in child_ownership["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/process.rs",
            "crabc-rs/src/process_x86_64.rs",
            "crabc-rs/tests/x86_64_child_ownership.rs",
            "compat/x86_64/run_x86_child_ownership_reference.sh",
            "compat/x86_64/x86_child_ownership_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, child_ownership["source_owners"])
        self.assertTrue(
            any(
                "clone=56" in prerequisite
                and "execve=59" in prerequisite
                and "wait4=61" in prerequisite
                for prerequisite in child_ownership["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "does not expose generic C fork/vfork/exec" in prerequisite
                and "pthread/atfork/cancellation" in prerequisite
                for prerequisite in child_ownership["x86_header_prerequisites"]
            )
        )
        self.assertIn("process.child-ownership", remaining["capabilities"])
        thread_kill = slices_by_id["process.thread-kill"]
        self.assertEqual(thread_kill["capabilities"], ["process.thread-kill"])
        self.assertEqual(
            thread_kill["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh thread-kill-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in thread_kill["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/process.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/signal.rs",
            "crabc-rs/tests/x86_64_thread_kill.rs",
            "crabc-rs/examples/thread_kill_direct_probe.rs",
            "compat/x86_64/run_x86_thread_kill_reference.sh",
            "compat/x86_64/x86_thread_kill_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, thread_kill["source_owners"])
        self.assertTrue(
            any(
                "tgkill=234" in prerequisite
                and "ESRCH" in prerequisite
                and "EINVAL" in prerequisite
                for prerequisite in thread_kill["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "SYS_tkill=200" in prerequisite
                and "SYS_gettid=186" in prerequisite
                and "pthread_kill uses SYS_tkill" in prerequisite
                for prerequisite in thread_kill["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "generic process/group signaling" in prerequisite
                and "signal masks" in prerequisite
                and "signalfd" in prerequisite
                and "pthread cancellation" in prerequisite
                for prerequisite in thread_kill["x86_header_prerequisites"]
            )
        )
        self.assertIn("process.thread-kill", remaining["capabilities"])
        memory_mapping = slices_by_id["memory.mapping"]
        self.assertEqual(memory_mapping["capabilities"], ["memory.mapping"])
        self.assertEqual(
            memory_mapping["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh mapping-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in memory_mapping["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/mm_x86_64.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/mm_x86_64.rs",
            "crabc-rs/tests/x86_64_memory_mapping.rs",
            "crabc-rs/examples/mapping_direct_probe.rs",
            "compat/x86_64/run_x86_mapping_reference.sh",
            "compat/x86_64/x86_mapping_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, memory_mapping["source_owners"])
        self.assertTrue(
            any(
                "mmap=9" in prerequisite
                and "mprotect=10" in prerequisite
                and "munmap=11" in prerequisite
                for prerequisite in memory_mapping["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "MAP_FIXED=0x10" in prerequisite
                and "MAP_32BIT=0x40" in prerequisite
                and "MAP_ANONYMOUS=0x20" in prerequisite
                for prerequisite in memory_mapping["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "pointer-provenance" in prerequisite
                and "no references survive munmap" in prerequisite
                for prerequisite in memory_mapping["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "only raw SYS_mprotect" in prerequisite
                and "musl 1.2.6 rounds" in prerequisite
                for prerequisite in memory_mapping["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "mremap" in prerequisite
                and "mapping locks/sync/advice/residency" in prerequisite
                and "separate memory.vm/brk/process-wide-lock/legacy-remap boundary" in prerequisite
                and "C mmap/mprotect/munmap API/header/ABI" in prerequisite
                for prerequisite in memory_mapping["x86_header_prerequisites"]
            )
        )
        self.assertIn("memory.mapping", remaining["capabilities"])
        memory_vm = slices_by_id["memory.vm"]
        self.assertEqual(memory_vm["capabilities"], ["memory.vm"])
        self.assertEqual(
            memory_vm["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh memory-vm-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in memory_vm["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/mm_x86_64.rs",
            "crabc-core/src/process.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/mm_x86_64.rs",
            "crabc-rs/src/process_x86_64.rs",
            "crabc-rs/tests/x86_64_memory_vm.rs",
            "crabc-rs/examples/memory_vm_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_memory_vm_reference.sh",
            "compat/x86_64/x86_memory_vm_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, memory_vm["source_owners"])
        self.assertTrue(
            any(
                "brk=12" in prerequisite
                and "mlockall=151" in prerequisite
                and "munlockall=152" in prerequisite
                and "remap_file_pages=216" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "MCL_CURRENT=1" in prerequisite
                and "MCL_FUTURE=2" in prerequisite
                and "MCL_ONFAULT=4" in prerequisite
                and "RLIMIT_MEMLOCK" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "queries with a null pointer" in prerequisite
                and "replays that exact returned pointer only" in prerequisite
                and "never asks Linux to move the break" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "musl 1.2.6 sbrk(0)" in prerequisite
                and "musl brk(current) deliberately returns ENOMEM" in prerequisite
                and "raw break remains unchanged" in prerequisite
                and "not selected Rust behavior" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "anonymous one-page mapping" in prerequisite
                and "direct EINVAL" in prerequisite
                and "file-backed remapping behavior" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "C brk/sbrk/mlockall/munlockall/remap_file_pages" in prerequisite
                and "allocator, heap, program-break adjustment" in prerequisite
                and "mremap or fixed maps" in prerequisite
                and "range locks, sync, advice, or residency" in prerequisite
                and "public x86 support" in prerequisite
                for prerequisite in memory_vm["x86_header_prerequisites"]
            )
        )
        self.assertIn("memory.vm", remaining["capabilities"])
        pty_basic = slices_by_id["terminal.pty-basic"]
        self.assertEqual(pty_basic["capabilities"], ["terminal.pty-basic"])
        self.assertEqual(
            pty_basic["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh pty-basic-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in pty_basic["native_evidence"])
        )
        self.assertIn(
            "musl grantpt's no-op success",
            pty_basic["native_evidence"][0]["scope"],
        )
        for source_owner in (
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-core/src/io.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/src/pty_x86_64.rs",
            "crabc-rs/tests/x86_64_pty_basic.rs",
            "crabc-rs/examples/pty_basic_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_pty_basic_reference.sh",
            "compat/x86_64/x86_pty_basic_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, pty_basic["source_owners"])
        self.assertTrue(
            any(
                "openat=257" in prerequisite
                and "ioctl=16" in prerequisite
                and "TIOCGPTN=0x80045430" in prerequisite
                and "TIOCSPTLCK=0x40045431" in prerequisite
                and "TIOCGPTPEER=0x5441" in prerequisite
                for prerequisite in pty_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "PtyPair::open requires RDWR" in prerequisite
                and "explicit O_NOCTTY request" in prerequisite
                and "controlling-terminal or session transition" in prerequisite
                for prerequisite in pty_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "ptsname_into" in prerequisite
                and "short caller storage" in prerequisite
                and "RANGE" in prerequisite
                and "C static buffer" in prerequisite
                for prerequisite in pty_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "openpty" in prerequisite
                and "ioctl_tiocgptpeer" in prerequisite
                and "TIOCSCTTY/setsid/process-session" in prerequisite
                and "termios/tty API" in prerequisite
                and "public x86 support" in prerequisite
                for prerequisite in pty_basic["x86_header_prerequisites"]
            )
        )
        terminal_session_control = slices_by_id["terminal.session-control"]
        self.assertEqual(
            terminal_session_control["capabilities"],
            [
                "terminal.pty-session",
                "terminal.termios-control",
                "terminal.termios-queue",
                "terminal.exclusive-mode",
                "terminal.special-codes",
                "terminal.tty-path",
                "terminal.tty-basic",
            ],
        )
        self.assertEqual(
            terminal_session_control["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh terminal-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in terminal_session_control["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/io.rs",
            "crabc-core/src/process.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/pty_x86_64.rs",
            "crabc-rs/src/termios_x86_64.rs",
            "crabc-rs/tests/x86_64_terminal.rs",
            "crabc-rs/examples/x86_64_terminal_direct_probe.rs",
            "compat/x86_64/run_x86_terminal_reference.sh",
            "compat/x86_64/x86_terminal_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, terminal_session_control["source_owners"])
        self.assertTrue(
            any(
                "36-byte align-4" in prerequisite
                and "60-byte align-4" in prerequisite
                and "NCCS=32" in prerequisite
                for prerequisite in terminal_session_control["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "TIOCSCTTY=0x540e" in prerequisite
                and "TIOCGSID=0x5429" in prerequisite
                and "winsize" in prerequisite
                for prerequisite in terminal_session_control["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "C terminal header/API/ABI" in prerequisite
                and "generic ioctl" in prerequisite
                and "openpty/forkpty/login_tty/vhangup" in prerequisite
                and "public x86 support" in prerequisite
                for prerequisite in terminal_session_control["x86_header_prerequisites"]
            )
        )
        verified_terminal_capabilities = {
            capability
            for slice_entry in slices_by_id.values()
            for capability in slice_entry["capabilities"]
            if capability.startswith("terminal.")
        }
        self.assertEqual(
            verified_terminal_capabilities,
            {
                "terminal.pty-basic",
                "terminal.pty-session",
                "terminal.termios-control",
                "terminal.termios-queue",
                "terminal.exclusive-mode",
                "terminal.special-codes",
                "terminal.tty-path",
                "terminal.tty-basic",
            },
        )
        for capability in (
            "terminal.pty-session",
            "terminal.termios-control",
            "terminal.termios-queue",
            "terminal.exclusive-mode",
            "terminal.special-codes",
            "terminal.tty-path",
            "terminal.tty-basic",
        ):
            self.assertIn(capability, remaining["capabilities"])
            self.assertIn(capability, verified_terminal_capabilities)
        interface_device = slices_by_id["network.interface-device"]
        self.assertEqual(interface_device["id"], "network.interface-device")
        self.assertEqual(
            interface_device["capabilities"],
            [
                "network.interface-addresses",
                "network.interface-index",
                "network.interface-name",
                "network.interface-enumeration",
            ],
        )
        self.assertEqual(
            interface_device["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh interface-device-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in interface_device["native_evidence"])
        )
        for source_owner in (
            "crabc-rs/src/netdevice.rs",
            "crabc-rs/tests/x86_64_interface_device.rs",
            "compat/x86_64/run_x86_interface_device_reference.sh",
            "compat/x86_64/x86_interface_device_reference_probe.c",
        ):
            self.assertIn(source_owner, interface_device["source_owners"])
        resolver_transport = slices_by_id["network.resolver-transport"]
        self.assertEqual(
            resolver_transport["capabilities"], ["network.resolver-transport"]
        )
        self.assertEqual(
            resolver_transport["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh resolver-transport-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in resolver_transport["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/resolver.rs",
            "crabc-core/tests/x86_64_resolver_transport.rs",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, resolver_transport["source_owners"])
        resolver = slices_by_id["network.resolver"]
        self.assertEqual(resolver["capabilities"], ["network.resolver"])
        self.assertEqual(
            resolver["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh resolver-facade-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in resolver["native_evidence"])
        )
        for source_owner in (
            "crabc-rs/src/resolver.rs",
            "crabc-rs/src/netdb.rs",
            "crabc-rs/tests/x86_64_resolver.rs",
            "crabc-rs/examples/resolver_hosts_direct_probe.rs",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, resolver["source_owners"])
        self.assertNotIn("network.netdb", resolver["capabilities"])
        netdb = slices_by_id["network.netdb"]
        self.assertEqual(netdb["capabilities"], ["network.netdb"])
        self.assertEqual(
            netdb["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh netdb-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in netdb["native_evidence"])
        )
        for source_owner in (
            "crabc-rs/src/netdb.rs",
            "crabc-rs/tests/x86_64_netdb.rs",
            "crabc-rs/examples/resolver_direct_probe.rs",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, netdb["source_owners"])
        users_databases = slices_by_id["users.databases"]
        self.assertEqual(users_databases["capabilities"], ["users.databases"])
        self.assertEqual(
            users_databases["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh users-databases-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in users_databases["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/io.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/src/users.rs",
            "crabc-rs/tests/x86_64_users_databases.rs",
            "crabc-rs/examples/users_databases_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_users_databases_reference.sh",
            "compat/x86_64/x86_users_databases_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, users_databases["source_owners"])
        self.assertTrue(
            any(
                "openat=257" in prerequisite
                and "read=0" in prerequisite
                and "close=3" in prerequisite
                and "O_CLOEXEC=0x00080000" in prerequisite
                for prerequisite in users_databases["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "one mebibyte" in prerequisite
                and "not an atomic multi-file transaction" in prerequisite
                for prerequisite in users_databases["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "exactly seven colon fields" in prerequisite
                and "exactly four colon fields" in prerequisite
                and "first-match only" in prerequisite
                for prerequisite in users_databases["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "getpwnam" in prerequisite
                and "getgrnam" in prerequisite
                and "shadow" in prerequisite
                and "utmp/utmpx" in prerequisite
                and "initgroups" in prerequisite
                and "process-global enumeration state" in prerequisite
                and "NSS/provider framework" in prerequisite
                for prerequisite in users_databases["x86_header_prerequisites"]
            )
        )
        self.assertIn("users.databases", remaining["capabilities"])
        mount_basic = slices_by_id["mount.basic"]
        self.assertEqual(mount_basic["capabilities"], ["mount.basic"])
        self.assertEqual(
            mount_basic["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh mount-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in mount_basic["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/mount.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/mount_x86_64.rs",
            "crabc-rs/tests/x86_64_mount.rs",
            "crabc-rs/examples/mount_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_mount_reference.sh",
            "compat/x86_64/x86_mount_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, mount_basic["source_owners"])
        self.assertTrue(
            any(
                "mount=165" in prerequisite
                and "umount2=166" in prerequisite
                and "rdi/rsi/rdx" in prerequisite
                and "r10" in prerequisite
                and "r8" in prerequisite
                for prerequisite in mount_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "unique nonexistent targets" in prerequisite
                and "interior-NUL" in prerequisite
                and "non-mutating" in prerequisite
                and "EPERM" in prerequisite
                and "ENOENT" in prerequisite
                for prerequisite in mount_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "null source/type" in prerequisite
                and "pivot_root" in prerequisite
                and "unshare" in prerequisite
                and "setns" in prerequisite
                and "fsopen" in prerequisite
                and "public x86 support" in prerequisite
                for prerequisite in mount_basic["x86_header_prerequisites"]
            )
        )
        self.assertIn("mount.basic", remaining["capabilities"])
        path_core = slices_by_id["filesystem.path-core"]
        self.assertEqual(path_core["capabilities"], ["filesystem.path-core"])
        self.assertEqual(
            path_core["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh path-core-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in path_core["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_path_lifecycle.rs",
            "crabc-rs/tests/x86_64_namespace.rs",
            "crabc-rs/tests/x86_64_readlink.rs",
            "crabc-rs/examples/path_core_owned_direct_probe.rs",
            "compat/x86_64/run_x86_path_lifecycle_reference.sh",
            "compat/x86_64/run_x86_readlinkat_reference.sh",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, path_core["source_owners"])
        xattr = slices_by_id["filesystem.xattr"]
        self.assertEqual(xattr["capabilities"], ["filesystem.xattr"])
        self.assertEqual(
            xattr["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh xattr-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in xattr["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_xattr.rs",
            "crabc-rs/examples/xattr_direct_probe.rs",
            "compat/x86_64/run_x86_xattr_reference.sh",
            "compat/x86_64/x86_xattr_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, xattr["source_owners"])
        directory = slices_by_id["filesystem.directory"]
        self.assertEqual(
            directory["capabilities"],
            [
                "filesystem.directory-stream",
                "filesystem.directory-position",
                "filesystem.raw-directory",
            ],
        )
        self.assertEqual(
            directory["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh directory-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in directory["native_evidence"])
        )
        for source_owner in (
            "crabc-rs/src/raw_dir.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_raw_directory.rs",
            "crabc-rs/tests/x86_64_directory.rs",
            "crabc-rs/tests/x86_64_directory_position.rs",
            "crabc-rs/examples/directory_direct_probe.rs",
            "crabc-rs/examples/directory_position_direct_probe.rs",
            "compat/x86_64/run_x86_directory_reference.sh",
            "compat/x86_64/x86_directory_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, directory["source_owners"])
        temporary_objects = slices_by_id["filesystem.temporary-objects"]
        self.assertEqual(
            temporary_objects["capabilities"],
            [
                "filesystem.named-temporary-file",
                "filesystem.anonymous-temporary-file",
                "filesystem.temporary-directory",
            ],
        )
        self.assertEqual(
            temporary_objects["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh temporary-object-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in temporary_objects["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_temporary_objects.rs",
            "crabc-rs/examples/fs_named_tempfile_direct_probe.rs",
            "crabc-rs/examples/fs_tempfile_direct_probe.rs",
            "crabc-rs/examples/fs_tempdir_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_temporary_object_reference.sh",
            "compat/x86_64/x86_temporary_object_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, temporary_objects["source_owners"])
        self.assertTrue(
            any(
                "O_TMPFILE=0x00410000" in prerequisite
                for prerequisite in temporary_objects["x86_abi_prerequisites"]
            )
        )
        extended_metadata = slices_by_id["filesystem.extended-metadata"]
        self.assertEqual(
            extended_metadata["capabilities"], ["filesystem.extended-metadata"]
        )
        self.assertEqual(
            extended_metadata["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh statx-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in extended_metadata["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_statx.rs",
            "crabc-rs/examples/statx_direct_probe.rs",
            "compat/x86_64/run_x86_statx_reference.sh",
            "compat/x86_64/x86_statx_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, extended_metadata["source_owners"])
        self.assertTrue(
            any(
                "SYS_statx=332" in prerequisite
                for prerequisite in extended_metadata["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "256-byte align-8" in prerequisite
                for prerequisite in extended_metadata["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "AT_EMPTY_PATH" in prerequisite
                for prerequisite in extended_metadata["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "ENOSYS" in prerequisite and "musl's fstatat fallback" in prerequisite
                for prerequisite in extended_metadata["x86_abi_prerequisites"]
            )
        )
        cwd_canonicalize = slices_by_id["filesystem.cwd-canonicalize"]
        self.assertEqual(
            cwd_canonicalize["capabilities"],
            ["filesystem.canonicalize", "filesystem.cwd-mutation"],
        )
        self.assertEqual(
            cwd_canonicalize["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh cwd-canonicalize-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in cwd_canonicalize["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-core/src/fs.rs",
            "crabc-core/src/process.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/src/process_x86_64.rs",
            "crabc-rs/tests/x86_64_canonicalize.rs",
            "crabc-rs/tests/x86_64_cwd_mutation.rs",
            "crabc-rs/examples/fs_canonicalize_direct_probe.rs",
            "crabc-rs/examples/process_cwd_direct_probe.rs",
            "compat/x86_64/run_x86_cwd_canonicalize_reference.sh",
            "compat/x86_64/x86_cwd_canonicalize_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, cwd_canonicalize["source_owners"])
        self.assertTrue(
            any(
                "getcwd=79" in prerequisite
                and "chdir=80" in prerequisite
                and "fchdir=81" in prerequisite
                for prerequisite in cwd_canonicalize["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "PATH_MAX=4096" in prerequisite and "forty" in prerequisite
                for prerequisite in cwd_canonicalize["x86_abi_prerequisites"]
            )
        )
        self.assertNotIn("process.root-change", cwd_canonicalize["capabilities"])
        self.assertIn("process.root-change", remaining["capabilities"])
        ipc_mqueue = slices_by_id["ipc.posix-mqueue"]
        self.assertEqual(ipc_mqueue["capabilities"], ["ipc"])
        self.assertEqual(
            ipc_mqueue["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh ipc-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in ipc_mqueue["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/ipc.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/ipc.rs",
            "crabc-rs/tests/x86_64_ipc.rs",
            "crabc-rs/examples/ipc_direct_probe.rs",
            "compat/x86_64/run_x86_mqueue_reference.sh",
            "compat/x86_64/x86_mqueue_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, ipc_mqueue["source_owners"])
        self.assertTrue(
            any(
                "mq_open=240" in prerequisite
                and "mq_unlink=241" in prerequisite
                and "mq_timedsend=242" in prerequisite
                and "mq_timedreceive=243" in prerequisite
                and "mq_getsetattr=245" in prerequisite
                for prerequisite in ipc_mqueue["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "mqd_t" in prerequisite
                and "64-byte align-8" in prerequisite
                and "16-byte align-8" in prerequisite
                for prerequisite in ipc_mqueue["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "no x86 C mq API/header" in prerequisite
                for prerequisite in ipc_mqueue["x86_header_prerequisites"]
            )
        )
        self.assertNotIn("ipc.posix-shm", ipc_mqueue["capabilities"])
        self.assertIn("ipc", remaining["capabilities"])
        self.assertIn("ipc.posix-shm", remaining["capabilities"])
        ipc_shm = slices_by_id["ipc.posix-shm"]
        self.assertEqual(ipc_shm["capabilities"], ["ipc.posix-shm"])
        self.assertEqual(
            ipc_shm["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh shm-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in ipc_shm["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/shm.rs",
            "crabc-rs/tests/x86_64_shm.rs",
            "crabc-rs/examples/shm_direct_probe.rs",
            "compat/x86_64/run_x86_shm_reference.sh",
            "compat/x86_64/x86_shm_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, ipc_shm["source_owners"])
        self.assertTrue(
            any(
                "openat=257" in prerequisite
                and "unlinkat=263" in prerequisite
                and "rdi/rsi/rdx/r10" in prerequisite
                for prerequisite in ipc_shm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "NAME_MAX=255" in prerequisite
                and "265-byte" in prerequisite
                and "/dev/shm/<name>" in prerequisite
                for prerequisite in ipc_shm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "O_CLOEXEC" in prerequisite
                and "O_NOFOLLOW" in prerequisite
                and "O_NONBLOCK" in prerequisite
                and "no raw/musl flag equivalence is claimed" in prerequisite
                for prerequisite in ipc_shm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "no x86 C shared-memory API/header/ABI" in prerequisite
                and "cancellation mechanics" in prerequisite
                and "mount policy/fallback" in prerequisite
                for prerequisite in ipc_shm["x86_header_prerequisites"]
            )
        )
        self.assertIn("ipc.posix-shm", remaining["capabilities"])
        self.assertNotIn("ipc.posix-shm", direct["capabilities"])
        system_inotify = slices_by_id["system.inotify"]
        self.assertEqual(system_inotify["capabilities"], ["system.inotify"])
        self.assertEqual(
            system_inotify["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh inotify-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in system_inotify["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/inotify.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/system_x86_64.rs",
            "crabc-rs/tests/x86_64_inotify.rs",
            "crabc-rs/examples/inotify_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_inotify_reference.sh",
            "compat/x86_64/x86_inotify_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, system_inotify["source_owners"])
        self.assertTrue(
            any(
                "inotify_init1=294" in prerequisite
                and "inotify_add_watch=254" in prerequisite
                and "inotify_rm_watch=255" in prerequisite
                for prerequisite in system_inotify["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "16-byte align-4" in prerequisite
                and "wd i32 at 0" in prerequisite
                and "mask u32 at 4" in prerequisite
                and "cookie u32 at 8" in prerequisite
                and "len u32 at 12" in prerequisite
                and "name at 16" in prerequisite
                for prerequisite in system_inotify["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "separate static-c-event-descriptors artifact" in prerequisite
                and "legacy inotify_init remains outside the Rust facade" in prerequisite
                for prerequisite in system_inotify["x86_header_prerequisites"]
            )
        )
        self.assertIn(
            "separate static-c-event-descriptors artifact",
            system_inotify["native_evidence"][0]["scope"],
        )
        self.assertIn("system.inotify", remaining["capabilities"])
        self.assertNotIn("system.inotify", direct["capabilities"])
        civil_calendar = slices_by_id["time.civil-calendar"]
        self.assertEqual(
            civil_calendar["capabilities"],
            [
                "time.wall-clock",
                "time.calendar-utc",
                "time.timezone-rules",
                "time.local-calendar",
            ],
        )
        self.assertEqual(
            civil_calendar["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh calendar-time-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in civil_calendar["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/time_x86_64.rs",
            "crabc-core/src/tests.rs",
            "crabc-rs/src/civil_time.rs",
            "crabc-rs/UPSTREAM.md",
            "crabc-rs/src/time_x86_64.rs",
            "crabc-rs/src/timezone.rs",
            "crabc-rs/tests/x86_64_calendar_time.rs",
            "crabc-rs/tests/time.rs",
            "crabc-rs/tests/calendar_utc.rs",
            "crabc-rs/tests/calendar_local.rs",
            "crabc-rs/tests/timezone_rules.rs",
            "crabc-rs/examples/time_direct_probe.rs",
            "crabc-rs/examples/calendar_utc_direct_probe.rs",
            "crabc-rs/examples/calendar_local_direct_probe.rs",
            "compat/x86_64/run_x86_calendar_time_reference.sh",
            "compat/x86_64/x86_calendar_time_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, civil_calendar["source_owners"])
        self.assertTrue(
            any(
                "gettimeofday=96" in prerequisite
                and "16-byte align-8 timeval" in prerequisite
                and "tv_sec" in prerequisite
                and "tv_usec" in prerequisite
                for prerequisite in civil_calendar["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "TZif v1/v2/v3" in prerequisite
                and "neither reads TZ nor loads system zoneinfo" in prerequisite
                for prerequisite in civil_calendar["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "one-way" in prerequisite
                and "no inverse local-to-instant conversion" in prerequisite
                for prerequisite in civil_calendar["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "no x86 C time API/header/ABI" in prerequisite
                and "libc timezone globals" in prerequisite
                and "inverse mktime-style local conversion" in prerequisite
                for prerequisite in civil_calendar["x86_header_prerequisites"]
            )
        )
        self.assertNotIn("time.clock-query", civil_calendar["capabilities"])
        self.assertNotIn("time.clock-set", civil_calendar["capabilities"])
        self.assertNotIn("time.clock-process-id", civil_calendar["capabilities"])
        self.assertNotIn("time.posix-timers", civil_calendar["capabilities"])
        advanced_time = slices_by_id["time.advanced-clocks-posix-timers"]
        self.assertEqual(
            advanced_time["capabilities"],
            [
                "time.clock-query",
                "time.clock-process-id",
                "time.clock-set",
                "time.posix-timers",
            ],
        )
        self.assertEqual(
            advanced_time["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh advanced-time-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in advanced_time["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-core/src/time_x86_64.rs",
            "crabc-core/src/tests.rs",
            "crabc-rs/src/time_x86_64.rs",
            "crabc-rs/tests/x86_64_advanced_time.rs",
            "crabc-rs/examples/time_dynamic_direct_probe.rs",
            "crabc-rs/examples/process_clock_id_direct_probe.rs",
            "crabc-rs/examples/time_settime_direct_probe.rs",
            "crabc-rs/examples/time_timers_direct_probe.rs",
            "compat/x86_64/run_x86_advanced_time_reference.sh",
            "compat/x86_64/x86_advanced_time_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, advanced_time["source_owners"])
        self.assertTrue(
            any(
                "clock_settime=227" in prerequisite
                and "clock_gettime=228" in prerequisite
                and "clock_getres=229" in prerequisite
                for prerequisite in advanced_time["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "timer_create=222" in prerequisite
                and "timer_settime=223" in prerequisite
                and "old-value pointer is passed in r10" in prerequisite
                for prerequisite in advanced_time["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "SIGEV_THREAD callback pointers" in prerequisite
                and "TIMER_ABSTIME=1" in prerequisite
                for prerequisite in advanced_time["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "no x86 C time.h timer_t/sigevent/clock API" in prerequisite
                and "callback runtime" in prerequisite
                for prerequisite in advanced_time["x86_header_prerequisites"]
            )
        )
        self.assertNotIn("process.fs-credentials", remaining["capabilities"])
        self.assertNotIn("process.supplementary-groups", remaining["capabilities"])
        for capability in (
            "memory.vm",
            "memory.mapping",
            "time.wall-clock",
            "time.calendar-utc",
            "time.timezone-rules",
            "time.local-calendar",
            "time.clock-query",
            "time.clock-process-id",
            "time.clock-set",
            "time.posix-timers",
        ):
            self.assertNotIn(capability, direct["capabilities"])
            self.assertIn(capability, remaining["capabilities"])
        self.assertIn("time.process-interval-control", direct["capabilities"])
        self.assertNotIn("time.process-interval-control", remaining["capabilities"])
        self.assertIn("filesystem.posix-allocate-range", direct["capabilities"])
        self.assertNotIn("filesystem.posix-allocate-range", remaining["capabilities"])
        self.assertIn("filesystem.allocate-range", direct["capabilities"])
        self.assertNotIn("filesystem.allocate-range", remaining["capabilities"])
        for capability in (
            "filesystem.fd-timestamps",
            "filesystem.directory-relative-timestamps",
            "filesystem.cwd-timestamps",
            "filesystem.symlink-timestamps",
            "filesystem.second-resolution-timestamps",
        ):
            self.assertIn(capability, direct["capabilities"])
            self.assertNotIn(capability, remaining["capabilities"])
        self.assertNotIn(
            "crabc-rs/tests/x86_64_epoll.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_epoll_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_epoll_reference_probe.c", remaining["source_owners"]
        )
        for source_owner in (
            "crabc-rs/tests/x86_64_posix_fallocate.rs",
            "crabc-rs/tests/x86_64_fallocate.rs",
            "compat/x86_64/run_x86_posix_fallocate_reference.sh",
            "compat/x86_64/x86_posix_fallocate_reference_probe.c",
            "compat/x86_64/run_x86_fallocate_reference.sh",
            "compat/x86_64/x86_fallocate_reference_probe.c",
            "crabc-rs/tests/x86_64_futimens.rs",
            "crabc-rs/tests/x86_64_timestamp_paths.rs",
            "compat/x86_64/run_x86_timestamp_reference.sh",
            "compat/x86_64/x86_timestamp_reference_probe.c",
            "crabc-rs/tests/x86_64_flock.rs",
            "compat/x86_64/run_x86_flock_reference.sh",
            "compat/x86_64/x86_flock_reference_probe.c",
            "crabc-rs/tests/x86_64_sendfile.rs",
            "compat/x86_64/run_x86_sendfile_reference.sh",
            "compat/x86_64/x86_sendfile_reference_probe.c",
            "crabc-rs/tests/x86_64_copy_file_range.rs",
            "compat/x86_64/run_x86_copy_file_range_reference.sh",
            "compat/x86_64/x86_copy_file_range_reference_probe.c",
            "crabc-rs/tests/x86_64_sync.rs",
            "compat/x86_64/run_x86_sync_reference.sh",
            "compat/x86_64/x86_sync_reference_probe.c",
            "crabc-rs/tests/x86_64_syncfs.rs",
            "compat/x86_64/run_x86_syncfs_reference.sh",
            "compat/x86_64/x86_syncfs_reference_probe.c",
            "crabc-rs/tests/x86_64_sync_file_range.rs",
            "compat/x86_64/run_x86_sync_file_range_reference.sh",
            "compat/x86_64/x86_sync_file_range_reference_probe.c",
        ):
            self.assertNotIn(source_owner, remaining["source_owners"])
        self.assertIn("crabc-rs/tests/x86_64_timerfd.rs", direct["source_owners"])
        self.assertNotIn(
            "crabc-rs/tests/x86_64_timerfd.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_pselect.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_rlimit_targeted.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_rlimit_targeted_reference.sh",
            remaining["source_owners"],
        )
        self.assertNotIn(
            "compat/x86_64/x86_rlimit_targeted_reference_probe.c",
            remaining["source_owners"],
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_rusage.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_getgroups.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_getitimer.rs", remaining["source_owners"]
        )
        self.assertIn("crabc-rs/tests/x86_64_setitimer.rs", direct["source_owners"])
        self.assertNotIn(
            "crabc-rs/tests/x86_64_setitimer.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_clock_nanosleep.rs", remaining["source_owners"]
        )
        self.assertIn(
            "crabc-rs/src/process_x86_64.rs", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_timerfd_reference.sh", direct["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_timerfd_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/x86_timerfd_reference_probe.c", direct["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_timerfd_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_pselect_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_pselect_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_rusage_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_getgroups_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_getitimer_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_setitimer_reference.sh", direct["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_setitimer_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_clock_nanosleep_reference.sh",
            remaining["source_owners"],
        )
        self.assertNotIn(
            "compat/x86_64/x86_rusage_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_getgroups_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_getitimer_reference_probe.c", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/x86_setitimer_reference_probe.c", direct["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_setitimer_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_clock_nanosleep_reference_probe.c",
            remaining["source_owners"],
        )
        self.assertIn("compat/x86_64/x86_statat_reference_probe.c", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_getcwd.rs", remaining["source_owners"])
        self.assertNotIn(
            "compat/x86_64/run_x86_getcwd_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_getcwd_reference_probe.c", remaining["source_owners"]
        )
        self.assertIn("crabc-core/src/fs.rs", remaining["source_owners"])
        self.assertIn("crabc-rs/src/fs_x86_64.rs", remaining["source_owners"])
        self.assertIn("crabc-rs/tests/x86_64_readlink.rs", remaining["source_owners"])
        self.assertIn("compat/x86_64/run_x86_readlinkat_reference.sh", remaining["source_owners"])
        self.assertIn("compat/x86_64/x86_readlinkat_reference_probe.c", remaining["source_owners"])
        self.assertIn("crabc-core/src/io.rs", remaining["source_owners"])
        self.assertIn("crabc-core/src/syscall_x86_64.rs", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_memfd.rs", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/run_x86_memfd_reference.sh", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/x86_memfd_reference_probe.c", remaining["source_owners"])
        self.assertNotIn("crabc-core/src/thread.rs", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_sched_rr_interval.rs", remaining["source_owners"])
        self.assertNotIn("crabc-rs/src/thread_x86_64.rs", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/run_x86_sched_rr_interval_reference.sh", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/x86_sched_rr_interval_reference_probe.c", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_sched_affinity.rs", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/run_x86_sched_affinity_reference.sh", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/x86_sched_affinity_reference_probe.c", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_sched_setaffinity.rs", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/run_x86_sched_setaffinity_reference.sh", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/x86_sched_setaffinity_reference_probe.c", remaining["source_owners"])
        self.assertEqual(len(remaining["native_evidence"]), 1)
        self.assertEqual(
            remaining["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh facade-record-owning",
        )
        self.assertIn(
            "exact twenty-four record-owning component runners",
            remaining["native_evidence"][0]["scope"],
        )
        self.assertNotIn("filesystem.path-core", direct["capabilities"])
        self.assertIn("filesystem.path-core", remaining["capabilities"])
        self.assertNotIn("filesystem.xattr", direct["capabilities"])
        self.assertIn("filesystem.xattr", remaining["capabilities"])
        for capability in (
            "filesystem.canonicalize",
            "filesystem.cwd-mutation",
            "process.root-change",
            "process.thread-kill",
        ):
            self.assertNotIn(capability, direct["capabilities"])
            self.assertIn(capability, remaining["capabilities"])
        for capability in (
            "filesystem.access-check",
            "filesystem.directory-relative-access-check",
            "filesystem.effective-access",
        ):
            self.assertIn(capability, direct["capabilities"])
            self.assertNotIn(capability, remaining["capabilities"])
        self.assertIn("filesystem.cwd", direct["capabilities"])
        self.assertNotIn("filesystem.cwd", remaining["capabilities"])
        self.assertIn("filesystem.path-metadata", direct["capabilities"])
        self.assertNotIn("filesystem.path-metadata", remaining["capabilities"])
        self.assertIn(
            "crabc-rs/tests/x86_64_current_dir_name.rs", direct["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_current_dir_name.rs", remaining["source_owners"]
        )
        self.assertEqual(remaining["status"], "foundation-verified")
        self.assertIn("thread.scheduler-rr-interval", direct["capabilities"])
        self.assertNotIn("thread.scheduler-rr-interval", remaining["capabilities"])
        self.assertIn("thread.cpu-affinity-observation", direct["capabilities"])
        self.assertNotIn("thread.cpu-affinity-observation", remaining["capabilities"])
        self.assertIn("thread.cpu-affinity-mutation", direct["capabilities"])
        self.assertNotIn("thread.cpu-affinity-mutation", remaining["capabilities"])
        self.assertIn("io.readiness-epoll", direct["capabilities"])
        self.assertNotIn("io.readiness-epoll", remaining["capabilities"])
        self.assertIn("io.readiness", direct["capabilities"])
        self.assertNotIn("io.readiness", remaining["capabilities"])
        self.assertNotIn("filesystem.access-advice", remaining["capabilities"])
        self.assertNotIn("process.scheduling-priority", remaining["capabilities"])
        self.assertNotIn("process.scheduling-priority-mutation", remaining["capabilities"])
        self.assertIn("process.resource-limits", direct["capabilities"])
        self.assertNotIn("process.resource-limits", remaining["capabilities"])
        self.assertNotIn("process.resource-limit-mutation", remaining["capabilities"])
        self.assertNotIn("process.umask", remaining["capabilities"])
        self.assertIn("process.resource-limits-targeted", direct["capabilities"])
        self.assertNotIn("process.resource-limits-targeted", remaining["capabilities"])
        self.assertIn("process.resource-usage", direct["capabilities"])
        self.assertNotIn("process.resource-usage", remaining["capabilities"])
        self.assertIn("time.process-accounting", direct["capabilities"])
        self.assertNotIn("time.process-accounting", remaining["capabilities"])
        self.assertIn("time.interval-timer-query", direct["capabilities"])
        self.assertNotIn("time.interval-timer-query", remaining["capabilities"])
        self.assertIn("time.clock-sleep", direct["capabilities"])
        self.assertNotIn("time.clock-sleep", remaining["capabilities"])
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct memfd_create=319")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private memory-file/seal")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 typed clock_nanosleep=230")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                "clock_nanosleep" in prerequisite
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sched_getaffinity=204")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sched_setaffinity=203")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct io readiness")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct timerfd=283/286/287")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private timerfd slice")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private pselect slice")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct targeted getrlimit")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct getcwd=79")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct access/accessat: access=21")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct fcntl status flags: fcntl=72")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        getcwd_evidence = next(
            evidence
            for evidence in direct["native_evidence"]
            if evidence["command"] == "./scripts/dev-x86_64.sh getcwd-reference"
        )
        self.assertIn("get_current_dir_name", getcwd_evidence["scope"])
        self.assertIn("newfstatat=262", getcwd_evidence["scope"])
        self.assertIn("never reads PWD", getcwd_evidence["scope"])
        self.assertFalse(
            any(
                prerequisite.startswith("Private CPU-affinity observation")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private CPU-affinity mutation")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private epoll slice")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private targeted resource-limit-query")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private getcwd slice")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertIn("process.supplementary-groups", direct["capabilities"])
        self.assertNotIn("process.supplementary-groups", remaining["capabilities"])
        pthread_tls = self.family(data, "libc.pthread-tls")
        self.assertEqual(pthread_tls["status"], "planned")
        self.assertIn("libc/src/c_abi/x86_64/atomic.rs", pthread_tls["source_owners"])
        self.assertIn("libc/src/c_abi/x86_64/clone.rs", pthread_tls["source_owners"])
        self.assertIn(
            "libc/src/c_abi/x86_64/pthread_once.rs", pthread_tls["source_owners"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/pthread_tsd.rs", pthread_tls["source_owners"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/pthread_cancel.rs", pthread_tls["source_owners"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/pthread_atfork.rs", pthread_tls["source_owners"]
        )
        self.assertIn(
            "Twenty-five separately verified static artifacts", pthread_tls["description"]
        )
        self.assertIn(
            "sole delivery point is explicit `pthread_testcancel`",
            pthread_tls["description"],
        )
        self.assertIn("two-worker aggregate", pthread_tls["description"])
        self.assertEqual(
            pthread_tls["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-atomic",
        )
        self.assertEqual(
            pthread_tls["native_evidence"][1]["command"],
            "./scripts/dev-x86_64.sh libc-clone-raw",
        )


    def test_pthread_family_admission_reuses_exact_posix_cohort_receipt(self) -> None:
        data = self.data()
        pthread = self.family(data, "libc.pthread-tls")
        posix = self.family(data, "libc.posix-runtime")
        pthread["status"] = "foundation-verified"
        posix["status"] = "foundation-verified"
        evidence = pthread["native_evidence"]
        for entry in evidence:
            entry["state"] = "verified"
        evidence[2]["receipt"] = ".work/x86_64/pthread-family-run/receipt.json"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / evidence[2]["receipt"]
            receipt.parent.mkdir(parents=True)
            receipt.write_text("{}", encoding="utf-8")
            posix_admission = {
                "inputs": {"source": "source-seal", "family_execution": "matrix-seal"}
            }
            component = {
                "schema": "crabc.x86_64-owned-pthread-family/v1",
                "status": "installed-behavior-component-verified",
                "family": "libc.pthread-tls",
                "component_complete": True,
                "family_completion": False,
                "promotion_ready": False,
                "public_support": False,
                "inputs": {"source": "source-seal", "family_execution": "matrix-seal"},
            }
            pthread_family = importlib.import_module("owned_pthread_family")
            with mock.patch.object(ledger, "ROOT", root), mock.patch.object(
                pthread_family,
                "validate_receipt",
                return_value=component,
            ) as validate_receipt:
                admitted = ledger.require_pthread_runtime_family_admission(
                    pthread, posix, posix_admission
                )
            self.assertIs(admitted, component)
            validate_receipt.assert_called_once_with(root, receipt)

    def test_pthread_family_admission_rejects_changed_or_missing_dependencies(self) -> None:
        data = self.data()
        pthread = self.family(data, "libc.pthread-tls")
        posix = self.family(data, "libc.posix-runtime")
        pthread["status"] = "foundation-verified"
        posix["status"] = "foundation-verified"
        evidence = pthread["native_evidence"]
        for entry in evidence:
            entry["state"] = "verified"
        evidence[2]["receipt"] = ".work/pthread-receipt.json"
        posix_admission = {
            "inputs": {"source": "source-seal", "family_execution": "matrix-seal"}
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / evidence[2]["receipt"]
            receipt.parent.mkdir(parents=True)
            receipt.write_text("{}", encoding="utf-8")
            pthread_family = importlib.import_module("owned_pthread_family")
            with mock.patch.object(ledger, "ROOT", root), mock.patch.object(
                pthread_family,
                "validate_receipt",
                return_value={"inputs": {"source": "source-seal", "family_execution": "matrix-seal"}},
            ):
                for mutate in (
                    lambda family: family["native_evidence"].pop(),
                    lambda family: family["native_evidence"][1].update(state="required"),
                    lambda family: family["native_evidence"][2].update(receipt=".work/missing.json"),
                ):
                    candidate = copy.deepcopy(pthread)
                    mutate(candidate)
                    with self.subTest(evidence=candidate["native_evidence"]):
                        with self.assertRaises(ledger.LedgerError):
                            ledger.require_pthread_runtime_family_admission(
                                candidate, posix, posix_admission
                            )

                candidate = copy.deepcopy(pthread)
                with self.assertRaises(ledger.LedgerError):
                    ledger.require_pthread_runtime_family_admission(
                        candidate,
                        posix,
                        {"inputs": {"source": "other-source", "family_execution": "matrix-seal"}},
                    )

    def test_pthread_family_admission_keeps_leaf_view_non_promoting(self) -> None:
        data = self.data()
        family = self.family(data, "libc.pthread-tls")
        planned = ledger.pthread_runtime_private_artifact_view(family, None)
        self.assertIs(planned, family)
        family["status"] = "foundation-verified"
        with self.assertRaises(ledger.LedgerError):
            ledger.pthread_runtime_private_artifact_view(family, None)
        admitted = ledger.pthread_runtime_private_artifact_view(family, {"status": "admitted"})
        self.assertEqual(admitted["status"], "planned")
        self.assertEqual(family["status"], "foundation-verified")

    def _admitted_resolver(self, data: dict) -> tuple[dict, dict]:
        resolver = self.family(data, "libc.resolver")
        posix = self.family(data, "libc.posix-runtime")
        resolver["status"] = "foundation-verified"
        posix["status"] = "foundation-verified"
        for entry in resolver["native_evidence"]:
            entry["state"] = "verified"
        resolver["native_evidence"][2]["receipt"] = ".work/x86_64/resolver-family/assessment.json"
        return resolver, posix

    def _resolver_admission_fixture(self, root: Path) -> tuple[dict, dict]:
        """Write one POSIX matrix whose cohort receipts the resolver must share."""
        import hashlib
        import json

        (root / ".work/x86_64/resolver-family").mkdir(parents=True)
        (root / ".work/x86_64/resolver-family/assessment.json").write_text("{}", encoding="utf-8")
        cohort = {
            "static_preparation": {"path": ".work/x86_64/static/preparation.json", "sha256": "1" * 64},
            "dynamic_qualification": {"path": ".work/x86_64/dynamic/qualification.json", "sha256": "2" * 64},
        }
        matrix = root / ".work/x86_64/posix-matrix/execution.json"
        matrix.parent.mkdir(parents=True)
        matrix.write_text(json.dumps({"inputs": {
            name: {**record, "size": 1} for name, record in cohort.items()
        }}), encoding="utf-8")
        posix_admission = {"inputs": {
            "source": {"revision": "r", "content_sha256": "c"},
            "family_execution": {
                "path": ".work/x86_64/posix-matrix/execution.json",
                "sha256": hashlib.sha256(matrix.read_bytes()).hexdigest(),
                "size": matrix.stat().st_size,
            },
        }}
        facts = {"assessment": "assessment-seal", "source": {"revision": "r", "content_sha256": "c"},
                 **{name: {**record, "byte_length": 1, "mode": 0o444} for name, record in cohort.items()}}
        return posix_admission, facts

    def test_resolver_family_admission_requires_the_posix_cohort_assessment(self) -> None:
        resolver, posix = self._admitted_resolver(self.data())
        resolver_family = importlib.import_module("owned_resolver_family")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            posix_admission, facts = self._resolver_admission_fixture(root)
            assessment = root / resolver["native_evidence"][2]["receipt"]
            with mock.patch.object(ledger, "ROOT", root), mock.patch.object(
                resolver_family, "admission_facts", return_value=facts,
            ) as admission_facts:
                admitted = ledger.require_resolver_family_admission(resolver, posix, posix_admission)
            self.assertIs(admitted, facts)
            admission_facts.assert_called_once_with(root, assessment)

    def test_resolver_family_admission_rejects_other_cohort_or_incomplete_evidence(self) -> None:
        resolver, posix = self._admitted_resolver(self.data())
        resolver_family = importlib.import_module("owned_resolver_family")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            posix_admission, facts = self._resolver_admission_fixture(root)
            with mock.patch.object(ledger, "ROOT", root):
                with mock.patch.object(resolver_family, "admission_facts", return_value=facts):
                    for mutate in (
                        lambda family: family["native_evidence"].pop(),
                        lambda family: family["native_evidence"][0].update(state="required"),
                        lambda family: family["native_evidence"][2].update(receipt=".work/missing.json"),
                        lambda family: family["native_evidence"][2].update(scope="narrower claim"),
                    ):
                        candidate = copy.deepcopy(resolver)
                        mutate(candidate)
                        with self.subTest(evidence=candidate["native_evidence"]):
                            with self.assertRaises(ledger.LedgerError):
                                ledger.require_resolver_family_admission(candidate, posix, posix_admission)
                    with self.assertRaises(ledger.LedgerError):
                        ledger.require_resolver_family_admission(resolver, posix, None)
                    planned_posix = copy.deepcopy(posix)
                    planned_posix["status"] = "planned"
                    with self.assertRaises(ledger.LedgerError):
                        ledger.require_resolver_family_admission(resolver, planned_posix, posix_admission)
                for name in ("static_preparation", "dynamic_qualification", "source"):
                    changed = copy.deepcopy(facts)
                    if name == "source":
                        changed["source"]["revision"] = "other"
                    else:
                        changed[name]["sha256"] = "3" * 64
                    with self.subTest(changed=name), mock.patch.object(
                        resolver_family, "admission_facts", return_value=changed,
                    ):
                        with self.assertRaises(ledger.LedgerError):
                            ledger.require_resolver_family_admission(resolver, posix, posix_admission)
                with mock.patch.object(
                    resolver_family, "admission_facts",
                    side_effect=resolver_family.ResolverFamilyError("assessment is not bound to current source"),
                ):
                    with self.assertRaises(ledger.LedgerError):
                        ledger.require_resolver_family_admission(resolver, posix, posix_admission)

    def test_planned_resolver_family_keeps_strict_leaf_view_without_assessment(self) -> None:
        data = self.data()
        resolver = self.family(data, "libc.resolver")
        posix = self.family(data, "libc.posix-runtime")
        self.assertIsNone(ledger.require_resolver_family_admission(resolver, posix, None))
        self.assertIs(ledger.resolver_private_artifact_view(resolver, None), resolver)
        attached = copy.deepcopy(resolver)
        attached["native_evidence"][2]["receipt"] = ".work/x86_64/resolver-family/assessment.json"
        with self.assertRaises(ledger.LedgerError):
            ledger.require_resolver_family_admission(attached, posix, None)
        admitted = copy.deepcopy(resolver)
        admitted["status"] = "foundation-verified"
        with self.assertRaises(ledger.LedgerError):
            ledger.resolver_private_artifact_view(admitted, None)
        view = ledger.resolver_private_artifact_view(admitted, {"source": "admitted"})
        self.assertEqual(view["status"], "planned")
        self.assertEqual(admitted["status"], "foundation-verified")


    def test_musl_oracle_is_a_native_precondition_not_public_support(self) -> None:
        data = self.data()
        family = self.family(data, "oracle.musl-toolchain")
        self.assertEqual(family["status"], "foundation-verified")
        self.assertEqual(
            family["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh musl-oracle",
        )
        self.assertIn("compat/x86_64/run_musl_oracle.sh", family["source_owners"])
        self.assertIn("docker/x86_64-musl-oracle-gcc", family["source_owners"])

    def test_every_musl_backed_family_depends_on_the_musl_oracle(self) -> None:
        data = self.data()
        for entry in data["family"]:
            assert isinstance(entry, dict)
            if entry["id"] != "oracle.musl-toolchain" and ledger.has_musl_oracle(entry):
                self.assertIn("oracle.musl-toolchain", entry["depends_on"])

        self.family(data, "libc.posix-runtime")["depends_on"].remove("oracle.musl-toolchain")
        with self.assertRaisesRegex(ledger.LedgerError, "must depend on oracle.musl-toolchain"):
            ledger.validate_ledger(data)

    def test_symbols_gate_is_accounted_for_by_the_abi_differential_family(self) -> None:
        data = self.data()
        self.assertIn("symbols", self.family(data, "compat.abi-differential")["aarch64_gates"])


    def test_qualification_posix_abi_admission_rejects_manifest_environment_drift(self) -> None:
        data = self.data()
        family = self.family(data, "compat.posix-process")
        environment = ledger.qualification_manifest_runner.controlled_environment()
        with mock.patch.object(
            ledger.qualification_manifest_runner,
            "controlled_environment",
            return_value={**environment, "LD_LIBRARY_PATH": "poison"},
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError, "execution environment drifted"
            ):
                ledger.require_posix_process_abi_admission_artifact(family)

    def test_baseline_capabilities_are_read_from_the_baseline_toml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.toml"
            path.write_text(
                '[[capability]]\nid = "dynamic.capability"\nkind = "semantic"\n',
                encoding="utf-8",
            )
            self.assertEqual(ledger.baseline_capability_ids(path), {"dynamic.capability"})

    def test_rejects_an_unassigned_baseline_capability(self) -> None:
        data = self.data()
        capabilities = self.family(data, "facade.direct")["capabilities"]
        assert isinstance(capabilities, list)
        capabilities.remove("random.state")
        with self.assertRaisesRegex(ledger.LedgerError, "leaves baseline capabilities unmapped: random.state"):
            ledger.validate_ledger(data)

    def test_rejects_a_duplicate_or_stale_capability_mapping(self) -> None:
        duplicate = self.data()
        self.family(duplicate, "core.architecture")["capabilities"].append("random.state")
        with self.assertRaisesRegex(ledger.LedgerError, "mapped by both"):
            ledger.validate_ledger(duplicate)

        stale = self.data()
        self.family(stale, "core.architecture")["capabilities"].append("obsolete.capability")
        with self.assertRaisesRegex(ledger.LedgerError, "maps stale baseline capabilities: obsolete.capability"):
            ledger.validate_ledger(stale)

    def test_rejects_a_missing_promotion_family(self) -> None:
        data = self.data()
        promotion = data["promotion"]
        assert isinstance(promotion, dict)
        required = promotion["required_families"]
        assert isinstance(required, list)
        required.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "roster drifted"):
            ledger.validate_ledger(data)

    def test_rejects_a_dependency_that_is_not_earlier(self) -> None:
        data = self.data()
        self.family(data, "capability.accounting")["depends_on"] = ["performance.release"]
        with self.assertRaisesRegex(ledger.LedgerError, "is not earlier"):
            ledger.validate_ledger(data)

    def test_rejects_a_foundation_misrepresented_as_complete_evidence(self) -> None:
        data = self.data()
        evidence = self.family(data, "libc.raw-syscall")["native_evidence"]
        assert isinstance(evidence, list) and evidence
        assert isinstance(evidence[0], dict)
        evidence[0]["state"] = "required"
        with self.assertRaisesRegex(ledger.LedgerError, "entirely verified"):
            ledger.validate_ledger(data)

    def test_rejects_an_incomplete_or_out_of_family_verified_slice(self) -> None:
        data = self.data()
        remaining = self.family(data, "facade.record-owning")
        slices = remaining["verified_slice"]
        assert isinstance(slices, list) and len(slices) == 24
        interface_device = next(
            slice_entry
            for slice_entry in slices
            if isinstance(slice_entry, dict)
            and slice_entry["id"] == "network.interface-device"
        )
        evidence = interface_device["native_evidence"]
        assert isinstance(evidence, list) and evidence
        assert isinstance(evidence[0], dict)
        evidence[0]["state"] = "required"
        with self.assertRaisesRegex(ledger.LedgerError, "entirely verified"):
            ledger.validate_ledger(data)

        data = self.data()
        remaining = self.family(data, "facade.record-owning")
        slices = remaining["verified_slice"]
        assert isinstance(slices, list) and len(slices) == 24
        interface_device = next(
            slice_entry
            for slice_entry in slices
            if isinstance(slice_entry, dict)
            and slice_entry["id"] == "network.interface-device"
        )
        capabilities = interface_device["capabilities"]
        assert isinstance(capabilities, list)
        capabilities.append("random.state")
        with self.assertRaisesRegex(ledger.LedgerError, "escape the owning family"):
            ledger.validate_ledger(data)

        data = self.data()
        remaining = self.family(data, "facade.record-owning")
        slices = remaining["verified_slice"]
        assert isinstance(slices, list) and len(slices) == 24
        resolver_transport = next(
            slice_entry
            for slice_entry in slices
            if isinstance(slice_entry, dict)
            and slice_entry["id"] == "network.resolver-transport"
        )
        capabilities = resolver_transport["capabilities"]
        assert isinstance(capabilities, list)
        capabilities.append("network.interface-index")
        with self.assertRaisesRegex(ledger.LedgerError, "duplicates a capability"):
            ledger.validate_ledger(data)

        data = self.data()
        remaining = self.family(data, "facade.record-owning")
        slices = remaining["verified_slice"]
        assert isinstance(slices, list) and len(slices) == 24
        interface_device = next(
            slice_entry
            for slice_entry in slices
            if isinstance(slice_entry, dict)
            and slice_entry["id"] == "network.interface-device"
        )
        capabilities = interface_device["capabilities"]
        assert isinstance(capabilities, list)
        capabilities.remove("network.interface-name")
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "must exactly cover the foundation family capabilities; missing: network.interface-name",
        ):
            ledger.validate_ledger(data)

    def test_rejects_capability_or_duplicate_identity_on_an_artifact_only_slice(self) -> None:
        data = self.data()
        headers = self.family(data, "libc.headers-layouts")
        artifacts = headers["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 17
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "public-header-c-consumability"
        )
        assert isinstance(artifact, dict)
        artifact["capabilities"] = ["math.fenv"]
        with self.assertRaisesRegex(ledger.LedgerError, "must not carry capabilities"):
            ledger.validate_ledger(data)

        data = self.data()
        headers = self.family(data, "libc.headers-layouts")
        artifacts = headers["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 17
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "public-header-c-consumability"
        )
        assert isinstance(artifact, dict)
        artifact["id"] = "filesystem.stat-compat"
        with self.assertRaisesRegex(ledger.LedgerError, "duplicate verified record id"):
            ledger.validate_ledger(data)


    def test_network_resolver_trace_owners_exclude_obsolete_transitive_headers(
        self,
    ) -> None:
        records = self.verified_records(self.data())
        excluded_owners = {
            "static-c-network-byte-order": ("include/sys/types.h",),
            "static-c-in6addr-any": (
                "include/arpa/inet.h",
                "include/sys/types.h",
            ),
            "static-c-in6addr-loopback": (
                "include/arpa/inet.h",
                "include/sys/types.h",
            ),
            "static-c-socket-transport": ("include/arpa/inet.h",),
            "static-c-inet-address-codecs": ("include/sys/types.h",),
            "static-c-inet-ntoa-scratch": ("include/sys/types.h",),
            "static-c-inet-classful": ("include/sys/types.h",),
            "static-c-inet-netof": ("include/sys/types.h",),
            "static-c-inet-network": ("include/sys/types.h",),
            "static-c-numeric-netdb": (
                "include/arpa/inet.h",
                "include/sys/types.h",
            ),
            "static-c-dn-skipname": ("include/sys/types.h",),
            "static-c-dn-expand": ("include/sys/types.h",),
            "static-c-ns-flagdata": ("include/sys/types.h",),
            "static-c-ns-get16": ("include/sys/types.h",),
            "static-c-ns-get32": ("include/sys/types.h",),
            "static-c-ns-put16": ("include/sys/types.h",),
            "static-c-ns-put32": ("include/sys/types.h",),
            "static-c-ns-skiprr": ("include/sys/types.h",),
            "static-c-nameser-wire-aggregate": ("include/sys/types.h",),
            "static-c-nameser-message-parser": ("include/sys/types.h",),
            "static-c-res-init": ("include/sys/types.h",),
            "static-c-protocol-database": ("include/sys/types.h",),
        }
        for artifact_id, owners in excluded_owners.items():
            source_owners = records[artifact_id]["source_owners"]
            assert isinstance(source_owners, list)
            for owner in owners:
                self.assertNotIn(owner, source_owners, artifact_id)

        provider = ledger.load_toml(
            ROOT / "compat" / "x86_64" / "nameser-message-parser-provider.toml"
        )
        work_package = provider["work_package"]
        assert isinstance(work_package, dict)
        self.assertNotIn("include/sys/types.h", work_package["source_owners"])


    def test_stdio_installed_file_engine_slice_is_bound_to_the_engine_receipt(self) -> None:
        data = self.data()
        family = self.family(data, "libc.text-math-locale-stdio")
        self.assertEqual(family["status"], "planned")
        ledger.require_stdio_installed_file_engine_slice(family)

        def changed(mutate) -> dict[str, object]:
            changed_data = self.data()
            changed_family = self.family(changed_data, "libc.text-math-locale-stdio")
            selected = next(
                entry
                for entry in changed_family["verified_slice"]
                if entry["id"] == "stdio.installed-file-engine"
            )
            mutate(selected)
            return changed_family

        cases = (
            (lambda entry: entry.__setitem__("capabilities", [*entry["capabilities"], "stdio.fopen64-alias"]),
             "stdio.installed-file-engine must select exactly the four FILE engine capabilities"),
            (lambda entry: entry["native_evidence"].pop(),
             "stdio.installed-file-engine must use its two installed-product evidence commands"),
            (lambda entry: entry.__setitem__(
                "description", entry["description"].replace("every frozen symbol of the four capabilities", "selected rows")),
             "stdio.installed-file-engine description omits every frozen symbol of the four capabilities"),
            (lambda entry: entry["source_owners"].remove("compat/x86_64/owned_stdio_surface_probe.c"),
             "stdio.installed-file-engine source owners omit compat/x86_64/owned_stdio_surface_probe.c"),
        )
        for mutate, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ledger.LedgerError, message):
                    ledger.require_stdio_installed_file_engine_slice(changed(mutate))

        promoted = self.data()
        promoted_family = self.family(promoted, "libc.text-math-locale-stdio")
        promoted_family["status"] = "foundation-verified"
        with self.assertRaisesRegex(
            ledger.LedgerError, "stdio.installed-file-engine must not promote libc.text-math-locale-stdio"
        ):
            ledger.require_stdio_installed_file_engine_slice(promoted_family)


    def test_rejects_an_unknown_aarch64_gate(self) -> None:
        data = self.data()
        self.family(data, "facade.direct")["aarch64_gates"] = ["invented-gate"]
        with self.assertRaisesRegex(ledger.LedgerError, "unknown AArch64 gates"):
            ledger.validate_ledger(data)

    def test_signal_header_trace_owners_follow_direct_fixture_includes(self) -> None:
        records = self.verified_records(self.data())
        required_leaf = {
            "static-c-signal-control",
            "static-c-signal-legacy-aliases",
            "static-c-sysv-signal-helpers",
            "static-c-child-reaping",
            "static-c-wait-extensions",
            "static-c-immediate-termination",
            "static-c-posix-exit",
            "static-c-signal-altstack",
            "static-c-signalfd",
            "static-c-process-signal-execution",
            "static-c-clock-nanosleep",
            "static-c-nanosleep",
            "static-c-usleep",
            "static-c-sleep",
            "static-c-readiness-signal-waits",
            "static-c-event-descriptors",
            "static-c-siginterrupt",
            "static-c-thrd-sleep",
        }
        for artifact_id in required_leaf:
            owners = records[artifact_id]["source_owners"]
            assert isinstance(owners, list)
            self.assertIn("include/bits/signal.h", owners, artifact_id)

        for artifact_id in ("static-c-descriptor-pipeline", "static-c-readiness-signal-waits", "static-c-timerfd"):
            owners = records[artifact_id]["source_owners"]
            assert isinstance(owners, list)
            self.assertIn("include/bits/poll.h", owners, artifact_id)

        for artifact_id in (
            "static-c-sysv-signal-helpers",
            "static-c-signalfd",
            "static-c-clock-nanosleep",
            "static-c-nanosleep",
            "static-c-sleep",
            "static-c-thrd-sleep",
        ):
            owners = records[artifact_id]["source_owners"]
            assert isinstance(owners, list)
            self.assertNotIn("include/sys/types.h", owners, artifact_id)

        for artifact_id in (
            "static-c-child-reaping",
            "static-c-wait-extensions",
            "static-c-immediate-termination",
            "static-c-posix-exit",
            "static-c-process-signal-execution",
            "static-c-descriptor-pipeline",
            "static-c-readiness-signal-waits",
            "static-c-event-descriptors",
        ):
            owners = records[artifact_id]["source_owners"]
            assert isinstance(owners, list)
            self.assertIn("include/sys/types.h", owners, artifact_id)

    def test_unistd_header_trace_owners_follow_direct_fixture_includes(self) -> None:
        records = self.verified_records(self.data())
        # These probes include unistd.h directly. On x86, musl's header owns
        # its narrow alltypes request; it does not inherit sys/types.h.
        unistd_only = (
            "static-c-isatty",
            "static-c-ttyname-r",
            "static-c-tcgetpgrp",
            "static-c-tcsetpgrp",
            "static-c-getpass",
            "static-c-confstr",
            "static-c-fpathconf",
            "static-c-pathconf",
            "static-c-sysconf",
            "static-c-syncfs",
            "static-c-explicit-bzero-swab",
        )
        for artifact_id in unistd_only:
            owners = records[artifact_id]["source_owners"]
            assert isinstance(owners, list)
            self.assertIn("include/bits/alltypes.h", owners, artifact_id)
            self.assertNotIn("include/sys/types.h", owners, artifact_id)

        # These runtime fixtures retain an explicit sys/types.h import even
        # though their direct header gates now follow musl's unistd.h closure.
        direct_types = (
            "static-c-sendfile",
            "static-c-copy-file-range",
            "static-c-credential-observation",
            "static-c-linkat",
            "static-c-readlinkat",
            "static-c-unlinkat",
        )
        for artifact_id in direct_types:
            owners = records[artifact_id]["source_owners"]
            assert isinstance(owners, list)
            self.assertIn("include/sys/types.h", owners, artifact_id)

    def test_epoll_and_signalfd_header_owners_do_not_import_signal_header(self) -> None:
        records = self.verified_records(self.data())
        event = records["static-c-event-descriptors"]
        owners = event["source_owners"]
        assert isinstance(owners, list)
        # The direct sys/epoll.h/sys/signalfd.h matrices request sigset_t from
        # bits/alltypes.h; signal.h remains owned only by fixtures that include
        # it explicitly.
        self.assertIn("include/sys/epoll.h", owners)
        self.assertIn("include/sys/types.h", owners)

        signalfd = records["static-c-signalfd"]["source_owners"]
        assert isinstance(signalfd, list)
        self.assertIn("include/sys/signalfd.h", signalfd)


if __name__ == "__main__":
    unittest.main()
