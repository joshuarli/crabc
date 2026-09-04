#!/usr/bin/env python3
"""Focused contracts for native x86 feature-archive provider ownership."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
ROSTER_PATH = ROOT / "compat" / "x86_64" / "feature_archive_roster.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ROSTER = load_module("feature_archive_roster_test", ROSTER_PATH)


def row(
    identifier: str,
    *,
    state: str = "verified",
    baseline_features: list[str] | None = None,
    additive_callables: list[str] | None = None,
    replacement_callables: list[str] | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "id": identifier,
        "state": state,
        "runner": f"compat/x86_64/run_{identifier}.sh",
        "baseline_features": [] if baseline_features is None else baseline_features,
        "enabled_features": [identifier],
        "additive_callables": [] if additive_callables is None else additive_callables,
        "replacement_callables": [] if replacement_callables is None else replacement_callables,
        "aliases": [],
    }
    if state == "verified":
        value["evidence_record"] = f"evidence.{identifier}"
        value["dispatch_command"] = identifier
    return value


class FeatureArchiveRosterTests(unittest.TestCase):
    def test_checked_roster_covers_every_cargo_x86_feature_once(self) -> None:
        cargo_features = ROSTER.load_cargo_x86_features()
        rows = ROSTER.load_feature_archive_roster()

        self.assertEqual([item.identifier for item in rows], list(cargo_features))
        self.assertEqual(len(rows), 27)
        self.assertEqual([item.identifier for item in rows if item.state == "planned"], [])
        resolver = next(item for item in rows if item.identifier == "x86-resolver-runtime")
        self.assertEqual(resolver.state, "verified")
        self.assertEqual(resolver.evidence_record, "static-c-resolver-runtime")
        self.assertEqual(resolver.dispatch_command, "libc-resolver-runtime")
        self.assertEqual(
            resolver.aliases,
            (
                ROSTER.ArchiveAlias("res_mkquery", "__res_mkquery", "weak-same-address"),
                ROSTER.ArchiveAlias("res_search", "res_query", "weak-same-address"),
                ROSTER.ArchiveAlias("res_send", "__res_send", "weak-same-address"),
            ),
        )
        self.assertEqual(
            next(item for item in rows if item.identifier == "x86-environment-runtime").additive_callables,
            (),
        )
        interval_timers = next(
            item for item in rows if item.identifier == "x86-interval-timers"
        )
        self.assertEqual(interval_timers.evidence_record, "static-c-interval-timers")
        self.assertEqual(interval_timers.dispatch_command, "libc-interval-timers")
        self.assertEqual(interval_timers.additive_callables, ("getitimer", "setitimer"))
        file_handles = next(
            item for item in rows if item.identifier == "x86-file-handles"
        )
        self.assertEqual(file_handles.evidence_record, "static-c-file-handles")
        self.assertEqual(file_handles.dispatch_command, "libc-file-handles")
        self.assertEqual(
            file_handles.additive_callables,
            ("name_to_handle_at", "open_by_handle_at"),
        )
        temporary_names = next(
            item for item in rows if item.identifier == "x86-temporary-names"
        )
        self.assertEqual(
            temporary_names.evidence_record,
            "static-c-temporary-names",
        )
        self.assertEqual(
            temporary_names.dispatch_command,
            "libc-temporary-names",
        )
        self.assertEqual(
            temporary_names.baseline_features,
            ("x86-allocator-runtime", "x86-allocator-string-duplication"),
        )
        self.assertEqual(temporary_names.additive_callables, ("tempnam", "tmpnam"))
        spawn_file_actions = next(
            item
            for item in rows
            if item.identifier == "x86-posix-spawn-file-actions"
        )
        self.assertEqual(
            spawn_file_actions.evidence_record,
            "static-c-posix-spawn-file-actions",
        )
        self.assertEqual(
            spawn_file_actions.dispatch_command,
            "libc-posix-spawn-file-actions",
        )
        self.assertEqual(
            spawn_file_actions.baseline_features,
            ("x86-allocator-runtime",),
        )
        self.assertEqual(
            spawn_file_actions.additive_callables,
            (
                "posix_spawn_file_actions_addchdir_np",
                "posix_spawn_file_actions_addclose",
                "posix_spawn_file_actions_adddup2",
                "posix_spawn_file_actions_addfchdir_np",
                "posix_spawn_file_actions_addopen",
                "posix_spawn_file_actions_destroy",
            ),
        )
        process_exec = next(item for item in rows if item.identifier == "x86-process-exec")
        self.assertEqual(process_exec.state, "verified")
        self.assertEqual(process_exec.evidence_record, "static-c-process-exec")
        self.assertEqual(process_exec.runner, "compat/x86_64/run_libc_process_exec.sh")
        self.assertEqual(process_exec.dispatch_command, "libc-process-exec")
        self.assertEqual(process_exec.baseline_features, ())
        self.assertEqual(
            process_exec.additive_callables,
            ("execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe", "fexecve"),
        )
        self.assertEqual(
            process_exec.aliases,
            (ROSTER.ArchiveAlias("execvpe", "__execvpe", "weak-same-address"),),
        )
        spin_operations = next(
            item
            for item in rows
            if item.identifier == "x86-pthread-spin-operations"
        )
        self.assertEqual(
            spin_operations.evidence_record,
            "static-c-pthread-spin-operations",
        )
        self.assertEqual(
            spin_operations.additive_callables,
            ("pthread_spin_lock", "pthread_spin_trylock", "pthread_spin_unlock"),
        )
        composition = next(
            item
            for item in rows
            if item.identifier == "x86-crypt-allocator-composition"
        )
        self.assertEqual(composition.evidence_record, "static-c-crypt-allocator-composition")
        self.assertEqual(composition.dispatch_command, "libc-crypt-allocator-composition")
        self.assertEqual(
            composition.baseline_features,
            ("x86-allocator-runtime", "x86-crypt"),
        )
        self.assertEqual(composition.additive_callables, ())
        self.assertEqual(composition.replacement_callables, ())

    def test_dependent_feature_requires_its_exact_cargo_baseline(self) -> None:
        cargo_features = {
            "x86-base": (),
            "x86-dependent": ("x86-base",),
        }
        rows = [row("x86-base"), row("x86-dependent")]

        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "baseline does not match its Cargo feature dependency closure",
        ):
            ROSTER.parse_feature_archive_roster(rows, cargo_features)

    def test_partition_rejects_default_static_additive_ownership(self) -> None:
        cargo_features = {"x86-extra": ()}
        rows = ROSTER.parse_feature_archive_roster(
            [row("x86-extra", additive_callables=["already_default"])],
            cargo_features,
        )

        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "not exclusively owned",
        ):
            ROSTER.partition_candidate_callables(
                rows,
                candidate_callables={"already_default"},
                static_exports={"already_default"},
            )

    def test_partition_keeps_declared_unverified_features_out_of_verified_ownership(self) -> None:
        cargo_features = {"x86-planned": ()}
        rows = ROSTER.parse_feature_archive_roster(
            [row("x86-planned", state="planned", additive_callables=["future_callable"])],
            cargo_features,
        )
        partition = ROSTER.partition_candidate_callables(
            rows,
            candidate_callables={"future_callable", "unprovided"},
            static_exports=set(),
        )

        self.assertEqual(partition.counts(), {
            "default_static": 0,
            "verified_feature_archives": 0,
            "declared_unverified_feature_archives": 1,
            "unprovided": 1,
        })


if __name__ == "__main__":
    unittest.main()
