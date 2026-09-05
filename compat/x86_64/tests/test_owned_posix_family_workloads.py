#!/usr/bin/env python3
"""Exact source-bound POSIX family workload ownership tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_posix_family_workloads as workloads


class OwnedPosixFamilyWorkloadTests(unittest.TestCase):
    def by_id(self) -> dict[str, workloads.Workload]:
        return {workload.id: workload for workload in workloads.WORKLOADS}

    def replace_workload(
        self, identifier: str, replacement: workloads.Workload
    ) -> tuple[workloads.Workload, ...]:
        return tuple(
            replacement if workload.id == identifier else workload
            for workload in workloads.WORKLOADS
        )

    def test_actual_frozen_catalog_has_one_exact_primary_owner_per_spelling(self) -> None:
        roster = workloads.validate_workloads()
        catalog = workloads.load_catalog()
        expected = {
            symbol
            for capability in catalog.capabilities.values()
            for symbol in capability.symbols
        }
        owners = {
            symbol: workload.id
            for workload in roster
            for symbol in workload.primary_symbols
        }

        self.assertEqual(roster, workloads.WORKLOADS)
        self.assertEqual(len(catalog.capabilities), 9)
        self.assertEqual(len(expected), 149)
        self.assertEqual(set(owners), expected)
        self.assertEqual(len(owners), 149)
        self.assertEqual(owners, workloads.EXPECTED_PRIMARY_OWNERS)
        self.assertEqual(owners["fork"], "fork")
        self.assertEqual(owners["clone"], "process-trio")
        self.assertEqual(owners["posix_spawn"], "spawn")

    def test_primary_and_supplemental_records_preserve_the_real_boundaries(self) -> None:
        by_id = self.by_id()

        self.assertEqual(by_id["process-trio"].primary_symbols, ("clone", "daemon", "vfork"))
        self.assertEqual(
            by_id["spawn"].primary_symbols,
            (
                "posix_spawn", "posix_spawnp",
                "posix_spawn_file_actions_addchdir_np",
                "posix_spawn_file_actions_addclose",
                "posix_spawn_file_actions_adddup2",
                "posix_spawn_file_actions_addfchdir_np",
                "posix_spawn_file_actions_addopen",
                "posix_spawn_file_actions_destroy",
                "posix_spawn_file_actions_init",
            ),
        )
        self.assertEqual(len(by_id["control-residual"].primary_symbols), 31)
        self.assertEqual(by_id["fork"].primary_symbols, ("fork",))
        self.assertEqual(by_id["fork"].product_scope, "dynamic")
        self.assertEqual(by_id["static-fork"].primary_symbols, ())
        self.assertEqual(by_id["static-fork"].product_scope, "static")
        self.assertEqual(workloads.STATIC_SUPPLEMENTAL_OWNERS, {"fork": "static-fork"})
        self.assertEqual(by_id["global-state-composition"].primary_symbols, ())

        self.assertEqual(len(by_id["signal-full"].primary_symbols), 23)
        self.assertEqual(len(by_id["signal-helpers"].primary_symbols), 8)
        self.assertEqual(by_id["io-cancellation"].primary_symbols,
                         ("sigtimedwait", "sigwait", "sigwaitinfo"))
        self.assertEqual(by_id["pthread-signal"].primary_symbols, ())
        self.assertEqual(by_id["posix-timers"].primary_symbols, ())

        self.assertEqual(len(by_id["linux-control"].primary_symbols), 18)
        self.assertEqual(by_id["syslog"].primary_symbols,
                         ("closelog", "openlog", "setlogmask", "syslog", "vsyslog"))
        self.assertEqual(by_id["system-cancellation"].primary_symbols, ("system",))

    def test_source_roles_and_product_cells_are_finite_and_source_bound(self) -> None:
        by_id = self.by_id()
        self.assertEqual(workloads.STATIC_PRODUCTS, ("primary", "reproduction", "extracted"))
        self.assertEqual(workloads.STATIC_LINKAGES, ("et-exec", "pie"))
        self.assertEqual(len(workloads.STATIC_CELLS), 6)
        self.assertEqual(workloads.DYNAMIC_PRODUCTS, ("installed", "second", "extracted"))
        self.assertEqual(workloads.DYNAMIC_LINKAGES, ("pie", "non-pie"))
        self.assertEqual(workloads.DYNAMIC_ENTRIES, ("kernel", "direct"))
        self.assertEqual(len(workloads.DYNAMIC_CELLS), 12)
        self.assertEqual(workloads.SCOPE_CELLS["both"],
                         workloads.STATIC_CELLS + workloads.DYNAMIC_CELLS)
        self.assertEqual(workloads.SCOPE_CELLS["static"], workloads.STATIC_CELLS)
        self.assertEqual(workloads.SCOPE_CELLS["dynamic"], workloads.DYNAMIC_CELLS)

        self.assertEqual(
            tuple((role.role, role.source, role.object_path)
                  for role in by_id["fork"].source_object_roles),
            (
                ("initial-dso", "compat/x86_64/general_dynamic_fork_library.c",
                 "objects/libfork-initial.o"),
                ("one-dso", "compat/x86_64/general_dynamic_fork_library.c",
                 "objects/libfork-one.o"),
                ("two-dso", "compat/x86_64/general_dynamic_fork_library.c",
                 "objects/libfork-two.o"),
                ("semantic-consumer", "compat/x86_64/general_dynamic_fork_consumer.c",
                 "objects/semantic-consumer.o"),
                ("owned-layout-consumer", "compat/x86_64/general_dynamic_fork_consumer.c",
                 "objects/owned-layout-consumer.o"),
            ),
        )
        self.assertEqual(
            tuple((role.role, role.source, role.object_path)
                  for role in by_id["static-fork"].source_object_roles),
            (
                ("atfork-registry", "compat/x86_64/owned_atfork_registry_probe.c",
                 "atfork-registry/workload.o"),
                ("static-posix-forkexec", "compat/x86_64/owned_static_posix_probe.c",
                 "static-posix-forkexec/workload.o"),
            ),
        )
        self.assertEqual(
            tuple((role.role, role.source, role.object_path)
                  for role in by_id["posix-timers"].source_object_roles),
            (
                ("application", "compat/x86_64/owned_posix_timers_probe.c", "probe.o"),
                ("timer-tls-dso", "compat/x86_64/owned_posix_timers_tls.c", "tls.o"),
            ),
        )
        self.assertEqual(len(by_id["io-cancellation"].source_object_roles), 10)
        self.assertEqual(by_id["pthread-signal"].script, "compat/x86_64/run_owned_pthread_signal.sh")
        self.assertEqual(by_id["pthread-signal"].dynamic_case, "pthread-signal")
        import owned_dynamic_qualification as qualification
        for workload in workloads.WORKLOADS:
            if workload.product_scope != "static":
                self.assertIn(workload.dynamic_case, qualification.CASES)

        for workload in workloads.WORKLOADS:
            for role in workload.source_object_roles:
                self.assertTrue((ROOT / role.source).is_file(), role.source)
            for source in workload.required_supplementary_sources:
                self.assertTrue((ROOT / source).is_file(), source)

    def test_omitted_duplicate_unknown_and_reassigned_primary_owners_fail(self) -> None:
        fork = self.by_id()["fork"]
        composition = self.by_id()["global-state-composition"]

        with self.assertRaisesRegex(workloads.WorkloadMapError, "omits frozen primary spelling: fork"):
            workloads.validate_workloads(self.replace_workload("fork", replace(fork, primary_symbols=())))

        with self.assertRaisesRegex(workloads.WorkloadMapError, "duplicate primary spelling: fork"):
            workloads.validate_workloads(
                self.replace_workload(
                    "global-state-composition",
                    replace(composition, primary_symbols=("fork",)),
                )
            )

        with self.assertRaisesRegex(workloads.WorkloadMapError, "unknown primary spelling: not-a-frozen-spelling"):
            workloads.validate_workloads(
                self.replace_workload(
                    "fork",
                    replace(fork, primary_symbols=("fork", "not-a-frozen-spelling")),
                )
            )

        reassigned = self.replace_workload("fork", replace(fork, primary_symbols=()))
        control = self.by_id()["control-residual"]
        reassigned = tuple(
            replace(workload, primary_symbols=control.primary_symbols + ("fork",))
            if workload.id == "control-residual" else workload
            for workload in reassigned
        )
        with self.assertRaisesRegex(workloads.WorkloadMapError,
                                    "primary spelling owner drifted: fork"):
            workloads.validate_workloads(reassigned)

    def test_required_supplemental_workloads_cannot_be_implied_by_primary_symbols(self) -> None:
        missing_static_fork = tuple(
            workload for workload in workloads.WORKLOADS if workload.id != "static-fork"
        )
        with self.assertRaisesRegex(workloads.WorkloadMapError,
                                    "missing required supplementary workload: static-fork"):
            workloads.validate_workloads(missing_static_fork)

        fork = self.by_id()["fork"]
        composition = self.by_id()["global-state-composition"]
        invalid = self.replace_workload("fork", replace(fork, primary_symbols=()))
        invalid = tuple(
            replace(workload, primary_symbols=("fork",))
            if workload.id == "global-state-composition" else workload
            for workload in invalid
        )
        with self.assertRaisesRegex(workloads.WorkloadMapError,
                                    "supplemental workload cannot own primary spellings: global-state-composition"):
            workloads.validate_workloads(invalid)


if __name__ == "__main__":
    unittest.main()
