#!/usr/bin/env python3
"""Structural contracts for exact shared-only bundled-mimalloc visibility."""
from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
LIST = ROOT / "libc/src/c_abi/x86_64/owned_mimalloc_hidden.list"
BUILDER = ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"
RUNNER = ROOT / "compat/x86_64/run_libc_mimalloc_export_visibility.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_mimalloc_export_visibility.py"
EVIDENCE_SPEC = importlib.util.spec_from_file_location("owned_mimalloc_export_visibility_test", EVIDENCE)
assert EVIDENCE_SPEC is not None and EVIDENCE_SPEC.loader is not None
evidence = importlib.util.module_from_spec(EVIDENCE_SPEC)
sys.modules[EVIDENCE_SPEC.name] = evidence
EVIDENCE_SPEC.loader.exec_module(evidence)


class OwnedMimallocExportVisibilityTests(unittest.TestCase):
    def test_exact_contract_is_sealed_and_not_a_prefix_rule(self) -> None:
        members = LIST.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(members), 424)
        self.assertEqual(members, sorted(set(members)))
        self.assertEqual(
            hashlib.sha256(LIST.read_bytes()).hexdigest(),
            "cd537f6579018bbba79d831ee148a7b07f51a0f3bda538a27970724751d78873",
        )
        for required in (
            "mi_malloc_aligned",
            "mi_usable_size",
            "_mi_os_alloc",
            "_ZSt15get_new_handlerv",
        ):
            self.assertIn(required, members)
        source = BUILDER.read_text(encoding="utf-8")
        self.assertIn("MIMALLOC_V3_HIDDEN_LIST_COUNT = 424", source)
        self.assertIn("MIMALLOC_V3_HIDDEN_LIST_SHA256", source)
        self.assertIn("members != tuple(sorted(set(members)))", source)
        self.assertNotIn("mi_*", source)
        self.assertNotIn("--exclude-libs", source)

    def test_only_the_shared_link_receives_the_exact_version_script(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        self.assertIn("shared_libc_mimalloc_hidden_exports", source)
        self.assertIn('f"--version-script={mimalloc_hidden_exports}"', source)
        self.assertIn('"linker_policy": "exact-local-symbols"', source)
        self.assertIn('"shared_mimalloc_hidden_exports": shared_mimalloc_hidden_exports', source)
        self.assertEqual(source.count("--version-script="), 2)
        static_builder = (ROOT / "scripts/build_x86_64_owned_sysroot.py").read_text(encoding="utf-8")
        self.assertNotIn("owned_mimalloc_hidden", static_builder)

    def test_local_contract_rejects_a_public_dynsym_row_or_nonlocal_symtab_row(self) -> None:
        members = ["hidden_function", "hidden_object"]
        provider = [
            {"raw_name": "hidden_function", "name": "hidden_function", "version": None,
             "version_default": False, "type": "FUNC", "size": "13", "size_bytes": 13,
             "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "1"},
            {"raw_name": "hidden_object", "name": "hidden_object", "version": None,
             "version_default": False, "type": "OBJECT", "size": "8", "size_bytes": 8,
             "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "2"},
        ]
        shared = [
            {**provider[0], "binding": "LOCAL"},
            {**provider[1], "binding": "LOCAL"},
        ]
        self.assertEqual(
            evidence.validate_local_contract_rows(members, [], shared, provider),
            ["hidden_function", "hidden_object"],
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "still has a dynsym row"):
            evidence.validate_local_contract_rows(members, [shared[0]], shared, provider)
        nonlocal_rows = [dict(row) for row in shared]
        nonlocal_rows[0]["binding"] = "GLOBAL"
        with self.assertRaisesRegex(evidence.EvidenceError, "is not LOCAL"):
            evidence.validate_local_contract_rows(members, [], nonlocal_rows, provider)
        version_drift = [dict(row) for row in shared]
        version_drift[0].update(raw_name="hidden_function@@CRABC_1", version="CRABC_1", version_default=True)
        with self.assertRaisesRegex(evidence.EvidenceError, "spelling/version/kind differs"):
            evidence.validate_local_contract_rows(members, [], version_drift, provider)

    def test_local_contract_rejects_object_size_drift_and_extra_hidden_public_row(self) -> None:
        members = ["hidden_object"]
        provider = [{"raw_name": "hidden_object", "name": "hidden_object", "version": None,
                     "version_default": False, "type": "OBJECT", "size": "8", "size_bytes": 8,
                     "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "2"}]
        shared = [{**provider[0], "binding": "LOCAL"}]
        size_drift = [dict(shared[0], size="9", size_bytes=9)]
        with self.assertRaisesRegex(evidence.EvidenceError, "object size differs"):
            evidence.validate_local_contract_rows(members, [], size_drift, provider)
        baseline = [
            {"raw_name": "hidden_object", "name": "hidden_object", "type": "OBJECT", "size": "8", "size_bytes": 8,
             "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "2",
             "version": None, "version_default": False},
            {"raw_name": "surviving_object", "name": "surviving_object", "type": "OBJECT", "size": "8", "size_bytes": 8,
             "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "3",
             "version": None, "version_default": False},
        ]
        current = [dict(baseline[1], size="9", size_bytes=9)]
        with self.assertRaisesRegex(evidence.EvidenceError, "data size changed"):
            evidence.validate_visible_symtab_delta(baseline, current, set(members))

    def test_runner_compares_the_prechange_product_and_reuses_behavioral_components(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        evidence = EVIDENCE.read_text(encoding="utf-8")
        for required in (
            "build_x86_64_owned_sysroot.py",
            "build_x86_64_owned_dynamic_sysroot.py",
            "owned_mimalloc_export_visibility.py",
            "run_owned_c_allocation_interposition.sh",
            "run_owned_mimalloc_startup_errno.sh",
            "PRECHANGE_ABI_REPORT PRECHANGE_LIBC_SO",
        ):
            self.assertIn(required, runner)
        for required in (
            "BASELINE_EXTRA_COUNT = 475",
            "REMAINING_EXTRA_COUNT = 51",
            "shared dynsym changed by names beyond the exact 424-name mimalloc local contract",
            "static allocator provider lost hidden shared-only names",
            "fresh shared link selected allocator member differs from the static provider",
            "shared symtab {member} spelling/version/kind differs from the static allocator provider",
            "surviving shared symtab data size changed",
            "--version-script=$BUILD/libc-mimalloc-hidden.exports",
            "public allocator entry {name} binding/visibility drifted",
        ):
            self.assertIn(required, evidence)


if __name__ == "__main__":
    unittest.main()
