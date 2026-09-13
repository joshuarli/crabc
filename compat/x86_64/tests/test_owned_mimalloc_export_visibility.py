#!/usr/bin/env python3
"""Structural contracts for exact shared-only bundled-mimalloc visibility."""
from __future__ import annotations

import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
LIST = ROOT / "libc/src/c_abi/x86_64/owned_mimalloc_hidden.list"
BUILDER = ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"
RUNNER = ROOT / "compat/x86_64/run_libc_mimalloc_export_visibility.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_mimalloc_export_visibility.py"


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
            "--version-script=$BUILD/libc-mimalloc-hidden.exports",
            "public allocator entry {name} binding/visibility drifted",
        ):
            self.assertIn(required, evidence)


if __name__ == "__main__":
    unittest.main()
