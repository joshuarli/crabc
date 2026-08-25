#!/usr/bin/env python3
"""Focused contracts for the owned static-runtime archive boundary."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "crabc_build_owned_sysroot_test", ROOT / "scripts/build_owned_sysroot.py"
)
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILD
SPEC.loader.exec_module(BUILD)


class StaticRuntimeArchiveTests(unittest.TestCase):
    def test_selects_only_runtime_and_documented_allocator_members(self) -> None:
        members = [
            "c.c.0123456789abcdef-cgu.0.rcgu.o",
            "aabb8c858634ccbb-lse_cas8_acq_rel.o",
            "b85de32113adef8e-static.o",
            "compiler_builtins-b672.compiler_builtins-cgu.000.rcgu.o",
            "45c91108d938afe8-addvdi3.o",
        ]

        selection = BUILD.select_static_runtime_members(members)

        self.assertEqual(selection.runtime_member, members[0])
        self.assertEqual(selection.allocator_member, members[2])
        self.assertEqual(selection.selected_members, (members[0], members[2]))
        self.assertEqual(selection.excluded_members, tuple(members[1:2] + members[3:]))

    def test_rejects_unclassified_staticlib_members(self) -> None:
        members = [
            "c.c.0123456789abcdef-cgu.0.rcgu.o",
            "b85de32113adef8e-static.o",
            "unreviewed-transitive-runtime.o",
        ]

        with self.assertRaises(BUILD.BuildError):
            BUILD.select_static_runtime_members(members)

    def test_runtime_build_environment_disables_outline_atomics_for_rust_and_c(self) -> None:
        environment = BUILD.deterministic_environment()

        self.assertEqual(
            environment["CFLAGS_aarch64_unknown_linux_musl"],
            "-mno-outline-atomics",
        )
        self.assertIn("target-feature=-crt-static,-outline-atomics", environment["CARGO_ENCODED_RUSTFLAGS"])


if __name__ == "__main__":
    unittest.main()
