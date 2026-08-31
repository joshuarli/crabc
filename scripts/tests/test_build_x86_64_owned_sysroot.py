#!/usr/bin/env python3
"""Focused contracts for the private x86 owned-static-sysroot builder."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build_x86_64_owned_sysroot.py"
SPEC = importlib.util.spec_from_file_location("build_x86_64_owned_sysroot", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = builder
SPEC.loader.exec_module(builder)


class BuildX86OwnedSysrootTests(unittest.TestCase):
    def test_libc_member_classification_separates_owned_and_stock_runtime_members(self) -> None:
        selected, excluded = builder.classify_libc_members(
            (
                "c.one.rcgu.o",
                "c.two.rcgu.o",
                "compiler_builtins-abc.rcgu.o",
                "core-312879cb10d0e978.core.7a0be3b8ae74ffc7-cgu.0.rcgu.o",
                "45c91108d938afe8-addvdi3.o",
            )
        )
        self.assertEqual(selected, ("c.one.rcgu.o", "c.two.rcgu.o"))
        self.assertEqual(
            excluded,
            (
                "compiler_builtins-abc.rcgu.o",
                "core-312879cb10d0e978.core.7a0be3b8ae74ffc7-cgu.0.rcgu.o",
                "45c91108d938afe8-addvdi3.o",
            ),
        )

    def test_libc_member_classification_fails_closed_on_foreign_runtime_input(self) -> None:
        with self.assertRaisesRegex(builder.BuildError, "unclassified target-runtime"):
            builder.classify_libc_members(
                (
                    "c.one.rcgu.o",
                    "compiler_builtins-abc.rcgu.o",
                    "core-312879cb10d0e978.core.7a0be3b8ae74ffc7-cgu.0.rcgu.o",
                    "45c91108d938afe8-addvdi3.o",
                    "crtbegin.o",
                )
            )

    def test_regular_tree_materialization_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "header.h").write_text("#define VALUE 1\n", encoding="utf-8")
            (source / "alias.h").symlink_to("header.h")
            with self.assertRaisesRegex(builder.BuildError, "contains a symlink"):
                builder.copy_regular_tree(source, root / "installed")

    def test_remove_owned_output_requires_exact_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "output"
            marker = root / "share" / "crabc" / "manifest.json"
            marker.parent.mkdir(parents=True)
            marker.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(builder.BuildError, "unrecognized output"):
                builder.remove_owned_output(root)
            marker.write_text(
                json.dumps({"format": builder.FORMAT, "target": builder.TARGET}) + "\n",
                encoding="utf-8",
            )
            builder.remove_owned_output(root)
            self.assertFalse(root.exists())

    def test_manifest_contract_names_installed_inputs_and_non_promotion_scope(self) -> None:
        manifest = builder.installed_manifest({"usr/lib/crt1.o": "0" * 64})
        self.assertEqual(manifest["format"], builder.FORMAT)
        self.assertEqual(manifest["target"], builder.TARGET)
        self.assertEqual(manifest["toolchain"], builder.PINNED_TOOLCHAIN)
        self.assertEqual(
            manifest["scope"],
            "private-static-pthread-tls-consumer-slice-not-family-completion-not-public-support",
        )
        self.assertEqual(
            manifest["installed"]["files"],
            {"usr/lib/crt1.o": "0" * 64},
        )
        self.assertEqual(
            manifest["purity"]["target_runtime_inputs"],
            list(builder.TARGET_RUNTIME_INPUTS),
        )
        for item in (
            "dynamic loader or PT_INTERP",
            "complete compiler-helper closure",
            "sysroot.static-tls family completion",
            "sysroot.owned-artifact family completion",
            "x86-64 promotion or public support",
        ):
            self.assertIn(item, manifest["not_selected"])

    def test_deterministic_environment_removes_ambient_target_search_and_tools(self) -> None:
        names = (
            "CPATH",
            "LIBRARY_PATH",
            "COMPILER_PATH",
            "GCC_EXEC_PREFIX",
            "RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "CC",
            "CFLAGS_x86_64_unknown_linux_musl",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER",
        )
        previous = {name: builder.os.environ.get(name) for name in names}
        try:
            for name in names:
                builder.os.environ[name] = "/ambient/target/input"
            environment = builder.deterministic_environment()
        finally:
            for name, value in previous.items():
                if value is None:
                    builder.os.environ.pop(name, None)
                else:
                    builder.os.environ[name] = value
        for name in names:
            self.assertNotIn(name, environment)


if __name__ == "__main__":
    unittest.main()
