#!/usr/bin/env python3
"""Contract tests for the private x86 static-PIE Rust LTO consumer."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/consumer_static_pie_lto.py"
SPEC = importlib.util.spec_from_file_location("consumer_static_pie_lto", RUNNER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ClosedInputTests(unittest.TestCase):
    def test_closed_link_inputs_name_every_owned_input_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            crt = work / "crt"
            crt.mkdir()
            paths = {
                "application": work / "application.o",
                "helper": work / "libhelper.rlib",
                "facade": work / "libcrabc_rs.rlib",
                "core": work / "libcrabc_core.rlib",
                "bitflags": work / "libbitflags.rlib",
                "toolchain_core": work / "libcore-pinned.rlib",
                "memory": work / "crabc-memory.o",
                "builtins": work / "libcrabc-builtins.a",
            }
            for name in ("rcrt1.o", "crti.o", "crtn.o"):
                (crt / name).touch()
            for path in paths.values():
                path.touch()

            self.assertEqual(
                MODULE.closed_link_inputs(
                    crt=crt,
                    application=paths["application"],
                    helper=paths["helper"],
                    facade=paths["facade"],
                    core=paths["core"],
                    bitflags=paths["bitflags"],
                    toolchain_core=paths["toolchain_core"],
                    memory=paths["memory"],
                    builtins=paths["builtins"],
                ),
                [
                    crt / "rcrt1.o",
                    crt / "crti.o",
                    paths["application"],
                    paths["helper"],
                    paths["facade"],
                    paths["core"],
                    paths["bitflags"],
                    paths["toolchain_core"],
                    paths["memory"],
                    crt / "crtn.o",
                    paths["builtins"],
                ],
            )

    def test_closed_link_inputs_rejects_an_extra_runtime(self) -> None:
        with self.assertRaisesRegex(MODULE.EvidenceError, "ambient CRT/runtime"):
            MODULE.closed_link_inputs(
                crt=Path("crt"),
                application=Path("application.o"),
                helper=Path("libhelper.rlib"),
                facade=Path("libcrabc_rs.rlib"),
                core=Path("libcrabc_core.rlib"),
                bitflags=Path("libbitflags.rlib"),
                toolchain_core=Path("libcore-pinned.rlib"),
                memory=Path("crabc-memory.o"),
                builtins=Path("libcrabc-builtins.a"),
                extras=(Path("libgcc.a"),),
            )


class PinnedCoreTests(unittest.TestCase):
    def test_resolve_pinned_core_requires_one_target_libcore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target_libdir = Path(temporary)
            expected = target_libdir / "libcore-0123456789abcdef.rlib"
            expected.touch()
            self.assertEqual(MODULE.resolve_pinned_core(target_libdir), expected)

    def test_resolve_pinned_core_rejects_ambiguous_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target_libdir = Path(temporary)
            (target_libdir / "libcore-one.rlib").touch()
            (target_libdir / "libcore-two.rlib").touch()
            with self.assertRaisesRegex(MODULE.EvidenceError, "exactly one pinned target libcore"):
                MODULE.resolve_pinned_core(target_libdir)


class ToolOutputTests(unittest.TestCase):
    def test_parse_defined_symbols_ignores_archive_headers(self) -> None:
        output = """
archive.a(member.o):
0000000000000000 T __udivti3
0000000000000010 t crabc_x86_consumer_lto_helper::fingerprint
"""
        self.assertEqual(
            MODULE.parse_defined_symbols(output),
            {"__udivti3", "crabc_x86_consumer_lto_helper::fingerprint"},
        )

    def test_forbidden_runtime_markers_are_case_insensitive(self) -> None:
        self.assertEqual(
            MODULE.forbidden_runtime_markers("/usr/lib/GCC/libgcc.a\ncompiler-rt/builtins.a"),
            ["/usr/lib/gcc/", "compiler-rt", "libgcc"],
        )
        self.assertEqual(MODULE.forbidden_runtime_markers("/tmp/libcrabc-builtins.a"), [])


class RustCompileCommandTests(unittest.TestCase):
    def test_control_rlib_keeps_native_code_and_embedded_bitcode(self) -> None:
        with mock.patch.object(MODULE, "rustc_command", return_value=["rustc"]):
            command = MODULE.rust_library_command(
                crate_name="helper",
                source=Path("helper.rs"),
                output=Path("libhelper.rlib"),
                linker_plugin_lto=False,
            )
        self.assertIn("embed-bitcode=yes", command)
        self.assertNotIn("linker-plugin-lto=yes", command)

    def test_lto_rlib_is_linker_plugin_bitcode(self) -> None:
        with mock.patch.object(MODULE, "rustc_command", return_value=["rustc"]):
            command = MODULE.rust_library_command(
                crate_name="helper",
                source=Path("helper.rs"),
                output=Path("libhelper.rlib"),
                linker_plugin_lto=True,
            )
        self.assertIn("linker-plugin-lto=yes", command)
        self.assertNotIn("embed-bitcode=yes", command)


if __name__ == "__main__":
    unittest.main()
