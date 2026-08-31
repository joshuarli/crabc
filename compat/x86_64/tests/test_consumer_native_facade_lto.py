#!/usr/bin/env python3
"""Contract tests for the private x86 native-facade LTO consumer."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/consumer_native_facade_lto.py"
SPEC = importlib.util.spec_from_file_location("consumer_native_facade_lto", RUNNER)
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
                MODULE.closed_link_inputs(crt=crt, **paths),
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


class CompileContractTests(unittest.TestCase):
    def test_application_command_uses_linker_plugin_lto_and_no_linker(self) -> None:
        with mock.patch.object(MODULE.BASE, "rustc_command", return_value=["rustc"]):
            command = MODULE.application_command(
                output=Path("application.o"),
                helper=Path("libhelper.rlib"),
                facade=Path("libcrabc_rs.rlib"),
                core=Path("libcrabc_core.rlib"),
            )
        self.assertIn("linker-plugin-lto=yes", command)
        self.assertIn("--emit=obj", command)
        self.assertNotIn("-C linker=cc", " ".join(command))

    def test_fixture_retains_the_aarch64_native_facade_operations(self) -> None:
        source = MODULE.FIXTURE.read_text(encoding="utf-8")
        for route in (
            "fs::openat",
            "pipe::pipe_with",
            "eventfd_write",
            "eventfd_read",
            "io::fcntl_getfd",
            "crabc_rs_native_facade_getpid_witness",
        ):
            self.assertIn(route, source)

    def test_workload_mapping_is_explicitly_not_same_source(self) -> None:
        mapping = MODULE.validate_workload_sources()
        self.assertTrue(mapping["route_mapping_complete"])
        self.assertFalse(mapping["same_source_claimed"])
        self.assertEqual(mapping["required_routes"], list(MODULE.WORKLOAD_ROUTES))


if __name__ == "__main__":
    unittest.main()
