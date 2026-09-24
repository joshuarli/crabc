#!/usr/bin/env python3
"""Fail-closed admission policy of the RuntimeV1 native-facade runner."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/runtime_private_facades.py"
SPEC = importlib.util.spec_from_file_location("runtime_private_facades", RUNNER)
assert SPEC is not None and SPEC.loader is not None
facades = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = facades
SPEC.loader.exec_module(facades)


def probe(example: str):
    return next(item for item in facades.PROBES if item.example == example)


class ProbeAdmissionTests(unittest.TestCase):
    def test_roster_keeps_each_frozen_probe_unchanged_and_every_facade_differential(self) -> None:
        frozen = {item.example for item in facades.PROBES if item.same_source_aarch64}
        self.assertEqual(frozen, {"loader_runtime_probe", "runtime_thread_probe", "cfile_direct_probe"})
        for item in facades.PROBES:
            self.assertTrue(item.fixture.is_file(), item.fixture)
            self.assertTrue((ROOT / "crabc-rs/examples" / f"{item.example}.rs").is_file())
            self.assertTrue(set(item.features) <= set(facades.FEATURES) | {"runtime-thread"})
        differentials = {item.features for item in facades.PROBES if not item.same_source_aarch64}
        self.assertEqual(differentials, {("runtime-loader",), ("runtime-thread-alloc",), ("runtime-stdio",)})

    def test_admits_only_the_private_getter_memory_primitives_and_declared_callbacks(self) -> None:
        thread = probe("x86_64_thread_facade_probe")
        facades.admit_probe_symbols(
            thread,
            ["__crabc_runtime_v1", "crabc_x86_64_thread_facade_c_self", "memcpy"],
            sorted(thread.entries | {"crabc_rs_signal_restorer"}),
        )

    def test_rejects_a_missing_private_getter(self) -> None:
        loader = probe("x86_64_loader_facade_probe")
        with self.assertRaisesRegex(facades.EvidenceError, "private runtime getter"):
            facades.admit_probe_symbols(loader, ["memcpy"], sorted(loader.entries))

    def test_rejects_public_c_abi_errno_and_allocator_imports_even_when_declared(self) -> None:
        loader = probe("x86_64_loader_facade_probe")
        declared = facades.Probe(
            loader.example, loader.features, loader.entries, loader.fixture,
            loader.expected_stdout, False, fixture_imports=frozenset({"dlopen"}),
        )
        for name in ("dlopen", "dlerror", "pthread_create", "fmemopen", "__errno_location", "malloc"):
            with self.subTest(name=name), self.assertRaisesRegex(facades.EvidenceError, "public C ABI"):
                facades.admit_probe_symbols(declared, ["__crabc_runtime_v1", name], sorted(loader.entries))

    def test_rejects_undeclared_imports_and_uninternalized_facade_definitions(self) -> None:
        cfile = probe("x86_64_cfile_facade_probe")
        with self.assertRaisesRegex(facades.EvidenceError, "undeclared imports"):
            facades.admit_probe_symbols(cfile, ["__crabc_runtime_v1", "__udivti3"], sorted(cfile.entries))
        with self.assertRaisesRegex(facades.EvidenceError, "internalize"):
            facades.admit_probe_symbols(
                cfile, ["__crabc_runtime_v1"],
                sorted(cfile.entries | {"_ZN8crabc_rs5cfile5CFile11from_memory17h0123456789abcdefE"}),
            )
        with self.assertRaisesRegex(facades.EvidenceError, "lacks probe entries"):
            facades.admit_probe_symbols(cfile, ["__crabc_runtime_v1"], ["crabc_rs_x86_64_cfile_facade_run"])

    def test_selects_exactly_the_fat_lto_member_and_never_builtins(self) -> None:
        members = [
            "x86_64_cfile_facade_probe-0123abcd.x86_64_cfile_facade_probe.4567ef-cgu.0.rcgu.o",
            "compiler_builtins-89ab.compiler_builtins.cdef-cgu.000.rcgu.o",
            "b2f3eb2f094cea5b-absvdi2.o",
        ]
        self.assertEqual(facades.select_lto_member(members, "x86_64_cfile_facade_probe"), members[0])
        with self.assertRaisesRegex(facades.EvidenceError, "exactly one"):
            facades.select_lto_member(members[1:], "x86_64_cfile_facade_probe")
        with self.assertRaisesRegex(facades.EvidenceError, "exactly one"):
            facades.select_lto_member(
                [members[0], members[0].replace("0123abcd", "0123abce")],
                "x86_64_cfile_facade_probe",
            )


if __name__ == "__main__":
    unittest.main()
