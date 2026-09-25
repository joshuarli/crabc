#!/usr/bin/env python3
"""Pinned ordinary-link regressions for ``owned_static_link_authority``.

The fixture is deliberately compiled from the selected freestanding RuntimeV1
probe and attach object.  It is supplied by the focused native command rather
than fabricated ELF bytes: the normal link has no TLS contribution, while the
second normal link adds one ordinary ``__thread`` object.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
from unittest import mock


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from loader_debug_abi_evidence import Elf
from owned_static_link_authority import (
    StaticFunctionContract,
    StaticLinkAuthorityError,
    require_static_functions,
)


class OwnedStaticLinkAuthorityTlsFreeTests(unittest.TestCase):
    """Exercise real LLD outputs, not edited ELF fields or relocation tables."""

    @classmethod
    def setUpClass(cls) -> None:
        value = os.environ.get("CRABC_STATIC_LINK_AUTHORITY_FIXTURE_DIR")
        if not value:
            raise unittest.SkipTest("set CRABC_STATIC_LINK_AUTHORITY_FIXTURE_DIR to a pinned LLD fixture")
        cls.fixture = Path(value).resolve()
        cls.container_fixture = os.environ.get(
            "CRABC_STATIC_LINK_AUTHORITY_CONTAINER_FIXTURE_DIR",
            "/workspace/.work/x86_64/static-link-authority-tls-free",
        )
        for name in (
            "normal", "normal.o", "normal.map", "normal-tls", "normal-tls.map", "tls.o",
            "absent", "absent.o", "absent.map",
            "unknown-weak", "unknown-weak.o", "unknown-weak.map",
            "wrong-relocation", "wrong-relocation.o", "wrong-relocation.map",
            "tls-relocation", "tls-relocation.o", "tls-relocation.map",
            "inputs/crabc-dynamic-attach.o",
        ):
            path = cls.fixture / name
            if not path.is_file() or path.is_symlink():
                raise AssertionError(f"ordinary static-link fixture is missing: {path}")

    @property
    def attachment_owner(self) -> str:
        return self.container_fixture + "/inputs/crabc-dynamic-attach.o"

    @property
    def contracts(self) -> tuple[StaticFunctionContract, ...]:
        return self.contracts_for(self.attachment_owner)

    @staticmethod
    def contracts_for(owner: str) -> tuple[StaticFunctionContract, ...]:
        return (
            StaticFunctionContract(
                "__crabc_x86_loader_tls_runtime_v1_attach", owner,
                "GLOBAL", "DEFAULT", "GLOBAL", "DEFAULT",
            ),
            StaticFunctionContract(
                "__crabc_x86_loader_tls_runtime_v1_record", owner,
                "GLOBAL", "HIDDEN", "LOCAL", "HIDDEN",
            ),
        )

    def admitted(self, include_tls: bool = False) -> dict[str, Path]:
        admitted = {
            self.container_fixture + "/normal.o": self.fixture / "normal.o",
            self.attachment_owner: self.fixture / "inputs/crabc-dynamic-attach.o",
        }
        if include_tls:
            admitted[self.container_fixture + "/tls.o"] = self.fixture / "tls.o"
        return admitted

    @staticmethod
    def tls_rows(path: Path) -> tuple[list[tuple[int, ...]], list[tuple[int, ...]]]:
        elf = Elf(path)
        return (
            [program for program in elf.programs if program[0] == 7],
            [section for section in elf.sections if section[2] & 0x400],
        )

    @staticmethod
    def named_symbols(path: Path, name: str) -> list[dict[str, object]]:
        elf = Elf(path)
        rows = []
        for table_index, table in enumerate(elf.sections):
            if table[1] != 2:
                continue
            for number in range(table[5] // 24):
                row = elf.symbol_row(table_index, number)
                if row["name"] == name:
                    rows.append(row)
        return rows

    def test_selected_normal_static_link_without_tls_is_proved(self) -> None:
        """A selected freestanding attach link has neither TLS form nor geometry."""
        programs, sections = self.tls_rows(self.fixture / "normal")
        self.assertEqual(programs, [])
        self.assertEqual(sections, [])
        with mock.patch("subprocess.Popen", side_effect=AssertionError("static authority spawned a process")):
            require_static_functions(
                self.fixture / "normal.map", self.fixture / "normal",
                self.admitted(), self.contracts,
            )

    def test_selected_static_tls_geometry_stays_required(self) -> None:
        """A genuine selected ``__thread`` input still uses the full TLS proof."""
        programs, sections = self.tls_rows(self.fixture / "normal-tls")
        self.assertEqual(len(programs), 1)
        self.assertTrue(sections)
        require_static_functions(
            self.fixture / "normal-tls.map", self.fixture / "normal-tls",
            self.admitted(include_tls=True), self.contracts,
        )

    def test_selected_tls_input_cannot_be_verified_against_a_tls_free_output(self) -> None:
        """TLS-free admission never skips geometry for a mapped TLS contribution."""
        with self.assertRaisesRegex(StaticLinkAuthorityError, "selected TLS input"):
            require_static_functions(
                self.fixture / "normal-tls.map", self.fixture / "normal",
                self.admitted(include_tls=True), self.contracts,
            )

    def test_selected_absent_weak_descriptor_proves_its_zero_got_slot(self) -> None:
        """The exact selected weak RuntimeV1 descriptor is an initialized zero GOT target."""
        descriptor = "__crabc_x86_64_loader_tls_runtime_v1"
        expected = [{
            "name": descriptor, "type": "0", "binding": "WEAK", "visibility": "DEFAULT",
            "section": 0, "value": 0, "size": 0, "version_index": 1,
        }]
        self.assertEqual(self.named_symbols(self.fixture / "inputs/crabc-dynamic-attach.o", descriptor), expected)
        self.assertEqual(self.named_symbols(self.fixture / "absent", descriptor), expected)
        require_static_functions(
            self.fixture / "absent.map", self.fixture / "absent", {
                self.container_fixture + "/absent.o": self.fixture / "absent.o",
                self.attachment_owner: self.fixture / "inputs/crabc-dynamic-attach.o",
            }, self.contracts,
        )

    def test_unknown_weak_undefined_target_is_not_a_zero_got_fallback(self) -> None:
        """A separate ordinary weak undefined name cannot inherit descriptor treatment."""
        owner = self.container_fixture + "/unknown-weak.o"
        with self.assertRaisesRegex(StaticLinkAuthorityError, "no unique selected definition"):
            require_static_functions(
                self.fixture / "unknown-weak.map", self.fixture / "unknown-weak", {
                    owner: self.fixture / "unknown-weak.o",
                }, self.contracts_for(owner),
            )

    def test_exact_weak_descriptor_requires_gotpcrel_minus_four(self) -> None:
        """The descriptor exception remains a zero GOT slot proof, never a direct zero target."""
        owner = self.container_fixture + "/wrong-relocation.o"
        with self.assertRaisesRegex(StaticLinkAuthorityError, "exact GOTPCREL relocation"):
            require_static_functions(
                self.fixture / "wrong-relocation.map", self.fixture / "wrong-relocation", {
                    owner: self.fixture / "wrong-relocation.o",
                }, self.contracts_for(owner),
            )

    def test_tls_relocation_cannot_use_tls_free_admission(self) -> None:
        """A mapped weak TLS relocation needs geometry even without a TLS input section."""
        owner = self.container_fixture + "/tls-relocation.o"
        programs, sections = self.tls_rows(self.fixture / "tls-relocation")
        self.assertEqual(programs, [])
        self.assertEqual(sections, [])
        with self.assertRaisesRegex(StaticLinkAuthorityError, "selected TLS relocation"):
            require_static_functions(
                self.fixture / "tls-relocation.map", self.fixture / "tls-relocation", {
                    owner: self.fixture / "tls-relocation.o",
                }, self.contracts_for(owner),
            )


class OwnedStaticLinkAuthorityCrossMemberTests(unittest.TestCase):
    """A selected function may reference hidden symbols from a sibling input.

    The installed static ``libc.a`` has one member per Rust module, so a
    selected body routinely calls a hidden helper or reads a hidden TLS object
    (whose Rust-mangled name LLD's map prints demangled) from another member.
    The fixture is one ordinary LLD static link of two C objects; its build
    commands are in ``owned-static-link-authority.md``.
    """

    @classmethod
    def setUpClass(cls) -> None:
        value = os.environ.get("CRABC_STATIC_LINK_AUTHORITY_CROSS_MEMBER_FIXTURE_DIR")
        if not value:
            raise unittest.SkipTest("set CRABC_STATIC_LINK_AUTHORITY_CROSS_MEMBER_FIXTURE_DIR to the cross-member link")
        cls.fixture = Path(value).resolve()
        for name in ("cross-member", "cross-member.map", "caller.o", "callee.o"):
            path = cls.fixture / name
            if not path.is_file() or path.is_symlink():
                raise AssertionError(f"cross-member static-link fixture is missing: {path}")

    contracts = (StaticFunctionContract("selected_entry", "caller.o", "GLOBAL", "DEFAULT", "GLOBAL", "DEFAULT"),)

    def test_undefined_hidden_target_joins_its_sibling_definition(self) -> None:
        for name in ("sibling_hidden", "_RNvCs0_5crate11SIBLING_TLS"):
            caller = OwnedStaticLinkAuthorityTlsFreeTests.named_symbols(self.fixture / "caller.o", name)
            self.assertEqual([(row["section"], row["visibility"]) for row in caller], [(0, "HIDDEN")])
        # LLD's map spells the Rust-mangled TLS name demangled.
        link_map = (self.fixture / "cross-member.map").read_text()
        self.assertIn("crate::SIBLING_TLS", link_map)
        self.assertNotIn(" _RNvCs0_5crate11SIBLING_TLS\n", link_map)
        require_static_functions(self.fixture / "cross-member.map", self.fixture / "cross-member", {
            "caller.o": self.fixture / "caller.o", "callee.o": self.fixture / "callee.o",
        }, self.contracts)

    def test_hidden_target_from_an_unadmitted_sibling_is_rejected(self) -> None:
        with self.assertRaisesRegex(StaticLinkAuthorityError, "untraced input"):
            require_static_functions(self.fixture / "cross-member.map", self.fixture / "cross-member", {
                "caller.o": self.fixture / "caller.o",
            }, self.contracts)
