#!/usr/bin/env python3
"""Pinned ordinary-link regressions for ``owned_static_link_authority``.

The freestanding RuntimeV1 fixture supplies real normal and TLS links. The
merged-constant fixture supplies a selected archive member and its LLD output;
negative cases alter copies of those physical ELF bytes.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
from unittest import mock


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from loader_debug_abi_evidence import Elf
from owned_syscall_alias_authority import archive_members, require_static_function_map
from owned_syscall_alias_contract_reader import ALIASES
from owned_static_link_authority import (
    StaticFunctionContract,
    StaticLinkAuthorityError,
    elf_bytes,
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
    The fixture is one ordinary LLD static link of two C objects.
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


class OwnedStaticLinkAuthorityMergedConstantTests(unittest.TestCase):
    """Replay the selected Rust archive member and ordinary LLD output."""

    TARGET_NAME = "anon.5030fea0625ac61d73023183e6bb3b4b.0.llvm.11517783602700916499"
    TARGET_MEMBER = "c.c.a4bf00fba12b58d3-cgu.0220.rcgu.o"

    @classmethod
    def setUpClass(cls) -> None:
        runner = os.environ.get("CRABC_STATIC_LINK_AUTHORITY_SYSCALL_RUNNER")
        product = os.environ.get("CRABC_STATIC_LINK_AUTHORITY_STATIC_PRODUCT")
        if not runner or not product:
            raise unittest.SkipTest("set the selected syscall runner and static product fixture paths")
        cls.runner, cls.product = Path(runner).resolve(), Path(product).resolve()
        cls.binary = cls.runner / "static-contract"
        cls.map = cls.runner / "static-contract.link.map"
        cls.archive = cls.product / "usr/lib/libc.a"
        cls.archive_owner = str(cls.archive) + "(" + cls.TARGET_MEMBER + ")"
        archives = {
            str(cls.archive): dict(archive_members(cls.archive.read_bytes())),
            str(cls.product / "usr/lib/libcrabc-builtins.a"):
                dict(archive_members((cls.product / "usr/lib/libcrabc-builtins.a").read_bytes())),
        }
        cls.admitted = {}
        for line in (cls.runner / "static-contract.link.trace").read_text().splitlines():
            if line in archives:
                continue
            matches = [(path, line[len(path) + 1:-1]) for path in archives
                       if line.startswith(path + "(") and line.endswith(")")]
            if matches:
                cls.admitted[line] = archives[matches[0][0]][matches[0][1]]
            else:
                cls.admitted[line] = Path(line)
        if cls.archive_owner not in cls.admitted:
            raise AssertionError("selected merged constant member is absent from the link trace")
        cls.scratch = SOURCE_DIR.parents[1] / ".work/x86_64/static-link-authority-merged"
        cls.scratch.mkdir(parents=True, exist_ok=True)

    @classmethod
    def symbol_location(cls, data: bytes, name: str) -> tuple[int, dict[str, object]]:
        elf = elf_bytes(data)
        found = []
        for index, table in enumerate(elf.sections):
            if table[1] == 2:
                for number in range(table[5] // 24):
                    row = elf.symbol_row(index, number)
                    if row["name"] == name:
                        found.append((table[4] + number * 24, row))
        if len(found) != 1:
            raise AssertionError("selected ELF has no unique merged constant symbol")
        return found[0]

    def prove(self, admitted=None, binary=None) -> None:
        require_static_function_map(
            self.map, self.binary if binary is None else binary,
            self.admitted if admitted is None else admitted,
            str(self.runner / "contract.o"), str(self.product / "usr/lib/crt1.o"),
            str(self.archive), [name for name, _body in ALIASES], False,
        )

    def test_selected_global_hidden_merged_constant_has_one_source_and_final_place(self) -> None:
        source = self.admitted[self.archive_owner]
        _position, before = self.symbol_location(source, self.TARGET_NAME)
        _position, after = self.symbol_location(self.binary.read_bytes(), self.TARGET_NAME)
        self.assertEqual((before["type"], before["binding"], before["visibility"], before["size"]),
                         ("OBJECT", "GLOBAL", "HIDDEN", 8))
        self.assertEqual((after["type"], after["binding"], after["visibility"], after["size"]),
                         ("OBJECT", "LOCAL", "HIDDEN", 8))
        self.prove()

    def test_other_source_bindings_and_visibility_still_reject(self) -> None:
        position, _symbol = self.symbol_location(self.admitted[self.archive_owner], self.TARGET_NAME)
        for info, visibility in ((0x21, 2), (0x11, 0), (0x11, 3)):
            with self.subTest(info=info, visibility=visibility):
                changed = bytearray(self.admitted[self.archive_owner])
                changed[position + 4] = info
                changed[position + 5] = visibility
                admitted = {**self.admitted, self.archive_owner: bytes(changed)}
                with self.assertRaisesRegex(ValueError, "unclassified merged static relocation target"):
                    self.prove(admitted=admitted)

    def test_final_symbol_cannot_claim_a_forged_constant_position(self) -> None:
        position, _symbol = self.symbol_location(self.binary.read_bytes(), self.TARGET_NAME)
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            changed = bytearray(self.binary.read_bytes())
            struct.pack_into("<Q", changed, position + 8, struct.unpack_from("<Q", changed, position + 8)[0] + 8)
            binary = Path(directory) / "static-contract"
            binary.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "merged static target final symbol placement differs"):
                self.prove(binary=binary)

    def test_source_position_and_bytes_must_match_the_selected_constant(self) -> None:
        original = self.admitted[self.archive_owner]
        position, symbol = self.symbol_location(original, self.TARGET_NAME)
        misplaced = bytearray(original)
        struct.pack_into("<Q", misplaced, position + 8, symbol["value"] + 8)
        with self.assertRaisesRegex(ValueError, "unclassified merged static relocation target"):
            self.prove(admitted={**self.admitted, self.archive_owner: bytes(misplaced)})
        source = elf_bytes(original)
        changed = bytearray(original)
        changed[source.sections[symbol["section"]][4] + symbol["value"]] ^= 1
        with self.assertRaisesRegex(ValueError, "merged static target lacks its unique selected constant"):
            self.prove(admitted={**self.admitted, self.archive_owner: bytes(changed)})

    def test_duplicate_final_constant_cannot_choose_a_second_position(self) -> None:
        line = next(line for line in self.map.read_text().splitlines()
                    if "<internal>:(.rodata.cst8)" in line)
        match = re.fullmatch(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\d+\s+<internal>:\(\.rodata\.cst8\)", line)
        self.assertIsNotNone(match)
        base, extent = (int(value, 16) for value in match.groups())
        self.assertEqual(extent, 16)
        _position, symbol = self.symbol_location(self.binary.read_bytes(), self.TARGET_NAME)
        other = base + 8 if symbol["value"] == base else base
        final = Elf(self.binary)
        rodata = next(section for section in final.sections if section[3] <= other < section[3] + section[5]
                      and section[2] & 2)
        source = elf_bytes(self.admitted[self.archive_owner])
        _position, target = self.symbol_location(self.admitted[self.archive_owner], self.TARGET_NAME)
        source_section = source.sections[target["section"]]
        constant = source.data[source_section[4] + target["value"]:
                               source_section[4] + target["value"] + target["size"]]
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            changed = bytearray(self.binary.read_bytes())
            offset = rodata[4] + other - rodata[3]
            changed[offset:offset + len(constant)] = constant
            binary = Path(directory) / "static-contract"
            binary.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "merged static target lacks its unique selected constant"):
                self.prove(binary=binary)
