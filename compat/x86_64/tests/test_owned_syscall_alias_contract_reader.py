#!/usr/bin/env python3
"""Regression coverage for exact ELF syscall alias identity checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from owned_syscall_alias_contract_reader import (
    PUBLIC_ALIAS_SOURCE_CALLERS,
    SymbolRow,
    require_same_probe_object,
    same_definition,
)


class OwnedSyscallAliasContractReaderTests(unittest.TestCase):
    def test_oracle_source_recompile_cannot_pass_same_object_evidence(self) -> None:
        object_path = "/workspace/.work/probe/contract.o"
        commands = {
            f"{prefix}-contract-link": ["cc", object_path, "-o", f"/out/{prefix}"]
            for prefix in (
                "oracle", "oracle-dynamic-pie", "oracle-dynamic-non-pie",
                "static", "static-pie", "dynamic-pie", "dynamic-non-pie",
            )
        }
        require_same_probe_object("contract", object_path, commands)
        for replacement in ("/source/contract.c", "/elsewhere/contract.o"):
            with self.subTest(replacement=replacement):
                changed = dict(commands)
                changed["oracle-contract-link"] = ["cc", replacement, "-o", "/out/oracle"]
                with self.assertRaisesRegex(ValueError, "same compiled probe object"):
                    require_same_probe_object("contract", object_path, changed)
        commands.pop("oracle-dynamic-non-pie-contract-link")
        with self.assertRaisesRegex(ValueError, "incomplete or additional probe links"):
            require_same_probe_object("contract", object_path, commands)

    def test_same_member_zero_value_different_sections_is_not_an_alias(self) -> None:
        alias = SymbolRow(
            member="clock_gettime.o",
            value="0000000000000000",
            symbol_type="FUNC",
            binding="WEAK",
            visibility="DEFAULT",
            section="17",
            name="clock_gettime",
        )
        forwarding_body = alias._replace(
            binding="GLOBAL",
            section="18",
            name="__clock_gettime",
        )

        self.assertFalse(same_definition(alias, forwarding_body))

    def test_public_source_caller_roster_includes_both_sigset_branches(self) -> None:
        self.assertEqual(
            PUBLIC_ALIAS_SOURCE_CALLERS,
            (
                ("__fxstat", "fstat"),
                ("__fxstatat", "fstatat"),
                ("ftime", "clock_gettime"),
                ("getloadavg", "sysinfo"),
                ("sigignore", "sigaction"),
                ("siginterrupt", "sigaction"),
                ("sigset", "sigaction"),
            ),
        )


    def test_static_call_displacement_cannot_be_resealed(self) -> None:
        path = self.runner / "static-contract"
        elf = authority.Elf(path)
        main = elf.symbol("main", dynamic=False)
        section = elf.sections[main["section"]]
        offset = section[4] + main["value"] - section[3] + 72
        data = bytearray(path.read_bytes())
        data[offset] ^= 1
        path.write_bytes(data)
        sidecar = self.runner / "static-contract.link.json"
        record = json.loads(sidecar.read_text())
        record["output"]["sha256"] = hashlib.sha256(data).hexdigest()
        sidecar.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_static_tls_displacement_cannot_be_resealed(self) -> None:
        path = self.runner / "static-contract"
        elf = authority.Elf(path)
        symbol = elf.symbol("clock_gettime", dynamic=False)
        section = elf.sections[symbol["section"]]
        offset = section[4] + symbol["value"] - section[3] + 23
        data = bytearray(path.read_bytes())
        data[offset] ^= 1
        path.write_bytes(data)
        sidecar = self.runner / "static-contract.link.json"
        record = json.loads(sidecar.read_text())
        record["output"]["sha256"] = hashlib.sha256(data).hexdigest()
        sidecar.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def assert_resealed_static_mutation_rejected(self, stem, mutate) -> None:
        path = self.runner / stem
        sidecar = self.runner / (stem + ".link.json")
        original, original_receipt = path.read_bytes(), sidecar.read_bytes()
        try:
            data = bytearray(original)
            mutate(data, authority.Elf(path))
            path.write_bytes(data)
            record = json.loads(original_receipt)
            record["output"]["sha256"] = hashlib.sha256(data).hexdigest()
            sidecar.write_text(json.dumps(record))
            with self.assertRaises(ReceiptError):
                validate_report(self.path)
        finally:
            path.write_bytes(original)
            sidecar.write_bytes(original_receipt)

    def test_each_observed_static_relocation_form_rejects_resealed_displacement(self) -> None:
        for mode in ("static", "static-pie"):
            for probe in ("contract", "override"):
                sites = [(4, "_start", 13 if mode == "static" else 1241)]
                sites += ([(2, "main", 697), (9, "clock_nanosleep", 274), (22, "clock_gettime", 23)]
                          if probe == "contract" else [(2, "clock_gettime", 17), (42, "sigaction", 92)])
                for kind, name, relative in sites:
                    with self.subTest(mode=mode, probe=probe, kind=kind):
                        def mutate(data, elf):
                            symbol = elf.symbol(name, dynamic=False)
                            section = elf.sections[symbol["section"]]
                            offset = section[4] + symbol["value"] - section[3] + relative
                            data[offset] ^= 1
                        self.assert_resealed_static_mutation_rejected(f"{mode}-{probe}", mutate)

    def test_static_relaxation_opcode_is_derived_with_its_displacement(self) -> None:
        for mode in ("static", "static-pie"):
            for probe, name, relative, opcode in (("contract", "clock_gettime", 23, 0x8d),
                                                   ("override", "sigaction", 92, 0x8b)):
                with self.subTest(mode=mode, probe=probe):
                    def mutate(data, elf):
                        symbol = elf.symbol(name, dynamic=False)
                        section = elf.sections[symbol["section"]]
                        offset = section[4] + symbol["value"] - section[3] + relative - 2
                        data[offset] = opcode
                    self.assert_resealed_static_mutation_rejected(f"{mode}-{probe}", mutate)

    def test_static_got_displacement_requires_the_selected_target_value(self) -> None:
        for mode in ("static", "static-pie"):
            with self.subTest(mode=mode):
                def mutate(data, elf):
                    symbol = elf.symbol("clock_nanosleep", dynamic=False)
                    section = elf.sections[symbol["section"]]
                    field = section[4] + symbol["value"] - section[3] + 274
                    slot = symbol["value"] + 274 + 4 + int.from_bytes(data[field:field + 4], "little", signed=True)
                    if mode == "static":
                        got = next(s for s in elf.sections if authority.section_name(elf, s) == ".got")
                        data[got[4] + slot - got[3]] ^= 1
                    else:
                        offsets = [section[4] + offset + 16 for section in elf.sections if section[1] == 4
                                   for offset in range(0, section[5], 24)
                                   if elf.unpack("<Q", section[4] + offset)[0] == slot]
                        self.assertEqual(len(offsets), 1)
                        data[offsets[0]] ^= 1
                self.assert_resealed_static_mutation_rejected(f"{mode}-contract", mutate)

    def test_static_tls_geometry_cannot_be_resealed(self) -> None:
        for mode in ("static", "static-pie"):
            with self.subTest(mode=mode):
                def mutate(data, elf):
                    index = next(i for i, program in enumerate(elf.programs) if program[0] == 7)
                    offset = elf.unpack("<Q", 32)[0] + index * 56 + 40
                    value = elf.unpack("<Q", offset)[0]
                    data[offset:offset + 8] = (value + 8).to_bytes(8, "little")
                self.assert_resealed_static_mutation_rejected(f"{mode}-contract", mutate)


if __name__ == "__main__":
    unittest.main()
