"""Real-object regressions for the finite pthread dynamic function relation.

Set CRABC_PTHREAD_DYNAMIC_AUTHORITY_FIXTURE to a retained directory containing
contract.o and both owned dynamic outputs. No compiler, linker or ELF command
is invoked by these tests. Scratch copies remain beneath this checkout .work.
"""
from pathlib import Path
import os
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_pthread_timed_dynamic_authority as authority
from loader_debug_abi_evidence import Elf


class PthreadTimedDynamicAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get("CRABC_PTHREAD_DYNAMIC_AUTHORITY_FIXTURE")
        if not value:
            raise unittest.SkipTest("requires retained pthread dynamic authority fixture")
        cls.fixture = Path(value).resolve(strict=True)
        cls.scratch = ROOT / ".work/x86_64/pthread-dynamic-authority-tests"
        cls.scratch.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=self.scratch)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        for name in ("contract.o", "dynamic-pie-contract", "dynamic-non-pie-contract"):
            shutil.copy2(self.fixture / name, self.work / name)

    def reject(self, binary, mutation, *, source=False, message=None):
        target = self.work / ("contract.o" if source else binary)
        original = target.read_bytes()
        elf = Elf(target)
        data = bytearray(original)
        mutation(elf, data)
        self.assertNotEqual(bytes(data), original)
        target.write_bytes(data)
        try:
            with self.assertRaisesRegex(authority.PthreadTimedDynamicAuthorityError, message or "."):
                authority.require_pthread_timed_probe_functions(self.work / "contract.o", self.work / binary)
        finally:
            target.write_bytes(original)

    def test_both_ordinary_dynamic_modes_replay_without_processes(self):
        with mock.patch("subprocess.Popen", side_effect=AssertionError("authority spawned a process")):
            for binary in ("dynamic-pie-contract", "dynamic-non-pie-contract"):
                authority.require_pthread_timed_probe_functions(self.work / "contract.o", self.work / binary)

    def test_every_probe_function_rejects_a_final_immediate_success_body(self):
        for binary in ("dynamic-pie-contract", "dynamic-non-pie-contract"):
            for name in authority.FUNCTIONS:
                def mutate(elf, data):
                    row = elf.symbol(name, dynamic=False)
                    section = elf.sections[row["section"]]
                    offset = section[4] + row["value"] - section[3]
                    data[offset:offset + 3] = b"\x31\xc0\xc3"
                with self.subTest(binary=binary, function=name):
                    self.reject(binary, mutate, message="function bytes differ")

    def test_pc32_data_and_plt32_call_displacements_are_not_masks(self):
        source = Elf(self.work / "contract.o")
        rela = authority.sections(source)[".rela.text"][1]
        positions = []
        for offset in range(0, rela[5], 24):
            position, info, _addend = source.unpack("<QQq", rela[4] + offset)
            positions.append((info & 0xffffffff, position))
        self.assertEqual({kind for kind, _ in positions}, {2, 4})
        for binary in ("dynamic-pie-contract", "dynamic-non-pie-contract"):
            for kind, position in positions:
                def mutate(elf, data):
                    row = elf.symbol("main", dynamic=False)
                    section = elf.sections[row["section"]]
                    base = row["value"] - source.symbol("main", dynamic=False)["value"]
                    offset = section[4] + base - section[3] + position
                    data[offset] ^= 1
                with self.subTest(binary=binary, relocation=kind, position=position):
                    self.reject(binary, mutate, message="function bytes differ")

    def test_plt_instruction_got_initial_target_and_jump_slot_identity_are_derived(self):
        for binary in ("dynamic-pie-contract", "dynamic-non-pie-contract"):
            for role in ("plt-displacement", "plt-ordinal", "got-target", "jump-slot-symbol", "jump-slot-destination"):
                def mutate(elf, data):
                    table = authority.sections(elf)
                    if role.startswith("plt-"):
                        offset = table[".plt"][1][4] + 16 + (2 if role == "plt-displacement" else 7)
                        data[offset] ^= 1
                    elif role == "got-target":
                        data[table[".got.plt"][1][4] + 24] ^= 1
                    else:
                        offset = table[".rela.plt"][1][4]
                        if role == "jump-slot-symbol":
                            struct.pack_into("<Q", data, offset + 8, elf.unpack("<Q", offset + 32)[0])
                        else:
                            struct.pack_into("<Q", data, offset, elf.unpack("<Q", offset)[0] + 8)
                with self.subTest(binary=binary, field=role):
                    self.reject(binary, mutate)

    def test_each_local_data_object_must_keep_the_selected_relative_geometry(self):
        for binary in ("dynamic-pie-contract", "dynamic-non-pie-contract"):
            for name in authority.OBJECTS:
                def mutate(elf, data):
                    index, table = authority.sections(elf)[".symtab"]
                    for number in range(table[5] // 24):
                        row = elf.symbol_row(index, number)
                        if row["name"] == name:
                            struct.pack_into("<Q", data, table[4] + number * 24 + 8, row["value"] + 4)
                            return
                    self.fail("fixture local object absent")
                with self.subTest(binary=binary, object=name):
                    self.reject(binary, mutate, message="data contribution differs")

    def test_constant_bytes_and_runtime_data_relocation_are_not_self_asserted(self):
        for binary in ("dynamic-pie-contract", "dynamic-non-pie-contract"):
            for role in ("constant", "runtime-relocation"):
                def mutate(elf, data):
                    table = authority.sections(elf)
                    if role == "constant":
                        data[table[".rodata"][1][4]] ^= 1
                    else:
                        struct.pack_into("<Q", data, table[".rela.dyn"][1][4],
                                         elf.symbol("force_spurious", dynamic=False)["value"])
                with self.subTest(binary=binary, field=role):
                    self.reject(binary, mutate)

    def test_dynamic_table_cannot_redirect_plt_relocation_input(self):
        for binary in ("dynamic-pie-contract", "dynamic-non-pie-contract"):
            def mutate(elf, data):
                section = authority.sections(elf)[".dynamic"][1]
                for offset in range(0, section[5], 16):
                    tag, value = elf.unpack("<QQ", section[4] + offset)
                    if tag == 23:
                        struct.pack_into("<Q", data, section[4] + offset + 8, value + 24)
                        return
                self.fail("fixture DT_JMPREL absent")
            self.reject(binary, mutate, message="dynamic PLT/symbol-table route differs")

    def test_source_relocation_kind_cannot_silently_extend_the_contract(self):
        def mutate(elf, data):
            rela = authority.sections(elf)[".rela.text"][1]
            info = elf.unpack("<Q", rela[4] + 8)[0]
            struct.pack_into("<Q", data, rela[4] + 8, (info & ~0xffffffff) | 1)
        self.reject("dynamic-pie-contract", mutate, source=True, message="unclassified probe relocation kind")

    def test_program_mapping_permissions_and_file_offset_are_part_of_the_relation(self):
        for binary in ("dynamic-pie-contract", "dynamic-non-pie-contract"):
            for role in ("permissions", "file-offset", "overlapping-load", "dynamic-program"):
                def mutate(elf, data):
                    phoff = elf.unpack("<Q", 32)[0]
                    text = authority.sections(elf)[".text"][1]
                    for number, program in enumerate(elf.programs):
                        if role == "dynamic-program" and program[0] == 2:
                            struct.pack_into("<Q", data, phoff + number * 56 + 16, program[3] + 16)
                            return
                        if role == "overlapping-load" and program[0] == 1 and program[1] == 4:
                            struct.pack_into("<Q", data, phoff + number * 56 + 40, text[3] + 1 - program[3])
                            return
                        if role in ("overlapping-load", "dynamic-program"):
                            continue
                        if program[0] == 1 and program[3] <= text[3] < program[3] + program[6]:
                            if role == "permissions":
                                struct.pack_into("<I", data, phoff + number * 56 + 4, 4)
                            else:
                                struct.pack_into("<Q", data, phoff + number * 56 + 8, program[2] + 1)
                            return
                    self.fail("fixture executable load absent")
                with self.subTest(binary=binary, field=role):
                    self.reject(binary, mutate)

    def test_physical_source_and_final_paths_are_required(self):
        link = self.work / "linked-output"
        link.symlink_to("dynamic-pie-contract")
        with self.assertRaisesRegex(authority.PthreadTimedDynamicAuthorityError, "symlink"):
            authority.require_pthread_timed_probe_functions(self.work / "contract.o", link)
