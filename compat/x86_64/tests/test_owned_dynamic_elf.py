#!/usr/bin/env python3
"""Final dynamic outputs are inspected before execution and rejected on drift.

These tests use a small synthetic ELF64 x86-64 image so each rejected field is
changed alone. The installed-driver tests separately inspect real LLD outputs.
"""
from __future__ import annotations

import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_dynamic_elf as elf

INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"


def build_image(*, elf_type: int = elf.ET_DYN, interpreter: str | None = INTERPRETER,
                needed=("libdep.so", "libc.so"), soname: str | None = None,
                runpath: str | None = "/usr/lib", rpath: str | None = None,
                flags: int = elf.DF_BIND_NOW, flags_1: int = elf.DF_1_NOW | elf.DF_1_PIE,
                stack_flags=(elf.PF_R | elf.PF_W,), relro: int = 1, load_flags: int = elf.PF_R,
                relocations=(8, 6), plt=(7,), extra_tags=(), tls: bool = False,
                eh_frame: bool = False, eh_frame_hdr: int = 0) -> bytes:
    """Lay out one PT_LOAD image whose virtual addresses equal file offsets."""

    strings = bytearray(b"\0")

    def string(value: str) -> int:
        offset = len(strings)
        strings.extend(value.encode() + b"\0")
        return offset

    needed_offsets = [string(name) for name in needed]
    soname_offset = string(soname) if soname is not None else None
    runpath_offset = string(runpath) if runpath is not None else None
    rpath_offset = string(rpath) if rpath is not None else None
    # symbol 1: strong import; 2: weak import; 3: definition.
    symbols = [(0, 0, 0), (string("puts"), 0x12, 0), (string("weak_hook"), 0x22, 0),
               (string("exported"), 0x12, 5)]

    phnum = 3 + (interpreter is not None) + len(stack_flags) + relro + tls + eh_frame_hdr
    cursor = 64 + 56 * phnum
    layout = {}

    def place(name: str, size: int) -> int:
        nonlocal cursor
        cursor = (cursor + 7) & ~7
        layout[name] = cursor
        cursor += size
        return layout[name]

    interp_bytes = interpreter.encode() + b"\0" if interpreter is not None else b""
    place("interp", len(interp_bytes))
    place("dynstr", len(strings))
    place("dynsym", 24 * len(symbols))
    place("hash", 4 * (2 + 1 + len(symbols)))
    place("rela", 24 * len(relocations))
    place("jmprel", 24 * len(plt))
    tags = [(elf.DT_NEEDED, offset) for offset in needed_offsets]
    if soname_offset is not None:
        tags.append((elf.DT_SONAME, soname_offset))
    if runpath_offset is not None:
        tags.append((elf.DT_RUNPATH, runpath_offset))
    if rpath_offset is not None:
        tags.append((elf.DT_RPATH, rpath_offset))
    tags += [(elf.DT_STRTAB, layout["dynstr"]), (elf.DT_STRSZ, len(strings)),
             (elf.DT_SYMTAB, layout["dynsym"]), (elf.DT_SYMENT, 24), (elf.DT_HASH, layout["hash"])]
    if relocations:
        tags += [(elf.DT_RELA, layout["rela"]), (elf.DT_RELASZ, 24 * len(relocations)),
                 (elf.DT_RELAENT, 24)]
    if plt:
        tags += [(elf.DT_JMPREL, layout["jmprel"]), (elf.DT_PLTRELSZ, 24 * len(plt)),
                 (elf.DT_PLTREL, elf.DT_RELA)]
    if flags:
        tags.append((elf.DT_FLAGS, flags))
    if flags_1:
        tags.append((elf.DT_FLAGS_1, flags_1))
    tags += list(extra_tags) + [(elf.DT_NULL, 0)]
    dynamic = place("dynamic", 16 * len(tags))
    tbss = place("tls", 16) if tls else None
    # Section names and headers: NULL, .shstrtab and, when requested, .eh_frame.
    section_names = b"\0.shstrtab\0.eh_frame\0"
    shstrtab = place("shstrtab", len(section_names))
    frames = place("eh_frame", 8)
    sections = place("sections", 64 * 3) if eh_frame else None
    image = bytearray(cursor)

    image[0:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, elf_type, elf.EM_X86_64, 1, 0x1000 if interpreter else 0,
                     64, sections or 0, 0, 64, 56, phnum, 64, 3 if eh_frame else 0, 1 if eh_frame else 0)
    if eh_frame:
        image[shstrtab:shstrtab + len(section_names)] = section_names
        struct.pack_into("<IIQQQQIIQQ", image, sections + 64, 1, 3, 0, 0, shstrtab, len(section_names), 0, 0, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", image, sections + 128, 11, 1, 2, frames, frames, 8, 0, 0, 8, 0)
    headers = [(elf.PT_LOAD, load_flags, 0, 0, len(image), len(image), 0x1000),
               (elf.PT_DYNAMIC, elf.PF_R | elf.PF_W, dynamic, dynamic, 16 * len(tags), 16 * len(tags), 8)]
    if interpreter is not None:
        headers.append((elf.PT_INTERP, elf.PF_R, layout["interp"], layout["interp"],
                        len(interp_bytes), len(interp_bytes), 1))
    headers += [(elf.PT_GNU_STACK, value, 0, 0, 0, 0, 16) for value in stack_flags]
    headers += [(elf.PT_GNU_RELRO, elf.PF_R, dynamic, dynamic, 16 * len(tags), 16 * len(tags), 1)] * relro
    if tls:
        headers.append((elf.PT_TLS, elf.PF_R, tbss, tbss, 8, 16, 8))
    headers += [(elf.PT_GNU_EH_FRAME, elf.PF_R, frames, frames, 8, 8, 4)] * eh_frame_hdr
    headers.append((0, 0, 0, 0, 0, 0, 0))  # PT_NULL keeps phnum stable for optional rows.
    for index, (kind, flag, offset, vaddr, filesz, memsz, align) in enumerate(headers[:phnum]):
        struct.pack_into("<IIQQQQQQ", image, 64 + 56 * index, kind, flag, offset, vaddr, vaddr,
                         filesz, memsz, align)
    image[layout["interp"]:layout["interp"] + len(interp_bytes)] = interp_bytes
    image[layout["dynstr"]:layout["dynstr"] + len(strings)] = strings
    for index, (name, info, section) in enumerate(symbols):
        struct.pack_into("<IBBHQQ", image, layout["dynsym"] + 24 * index, name, info, 0, section,
                         0x1000 if section else 0, 0)
    struct.pack_into("<II", image, layout["hash"], 1, len(symbols))
    for index, kind in enumerate(relocations):
        struct.pack_into("<QQq", image, layout["rela"] + 24 * index, 0x2000, (1 << 32 if kind != 8 else 0) | kind, 0)
    for index, kind in enumerate(plt):
        struct.pack_into("<QQq", image, layout["jmprel"] + 24 * index, 0x2008, (1 << 32) | kind, 0)
    for index, (tag, value) in enumerate(tags):
        struct.pack_into("<qQ", image, dynamic + 16 * index, tag, value)
    return bytes(image)


def expectation(**changes) -> elf.Expectation:
    values = dict(mode="pie", interpreter=INTERPRETER, needed=("libdep.so", "libc.so"), soname=None,
                  search_kind="runpath", search_path="/usr/lib", binding="now", hash_style="sysv",
                  runtime_imports=frozenset(), provided_symbols=frozenset({"puts"}))
    values.update(changes)
    return elf.Expectation(**values)


class FinalElfInspectionTests(unittest.TestCase):
    def setUp(self):
        temporary_root = ROOT / ".work/x86_64/tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def check(self, data: bytes, expected: elf.Expectation) -> dict:
        facts = elf.inspect(self.write("output", data))
        elf.require_expected(facts, expected)
        return facts

    def test_declared_pie_executable_records_all_inspected_facts(self):
        facts = self.check(build_image(), expectation())
        self.assertEqual(facts["interpreter"], INTERPRETER)
        self.assertEqual(facts["needed"], ["libdep.so", "libc.so"])
        self.assertEqual(facts["runpath"], "/usr/lib")
        self.assertEqual(facts["relocations"], {"R_X86_64_GLOB_DAT": 1, "R_X86_64_JUMP_SLOT": 1,
                                                "R_X86_64_RELATIVE": 1})
        self.assertEqual(facts["undefined_symbols"], ["puts"])
        self.assertEqual(facts["weak_undefined_symbols"], ["weak_hook"])
        self.assertEqual(facts["gnu_stack_flags"], [elf.PF_R | elf.PF_W])
        self.assertEqual((facts["relro_segments"], facts["tls"]), (1, None))

    def test_shared_object_and_non_pie_executable_have_their_own_shape(self):
        shared = build_image(interpreter=None, soname="libplugin.so", flags_1=elf.DF_1_NOW, tls=True)
        facts = self.check(shared, expectation(mode="shared", soname="libplugin.so"))
        self.assertEqual(facts["tls"], {"filesz": 8, "memsz": 16, "align": 8})
        self.check(build_image(elf_type=elf.ET_EXEC, flags_1=elf.DF_1_NOW, relocations=(8, 6, 5)),
                   expectation(mode="exec"))

    def test_interpreter_drift_is_rejected_for_each_mode(self):
        cases = (
            (build_image(interpreter=None), expectation(), "interpreter"),
            (build_image(interpreter="/lib/ld-musl-x86_64.so.1"), expectation(), "interpreter"),
            (build_image(soname="libplugin.so", flags_1=elf.DF_1_NOW),
             expectation(mode="shared", soname="libplugin.so"), "shared object has an interpreter"),
            (build_image(), expectation(mode="exec"), "ET_EXEC"),
        )
        for data, expected, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(elf.InspectionError, message):
                self.check(data, expected)

    def test_stack_relro_and_writable_code_are_rejected(self):
        cases = (
            (build_image(stack_flags=(elf.PF_R | elf.PF_W | elf.PF_X,)), "non-executable GNU_STACK"),
            (build_image(stack_flags=()), "non-executable GNU_STACK"),
            (build_image(relro=0), "PT_GNU_RELRO"),
            (build_image(load_flags=elf.PF_R | elf.PF_W | elf.PF_X), "writable executable"),
        )
        for data, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(elf.InspectionError, message):
                self.check(data, expectation())

    def test_eh_frame_requires_exactly_one_eh_frame_header_segment(self):
        """dl_iterate_phdr unwinders find a module's FDEs only through PT_GNU_EH_FRAME."""

        facts = self.check(build_image(eh_frame=True, eh_frame_hdr=1), expectation())
        self.assertEqual((facts["eh_frame"], facts["eh_frame_hdr_segments"]), (True, 1))
        facts = self.check(build_image(), expectation())
        self.assertEqual((facts["eh_frame"], facts["eh_frame_hdr_segments"]), (False, 0))
        for data, message in (
            (build_image(eh_frame=True), "lacks exactly one PT_GNU_EH_FRAME"),
            (build_image(eh_frame=True, eh_frame_hdr=2), "lacks exactly one PT_GNU_EH_FRAME"),
            (build_image(eh_frame_hdr=1), "without .eh_frame has a PT_GNU_EH_FRAME"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(elf.InspectionError, message):
                self.check(data, expectation())

    def test_dependency_search_binding_and_hash_drift_are_rejected(self):
        cases = (
            (build_image(needed=("libc.so",)), expectation(), "DT_NEEDED"),
            (build_image(needed=("libc.so", "libdep.so")), expectation(), "DT_NEEDED"),
            (build_image(runpath=None, rpath="/usr/lib"), expectation(), "search path"),
            (build_image(runpath="/foreign"), expectation(), "search path"),
            (build_image(flags=0, flags_1=elf.DF_1_PIE), expectation(), "binding"),
            (build_image(), expectation(binding="lazy"), "binding"),
            (build_image(), expectation(hash_style="gnu"), "hash"),
            (build_image(flags_1=elf.DF_1_NOW), expectation(), "DF_1_PIE"),
            (build_image(soname="libstray.so"), expectation(), "DT_SONAME"),
        )
        for data, expected, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(elf.InspectionError, message):
                self.check(data, expected)

    def test_text_relocations_versions_and_unadmitted_relocations_are_rejected(self):
        cases = (
            (build_image(extra_tags=((elf.DT_TEXTREL, 0),)), "text relocations"),
            (build_image(flags=elf.DF_BIND_NOW | elf.DF_TEXTREL), "text relocations"),
            (build_image(extra_tags=((elf.DT_VERSYM, 0x40),)), "versioning"),
            (build_image(relocations=(8, 36)), "unadmitted dynamic relocation kind 36"),
            (build_image(relocations=(37,)), "unadmitted dynamic relocation kind 37"),
            (build_image(plt=(6,)), "non-JUMP_SLOT"),
            (build_image(extra_tags=((elf.DT_REL, 0x40),)), "REL relocations"),
        )
        for data, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(elf.InspectionError, message):
                self.check(data, expectation())
        with self.assertRaisesRegex(elf.InspectionError, "COPY"):
            self.check(build_image(interpreter=None, soname="libplugin.so", flags_1=elf.DF_1_NOW,
                                   relocations=(5,)), expectation(mode="shared", soname="libplugin.so"))

    def test_undeclared_unresolved_imports_are_rejected_and_declared_ones_admitted(self):
        with self.assertRaisesRegex(elf.InspectionError, r"unresolved.*puts"):
            self.check(build_image(), expectation(provided_symbols=frozenset()))
        self.check(build_image(), expectation(provided_symbols=frozenset(),
                                              runtime_imports=frozenset({"puts"})))

    def test_truncated_or_foreign_images_fail_as_inspection_errors(self):
        valid = build_image()
        for data in (valid[:40], b"\x7fELF\x01" + valid[5:], valid[:18] + b"\x03\x00" + valid[20:],
                     valid[:200]):
            with self.subTest(size=len(data)), self.assertRaises(elf.InspectionError):
                elf.inspect(self.write("foreign", data))

    def test_sidecar_replay_binds_output_map_and_recorded_mount(self):
        output = self.write("consumer", build_image())
        _, link_map = elf.sidecar_paths(output)
        link_map.write_text("map\n")
        expected = expectation()
        facts = elf.inspect(output)
        value = elf.record(output, facts, expected, output_format=FORMAT, link_map=link_map)
        mount = lambda local: "/workspace/" + local.name
        value["output_path"], value["link_map"]["path"] = mount(output), mount(link_map)
        value = json.loads(json.dumps(value))

        def fail(message: str) -> None:
            raise ValueError(message)

        self.assertEqual(elf.validate_record(value, output, output_format=FORMAT, fail=fail,
                                             recorded_path=mount), facts)
        with self.assertRaisesRegex(ValueError, "differs"):
            elf.validate_record(value, output, output_format=FORMAT, fail=fail)
        link_map.write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "differs"):
            elf.validate_record(value, output, output_format=FORMAT, fail=fail, recorded_path=mount)
        link_map.write_text("map\n")
        forged = json.loads(json.dumps(value))
        forged["declared"]["needed"] = ["libc.so"]
        with self.assertRaisesRegex(ValueError, "does not replay"):
            elf.validate_record(forged, output, output_format=FORMAT, fail=fail, recorded_path=mount)
        output.write_bytes(build_image(runpath="/foreign"))
        with self.assertRaisesRegex(ValueError, "retained output"):
            elf.validate_record(value, output, output_format=FORMAT, fail=fail, recorded_path=mount)


if __name__ == "__main__":
    unittest.main()
