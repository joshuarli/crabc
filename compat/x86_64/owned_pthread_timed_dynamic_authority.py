"""Bind the finite pthread timed probe object to its ordinary dynamic image.

The component reader owns source, compiler, product, link receipt and mode
admission. This proof covers the eleven probe functions, their twelve local
zero-initialized objects and one string. It admits only the observed x86-64
PC32 data references and PLT32 calls through the ordinary LLD PLT. No output
instruction or relocation field is ignored or copied into the expected bytes.
"""
from __future__ import annotations

from pathlib import Path
import struct

from loader_debug_abi_evidence import Elf


class PthreadTimedDynamicAuthorityError(ValueError):
    pass


FUNCTIONS = (
    "deadline_after", "wait_ready", "mutex_holder", "test_mutex_timedlock",
    "first_spurious_timedwait", "signaler", "test_condition_timedwait",
    "target", "cancelable_joiner", "test_join_modes", "main",
)
OBJECTS = (
    "timed_mutex", "mutex_locked", "mutex_release", "condition_mutex",
    "condition", "signaler_ready", "force_spurious", "spurious_while_held",
    "target_ready", "target_release", "cancel_target", "joiner_ready",
)
IMPORTS = (
    "clock_gettime", "__errno_location", "sched_yield", "pthread_mutex_lock",
    "pthread_mutex_unlock", "pthread_mutex_init", "pthread_create",
    "pthread_mutex_timedlock", "pthread_join", "pthread_mutex_destroy",
    "pthread_mutex_trylock", "pthread_cond_timedwait", "pthread_cond_signal",
    "pthread_cond_init", "pthread_cond_destroy", "pthread_timedjoin_np",
    "pthread_tryjoin_np", "pthread_cancel", "puts",
)


def require(condition, message):
    if not condition:
        raise PthreadTimedDynamicAuthorityError(message)


def physical(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "unsafe probe authority path")
    require(all(not node.is_symlink() for node in (path, *path.parents)),
            "probe authority traverses a symlink")
    require(path.is_file(), "probe authority input is not a file")
    return path


def sections(elf):
    table = elf.sections[elf.unpack("<H", 62)[0]]
    require(table[1] == 3 and table[4] + table[5] <= len(elf.data), "invalid section names")
    result = {}
    for index, section in enumerate(elf.sections):
        start = table[4] + section[0]
        end = elf.data.find(b"\0", start, table[4] + table[5])
        require(table[4] <= start <= end < table[4] + table[5], "invalid section name")
        name = elf.data[start:end].decode("ascii")
        require(name not in result, "duplicate named ELF section")
        if section[1] != 8:
            require(section[4] + section[5] <= len(elf.data), "truncated ELF section")
        result[name] = (index, section)
    return result


def symbols(elf, index):
    table = elf.sections[index]
    require(table[1] in (2, 11) and table[9] == 24 and table[5] % 24 == 0,
            "invalid probe symbol table")
    return [elf.symbol_row(index, number) for number in range(table[5] // 24)]


def named(rows, names):
    result = {}
    for row in rows:
        if row["name"] in names and row["section"]:
            require(row["name"] not in result, "duplicate probe definition")
            result[row["name"]] = row
    require(set(result) == set(names), "missing probe definition")
    return result


def mapped(elf, section, flags, *, zero=False):
    require(section[5] > 0, "empty probe mapping")
    start, end = section[3], section[3] + section[5]
    loads = [p for p in elf.programs if p[0] == 1 and p[3] < end and start < p[3] + p[6]]
    require(len(loads) == 1 and loads[0][1] == flags
            and loads[0][3] <= start and end <= loads[0][3] + loads[0][6],
            "probe mapping permissions or overlapping loads differ")
    load = loads[0]
    require(load[5] <= load[6] and load[2] + load[5] <= len(elf.data), "truncated probe load")
    if zero:
        require(section[1] == 8 and start >= load[3] + load[5], "probe data is not zero initialized")
    else:
        require(end <= load[3] + load[5] and section[4] == load[2] + start - load[3],
                "probe section differs from loaded bytes")


def i32(value):
    require(-(1 << 31) <= value < 1 << 31, "probe displacement is out of range")
    return struct.pack("<i", value)


def plt_imports(final, table):
    """Derive import call addresses from complete ordinary LLD PLT/GOT records."""
    _, plt = table[".plt"]
    _, got = table[".got.plt"]
    _, rela = table[".rela.plt"]
    _, dynamic = table[".dynamic"]
    dynsym_index, dynsym = table[".dynsym"]
    _, dynstr = table[".dynstr"]
    require(plt[1:3] == (1, 6) and plt[8:] == (16, 0)
            and got[1:3] == (1, 3) and got[8:] == (8, 0), "unclassified PLT/GOT sections")
    mapped(final, plt, 5)
    mapped(final, got, 6)
    require(rela[1:3] == (4, 66) and rela[6] == dynsym_index
            and rela[9] == 24 and rela[5] % 24 == 0, "unclassified PLT relocations")
    mapped(final, rela, 4)
    require(dynamic[1:3] == (6, 3) and dynamic[9] == 16 and dynamic[5] % 16 == 0,
            "invalid dynamic table")
    mapped(final, dynamic, 6)
    program_dynamic = [p for p in final.programs if p[0] == 2]
    require(len(program_dynamic) == 1 and program_dynamic[0][1] == 6
            and (program_dynamic[0][2], program_dynamic[0][3], program_dynamic[0][5], program_dynamic[0][6])
                == (dynamic[4], dynamic[3], dynamic[5], dynamic[5]), "loaded dynamic table differs")
    entries = [final.unpack("<QQ", dynamic[4] + offset) for offset in range(0, dynamic[5], 16)]
    require(entries[-1] == (0, 0) and all(tag != 0 for tag, _ in entries[:-1]),
            "dynamic table termination differs")
    tags = {}
    for tag, value in entries[:-1]:
        require(tag not in tags, "duplicate dynamic tag")
        tags[tag] = value
    expected_tags = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 20, 21, 23, 29, 30, 0x6ffffffb}
    if final.elf_type == 3:
        expected_tags.add(0x6ffffff9)
    require(set(tags) == expected_tags, "unclassified ordinary dynamic tags")
    for tag, value in ((23, rela[3]), (2, rela[5]), (3, got[3]), (20, 7),
                       (6, dynsym[3]), (11, 24), (5, dynstr[3]), (10, dynstr[5])):
        require(tags.get(tag) == value, "dynamic PLT/symbol-table route differs")
    require(tags.get(30) == 8 and 22 not in tags, "probe requires NOW without text relocations")
    dynamic_rela = table[".rela.dyn"][1]
    require(dynamic_rela[1] == 4 and dynamic_rela[9] == 24
            and dynamic_rela[5] % 24 == 0
            and (tags.get(7), tags.get(8), tags.get(9)) ==
                (dynamic_rela[3], dynamic_rela[5], 24), "dynamic relocation route differs")
    mapped(final, dynamic_rela, 4)
    # No dynamic relocation can replace bytes that this static replay proves.
    for offset in range(0, dynamic_rela[5], 24):
        address, info, _addend = final.unpack("<QQq", dynamic_rela[4] + offset)
        require(info & 0xffffffff in (6, 8), "unclassified ordinary dynamic relocation")
        protected = (table[".text"][1], plt, got, table[".bss"][1], table[".rodata"][1])
        require(not any(address < s[3] + s[5] and s[3] < address + 8 for s in protected),
                "dynamic relocation rewrites probe code, data or PLT/GOT")
    names = list(IMPORTS) if final.elf_type == 3 else ["__libc_start_main", *IMPORTS]
    count = len(names)
    require(rela[5] == count * 24 and plt[5] == (count + 1) * 16
            and got[5] == (count + 3) * 8, "PLT import roster differs")
    expected_plt = bytearray(b"\xff\x35" + i32(got[3] + 8 - (plt[3] + 6))
                             + b"\xff\x25" + i32(got[3] + 16 - (plt[3] + 12))
                             + b"\x0f\x1f\x40\x00")
    expected_got = bytearray(struct.pack("<QQQ", dynamic[3], 0, 0))
    result = {}
    for ordinal, name in enumerate(names):
        address, info, addend = final.unpack("<QQq", rela[4] + ordinal * 24)
        symbol = final.symbol_row(dynsym_index, info >> 32)
        require(info & 0xffffffff == 7 and addend == 0
                and address == got[3] + (ordinal + 3) * 8, "PLT relocation target differs")
        require(symbol["name"] == name and symbol["type"] == "FUNC"
                and symbol["binding"] == "GLOBAL" and symbol["visibility"] == "DEFAULT"
                and symbol["section"] == 0 and symbol["value"] == 0 and symbol["size"] == 0
                and symbol["version_index"] == 1, "PLT import symbol differs")
        stub = plt[3] + (ordinal + 1) * 16
        expected_plt += (b"\xff\x25" + i32(address - (stub + 6))
                         + b"\x68" + struct.pack("<I", ordinal)
                         + b"\xe9" + i32(plt[3] - (stub + 16)))
        expected_got += struct.pack("<Q", stub + 6)
        result[name] = stub
    require(final.data[plt[4]:plt[4] + plt[5]] == expected_plt, "PLT instruction bytes differ")
    require(final.data[got[4]:got[4] + got[5]] == expected_got, "GOT initial target bytes differ")
    return result


def _require_probe(source, final):
    require(source.elf_type == 1 and final.elf_type in (2, 3), "probe ELF kinds differ")
    before, after = sections(source), sections(final)
    text_index, text = before[".text"]
    bss_index, bss = before[".bss"]
    rodata_index, rodata = before[".rodata"]
    require(text[1:3] == (1, 6) and bss[1:3] == (8, 3) and rodata[1:3] == (1, 2),
            "probe input sections differ")
    source_rows = symbols(source, before[".symtab"][0])
    definitions = {r["name"] for r in source_rows if r["section"] and r["type"] in ("FUNC", "OBJECT")}
    require(definitions == set(FUNCTIONS) | set(OBJECTS), "probe input definition roster differs")
    source_functions = named(source_rows, FUNCTIONS)
    source_objects = named(source_rows, OBJECTS)
    final_rows = symbols(final, after[".symtab"][0])
    final_functions = named(final_rows, FUNCTIONS)
    final_objects = named(final_rows, OBJECTS)
    public_rows = symbols(final, after[".dynsym"][0])
    require([row for row in public_rows if row["name"] == "main"] == [final_functions["main"]]
            and not any(row["name"] in (set(FUNCTIONS) - {"main"}) | set(OBJECTS) for row in public_rows),
            "probe public/private definition boundary differs")
    final_text_index, final_text = after[".text"]
    final_bss_index, final_bss = after[".bss"]
    final_rodata = after[".rodata"][1]
    require(final_text[1:3] == (1, 6) and final_bss[1:3] == (8, 3)
            and final_rodata[1:3] == (1, 2), "probe output sections differ")
    mapped(final, final_text, 5)
    mapped(final, final_bss, 6, zero=True)
    mapped(final, final_rodata, 4)
    text_bases, bss_bases = set(), set()
    cursor = 0
    for name in FUNCTIONS:
        old, new = source_functions[name], final_functions[name]
        binding = "GLOBAL" if name == "main" else "LOCAL"
        require(old["type"] == new["type"] == "FUNC"
                and old["binding"] == new["binding"] == binding
                and old["visibility"] == new["visibility"] == "DEFAULT"
                and old["version_index"] == new["version_index"] == 1
                and old["section"] == text_index and new["section"] == final_text_index
                and old["size"] == new["size"] > 0 and old["value"] == cursor,
                "probe function metadata or input placement differs: " + name)
        text_bases.add(new["value"] - old["value"])
        cursor += old["size"]
    require(cursor == text[5] and len(text_bases) == 1, "probe text contribution differs")
    text_base = text_bases.pop()
    require(final_text[3] <= text_base and text_base + text[5] <= final_text[3] + final_text[5],
            "probe text exceeds final section")
    previous_end = 0
    for name in OBJECTS:
        old, new = source_objects[name], final_objects[name]
        require(old["type"] == new["type"] == "OBJECT"
                and old["binding"] == new["binding"] == "LOCAL"
                and old["visibility"] == new["visibility"] == "DEFAULT"
                and old["version_index"] == new["version_index"] == 1
                and old["section"] == bss_index and new["section"] == final_bss_index
                and old["size"] == new["size"] > 0
                and previous_end <= old["value"] and old["value"] + old["size"] <= bss[5],
                "probe object metadata or input placement differs: " + name)
        bss_bases.add(new["value"] - old["value"])
        previous_end = old["value"] + old["size"]
    require(len(bss_bases) == 1 and previous_end == bss[5], "probe data contribution differs")
    bss_base = bss_bases.pop()
    require(bss[8] > 0 and bss_base % bss[8] == 0 and final_bss[3] <= bss_base
            and bss_base + bss[5] <= final_bss[3] + final_bss[5], "probe data geometry differs")
    constant = source.data[rodata[4]:rodata[4] + rodata[5]]
    require(constant == b"owned-pthread-timed-feature-contract-ok\0", "probe string input differs")
    final_constants = final.data[final_rodata[4]:final_rodata[4] + final_rodata[5]]
    offset = final_constants.find(constant)
    require(offset >= 0 and final_constants.find(constant, offset + 1) < 0
            and rodata[8] > 0 and (final_rodata[3] + offset) % rodata[8] == 0,
            "probe string has no unique final placement")
    rodata_base = final_rodata[3] + offset
    imports = plt_imports(final, after)
    expected = bytearray(source.data[text[4]:text[4] + text[5]])
    relas = [(index, section) for index, section in enumerate(source.sections)
             if section[1] in (4, 9) and section[7] == text_index]
    require(len(relas) == 1, "probe text relocation roster differs")
    _, rela = relas[0]
    require(rela[1] == 4 and rela[9] == 24 and rela[5] % 24 == 0
            and rela[6] == before[".symtab"][0], "probe text relocations differ")
    occupied = set()
    observed_imports = set()
    for offset in range(0, rela[5], 24):
        position, info, addend = source.unpack("<QQq", rela[4] + offset)
        require(position + 4 <= len(expected) and not occupied.intersection(range(position, position + 4)),
                "overlapping or out-of-bounds probe relocation")
        occupied.update(range(position, position + 4))
        require(expected[position:position + 4] == b"\0" * 4, "probe RELA input field differs")
        symbol = source.symbol_row(rela[6], info >> 32)
        kind = info & 0xffffffff
        if kind == 2:
            require(symbol["name"] == "" and symbol["type"] == "3"
                    and symbol["binding"] == "LOCAL" and symbol["visibility"] == "DEFAULT"
                    and symbol["value"] == symbol["size"] == 0, "probe PC32 source target differs")
            if symbol["section"] == bss_index:
                require(addend + 4 in {row["value"] for row in source_objects.values()},
                        "probe PC32 does not name a local object")
                target = bss_base
            else:
                require(symbol["section"] == rodata_index and addend == -4,
                        "unclassified probe PC32 data target")
                target = rodata_base
        elif kind == 4:
            require(symbol["name"] in IMPORTS and symbol["type"] == "0"
                    and symbol["binding"] == "GLOBAL" and symbol["visibility"] == "DEFAULT"
                    and symbol["section"] == symbol["value"] == symbol["size"] == 0
                    and addend == -4 and position > 0 and expected[position - 1] == 0xe8,
                    "unclassified probe PLT32 call")
            target = imports[symbol["name"]]
            observed_imports.add(symbol["name"])
        else:
            raise PthreadTimedDynamicAuthorityError("unclassified probe relocation kind: " + str(kind))
        expected[position:position + 4] = i32(target + addend - (text_base + position))
    require(observed_imports == set(IMPORTS), "probe call import roster differs")
    file_offset = final_text[4] + text_base - final_text[3]
    require(final.data[file_offset:file_offset + len(expected)] == expected,
            "linked pthread probe function bytes differ from selected object")


def require_pthread_timed_probe_functions(object_path: Path, executable_path: Path) -> None:
    """Prove the exact admitted probe object's functions in one dynamic output.

    Callers first admit the selected object, image/tool/product inputs, dynamic
    link receipt and executable mode. Paths must be absolute physical files.
    This routine starts no process and does not admit additional probe shapes.
    """
    try:
        _require_probe(Elf(physical(object_path)), Elf(physical(executable_path)))
    except PthreadTimedDynamicAuthorityError:
        raise
    except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as error:
        raise PthreadTimedDynamicAuthorityError("malformed pthread dynamic authority input: " + str(error)) from error
