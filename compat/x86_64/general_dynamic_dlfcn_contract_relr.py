#!/usr/bin/env python3
"""Pack one DSO's R_X86_64_RELATIVE relocations into a DT_RELR table.

The installed dynamic driver has no packed-relative-relocation option, so the
runtime RELR differential rewrites a private copy of a driver-built object in
the form GNU ld's `-z pack-relative-relocs` produces for the pinned-musl
oracle: each implicit addend is stored in its word, the ELF gABI RELR stream
(an address entry, then 63-word bitmaps) replaces the leading RELATIVE block
of DT_RELA. DT_RELR/DT_RELRSZ/DT_RELRENT reuse optional DT_RELACOUNT,
DT_RUNPATH and DT_SONAME slots or zero padding before a final DT_NULL.
A filename dlopen through LD_LIBRARY_PATH does not consult the retired names. Usage: SOURCE_DSO OUTPUT_DSO (checkout .work).
"""
from pathlib import Path
import struct
import sys

DT_SONAME, DT_RELA, DT_RELASZ, DT_RELAENT, DT_RUNPATH = 14, 7, 8, 9, 29
DT_RELRSZ, DT_RELR, DT_RELRENT, DT_RELACOUNT = 35, 36, 37, 0x6FFFFFF9
PT_LOAD, PT_DYNAMIC, R_X86_64_RELATIVE = 1, 2, 8


def relr_stream(offsets: list[int]) -> list[int]:
    words, index = [], 0
    while index < len(offsets):
        base = offsets[index]
        words.append(base)
        index += 1
        base += 8
        while True:
            bitmap = 0
            while index < len(offsets):
                delta = offsets[index] - base
                if delta >= 63 * 8 or delta % 8:
                    break
                bitmap |= 1 << (delta // 8)
                index += 1
            if not bitmap:
                break
            words.append(bitmap << 1 | 1)
            base += 63 * 8
    return words


def pack(image: bytearray) -> int:
    if len(image) < 64 or image[:6] != b"\x7fELF\x02\x01":
        raise SystemExit("source must be a little-endian ELF64 object")
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    if phentsize < 56 or phoff + phentsize * phnum > len(image):
        raise SystemExit("source has a malformed program-header table")
    headers = [struct.unpack_from("<IIQQQQQQ", image, phoff + index * phentsize) for index in range(phnum)]

    def file_offset(address: int, size: int = 1) -> int:
        for kind, _, offset, vaddr, _, filesz, _, _ in headers:
            if kind == PT_LOAD and vaddr <= address and address + size <= vaddr + filesz:
                result = offset + address - vaddr
                if result + size <= len(image):
                    return result
        raise SystemExit(f"address {address:#x} is not file-backed")

    dynamic_headers = [header for header in headers if header[0] == PT_DYNAMIC]
    if len(dynamic_headers) != 1:
        raise SystemExit("source must have exactly one PT_DYNAMIC segment")
    dynamic, = dynamic_headers
    if dynamic[5] % 16 or dynamic[2] + dynamic[5] > len(image):
        raise SystemExit("source has a malformed dynamic table")
    entries = []
    terminator = None
    for at in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from("<qQ", image, at)
        entries.append((at, tag, value))
        if tag == 0 and terminator is None:
            terminator = len(entries) - 1
    if terminator is None:
        raise SystemExit("source dynamic table has no DT_NULL terminator")
    if any(tag != 0 or value != 0 for _, tag, value in entries[terminator:]):
        raise SystemExit("source dynamic table has nonzero data after DT_NULL")

    relevant = (DT_RELA, DT_RELASZ, DT_RELAENT, DT_RELACOUNT, DT_RUNPATH, DT_SONAME)
    slots = {tag: [(at, value) for at, entry_tag, value in entries if entry_tag == tag]
             for tag in relevant}
    if any(len(slots[tag]) > 1 for tag in relevant):
        raise SystemExit("source dynamic table has duplicate RELA rewrite tags")
    if any(not slots[tag] for tag in (DT_RELA, DT_RELASZ, DT_RELAENT)):
        raise SystemExit("source lacks DT_RELA, DT_RELASZ, or DT_RELAENT")
    rela, rela_size = slots[DT_RELA][0][1], slots[DT_RELASZ][0][1]
    rela_entry_size = slots[DT_RELAENT][0][1]
    if rela_entry_size != 24 or rela_size % rela_entry_size:
        raise SystemExit("source has a malformed DT_RELA table size")
    table = file_offset(rela, rela_size)
    relocations = [
        struct.unpack_from("<QQq", image, table + index * rela_entry_size)
        for index in range(rela_size // rela_entry_size)
    ]
    count = 0
    for _, info, _ in relocations:
        relocation_type = info & 0xFFFFFFFF
        symbol_index = info >> 32
        if relocation_type != R_X86_64_RELATIVE:
            break
        if symbol_index != 0:
            raise SystemExit("leading R_X86_64_RELATIVE relocation has a nonzero symbol")
        count += 1
    if not count:
        raise SystemExit("source has no leading RELATIVE block in DT_RELA")
    if count == len(relocations):
        raise SystemExit("rewrite needs a remaining RELA entry")
    if slots[DT_RELACOUNT] and slots[DT_RELACOUNT][0][1] != count:
        raise SystemExit("DT_RELACOUNT disagrees with the leading RELATIVE block")

    relative = relocations[:count]
    offsets = [offset for offset, _, _ in relative]
    if any(offset % 8 for offset in offsets) or len(set(offsets)) != len(offsets):
        raise SystemExit("leading RELATIVE block has unaligned or duplicate targets")
    target_offsets = [(offset, addend, file_offset(offset, 8)) for offset, _, addend in relative]
    words = relr_stream(sorted(offsets))
    prefix_size = count * rela_entry_size
    if len(words) * 8 > prefix_size:
        raise SystemExit("rewrite has no room for the RELR stream in the leading RELATIVE block")

    destinations = {
        DT_RELR: slots[DT_RELACOUNT][0][0] if slots[DT_RELACOUNT] else None,
        DT_RELRSZ: slots[DT_RUNPATH][0][0] if slots[DT_RUNPATH] else None,
        DT_RELRENT: slots[DT_SONAME][0][0] if slots[DT_SONAME] else None,
    }
    free_slots = [at for at, tag, _ in entries[terminator:-1] if tag == 0]
    missing = [tag for tag, at in destinations.items() if at is None]
    if len(free_slots) < len(missing):
        raise SystemExit("no dynamic-table slot remains before the required DT_NULL terminator")
    for tag, at in zip(missing, free_slots):
        destinations[tag] = at

    shoff = struct.unpack_from("<Q", image, 40)[0]
    shentsize, shnum = struct.unpack_from("<HH", image, 58)
    if shentsize < 64 or shoff + shentsize * shnum > len(image):
        raise SystemExit("source has a malformed section-header table")
    rela_sections = []
    for index in range(shnum):
        at = shoff + index * shentsize
        kind, _, address, offset, size = struct.unpack_from("<IQQQQ", image, at + 4)
        if kind == 4 and address == rela:
            if offset != table or size != rela_size:
                raise SystemExit("DT_RELA and its section header disagree")
            rela_sections.append(at)

    for _, addend, target in target_offsets:
        struct.pack_into("<q", image, target, addend)
    image[table:table + prefix_size] = bytes(prefix_size)
    for index, word in enumerate(words):
        struct.pack_into("<Q", image, table + index * 8, word)
    struct.pack_into("<qQ", image, slots[DT_RELA][0][0], DT_RELA, rela + prefix_size)
    struct.pack_into("<qQ", image, slots[DT_RELASZ][0][0], DT_RELASZ, rela_size - prefix_size)
    struct.pack_into("<qQ", image, destinations[DT_RELR], DT_RELR, rela)
    struct.pack_into("<qQ", image, destinations[DT_RELRSZ], DT_RELRSZ, len(words) * 8)
    struct.pack_into("<qQ", image, destinations[DT_RELRENT], DT_RELRENT, 8)
    for at in rela_sections:
        struct.pack_into("<QQQ", image, at + 16, rela + prefix_size, table + prefix_size,
                         rela_size - prefix_size)
    return count


def main() -> None:
    source, target = map(Path, sys.argv[1:3])
    state = Path(__file__).resolve().parents[2] / ".work"
    for path in (source, target):
        if path.is_symlink() or not path.resolve().is_relative_to(state):
            raise SystemExit("RELR rewrite artifacts must remain in checkout .work")
    image = bytearray(source.read_bytes())
    if image[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", image, 16)[0] != 3:
        raise SystemExit("source must be a little-endian ELF64 ET_DYN object")
    packed = pack(image)
    with target.open("xb") as output:
        output.write(image)
    print(f"packed {packed} RELATIVE relocations")


if __name__ == "__main__":
    main()
