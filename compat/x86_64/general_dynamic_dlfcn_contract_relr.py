#!/usr/bin/env python3
"""Pack one DSO's R_X86_64_RELATIVE relocations into a DT_RELR table.

The installed dynamic driver has no packed-relative-relocation option, so the
runtime RELR differential rewrites a private copy of a driver-built object in
the form GNU ld's `-z pack-relative-relocs` produces for the pinned-musl
oracle: each implicit addend is stored in its word, the ELF gABI RELR stream
(an address entry, then 63-word bitmaps) replaces the leading RELATIVE block
of DT_RELA, and DT_RELR/DT_RELRSZ/DT_RELRENT reuse the DT_RELACOUNT,
DT_RUNPATH and DT_SONAME slots, which a filename dlopen through
LD_LIBRARY_PATH does not consult. Usage: SOURCE_DSO OUTPUT_DSO (checkout .work).
"""
from pathlib import Path
import struct
import sys

DT_SONAME, DT_RELA, DT_RELASZ, DT_RUNPATH = 14, 7, 8, 29
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
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    headers = [struct.unpack_from("<IIQQQQQQ", image, phoff + index * phentsize) for index in range(phnum)]

    def file_offset(address: int) -> int:
        for kind, _, offset, vaddr, _, filesz, _, _ in headers:
            if kind == PT_LOAD and vaddr <= address < vaddr + filesz:
                return offset + address - vaddr
        raise SystemExit(f"address {address:#x} is not file-backed")

    dynamic, = [header for header in headers if header[0] == PT_DYNAMIC]
    entries = []
    for at in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from("<qQ", image, at)
        entries.append((at, tag, value))
        if tag == 0:
            break
    slot = {tag: (at, value) for at, tag, value in entries}
    if any(tag not in slot for tag in (DT_RELA, DT_RELASZ, DT_RELACOUNT, DT_RUNPATH, DT_SONAME)):
        raise SystemExit("source lacks the RELA/RELACOUNT/RUNPATH/SONAME entries this rewrite reuses")
    rela, rela_size = slot[DT_RELA][1], slot[DT_RELASZ][1]
    count = slot[DT_RELACOUNT][1]
    table = file_offset(rela)
    relocations = []
    for index in range(count):
        offset, info, addend = struct.unpack_from("<QQq", image, table + index * 24)
        if info != R_X86_64_RELATIVE:
            raise SystemExit("DT_RELACOUNT does not describe a leading RELATIVE block")
        relocations.append((offset, addend))
    relocations.sort()
    for offset, addend in relocations:
        struct.pack_into("<q", image, file_offset(offset), addend)
    words = relr_stream([offset for offset, _ in relocations])
    if count * 24 == rela_size or len(words) * 8 > count * 24:
        raise SystemExit("rewrite needs a remaining RELA entry and room for the RELR stream")
    image[table:table + count * 24] = bytes(count * 24)
    for index, word in enumerate(words):
        struct.pack_into("<Q", image, table + index * 8, word)
    struct.pack_into("<qQ", image, slot[DT_RELA][0], DT_RELA, rela + count * 24)
    struct.pack_into("<qQ", image, slot[DT_RELASZ][0], DT_RELASZ, rela_size - count * 24)
    struct.pack_into("<qQ", image, slot[DT_RELACOUNT][0], DT_RELR, rela)
    struct.pack_into("<qQ", image, slot[DT_RUNPATH][0], DT_RELRSZ, len(words) * 8)
    struct.pack_into("<qQ", image, slot[DT_SONAME][0], DT_RELRENT, 8)
    # Keep the section view (readelf) consistent with the remaining RELA.
    shoff = struct.unpack_from("<Q", image, 40)[0]
    shentsize, shnum = struct.unpack_from("<HH", image, 58)
    for index in range(shnum):
        at = shoff + index * shentsize
        kind, _, address, offset, size = struct.unpack_from("<IQQQQ", image, at + 4)
        if kind == 4 and address == rela:
            struct.pack_into("<QQQ", image, at + 16, address + count * 24, offset + count * 24, size - count * 24)
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
