#!/usr/bin/env python3
"""Move a selected DSO's PHDR table into a later file-backed PT_LOAD span."""
from pathlib import Path
import struct
import sys

MARKER = b"LATEPHDR"
PAGE = 4096
PHDR_SIZE = 56
PT_LOAD = 1
PT_PHDR = 6
PF_R = 4


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: general_dynamic_phdr_late_mutate.py SOURCE TARGET")
    source, target = map(Path, sys.argv[1:])
    work = Path(__file__).resolve().parents[2] / ".work"
    for path in (source, target):
        if path.is_symlink() or not path.resolve().is_relative_to(work):
            raise SystemExit("late PHDR artifacts must remain in checkout .work")
    image = bytearray(source.read_bytes())
    if image[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", image, 18)[0] != 62:
        raise SystemExit("expected little-endian ELF64 x86-64")
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    size = phnum * PHDR_SIZE
    if phentsize != PHDR_SIZE or not 0 < phnum <= 32 or phoff + size > len(image):
        raise SystemExit("unexpected program-header table")
    marker = image.find(MARKER)
    if marker <= PAGE or image.find(MARKER, marker + 1) != -1:
        raise SystemExit("missing or ambiguous later PHDR reserve")
    if marker % 8 or marker + size > len(image) or any(image[marker + len(MARKER):marker + size]):
        raise SystemExit("later PHDR reserve is not aligned and empty")
    headers = [list(struct.unpack_from("<IIQQQQQQ", image, phoff + index * PHDR_SIZE))
               for index in range(phnum)]
    loads = [header for header in headers if header[0] == PT_LOAD and header[1] & PF_R
             and header[2] <= marker and marker + size <= header[2] + header[5]]
    if len(loads) != 1:
        raise SystemExit("later PHDR table must lie in one readable file-backed PT_LOAD")
    phdrs = [header for header in headers if header[0] == PT_PHDR]
    if len(phdrs) > 1:
        raise SystemExit("expected at most one PT_PHDR entry")
    load = loads[0]
    mapped_address = load[3] + marker - load[2]
    if phdrs:
        phdr = phdrs[0]
        phdr[2] = marker
        phdr[3] = mapped_address
        phdr[4] = mapped_address
        phdr[5] = size
        phdr[6] = size
    for index, header in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", image, marker + index * PHDR_SIZE, *header)
    struct.pack_into("<Q", image, 32, marker)
    with target.open("xb") as output:
        output.write(image)


if __name__ == "__main__":
    main()
