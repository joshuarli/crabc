#!/usr/bin/env python3
"""Mutate only private admitted DSO copies for runtime transaction regressions."""
from pathlib import Path
import struct
import sys


def main():
    source, target = map(Path, sys.argv[1:3])
    case = sys.argv[3]
    state = Path(__file__).resolve().parents[2] / ".work"
    for path in (source, target):
        if path.is_symlink() or not path.resolve().is_relative_to(state):
            raise SystemExit("runtime failure artifacts must remain in checkout .work")
    data = bytearray(source.read_bytes())
    if data[:6] != b"\x7fELF\x02\x01":
        raise SystemExit("expected ELF64 little endian")
    get = lambda fmt, at: struct.unpack_from("<" + fmt, data, at)
    put = lambda fmt, at, value: struct.pack_into("<" + fmt, data, at, value)
    phoff = get("Q", 32)[0]
    phsize, phnum = get("HH", 54)
    headers = [(phoff + i * phsize, get("IIQQQQQQ", phoff + i * phsize)) for i in range(phnum)]
    shoff = get("Q", 40)[0]
    shsize, shnum = get("HH", 58)
    sections = [get("IIQQQQIIQQ", shoff + i * shsize) for i in range(shnum)]
    if case == "unresolved":
        symbols = next(section for section in sections if section[1] == 11)
        strings = sections[symbols[6]]
        for at in range(symbols[4], symbols[4] + symbols[5], symbols[9]):
            start = strings[4] + get("I", at)[0]
            if data[start:data.index(0, start)] == b"puts":
                data[start:start + 4] = b"xxxx"
                break
        else:
            raise SystemExit("missing puts import")
    elif case == "array-half":
        dynamic = next(header for _, header in headers if header[0] == 2)
        at = next(at for at in range(dynamic[2], dynamic[2] + dynamic[5], 16) if get("Q", at)[0] == 27)
        put("Q", at, 0x60000001)
    elif case == "tls-filesz":
        at, tls = next(item for item in headers if item[1][0] == 7)
        put("Q", at + 32, tls[6] + 1)
    elif case == "relocation-kind":
        rela = next(section for section in sections if section[1] == 4 and section[5])
        at = rela[4] + 8
        put("Q", at, (get("Q", at)[0] & ~0xffffffff) | 0x7fffffff)
    else:
        raise SystemExit("unknown runtime failure mutation")
    with target.open("xb") as output:
        output.write(data)


if __name__ == "__main__":
    main()
