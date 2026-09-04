#!/usr/bin/env python3
"""Named ELF mutations for the general relocation boundary, never host inputs."""
from pathlib import Path
import struct
import sys


def main() -> None:
    source, destination = map(Path, sys.argv[1:3])
    case = sys.argv[3]
    state = Path(__file__).resolve().parents[2] / ".work"
    for path in (source, destination):
        if not path.resolve().is_relative_to(state) or path.is_symlink():
            raise SystemExit("relocation mutations require checkout .work artifacts")
    data = bytearray(source.read_bytes())
    if data[:6] != b"\x7fELF\x02\x01":
        raise SystemExit("expected ELF64 little endian")
    unpack = lambda fmt, offset: struct.unpack_from("<" + fmt, data, offset)
    put = lambda fmt, offset, value: struct.pack_into("<" + fmt, data, offset, value)
    shoff = unpack("Q", 40)[0]
    shentsize, shnum = unpack("HH", 58)
    sections = [unpack("IIQQQQIIQQ", shoff + i * shentsize) for i in range(shnum)]
    dynsym = next(section for section in sections if section[1] == 11)
    strings = sections[dynsym[6]]
    names = {}
    for index in range(dynsym[5] // dynsym[9]):
        offset = dynsym[4] + index * dynsym[9]
        start = strings[4] + unpack("I", offset)[0]
        name = data[start:data.index(0, start)].decode()
        names[name] = (index, offset)

    def symbol(name: str) -> int:
        return names[name][1]

    def relocation(name: str, kind: int) -> int:
        wanted = names[name][0]
        for section in sections:
            if section[1] != 4:
                continue
            for offset in range(section[4], section[4] + section[5], section[9]):
                info = unpack("Q", offset + 8)[0]
                if info >> 32 == wanted and info & 0xffffffff == kind:
                    return offset
        raise ValueError(f"missing {name} relocation {kind}")

    phoff = unpack("Q", 32)[0]
    phentsize, phnum = unpack("HH", 54)
    headers = [(phoff + i * phentsize, unpack("IIQQQQQQ", phoff + i * phentsize)) for i in range(phnum)]
    if case == "consumer-clear-static-tls":
        header = next(header for _, header in headers if header[0] == 2)
        entry = next(offset for offset in range(header[2], header[2] + header[5], 16)
                     if unpack("Q", offset)[0] == 30)
        put("Q", entry + 8, unpack("Q", entry + 8)[0] & ~16)
    elif case == "main-array-half":
        header = next(header for _, header in headers if header[0] == 2)
        entry = next(offset for offset in range(header[2], header[2] + header[5], 16)
                     if unpack("Q", offset)[0] == 21)
        put("Q", entry, 25)
        put("Q", entry + 8, unpack("Q", symbol("copied_payload") + 8)[0])
    elif case in {"provider-size-small", "provider-size-large"}:
        put("Q", symbol("copied_bytes") + 16, 16 if case.endswith("small") else 80)
    elif case == "copy-offset":
        offset = relocation("copied_payload", 5)
        put("Q", offset, unpack("Q", offset)[0] + 8)
    elif case == "copy-size":
        put("Q", symbol("copied_payload") + 16, 1 << 63)
    elif case == "copy-addend":
        put("q", relocation("copied_payload", 5) + 16, 1)
    elif case == "copy-overlap":
        address = unpack("Q", symbol("copied_payload") + 8)[0] + 8
        put("Q", symbol("copied_bytes") + 8, address)
        put("Q", relocation("copied_bytes", 5), address)
    elif case == "copy-readonly":
        address = next(header[3] for _, header in headers if header[0] == 1 and not header[1] & 2)
        put("Q", symbol("copied_payload") + 8, address)
        put("Q", relocation("copied_payload", 5), address)
    elif case == "copy-in-dso":
        offset = relocation("copied_payload", 1)
        put("Q", offset + 8, names["copied_payload"][0] << 32 | 5)
        put("q", offset + 16, 0)
    elif case == "copy-source-size":
        put("Q", symbol("copied_payload") + 16, 1 << 63)
    elif case == "copy-source-extent":
        address = unpack("Q", symbol("copied_bytes") + 8)[0]
        header = next(header for _, header in headers if header[0] == 1 and header[3] <= address < header[3] + header[6])
        put("Q", symbol("copied_bytes") + 8, header[3] + header[6] - 16)
        put("Q", symbol("copied_bytes") + 16, 1)
    elif case in {"copy-source-hidden", "copy-source-protected", "copy-source-local", "copy-source-tls"}:
        offset = symbol("copied_payload")
        if case.endswith("hidden"):
            data[offset + 5] = 2
        elif case.endswith("protected"):
            data[offset + 5] = 3
        elif case.endswith("local"):
            data[offset + 4] &= 15
        else:
            data[offset + 4] = data[offset + 4] & 0xf0 | 6
    elif case in {"tls-offset", "tls-size", "tls-kind", "tls-no-module"}:
        tls_offset, header = next((offset, header) for offset, header in headers if header[0] == 7)
        if case == "tls-kind":
            data[symbol("high_tls") + 4] = 0x11
        elif case == "tls-no-module":
            put("I", tls_offset, 0)
        else:
            put("Q", symbol("high_tls") + (8 if case == "tls-offset" else 16), header[6] + 1)
    elif case in {"tls-addend-positive", "tls-addend-negative", "tls-unaligned", "tls-invalid-index"}:
        offset = relocation("high_tls", 18)
        if case.startswith("tls-addend"):
            put("q", offset + 16, -(1 << 62) if case.endswith("negative") else 1 << 62)
        elif case == "tls-unaligned":
            put("Q", offset, unpack("Q", offset)[0] + 1)
        else:
            put("Q", offset + 8, 0xffffffff00000012)
    else:
        raise ValueError(f"unknown mutation {case}")
    destination.write_bytes(data)
    destination.chmod(source.stat().st_mode & 0o777)


if __name__ == "__main__":
    main()
