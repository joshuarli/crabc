"""Preserve an allocated data symbol as ELF STT_COMMON in a DSO fixture.

GNU ld converts allocated commons to STT_OBJECT. Only the named symbol's
type changes here: its binding, section, size, value, and mappings stay intact.
Both symbol tables describe the same allocated uninitialized storage.
"""
import struct
import sys
from pathlib import Path


def main():
    path = Path(sys.argv[1])
    data = bytearray(path.read_bytes())
    assert data[:6] == b"\x7fELF\x02\x01"
    assert struct.unpack_from("<HH", data, 16) == (3, 62)
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_size, section_count = struct.unpack_from("<HH", data, 58)
    assert section_size == 64
    sections = [struct.unpack_from("<IIQQQQIIQQ", data,
        section_offset + index * section_size) for index in range(section_count)]
    changed = 0
    for section in sections:
        if section[1] not in (2, 11):
            continue
        assert section[9] == 24 and section[5] % 24 == 0
        strings_section = sections[section[6]]
        strings = data[strings_section[4]:strings_section[4] + strings_section[5]]
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, _, owner, value, size = struct.unpack_from("<IBBHQQ", data, offset)
            assert name < len(strings)
            end = strings.find(0, name)
            assert end >= name
            if strings[name:end] != b"loader_allocated_common_value":
                continue
            assert info == 0x11 and 0 < owner < section_count
            storage = sections[owner]
            assert storage[1] == 8 and storage[2] & 3 == 3
            assert size == 4 and storage[3] <= value <= storage[3] + storage[5] - size
            data[offset + 4] = 0x15
            changed += 1
    assert changed == 2
    path.write_bytes(data)


if __name__ == "__main__":
    main()
