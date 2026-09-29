#!/usr/bin/env python3
"""Change one linked DSO import into a missing relocation target."""
from pathlib import Path
import struct
import sys

image_path = Path(sys.argv[1])
work = Path(__file__).resolve().parents[2] / ".work"
if image_path.is_symlink() or not image_path.resolve().is_relative_to(work):
    raise SystemExit("failed-open image must stay in checkout .work")
image = bytearray(image_path.read_bytes())
if image[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", image, 16)[0] != 3:
    raise SystemExit("expected little-endian ELF64 shared object")
section_offset = struct.unpack_from("<Q", image, 40)[0]
section_size, section_count, name_index = struct.unpack_from("<HHH", image, 58)
if section_size < 64 or not 0 < name_index < section_count:
    raise SystemExit("expected ordinary ELF64 section headers")
if section_offset + section_size * section_count > len(image):
    raise SystemExit("section headers exceed image")


def section(index):
    start = section_offset + section_size * index
    offset, size = struct.unpack_from("<QQ", image, start + 24)
    if offset + size > len(image):
        raise SystemExit("section exceeds image")
    return offset, size


names_offset, names_size = section(name_index)
names = image[names_offset:names_offset + names_size]
dynamic_strings = None
for index in range(section_count):
    start = section_offset + section_size * index
    name_offset = struct.unpack_from("<I", image, start)[0]
    if name_offset >= len(names):
        raise SystemExit("section name exceeds string table")
    end = names.find(b"\0", name_offset)
    if end < 0:
        raise SystemExit("unterminated section name")
    if names[name_offset:end] == b".dynstr":
        dynamic_strings = section(index)
        break
if dynamic_strings is None:
    raise SystemExit("missing dynamic string table")
offset, size = dynamic_strings
old = b"getpid\0"
new = b"badpid\0"
strings = image[offset:offset + size]
if strings.count(old) != 1:
    raise SystemExit("expected one linked getpid import")
image[offset:offset + size] = strings.replace(old, new)
image_path.write_bytes(image)
