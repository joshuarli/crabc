#!/usr/bin/env python3
"""Change the fixture's one pointer relocation into an x86-64 PC32 relocation."""

from pathlib import Path
import struct
import sys

assert len(sys.argv) in (3, 4)
source, destination = map(Path, sys.argv[1:3])
invalid_target = len(sys.argv) == 4 and sys.argv[3] == "--invalid-target"
assert len(sys.argv) == 3 or invalid_target
image = bytearray(source.read_bytes())
assert image[:5] == b"\x7fELF\x02" and image[5] == 1
phoff = struct.unpack_from("<Q", image, 32)[0]
phentsize, phnum = struct.unpack_from("<HH", image, 54)
loads = []
dynamic = None
writable_end = None
for index in range(phnum):
    entry = phoff + index * phentsize
    kind, flags = struct.unpack_from("<II", image, entry)
    offset, virtual = struct.unpack_from("<QQ", image, entry + 8)
    file_size, = struct.unpack_from("<Q", image, entry + 32)
    memory_size, = struct.unpack_from("<Q", image, entry + 40)
    if kind == 1:
        loads.append((virtual, virtual + file_size, offset))
        if flags & 2:
            writable_end = virtual + memory_size
    if kind == 2:
        dynamic = (offset, file_size)


def file_offset(virtual, length):
    for start, end, offset in loads:
        if start <= virtual and virtual + length <= end:
            return offset + virtual - start
    raise ValueError("dynamic address outside file backed load")


assert dynamic is not None
tags = {}
for entry in range(dynamic[0], dynamic[0] + dynamic[1], 16):
    tag, value = struct.unpack_from("<qQ", image, entry)
    if tag == 0:
        break
    tags[tag] = value
assert tags[9] == 24 and tags[8] % 24 == 0
rela = file_offset(tags[7], tags[8])
pointer_relocations = []
for entry in range(rela, rela + tags[8], 24):
    target, info = struct.unpack_from("<QQ", image, entry)
    if info & 0xffffffff == 1:
        pointer_relocations.append((entry, target, info))
assert len(pointer_relocations) == 1
entry, target, info = pointer_relocations[0]
assert struct.unpack_from("<Q", image, file_offset(target, 8))[0] == 0
struct.pack_into("<Q", image, entry + 8, (info & ~0xffffffff) | 2)
if invalid_target:
    assert writable_end is not None and writable_end >= 3
    struct.pack_into("<Q", image, entry, writable_end - 3)
destination.write_bytes(image)
