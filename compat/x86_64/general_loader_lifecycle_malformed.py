#!/usr/bin/env python3
"""Derive one malformed fini-array tag from an otherwise valid native DSO."""

import pathlib
import struct
import sys

source, destination, case = sys.argv[1:]
data = bytearray(pathlib.Path(source).read_bytes())
assert data[:7] == b"\x7fELF\x02\x01\x01"
assert struct.unpack_from("<H", data, 18)[0] == 62
phoff = struct.unpack_from("<Q", data, 32)[0]
phentsize, phnum = struct.unpack_from("<HH", data, 54)
dynamic = None
for index in range(phnum):
    offset = phoff + index * phentsize
    if struct.unpack_from("<I", data, offset)[0] == 2:
        dynamic = struct.unpack_from("<Q", data, offset + 8)[0]
        size = struct.unpack_from("<Q", data, offset + 32)[0]
        break
assert dynamic is not None
tag = 28 if case in {"unpaired", "zero-size", "oversized"} else 26
for offset in range(dynamic, dynamic + size, 16):
    actual, value = struct.unpack_from("<qQ", data, offset)
    if actual == tag:
        if case == "unpaired":
            struct.pack_into("<q", data, offset, 21)  # DT_DEBUG, leaving DT_FINI_ARRAY alone
        elif case == "unreadable":
            for index in range(phnum):
                header = phoff + index * phentsize
                kind, flags = struct.unpack_from("<II", data, header)
                start = struct.unpack_from("<Q", data, header + 16)[0]
                length = struct.unpack_from("<Q", data, header + 40)[0]
                if kind == 1 and start <= value < start + length:
                    struct.pack_into("<I", data, header + 4, flags & ~4)
                    break
            else:
                raise AssertionError("fini array is not in a load segment")
        else:
            replacement = {
                "zero-size": 0, "oversized": 17 * 8,
                "unaligned": value + 1, "outside-load": (1 << 63),
            }[case]
            struct.pack_into("<Q", data, offset + 8, replacement)
        break
else:
    raise AssertionError("fixture lacks the required fini-array dynamic tag")
pathlib.Path(destination).write_bytes(data)
