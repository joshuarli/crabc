#!/usr/bin/env python3
"""Make an ET_REL dependency from a valid ELF64 DSO in checkout-owned scratch."""
from pathlib import Path
import struct
import sys

source, target = map(Path, sys.argv[1:])
work = Path(__file__).resolve().parents[2] / ".work"
for path in (source, target):
    if path.is_symlink() or not path.resolve().is_relative_to(work):
        raise SystemExit("failed-open inputs must stay in checkout .work")
image = bytearray(source.read_bytes())
if image[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", image, 16)[0] != 3:
    raise SystemExit("expected little-endian ELF64 shared object")
struct.pack_into("<H", image, 16, 1)
target.write_bytes(image)
