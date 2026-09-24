#!/usr/bin/env python3
"""Write malformed copies of one valid DSO for the dlfcn malformed-input differential.

Every case is an input pinned musl 1.2.6 ldso/dynlink.c::map_library rejects
with ENOEXEC: fewer bytes than an ELF header, an e_type other than ET_DYN or
ET_EXEC, a program-header table that ends past EOF, no program headers, or
no PT_DYNAMIC. Usage: SOURCE_DSO OUTPUT_DIRECTORY [CASE...]. Outputs are
libmf_<case>.so in the (checkout .work) output directory; named cases
restrict the set.
"""
from pathlib import Path
import struct
import sys

ET_REL, ET_CORE, PT_NULL, PT_DYNAMIC = 1, 4, 0, 2


def cases(image: bytes) -> dict[str, bytes]:
    if image[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", image, 16)[0] != 3:
        raise SystemExit("source must be a little-endian ELF64 ET_DYN object")
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)

    def patched(offset: int, form: str, value: int) -> bytes:
        data = bytearray(image)
        struct.pack_into("<" + form, data, offset, value)
        return bytes(data)

    dynamic = [phoff + index * phentsize for index in range(phnum)
               if struct.unpack_from("<I", image, phoff + index * phentsize)[0] == PT_DYNAMIC]
    if len(dynamic) != 1 or phoff < 64:
        raise SystemExit("source must have one PT_DYNAMIC after its ELF header")
    return {
        "empty": b"",
        "short": image[:40],
        "relocatable": patched(16, "H", ET_REL),
        "core": patched(16, "H", ET_CORE),
        "truncated-phdr": image[:phoff + 8],
        "no-phdr": patched(56, "H", 0),
        "no-dynamic": patched(dynamic[0], "I", PT_NULL),
    }


def main() -> None:
    source, output = map(Path, sys.argv[1:3])
    state = Path(__file__).resolve().parents[2] / ".work"
    for path in (source, output):
        if path.is_symlink() or not path.resolve().is_relative_to(state):
            raise SystemExit("malformed-input artifacts must remain in checkout .work")
    selected = set(sys.argv[3:])
    for name, data in cases(source.read_bytes()).items():
        if selected and name not in selected:
            continue
        with (output / f"libmf_{name}.so").open("xb") as handle:
            handle.write(data)


if __name__ == "__main__":
    main()
