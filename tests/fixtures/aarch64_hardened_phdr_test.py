import os
import pathlib
import struct
import subprocess
import sys

original = pathlib.Path(sys.argv[1])
data = original.read_bytes()
phoff = struct.unpack_from('<Q', data, 32)[0]
phentsize, phnum = struct.unpack_from('<HH', data, 54)
entries = [phoff + i * phentsize for i in range(phnum)]

for name, kind, flag in [('exec-stack', 0x6474e551, 1), ('writable-exec', 1, 3)]:
    modified = bytearray(data)
    for entry in entries:
        p_type, flags = struct.unpack_from('<II', modified, entry)
        if p_type == kind and (kind != 1 or flags & 2):
            struct.pack_into('<I', modified, entry + 4, flags | flag)
            break
    else:
        raise SystemExit(f'missing {name} segment')
    path = original.with_name(original.name + '-' + name)
    path.write_bytes(modified)
    path.chmod(0o755)
    result = subprocess.run([str(path)], check=False)
    if result.returncode != 127:
        raise SystemExit(f'{name}: expected 127, got {result.returncode}')
    os.unlink(path)

modified = bytearray(data)
struct.pack_into('<H', modified, 52, 65)
path = original.with_name(original.name + '-invalid-ehsize')
path.write_bytes(modified)
path.chmod(0o755)
result = subprocess.run([str(path)], check=False)
if result.returncode != 127:
    raise SystemExit(f'invalid-ehsize: expected 127, got {result.returncode}')
os.unlink(path)
