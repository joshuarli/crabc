#!/usr/bin/env python3
"""Compile a native AArch64 dynamic PIE against the installed crabc sysroot."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent.parent
lib = root / "usr/lib"
args = sys.argv[1:]
if "-o" not in args or args.count("-o") != 1:
    sys.exit("crabc-cc-dynamic: supply one -o output")
index = args.index("-o")
if index + 1 >= len(args):
    sys.exit("crabc-cc-dynamic: missing output")
output = args[index + 1]
inputs = args[:index] + args[index + 2:]
if not inputs or any(value.startswith("-") for value in inputs):
    sys.exit("crabc-cc-dynamic: expected C source inputs")
with tempfile.TemporaryDirectory(prefix="crabc-aarch64-dynamic-") as temporary:
    objects = []
    for index, source in enumerate(inputs):
        obj = str(Path(temporary) / f"{index}.o")
        subprocess.run(["/usr/local/bin/crabc-aarch64-mold-gcc", "-nostdinc", "-isystem", str(root / "usr/include"), "-fPIE", "-c", source, "-o", obj], check=True)
        objects.append(obj)
    subprocess.run(["/usr/bin/mold", "-pie", "--dynamic-linker", "/lib/ld-crabc-aarch64.so.1", "--no-undefined", "--eh-frame-hdr", "-z", "relro", "-z", "now", "-e", "_start", str(lib / "Scrt1.o"), str(lib / "crti.o"), *objects, str(lib / "libc.so"), str(lib / "libcrabc-builtins.a"), str(lib / "crtn.o"), "-o", output], check=True)
