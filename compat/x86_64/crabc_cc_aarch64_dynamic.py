#!/usr/bin/env python3
"""Compile a native AArch64 dynamic PIE against the installed crabc sysroot."""
import importlib.machinery
import importlib.util
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
loader = importlib.machinery.SourceFileLoader("crabc_cc_static", str(root / "share/crabc/crabc_cc_static.py"))
spec = importlib.util.spec_from_loader(loader.name, loader)
shared = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = shared
loader.exec_module(shared)
dsos = [value for value in inputs if value.endswith(".so")]
objects_in = [value for value in inputs if value.endswith(".o")]
sources = [value for value in inputs if value not in dsos and value not in objects_in]
if not (sources or objects_in) or any(value.startswith("-") for value in inputs):
    sys.exit("crabc-cc-dynamic: expected C source or object inputs")
try:
    objects_in = [str(shared.require_x86_64_relocatable_object(root, Path(value), architecture="aarch64")) for value in objects_in if not shared.rejects_runtime_object(Path(value))]
    if len(objects_in) != sum(value.endswith(".o") for value in inputs):
        raise shared.DriverError("unowned target-runtime object is rejected")
    shared.validate_application_output(root, Path(output))
    shared.validate_application_output_disjoint(Path(output), [Path(value) for value in (*sources, *objects_in, *dsos)])
except shared.DriverError as error:
    sys.exit(f"crabc-cc-dynamic: {error}")
with tempfile.TemporaryDirectory(prefix="crabc-aarch64-dynamic-") as temporary:
    objects = list(objects_in)
    for index, source in enumerate(sources):
        obj = str(Path(temporary) / f"{index}.o")
        subprocess.run(["/usr/local/bin/crabc-aarch64-mold-gcc", "-nostdinc", "-isystem", str(root / "usr/include"), "-fPIE", "-c", source, "-o", obj], check=True)
        objects.append(obj)
    subprocess.run(["/usr/bin/mold", "-pie", "-z", "dynamic-undefined-weak", "--dynamic-linker", "/lib/ld-crabc-aarch64.so.1", "--no-undefined", "--eh-frame-hdr", "-z", "relro", "-z", "now", "-e", "_start", str(lib / "Scrt1.o"), str(lib / "crti.o"), *objects, *dsos, str(lib / "libc.so"), str(lib / "libcrabc-builtins.a"), str(lib / "crtn.o"), "-o", output], check=True)
