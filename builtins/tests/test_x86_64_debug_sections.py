from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("builtins_x86_64", ROOT / "builtins/build_x86_64.py")
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class DebugSectionTests(unittest.TestCase):
    def test_only_empty_unwind_terminator_is_removed(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as temporary:
            root = Path(temporary)
            source = root / "fixture.s"
            obj = root / "fixture.o"
            objcopy = builder.tool("llvm-objcopy")
            readelf = builder.tool("llvm-readelf")
            for content in (".long 0", ".long 1"):
                source.write_text(f'.section .eh_frame,"a",@progbits\n{content}\n')
                subprocess.run(["/usr/bin/gcc", "-c", str(source), "-o", str(obj)], check=True)
                builder.remove_empty_unwind_terminator(obj, root, objcopy)
                if content == ".long 0":
                    builder.audit_object(readelf, obj)
                else:
                    with self.assertRaises(builder.BuildError):
                        builder.audit_object(readelf, obj)
