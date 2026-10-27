from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("builtins_x86_64", ROOT / "builtins/build_x86_64.py")
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class DebugSectionTests(unittest.TestCase):
    def test_debug_helper_closes_core_calls_with_source_compiler_builtins(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as temporary:
            root = Path(temporary)
            helper = root / "helper.o"
            names = sorted(builder.REQUIRED_SYMBOLS)
            assembly = "\n".join(f".globl {name}\n{name}:\n" +
                                 ("call _Rcore_probe\n" if name == names[0] else "") + "ret"
                                 for name in names)
            for name, body in (("helper", assembly),
                               ("core", ".globl _Rcore_probe\n_Rcore_probe:\ncall __extendhfsf2\ncall memcmp\ncall memcpy\ncall memset\nret"),
                               ("compiler", ".globl __extendhfsf2\n__extendhfsf2:\nret"),
                               ("libc", ".globl memcmp, memcpy, memset\nmemcmp:\nmemcpy:\nmemset:\nret")):
                source = root / f"{name}.s"
                source.write_text(".text\n" + body + "\n")
                subprocess.run(["/usr/bin/gcc", "-c", str(source), "-o", str(root / f"{name}.o")], check=True)
                if name != "helper":
                    subprocess.run([builder.tool("llvm-ar"), "rcsD", str(root / f"{name}.rlib"), str(root / f"{name}.o")], check=True)
            core = root / "core.rmeta"
            compiler = root / "compiler.rmeta"
            core.touch()
            compiler.touch()

            def compile_fixture(output: Path, **_kwargs: object) -> list[str]:
                shutil.copyfile(helper, output)
                return ["/usr/bin/gcc", "/usr/bin/gcc", "-o", str(output)]

            with mock.patch.object(builder, "compile_object", side_effect=compile_fixture):
                result = builder.build(root / "libcrabc-builtins.a", profile="debug", runtime_core=core,
                                       runtime_compiler_builtins=compiler, runtime_libc=root / "libc.rlib")
            self.assertEqual(result["defined_symbols"], sorted(builder.REQUIRED_SYMBOLS))
            undefined = builder.symbols(builder.tool("llvm-nm"), root / "libcrabc-builtins.a", "--undefined-only")
            self.assertEqual(undefined, {"memcmp", "memcpy", "memset"})

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
