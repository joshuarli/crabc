"""Prove that the archive resolves compiler-emitted AArch64 int128 helpers."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "aarch64-unknown-linux-musl"


def run(command: list[str]) -> str:
    completed = subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return completed.stdout


class ArchiveLinkTests(unittest.TestCase):
    def test_archive_resolves_compiler_emitted_integer_division_helpers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crabc-builtins-link-") as temporary:
            directory = pathlib.Path(temporary)
            source = directory / "int128.c"
            object_file = directory / "int128.o"
            archive = directory / "libcrabc-builtins.a"
            linked = directory / "int128-linked.o"
            source.write_text(
                """
                unsigned __int128 unsigned_divide(unsigned __int128 left, unsigned __int128 right) {
                    return left / right;
                }
                unsigned __int128 unsigned_remainder(unsigned __int128 left, unsigned __int128 right) {
                    return left % right;
                }
                __int128 signed_divide(__int128 left, __int128 right) {
                    return left / right;
                }
                __int128 signed_remainder(__int128 left, __int128 right) {
                    return left % right;
                }
                """,
                encoding="utf-8",
            )
            run([sys.executable, str(ROOT / "build.py"), "--output", str(archive)])
            run(
                [
                    "clang",
                    f"--target={TARGET}",
                    "-O2",
                    "-fno-stack-protector",
                    "-c",
                    str(source),
                    "-o",
                    str(object_file),
                ]
            )
            compiler_references = set(run(["llvm-nm", "--undefined-only", str(object_file)]).split())
            expected = {"__udivti3", "__umodti3", "__divti3", "__modti3"}
            self.assertTrue(expected.issubset(compiler_references), compiler_references)
            run(["ld.lld", "-r", str(object_file), str(archive), "-o", str(linked)])
            remaining = set(run(["llvm-nm", "--undefined-only", str(linked)]).split())
            self.assertFalse(expected.intersection(remaining), remaining)

    def test_archive_resolves_compiler_emitted_complex_and_binary128_helpers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crabc-builtins-floating-link-") as temporary:
            directory = pathlib.Path(temporary)
            source = directory / "complex_binary128.c"
            object_file = directory / "complex_binary128.o"
            archive = directory / "libcrabc-builtins.a"
            linked = directory / "complex_binary128-linked.o"
            source.write_text(
                """
                #include <complex.h>

                double complex multiply(double complex left, double complex right) {
                    return left * right;
                }

                int binary128_not_equal(long double left, long double right) {
                    return left != right;
                }

                long double binary128_arithmetic(
                    float narrow,
                    double widened,
                    long double left,
                    long double right
                ) {
                    long double sum = (long double)narrow + (long double)widened;
                    long double product = sum * left;
                    long double quotient = product / right;
                    return quotient - left;
                }

                int binary128_surface(
                    float narrow,
                    double widened,
                    long double left,
                    long double right
                ) {
                    long double value = binary128_arithmetic(narrow, widened, left, right);
                    float narrowed_float = (float)value;
                    double narrowed_double = (double)value;
                    return value == left || value < right || value > left || value != right
                        || narrowed_float == 0.0f || narrowed_double == 0.0;
                }
                """,
                encoding="utf-8",
            )
            run([sys.executable, str(ROOT / "build.py"), "--output", str(archive)])
            run(
                [
                    "clang",
                    f"--target={TARGET}",
                    "-O0",
                    "-fno-stack-protector",
                    "-c",
                    str(source),
                    "-o",
                    str(object_file),
                ]
            )
            compiler_references = set(run(["llvm-nm", "--undefined-only", str(object_file)]).split())
            expected = {
                "__addtf3",
                "__divtf3",
                "__eqtf2",
                "__extenddftf2",
                "__extendsftf2",
                "__gttf2",
                "__lttf2",
                "__muldc3",
                "__multf3",
                "__netf2",
                "__subtf3",
                "__trunctfdf2",
                "__trunctfsf2",
            }
            self.assertTrue(expected.issubset(compiler_references), compiler_references)
            run(["ld.lld", "-r", str(object_file), str(archive), "-o", str(linked)])
            remaining = set(run(["llvm-nm", "--undefined-only", str(linked)]).split())
            self.assertFalse(expected.intersection(remaining), remaining)


if __name__ == "__main__":
    unittest.main()
