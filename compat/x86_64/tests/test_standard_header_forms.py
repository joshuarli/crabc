#!/usr/bin/env python3
"""Regression tests for the pinned musl standard-header source forms."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
INCLUDE = ROOT / "include"


class StandardHeaderFormsTests(unittest.TestCase):
    def test_headers_retain_pinned_musl_source_forms(self) -> None:
        assert_source = (INCLUDE / "assert.h").read_text(encoding="utf-8")
        self.assertEqual(
            assert_source,
            """#include <features.h>

#undef assert

#ifdef NDEBUG
#define\tassert(x) (void)0
#else
#define assert(x) ((void)((x) || (__assert_fail(#x, __FILE__, __LINE__, __func__),0)))
#endif

#if __STDC_VERSION__ >= 201112L && !defined(__cplusplus)
#define static_assert _Static_assert
#endif

#ifdef __cplusplus
extern \"C\" {
#endif

_Noreturn void __assert_fail (const char *, const char *, int, const char *);

#ifdef __cplusplus
}
#endif
""",
        )

        self.assertEqual(
            (INCLUDE / "byteswap.h").read_text(encoding="utf-8"),
            """#ifndef _BYTESWAP_H
#define _BYTESWAP_H

#include <features.h>
#include <stdint.h>

static __inline uint16_t __bswap_16(uint16_t __x)
{
\treturn __x<<8 | __x>>8;
}

static __inline uint32_t __bswap_32(uint32_t __x)
{
\treturn __x>>24 | __x>>8&0xff00 | __x<<8&0xff0000 | __x<<24;
}

static __inline uint64_t __bswap_64(uint64_t __x)
{
\treturn __bswap_32(__x)+0ULL<<32 | __bswap_32(__x>>32);
}

#define bswap_16(x) __bswap_16(x)
#define bswap_32(x) __bswap_32(x)
#define bswap_64(x) __bswap_64(x)

#endif
""",
        )
        self.assertEqual(
            (INCLUDE / "memory.h").read_text(encoding="utf-8"),
            "#include <string.h>\n",
        )

    def test_c_and_cpp_witnesses_compile_with_assert_and_byteswap_forms(self) -> None:
        c_source = """
#include <assert.h>
#include <byteswap.h>
#include <memory.h>
int main(void) {
    uint16_t value = 0x1234;
    assert(bswap_16(value) == 0x3412);
    return 0;
}
"""
        cpp_source = """
#include <assert.h>
#include <byteswap.h>
#include <memory.h>
extern "C" void __assert_fail(const char *, const char *, int, const char *);
int main() {
    auto value = static_cast<uint16_t>(0x1234);
    assert(bswap_16(value) == 0x3412);
    auto function = &__assert_fail;
    return function != nullptr ? 0 : 1;
}
"""
        with tempfile.TemporaryDirectory(prefix="crabc-standard-header-forms-") as temporary:
            directory = Path(temporary)
            c_path = directory / "probe.c"
            cpp_path = directory / "probe.cpp"
            c_path.write_text(c_source, encoding="utf-8")
            cpp_path.write_text(cpp_source, encoding="utf-8")
            c_result = subprocess.run(
                [
                    "clang",
                    "-std=c11",
                    "-nostdinc",
                    "-I",
                    str(INCLUDE),
                    "-fsyntax-only",
                    str(c_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            cpp_result = subprocess.run(
                [
                    "clang++",
                    "-std=c++17",
                    "-nostdinc",
                    "-I",
                    str(INCLUDE),
                    "-fsyntax-only",
                    str(cpp_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(c_result.returncode, 0, c_result.stderr)
        self.assertEqual(cpp_result.returncode, 0, cpp_result.stderr)

    def test_cpp_assert_reference_is_unmangled(self) -> None:
        source = """
#include <assert.h>
void use_assert_fail(void) {
    __assert_fail("expression", "file", 1, "function");
}
"""
        with tempfile.TemporaryDirectory(prefix="crabc-standard-header-linkage-") as temporary:
            source_path = Path(temporary) / "linkage.cpp"
            object_path = Path(temporary) / "linkage.o"
            source_path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [
                    "clang++",
                    "-std=c++17",
                    "-nostdinc",
                    "-I",
                    str(INCLUDE),
                    "-c",
                    str(source_path),
                    "-o",
                    str(object_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            symbols = subprocess.run(
                ["nm", "-u", str(object_path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(symbols.returncode, 0, symbols.stderr)
        self.assertIn("__assert_fail", symbols.stdout)
        self.assertNotIn("_Z", symbols.stdout)


if __name__ == "__main__":
    unittest.main()
