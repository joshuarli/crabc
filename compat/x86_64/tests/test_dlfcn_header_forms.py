#!/usr/bin/env python3
"""Regression for the pinned musl dlfcn.h declaration and source form."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "dlfcn.h"
class DlfcnHeaderFormTests(unittest.TestCase):
    def test_header_preserves_pinned_musl_source_contract(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        self.assertIn("#include <features.h>\n", header)
        self.assertIn("#define RTLD_GLOBAL 256\n", header)
        self.assertIn("int    dlclose(void *);\n", header)
        self.assertIn("char  *dlerror(void);\n", header)
        self.assertIn("void  *dlopen(const char *, int);\n", header)
        self.assertIn("#if _REDIR_TIME64\n__REDIR(dlsym, __dlsym_time64);\n#endif\n", header)

    def test_header_compiles_in_c_and_cpp_with_time64_redirect(self) -> None:
        compiler = shutil.which("clang")
        self.assertIsNotNone(compiler, "focused dlfcn-header regression requires clang")
        assert compiler is not None
        source = "#include <dlfcn.h>\nint main(void) { return dlsym(0, 0) != 0; }\n"
        for language, standard in (("c", "c11"), ("c++", "c++17")):
            result = subprocess.run(
                [
                    compiler,
                    "-x",
                    language,
                    f"-std={standard}",
                    "-D_GNU_SOURCE",
                    "-D_REDIRECT_TIME64=1",
                    "-D_REDIR_TIME64=1",
                    "-fsyntax-only",
                    "-nostdinc",
                    "-nostdinc++",
                    "-I",
                    str(ROOT / "include"),
                    "-",
                ],
                cwd=ROOT,
                input=source,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, f"{language} compile failed: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
