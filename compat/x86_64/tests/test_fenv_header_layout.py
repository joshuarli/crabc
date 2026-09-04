#!/usr/bin/env python3
"""Regression for the pinned musl x86 fenv physical record boundary."""

from __future__ import annotations

import json
import importlib.util
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = ROOT / "compat" / "x86_64" / "header_record_layout_matrix.py"


def load_matrix():
    spec = importlib.util.spec_from_file_location("fenv_header_layout_matrix", MATRIX_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MATRIX = load_matrix()


class FenvHeaderLayoutTests(unittest.TestCase):
    def test_fenv_record_is_owned_by_target_bits_header(self) -> None:
        """The wrapper must not claim musl's transitive fenv_t declaration."""
        with tempfile.TemporaryDirectory(prefix="crabc-fenv-header-") as temporary:
            source = Path(temporary) / "probe.c"
            source.write_text("#include <fenv.h>\nchar force[sizeof(fenv_t)];\n", encoding="utf-8")
            result = subprocess.run(
                [
                    "clang",
                    "-x",
                    "c",
                    "-std=c11",
                    "-nostdinc",
                    "-I",
                    str(ROOT / "include"),
                    "-Xclang",
                    "-ast-dump=json",
                    "-fsyntax-only",
                    str(source),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        ast = json.loads(result.stdout)
        wrapper_records = MATRIX.direct_records(ast, ROOT / "include", "fenv.h")
        self.assertEqual(wrapper_records, [])

        with tempfile.TemporaryDirectory(prefix="crabc-fenv-bits-") as temporary:
            source = Path(temporary) / "bits.c"
            profile = MATRIX.load_contract().profiles[0]
            bits_ast = MATRIX.ast_for_header(
                "clang",
                profile,
                "bits/fenv.h",
                ROOT / "include",
                MATRIX.inventory.compiler_resource_include("clang"),
                Path("/usr/include"),
                source,
            )
        bits_records = MATRIX.direct_records(bits_ast, ROOT / "include", "bits/fenv.h")
        self.assertEqual([record.key for record in bits_records], ["struct-typedef:fenv_t"])


if __name__ == "__main__":
    unittest.main()
