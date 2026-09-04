#!/usr/bin/env python3
"""Regression for the pinned musl x86 termios physical record boundary."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class TermiosHeaderLayoutTests(unittest.TestCase):
    def test_termios_record_is_owned_by_target_bits_header(self) -> None:
        """The wrapper must not claim musl's transitive termios declaration."""
        with tempfile.TemporaryDirectory(prefix="crabc-termios-header-") as temporary:
            source = Path(temporary) / "probe.c"
            source.write_text(
                "#include <termios.h>\nchar force[sizeof(struct termios)];\n",
                encoding="utf-8",
            )
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
        records = []
        stack = [ast]
        while stack:
            node = stack.pop()
            if (
                node.get("kind") == "RecordDecl"
                and node.get("name") == "termios"
                and node.get("completeDefinition") is True
            ):
                records.append(node)
            stack.extend(child for child in node.get("inner", []) if isinstance(child, dict))
        self.assertEqual(len(records), 1)
        location = records[0].get("loc", {})
        self.assertTrue(str(location.get("file", "")).endswith("include/bits/termios.h"))


if __name__ == "__main__":
    unittest.main()
