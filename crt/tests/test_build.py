#!/usr/bin/env python3
"""Focused contract checks for the Rust-owned CRT object builder."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CRT_ROOT = Path(__file__).resolve().parents[1]
BUILDER = CRT_ROOT / "build.py"


class CrtBuildTests(unittest.TestCase):
    def test_builder_produces_all_aarch64_objects_with_recorded_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "objects"
            result = subprocess.run(
                [sys.executable, str(BUILDER), "--out-dir", str(output)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            report = json.loads((output / "objects.json").read_text())
            self.assertEqual(
                set(report["objects"]),
                {"crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o"},
            )
            self.assertNotEqual(
                report["objects"]["crt1.o"]["sha256"],
                report["objects"]["Scrt1.o"]["sha256"],
            )
            self.assertTrue(report["objects"]["Scrt1.o"]["owned_lifecycle_note"])
            self.assertFalse(report["objects"]["crt1.o"]["owned_lifecycle_note"])
            for name in ("crt1.o", "Scrt1.o", "rcrt1.o"):
                undefined = report["objects"][name]["undefined_symbols"]
                self.assertIn("__libc_start_main", undefined)
                self.assertNotIn("exit", undefined)
            self.assertEqual(report["commands"]["name"], "commands.json")
            self.assertEqual(len(report["commands"]["sha256"]), 64)
            for name, object_report in report["objects"].items():
                self.assertEqual(object_report["path"], name)
                self.assertIn(f"$CRABC_CRT_OUT/{name}", object_report["producer"])
            commands = json.loads((output / "commands.json").read_text())
            self.assertEqual([entry["object"] for entry in commands if entry["kind"] == "compile"], [
                "crt1.o",
                "Scrt1.o",
                "rcrt1.o",
                "crti.o",
                "crtn.o",
            ])
            self.assertEqual(
                [entry["object"] for entry in commands if entry["kind"] == "machine_entry_audit"],
                ["crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o"],
            )
            for name, object_report in report["objects"].items():
                self.assertTrue((output / name).is_file())
                self.assertIn(".note.GNU-stack", object_report["sections"])
                self.assertEqual(object_report["source_languages"], ["Rust"])
                self.assertIn("--emit=obj", object_report["producer"])
            for name in ("crt1.o", "Scrt1.o", "rcrt1.o"):
                machine = report["objects"][name]["entry_machine_contract"]
                self.assertEqual(machine["status"], "verified")
                self.assertTrue(machine["no_return_or_call_before_handoff"])
                self.assertTrue(machine["no_early_system_or_tls_register_read"])

    def test_builder_refuses_source_tree_output(self) -> None:
        result = subprocess.run(
            [sys.executable, str(BUILDER), "--out-dir", str(CRT_ROOT / "generated")],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"must not place generated CRT objects", result.stderr)


if __name__ == "__main__":
    unittest.main()
