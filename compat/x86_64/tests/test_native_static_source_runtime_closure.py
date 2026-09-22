#!/usr/bin/env python3
"""Focused contracts for the native source-runtime Cargo evidence parser."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "native_static_source_runtime_closure.py"
SPEC = importlib.util.spec_from_file_location("native_static_source_runtime_closure", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load native static source-runtime closure helper")
CLOSURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOSURE)


class NativeStaticSourceRuntimeClosureTests(unittest.TestCase):
    def _command(self, *, immediate_abort: bool) -> tuple[list[str], Path, dict[str, Path], Path]:
        work = ROOT / ".work"
        work.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(dir=work))
        self.addCleanup(lambda: __import__("shutil").rmtree(temporary, ignore_errors=True))
        target = temporary / "target"
        target.mkdir()
        source = temporary / "lib.rs"
        source.write_text("#![no_std]\n", encoding="utf-8")
        runtime: dict[str, Path] = {}
        for name in ("core", "alloc", "compiler_builtins"):
            artifact = target / f"lib{name}.rlib"
            artifact.write_bytes(name.encode("ascii"))
            runtime[name] = artifact
        flags = ["-Ztls-model=initial-exec", "-Zunstable-options"]
        flags.append("-Cpanic=immediate-abort" if immediate_abort else "-Cpanic=abort")
        flags.extend(["-Cforce-unwind-tables=no", "-Crelocation-model=static", "-Ccode-model=small"])
        command = [
            "rustc", "--crate-name", "c", "--target", CLOSURE.TARGET, *flags, str(source),
        ]
        for name, artifact in runtime.items():
            command.extend(["--extern", f"{name}={artifact}"])
        return command, target, runtime, source

    def test_primary_record_binds_all_source_runtime_externs(self) -> None:
        command, target, runtime, source = self._command(immediate_abort=True)

        record = CLOSURE.command_record(command, target, runtime, "crabc-libc", source)

        self.assertEqual(set(record["runtime_externs"]), set(runtime))
        self.assertEqual(
            [record["runtime_externs"][name]["path"] for name in sorted(runtime)],
            [str(runtime[name]) for name in sorted(runtime)],
        )

    def test_primary_record_rejects_abort_profile_without_immediate_abort(self) -> None:
        command, target, runtime, source = self._command(immediate_abort=False)

        with self.assertRaisesRegex(CLOSURE.ClosureError, "panic=immediate-abort"):
            CLOSURE.command_record(command, target, runtime, "crabc-libc", source)


if __name__ == "__main__":
    unittest.main()
