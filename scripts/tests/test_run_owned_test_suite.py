"""Focused cleanup and isolation checks for the owned-test launcher."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("crabc_run_owned_test_suite", ROOT / "scripts/run_owned_test_suite.py")
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class DebugRuntimeAliasTests(unittest.TestCase):
    def create_layout(self, root: Path) -> tuple[Path, Path]:
        installed = root / "sysroot/usr/lib"
        debug = root / "debug"
        installed.mkdir(parents=True)
        debug.mkdir()
        (installed / "libc.so").write_bytes(b"installed libc")
        (installed / "libdl.so").symlink_to("libc.so")
        (installed / "libpthread.so").symlink_to("libc.so")
        (installed / "not-runtime.so").write_bytes(b"not libc")
        (installed / "libnot-runtime.so").symlink_to("not-runtime.so")
        (debug / "libc.so").write_bytes(b"debug libc")
        (debug / "libldso.so").write_bytes(b"debug loader")
        return root / "sysroot", debug / "libldso.so"

    def test_aliases_mirror_only_installed_libc_aliases_and_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot, loader = self.create_layout(Path(temporary))
            debug = loader.parent
            with RUNNER.staged_debug_runtime_aliases(sysroot, loader):
                for name in ("libdl.so", "libpthread.so"):
                    self.assertTrue((debug / name).is_symlink())
                    self.assertEqual((debug / name).readlink(), Path("libc.so"))
                self.assertFalse((debug / "libnot-runtime.so").exists())
            for name in ("libdl.so", "libpthread.so"):
                self.assertFalse((debug / name).exists())
                self.assertFalse((debug / name).is_symlink())

    def test_existing_alias_rejects_without_leaving_a_partial_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot, loader = self.create_layout(Path(temporary))
            debug = loader.parent
            (debug / "libpthread.so").write_bytes(b"unexpected artifact")
            with self.assertRaises(RUNNER.TestSuiteError):
                with RUNNER.staged_debug_runtime_aliases(sysroot, loader):
                    self.fail("an existing debug alias must reject staging")
            self.assertFalse((debug / "libdl.so").exists())
            self.assertTrue((debug / "libpthread.so").is_file())


if __name__ == "__main__":
    unittest.main()
