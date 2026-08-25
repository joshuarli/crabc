#!/usr/bin/env python3
"""Pure host-side tests for the Lua owned-sysroot runner."""

from __future__ import annotations

import importlib.util
import io
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_lua_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class ManifestTests(unittest.TestCase):
    def test_lua_pin_is_complete_and_uses_the_expected_release(self) -> None:
        manifest = RUNNER.load_manifest()
        lua = manifest["lua"]
        self.assertEqual(lua["version"], "5.4.8")
        self.assertEqual(lua["archive_root"], "lua-5.4.8")
        self.assertEqual(
            lua["sha256"],
            "4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae",
        )
        self.assertEqual(manifest["musl"]["version"], "1.2.6")

    def test_source_lists_are_nonempty_and_do_not_repeat_or_include_mains(self) -> None:
        sources = (*RUNNER.CORE_SOURCES, *RUNNER.LIB_SOURCES)
        self.assertEqual(len(sources), len(set(sources)))
        self.assertNotIn("lua.c", sources)
        self.assertNotIn("luac.c", sources)
        self.assertGreater(len(RUNNER.CORE_SOURCES), 10)
        self.assertGreater(len(RUNNER.LIB_SOURCES), 10)

    def test_safe_extract_accepts_the_archive_root_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "lua.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                directory = tarfile.TarInfo("lua-5.4.8")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                stream.addfile(directory)
                source = tarfile.TarInfo("lua-5.4.8/src/lua.c")
                contents = b"int main(void) { return 0; }\n"
                source.size = len(contents)
                source.mode = 0o644
                stream.addfile(source, io.BytesIO(contents))
            extracted = RUNNER.safe_extract(archive, root / "out", "lua-5.4.8")
            self.assertEqual((extracted / "src/lua.c").read_bytes(), contents)


class ElfAndDiagnosticTests(unittest.TestCase):
    def test_interpreter_patch_preserves_bytes_outside_interp(self) -> None:
        binary = bytearray(320)
        binary[:4] = b"\x7fELF"
        binary[4] = 2
        binary[5] = 1
        binary[18:20] = (183).to_bytes(2, "little")
        binary[32:40] = (64).to_bytes(8, "little")
        binary[54:56] = (56).to_bytes(2, "little")
        binary[56:58] = (1).to_bytes(2, "little")
        binary[64:68] = (3).to_bytes(4, "little")
        binary[72:80] = (192).to_bytes(8, "little")
        binary[96:104] = (60).to_bytes(8, "little")
        binary[192:252] = b"/workspace/candidate/lib/ld.so\0".ljust(60, b"\0")
        patched = RUNNER.patch_interpreter_bytes(bytes(binary), "/opt/musl-1.2.6/lib/ld-musl-aarch64.so.1")
        self.assertEqual(patched[:192], bytes(binary[:192]))
        self.assertIn(b"/opt/musl-1.2.6", patched[192:252])
        self.assertEqual(patched[252:], bytes(binary[252:]))

    def test_interpreter_patch_rejects_wrong_machine_and_overlong_path(self) -> None:
        binary = bytearray(256)
        binary[:4] = b"\x7fELF"
        binary[4] = 2
        binary[5] = 1
        binary[18:20] = (62).to_bytes(2, "little")
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.patch_interpreter_bytes(bytes(binary), "/tmp/ld")

    def test_syscall_summary_counts_calls_and_errors(self) -> None:
        summary = RUNNER.syscall_summary(
            "123 openat(AT_FDCWD, \"/x\", O_RDONLY) = 3\n"
            "123 close(3) = 0\n"
            "124 openat(AT_FDCWD, \"/missing\", O_RDONLY) = -1 ENOENT\n"
        )
        self.assertEqual(summary["total_calls"], 3)
        self.assertEqual(summary["calls"], {"close": 1, "openat": 2})
        self.assertEqual(summary["errors"], {"openat": 1})


class FixtureAndEnvironmentTests(unittest.TestCase):
    def test_fixture_contract_markers_are_present(self) -> None:
        for name in ("header_probe.c", "crabc_probe.c", "crabc_fail.c", "exercise.lua"):
            self.assertTrue((RUNNER.FIXTURES / name).is_file(), name)
        source = (RUNNER.FIXTURES / "exercise.lua").read_text(encoding="utf-8")
        for marker in ("require(\"crabc_probe\")", "crabc_missing", "crabc_fail", "maps-ready", "utf8", "io.popen"):
            self.assertIn(marker, source)

    def test_sanitized_environment_removes_runtime_path_overrides(self) -> None:
        prior = dict(os.environ)
        try:
            os.environ.update({"LD_LIBRARY_PATH": "/bad", "LUA_PATH": "/bad", "CRABC_LUA_ENV": "bad"})
            environment = RUNNER.sanitize_environment()
        finally:
            for key in tuple(os.environ):
                if key not in prior:
                    del os.environ[key]
            os.environ.update(prior)
        self.assertNotIn("LD_LIBRARY_PATH", environment)
        self.assertNotIn("LUA_PATH", environment)
        self.assertNotIn("CRABC_LUA_ENV", environment)
        self.assertEqual(environment["LC_ALL"], "C")


if __name__ == "__main__":
    unittest.main()
