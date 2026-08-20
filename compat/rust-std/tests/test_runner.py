#!/usr/bin/env python3
"""Pure host-side checks for the stock Rust std differential runner."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_rust_std_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class PureHelperTests(unittest.TestCase):
    def test_interpreter_patch_preserves_other_elf_bytes(self) -> None:
        binary = bytearray(256)
        binary[:4] = b"\x7fELF"
        binary[4] = 2
        binary[5] = 1
        binary[18:20] = (183).to_bytes(2, "little")
        binary[32:40] = (64).to_bytes(8, "little")
        binary[54:56] = (56).to_bytes(2, "little")
        binary[56:58] = (1).to_bytes(2, "little")
        binary[64:68] = (3).to_bytes(4, "little")
        binary[72:80] = (192).to_bytes(8, "little")
        binary[96:104] = (26).to_bytes(8, "little")
        binary[192:218] = b"/lib/ld-musl-aarch64.so.1\0"
        patched = RUNNER.patched_interpreter_bytes(bytes(binary), "/tmp/r")
        self.assertEqual(patched[:192], bytes(binary[:192]))
        self.assertEqual(patched[192:218], b"/tmp/r\0" + b"\0" * 19)
        self.assertEqual(patched[218:], bytes(binary[218:]))

    def test_interpreter_patch_rejects_a_path_that_does_not_fit(self) -> None:
        binary = bytearray(256)
        binary[:4] = b"\x7fELF"
        binary[4] = 2
        binary[5] = 1
        binary[18:20] = (183).to_bytes(2, "little")
        binary[32:40] = (64).to_bytes(8, "little")
        binary[54:56] = (56).to_bytes(2, "little")
        binary[56:58] = (1).to_bytes(2, "little")
        binary[64:68] = (3).to_bytes(4, "little")
        binary[72:80] = (192).to_bytes(8, "little")
        binary[96:104] = (4).to_bytes(8, "little")
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.patched_interpreter_bytes(bytes(binary), "/tmp/too-long")

    def test_comparison_keeps_raw_nul_and_signal_status(self) -> None:
        reference = RUNNER.ProcessResult(-11, b"ok\0\n", b"musl\n")
        candidate = RUNNER.ProcessResult(139, b"ok\0\n", b"crabc\n")
        comparison = RUNNER.compare_results(reference, candidate)
        self.assertFalse(comparison["passed"])
        self.assertFalse(comparison["status_match"])
        self.assertFalse(comparison["stderr_match"])
        self.assertEqual(comparison["reference"]["stdout"]["hex"], "6f6b000a")
        self.assertEqual(comparison["normalization"], "none")

    def test_environment_has_one_explicit_boundary(self) -> None:
        previous = dict(os.environ)
        try:
            os.environ.update(
                {
                    "LD_LIBRARY_PATH": "/glibc",
                    "LD_PRELOAD": "/glibc.so",
                    "RUSTFLAGS": "-C link-dead-code",
                    "CRABC_RUST_STD_TEST": "wrong",
                }
            )
            environment = RUNNER.sanitize_environment()
        finally:
            for key in tuple(os.environ):
                if key not in previous:
                    del os.environ[key]
            os.environ.update(previous)
        self.assertNotIn("LD_LIBRARY_PATH", environment)
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertNotIn("RUSTFLAGS", environment)
        self.assertEqual(environment["CRABC_RUST_STD_TEST"], "musl-abi")
        self.assertEqual(environment["PATH"], "/bin:/usr/bin")

    def test_fixture_is_dependency_free_and_exercises_requested_surfaces(self) -> None:
        source = RUNNER.FIXTURE.read_text(encoding="utf-8")
        for marker in (
            "Vec",
            "String",
            "read_dir",
            "TcpListener",
            "UdpSocket",
            "to_socket_addrs",
            "Mutex",
            "Condvar",
            "wait_with_output",
            "println!",
        ):
            self.assertIn(marker, source)
        cargo = RUNNER.FIXTURE.parents[1] / "Cargo.toml"
        self.assertNotIn("[dependencies]", cargo.read_text(encoding="utf-8"))

    def test_dependent_fixture_is_a_pinned_normal_cargo_application(self) -> None:
        fixture = RUNNER.FIXTURE.parents[2] / "dependent-fixture/src/main.rs"
        manifest = fixture.parents[1] / "Cargo.toml"
        lock = manifest.with_name("Cargo.lock")
        self.assertTrue(fixture.is_file())
        self.assertTrue(manifest.is_file())
        self.assertTrue(lock.is_file())
        self.assertEqual(RUNNER.fixture_package_name(manifest), "crabc-rust-dependent-fixture")
        self.assertTrue(RUNNER.fixture_has_dependencies(manifest))
        cargo = manifest.read_text(encoding="utf-8")
        for dependency in ("async-net = \"=2.0.0\"", "futures-lite = \"=2.6.0\"", "smol = \"=2.0.2\""):
            self.assertIn(dependency, cargo)
        lock_text = lock.read_text(encoding="utf-8")
        self.assertIn("version = 4", lock_text)
        for dependency in ("name = \"async-net\"", "name = \"futures-lite\"", "name = \"smol\""):
            self.assertIn(dependency, lock_text)
        self.assertGreaterEqual(lock_text.count("checksum = \""), 3)
        source = fixture.read_text(encoding="utf-8")
        for marker in (
            "TcpListener::bind",
            "smol::block_on",
            "Mutex",
            "Condvar",
            "wait_with_output",
            "ErrorKind::NotFound",
        ):
            self.assertIn(marker, source)

    def test_fixture_manifest_helpers_distinguish_default_and_dependent_apps(self) -> None:
        default_manifest = RUNNER.FIXTURE.parents[1] / "Cargo.toml"
        dependent_manifest = RUNNER.FIXTURE.parents[2] / "dependent-fixture/Cargo.toml"
        self.assertEqual(RUNNER.fixture_package_name(default_manifest), "crabc-rust-std-fixture")
        self.assertFalse(RUNNER.fixture_has_dependencies(default_manifest))
        self.assertEqual(RUNNER.fixture_package_name(dependent_manifest), "crabc-rust-dependent-fixture")
        self.assertTrue(RUNNER.fixture_has_dependencies(dependent_manifest))


class PinTests(unittest.TestCase):
    def test_upstream_pins_match_stage_target(self) -> None:
        pins = RUNNER.load_pins()
        self.assertEqual(pins["environment"]["platform"], "linux/arm64")
        self.assertEqual(pins["environment"]["rust_toolchain"], RUNNER.TOOLCHAIN)
        self.assertEqual(pins["musl"]["version"], RUNNER.MUSL_VERSION)

    def test_default_report_uses_shared_generated_report_root(self) -> None:
        self.assertEqual(RUNNER.REPORT, RUNNER.ROOT / "compat/reports/rust-std/latest.json")


if __name__ == "__main__":
    unittest.main()
