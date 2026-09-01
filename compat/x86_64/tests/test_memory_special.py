#!/usr/bin/env python3
"""Contract for the opt-in x86 ``explicit_bzero``/``swab`` C ABI artifact."""

from __future__ import annotations

import stat
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_special.rs"
C_HEADER_PROBE = ROOT / "compat" / "x86_64" / "memory_special_header_abi_probe.c"
CXX_HEADER_PROBE = ROOT / "compat" / "x86_64" / "memory_special_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_memory_special_header_abi.sh"
PROBE = ROOT / "compat" / "x86_64" / "libc_memory_special_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_memory_special_start.S"
DEAD_WIPE_PROBE = ROOT / "compat" / "x86_64" / "libc_explicit_bzero_dead_wipe_probe.c"
DEAD_WIPE_START = ROOT / "compat" / "x86_64" / "libc_explicit_bzero_dead_wipe_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_memory_special.sh"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
PARITY = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class MemorySpecialTests(unittest.TestCase):
    def test_opt_in_explicit_bzero_swab_artifact_is_non_eliding_and_bounded(self) -> None:
        for path in (
            SOURCE,
            C_HEADER_PROBE,
            CXX_HEADER_PROBE,
            HEADER_RUNNER,
            PROBE,
            START,
            DEAD_WIPE_PROBE,
            DEAD_WIPE_START,
            RUNNER,
        ):
            self.assertTrue(path.is_file(), f"missing memory-special input: {path}")
        for runner in (HEADER_RUNNER, RUNNER):
            self.assertEqual(stat.S_IMODE(runner.stat().st_mode), 0o755)
            syntax = subprocess.run(
                ["bash", "-n", str(runner)],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

        manifest = MANIFEST.read_text(encoding="utf-8")
        static_root = STATIC_ROOT.read_text(encoding="utf-8")
        source = SOURCE.read_text(encoding="utf-8")
        c_header_probe = C_HEADER_PROBE.read_text(encoding="utf-8")
        cxx_header_probe = CXX_HEADER_PROBE.read_text(encoding="utf-8")
        header_runner = HEADER_RUNNER.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")
        dead_wipe_probe = DEAD_WIPE_PROBE.read_text(encoding="utf-8")
        dead_wipe_start = DEAD_WIPE_START.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        parity = PARITY.read_text(encoding="utf-8")
        static_exports = STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()

        self.assertIn("x86-memory-special = []", manifest)
        self.assertIn(
            '#[cfg(feature = "x86-memory-special")]\n'
            '#[path = "memory_special.rs"]\n'
            "mod memory_special;",
            static_root,
        )
        for required in (
            "Bounded Linux/x86-64 explicit_bzero/swab C ABI boundary",
            "src/string/explicit_bzero.c::explicit_bzero",
            "src/string/swab.c::swab",
            'fn memset(destination: *mut c_void, byte: c_int, count: usize)',
            "core::arch::asm!",
            "cleared = in(reg) cleared",
            "# Safety",
            'pub unsafe extern "C" fn explicit_bzero',
            'pub unsafe extern "C" fn swab',
        ):
            self.assertIn(required, source)
        for forbidden in ("alloc::", "pthread_", "raw_syscall", "errno"):
            self.assertNotIn(forbidden, source)

        for header_probe in (c_header_probe, cxx_header_probe):
            self.assertIn("explicit_bzero", header_probe)
            self.assertIn("swab", header_probe)
        for required in (
            "CRABC_EXPECT_EXPLICIT_BZERO",
            "CRABC_EXPECT_SWAB",
            "CRABC_REQUIRE_EXPLICIT_BZERO_HIDDEN",
            "CRABC_REQUIRE_SWAB_HIDDEN",
            "unmangled explicit_bzero",
            "unmangled swab",
            "strict_definitions",
            "xopen_definitions",
            "bsd_definitions",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "check_explicit_bzero_matrix",
            "check_swab_matrix",
            "CRABC_MEMORY_SPECIAL_MAX_OFFSET = 7",
            "-1, 0, 1, 2, 3",
            "odd trailing byte",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_memory_special_probe", start)
        self.assertIn("__attribute__((noinline, used))", dead_wipe_probe)
        self.assertIn("explicit_bzero(secret, sizeof(secret))", dead_wipe_probe)
        self.assertIn("crabc_x86_64_explicit_bzero_dead_wipe", dead_wipe_start)

        for required in (
            "x86-memory-special",
            "assert_feature_delta",
            "run_memory_special_header_abi.sh",
            "explicit_bzero\\nswab",
            "-O3",
            "dead-wipe",
            "retains no optimized explicit_bzero call or zeroing stores",
            "calls no selected memset owner",
            "-nostdlib -static",
            "candidate unexpectedly selects TLS",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertNotIn("explicit_bzero", static_exports)
        self.assertNotIn("swab", static_exports)
        for required in (
            "run_memory_special_header_abi()",
            "run_libc_memory_special_probe()",
            "memory-special-header-abi)",
            "libc-memory-special)",
            "libc-memory-special takes no arguments",
        ):
            self.assertIn(required, dispatcher)

        ledger = tomllib.loads(parity)
        posix_runtime = next(
            family for family in ledger["family"] if family["id"] == "libc.posix-runtime"
        )
        self.assertEqual("planned", posix_runtime["status"])
        artifact = next(
            record
            for record in posix_runtime["verified_artifact"]
            if record["id"] == "static-c-explicit-bzero-swab"
        )
        self.assertNotIn("capabilities", artifact)
        self.assertIn("x86-memory-special", artifact["description"])
        self.assertIn("does not complete or promote memory.bytes-special", artifact["description"])
        self.assertIn(
            "libc/src/c_abi/x86_64/memory_special.rs", artifact["source_owners"]
        )
        self.assertEqual(1, len(artifact["native_evidence"]))
        evidence = artifact["native_evidence"][0]
        self.assertEqual("verified", evidence["state"])
        self.assertEqual(
            "./scripts/dev-x86_64.sh libc-memory-special", evidence["command"]
        )
        for boundary in (
            "exactly explicit_bzero and swab",
            "does not complete or promote memory.bytes-special",
            "public x86 support",
        ):
            self.assertIn(boundary, evidence["scope"])


if __name__ == "__main__":
    unittest.main()
