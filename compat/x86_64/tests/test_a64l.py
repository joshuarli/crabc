#!/usr/bin/env python3
"""Contract for the opt-in x86 ``a64l`` static C ABI artifact."""

from __future__ import annotations

import stat
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "a64l.rs"
C_HEADER_PROBE = ROOT / "compat" / "x86_64" / "l64a_header_abi_probe.c"
CXX_HEADER_PROBE = ROOT / "compat" / "x86_64" / "l64a_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_l64a_header_abi.sh"
PROBE = ROOT / "compat" / "x86_64" / "libc_a64l_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_a64l_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_a64l.sh"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
PARITY = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class A64lTests(unittest.TestCase):
    def test_opt_in_decoder_is_source_split_and_stateless(self) -> None:
        for path in (SOURCE, C_HEADER_PROBE, CXX_HEADER_PROBE, HEADER_RUNNER, PROBE, START, RUNNER):
            self.assertTrue(path.is_file(), f"missing a64l input: {path}")
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
        runner = RUNNER.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        static_exports = STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()
        ledger = tomllib.loads(PARITY.read_text(encoding="utf-8"))

        self.assertIn("x86-a64l = []", manifest)
        self.assertIn("no byte-string", manifest)
        self.assertNotIn("needs the selected byte-string strchr owner", manifest)
        self.assertIn(
            '#[cfg(feature = "x86-a64l")]\n#[path = "a64l.rs"]\nmod a64l;',
            static_root,
        )
        self.assertIn("no\n// byte-string archive dependency", static_root)
        self.assertNotIn("composes the selected byte-string `strchr` owner", static_root)
        for required in (
            "Pinned musl 1.2.6",
            "src/misc/a64l.c::a64l",
            "DIGITS",
            "equivalent bounded scan",
            "fn find_digit",
            "for shift in (0..36).step_by(6)",
            "while index < 64",
            'pub unsafe extern "C" fn a64l',
            "# Safety",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "static mut",
            "alloc::",
            "errno::",
            "__errno_location",
            "raw_syscall",
            "thread_local",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn('unsafe extern "C" {', source)

        for header_probe in (c_header_probe, cxx_header_probe):
            self.assertIn("a64l", header_probe)
            self.assertIn("long", header_probe)
            self.assertIn("CRABC_EXPECT_A64L", header_probe)
            self.assertIn("CRABC_REQUIRE_A64L_HIDDEN", header_probe)
        for required in (
            "a64l/l64a",
            "CRABC_EXPECT_A64L",
            "CRABC_REQUIRE_A64L_HIDDEN",
            "${symbol} is visible",
            "unmangled a64l",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "check_alphabet",
            "check_bit_packing",
            "check_invalid_and_bound",
            "nul_with_suffix",
            "check_signed_result",
            "check_input_is_unchanged",
            '".....0"',
            "CRABC_A64L_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_a64l_probe", start)
        self.assertNotIn("ARCH_SET_FS", start)

        for required in (
            "x86-a64l",
            "assert_feature_delta",
            "run_l64a_header_abi.sh",
            "a64l\\n",
            "a64l owner has an unexpected direct dependency",
            "l64a|strchr|index|memchr",
            "-nostdlib -static",
            "--gc-sections",
            "candidate unexpectedly selects TLS",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertNotIn("a64l", static_exports)
        for required in (
            "libc-a64l)",
            "libc-a64l takes no arguments",
            "run_in_container bash /workspace/compat/x86_64/run_libc_a64l.sh",
        ):
            self.assertIn(required, dispatcher)

        family = next(
            family for family in ledger["family"] if family["id"] == "libc.c-abi-compat"
        )
        self.assertEqual("planned", family["status"])
        artifact = next(
            record for record in family["verified_artifact"] if record["id"] == "static-c-a64l"
        )
        self.assertNotIn("capabilities", artifact)
        self.assertIn("x86-a64l", artifact["description"])
        self.assertIn("does not complete", artifact["description"])
        self.assertIn("libc/src/c_abi/x86_64/a64l.rs", artifact["source_owners"])
        self.assertIn("scripts/check_structure.py", artifact["source_owners"])
        self.assertNotIn("libc/src/c_abi/x86_64/byte_strings.rs", artifact["source_owners"])
        self.assertEqual(1, len(artifact["native_evidence"]))
        evidence = artifact["native_evidence"][0]
        self.assertEqual("verified", evidence["state"])
        self.assertEqual("./scripts/dev-x86_64.sh libc-a64l", evidence["command"])
        for boundary in (
            "exactly a64l",
            "does not complete",
            "public x86 support",
        ):
            self.assertIn(boundary, evidence["scope"])


if __name__ == "__main__":
    unittest.main()
