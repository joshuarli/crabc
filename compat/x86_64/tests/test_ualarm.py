#!/usr/bin/env python3
"""Contract for the opt-in x86 ``ualarm`` static C ABI artifact."""

from __future__ import annotations

import stat
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_ualarm.rs"
C_HEADER_PROBE = ROOT / "compat" / "x86_64" / "ualarm_header_abi_probe.c"
CXX_HEADER_PROBE = ROOT / "compat" / "x86_64" / "ualarm_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_ualarm_header_abi.sh"
PROBE = ROOT / "compat" / "x86_64" / "libc_ualarm_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_ualarm_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_ualarm.sh"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
PARITY = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class UalarmTests(unittest.TestCase):
    def test_opt_in_ualarm_keeps_the_default_archive_closed(self) -> None:
        required_paths = (
            SOURCE,
            C_HEADER_PROBE,
            CXX_HEADER_PROBE,
            HEADER_RUNNER,
            PROBE,
            START,
            RUNNER,
        )
        for path in required_paths:
            if not path.is_file():
                self.fail(f"missing ualarm input: {path}")

        self.assertEqual(stat.S_IMODE(HEADER_RUNNER.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        for runner in (HEADER_RUNNER, RUNNER):
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
        header = (ROOT / "include" / "unistd.h").read_text(encoding="utf-8")
        c_header_probe = C_HEADER_PROBE.read_text(encoding="utf-8")
        cxx_header_probe = CXX_HEADER_PROBE.read_text(encoding="utf-8")
        header_runner = HEADER_RUNNER.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = tomllib.loads(PARITY.read_text(encoding="utf-8"))

        self.assertIn("x86-ualarm = []", manifest)
        self.assertIn(
            '#[cfg(feature = "x86-ualarm")]\n#[path = "signal_ualarm.rs"]\nmod signal_ualarm;',
            static_root,
        )
        for required in (
            "pinned musl 1.2.6",
            "src/unistd/ualarm.c",
            "src/signal/setitimer.c",
            "raw_syscall::SYS_SETITIMER",
            "pub extern \"C\" fn ualarm(value: c_uint, interval: c_uint) -> c_uint",
            "wrapping_mul",
            "zero-initialized old record",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertIn("unsigned int ualarm(unsigned int, unsigned int);", header)

        for header_probe in (c_header_probe, cxx_header_probe):
            self.assertIn("CRABC_EXPECT_UALARM", header_probe)
            self.assertIn("CRABC_REQUIRE_UALARM_HIDDEN", header_probe)
            self.assertIn("ualarm_signature", header_probe)
        for required in (
            "xopen_600_definitions",
            "bsd_definitions",
            "gnu_definitions",
            "XOPEN=700",
            "retained a mangled",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "raw_setitimer_real",
            "SYS_setitimer == 38",
            "ualarm(200000U, 300000U)",
            "ualarm(1000000U, 0U)",
            "errno != EINVAL",
            "CRABC_UALARM_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertIn("crabc_x86_64_ualarm_probe", start)

        for required in (
            "x86-ualarm",
            "assert_feature_delta",
            "ualarm.lo",
            "--features \"$FEATURE\"",
            "-nostdlib -static",
            "assert_named_syscall ualarm 26",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertNotIn("ualarm", static_exports)
        for required in (
            "ualarm-header-abi)",
            "libc-ualarm)",
            "run_ualarm_header_abi.sh",
            "run_libc_ualarm.sh",
        ):
            self.assertIn(required, dispatcher)

        posix_runtime = next(
            family for family in ledger["family"] if family["id"] == "libc.posix-runtime"
        )
        self.assertEqual("planned", posix_runtime["status"])
        artifact = next(
            record
            for record in posix_runtime["verified_artifact"]
            if record["id"] == "static-c-ualarm"
        )
        self.assertNotIn("capabilities", artifact)
        self.assertIn("ualarm", artifact["description"])
        self.assertIn("does not complete", artifact["description"])
        self.assertIn("libc/src/c_abi/x86_64/signal_ualarm.rs", artifact["source_owners"])
        self.assertEqual(1, len(artifact["native_evidence"]))
        evidence = artifact["native_evidence"][0]
        self.assertEqual("verified", evidence["state"])
        self.assertEqual("./scripts/dev-x86_64.sh libc-ualarm", evidence["command"])
        for boundary in ("does not complete", "public x86 support"):
            self.assertIn(boundary, evidence["scope"])

        feature = next(
            record for record in ledger["feature_archive"] if record["id"] == "x86-ualarm"
        )
        self.assertEqual("verified", feature["state"])
        self.assertEqual([], feature["baseline_features"])
        self.assertEqual(["ualarm"], feature["additive_callables"])


if __name__ == "__main__":
    unittest.main()
